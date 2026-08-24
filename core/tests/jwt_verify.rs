// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end verification tests: sign real tokens with the fixture RSA key
//! and run them through JwtVerifier against the fixture JWKS.

use std::time::{SystemTime, UNIX_EPOCH};

use crudeoauth_core::jwt::{JwtPolicy, JwtVerifier, OAuthError};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

const KID: &str = "test-key-1";
const ISSUER: &str = "https://sso.example.org/realms/master";
const AUDIENCE: &str = "ldaps://example.org/";

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn encoding_key() -> EncodingKey {
    EncodingKey::from_rsa_pem(include_bytes!("fixtures/test_rsa.pem")).unwrap()
}

fn policy() -> JwtPolicy {
    JwtPolicy {
        uid_attr: "preferred_username".into(),
        grace: 3,
        trusted_issuer: ISSUER.into(),
        trusted_audiences: vec![AUDIENCE.into()],
        trusted_authorized_parties: vec![],
        required_scopes: vec![],
        disallowed_usernames: vec![],
        allowed_algorithms: None,
        disallowed_algorithms: vec![],
    }
}

fn verifier(policy: JwtPolicy) -> JwtVerifier {
    JwtVerifier::from_jwks_json(policy, include_str!("fixtures/jwks.json")).unwrap()
}

fn base_claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now() + 300,
        "iat": now(),
        "preferred_username": "administrator",
        "scope": "openid profile email",
    })
}

fn sign(claims: &Value) -> String {
    sign_with(claims, Algorithm::RS256, Some(KID))
}

fn sign_with(claims: &Value, alg: Algorithm, kid: Option<&str>) -> String {
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    encode(&header, claims, &encoding_key()).unwrap()
}

#[test]
fn valid_token_yields_username() {
    let token = sign(&base_claims());
    assert_eq!(verifier(policy()).verify(&token).unwrap(), "administrator");
}

#[test]
fn wrong_issuer_is_rejected() {
    let mut claims = base_claims();
    claims["iss"] = json!("https://evil.example.org/realms/master");
    let err = verifier(policy()).verify(&sign(&claims)).unwrap_err();
    assert!(matches!(err, OAuthError::InvalidIssuer { .. }), "{err:?}");
}

#[test]
fn missing_issuer_is_rejected() {
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("iss");
    let err = verifier(policy()).verify(&sign(&claims)).unwrap_err();
    assert!(matches!(err, OAuthError::InvalidIssuer { found: None }), "{err:?}");
}

#[test]
fn wrong_audience_is_rejected() {
    let mut claims = base_claims();
    claims["aud"] = json!("ldaps://other.example.org/");
    let err = verifier(policy()).verify(&sign(&claims)).unwrap_err();
    assert_eq!(err, OAuthError::InvalidAudience);
}

#[test]
fn audience_array_with_match_is_accepted() {
    let mut claims = base_claims();
    claims["aud"] = json!(["something-else", AUDIENCE]);
    assert!(verifier(policy()).verify(&sign(&claims)).is_ok());
}

#[test]
fn expired_token_is_rejected() {
    let mut claims = base_claims();
    claims["exp"] = json!(now() - 60);
    let err = verifier(policy()).verify(&sign(&claims)).unwrap_err();
    assert_eq!(err, OAuthError::ClaimExpired);
}

#[test]
fn expiry_within_grace_is_accepted() {
    let policy = JwtPolicy { grace: 120, ..policy() };
    let mut claims = base_claims();
    claims["exp"] = json!(now() - 60);
    assert!(verifier(policy).verify(&sign(&claims)).is_ok());
}

#[test]
fn future_nbf_is_rejected() {
    let mut claims = base_claims();
    claims["nbf"] = json!(now() + 300);
    let err = verifier(policy()).verify(&sign(&claims)).unwrap_err();
    assert_eq!(err, OAuthError::ClaimExpired);
}

// Documents a quirk inherited from the C implementation: exp is validated
// only when present, so a token without exp never expires.
#[test]
fn missing_exp_is_currently_accepted() {
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("exp");
    assert!(verifier(policy()).verify(&sign(&claims)).is_ok());
}

#[test]
fn unknown_kid_is_rejected() {
    let token = sign_with(&base_claims(), Algorithm::RS256, Some("nonexistent-kid"));
    let err = verifier(policy()).verify(&token).unwrap_err();
    assert!(matches!(err, OAuthError::UnknownSigningKey { kid: Some(_) }), "{err:?}");
}

#[test]
fn missing_kid_is_rejected() {
    let token = sign_with(&base_claims(), Algorithm::RS256, None);
    let err = verifier(policy()).verify(&token).unwrap_err();
    assert!(matches!(err, OAuthError::UnknownSigningKey { kid: None }), "{err:?}");
}

#[test]
fn hmac_signed_token_is_rejected() {
    // Algorithm-confusion attempt: HS256 token whose header names a trusted
    // RSA kid must never reach HMAC verification with public key material.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.into());
    let token = encode(
        &header,
        &base_claims(),
        &EncodingKey::from_secret(b"attacker-known-secret"),
    )
    .unwrap();
    let err = verifier(policy()).verify(&token).unwrap_err();
    assert_eq!(err, OAuthError::InvalidSignature);
}

#[test]
fn alg_differing_from_jwk_alg_is_rejected() {
    // The fixture JWK pins alg=RS256; an RS384 header must not pass the
    // metadata cross-check even though the RSA key could verify it.
    let token = sign_with(&base_claims(), Algorithm::RS384, Some(KID));
    let err = verifier(policy()).verify(&token).unwrap_err();
    assert_eq!(err, OAuthError::InvalidSignature);
}

#[test]
fn tampered_payload_is_rejected() {
    // Swap the payload of a validly signed token, keeping the original signature.
    let token = sign(&base_claims());
    let mut parts: Vec<&str> = token.split('.').collect();
    let mut forged_claims = base_claims();
    forged_claims["preferred_username"] = json!("root");
    let payload = base64_url(&serde_json::to_vec(&forged_claims).unwrap());
    parts[1] = &payload;
    let token = parts.join(".");
    let err = verifier(policy()).verify(&token).unwrap_err();
    assert_eq!(err, OAuthError::InvalidSignature);
}

#[test]
fn missing_required_scope_is_rejected() {
    let policy = JwtPolicy { required_scopes: vec!["ldap-access".into()], ..policy() };
    let err = verifier(policy).verify(&sign(&base_claims())).unwrap_err();
    assert!(matches!(err, OAuthError::MissingScope { .. }), "{err:?}");
}

#[test]
fn present_required_scope_is_accepted() {
    let policy = JwtPolicy { required_scopes: vec!["openid".into()], ..policy() };
    assert!(verifier(policy).verify(&sign(&base_claims())).is_ok());
}

#[test]
fn scope_matching_is_not_substring_based() {
    let policy = JwtPolicy { required_scopes: vec!["open".into()], ..policy() };
    let err = verifier(policy).verify(&sign(&base_claims())).unwrap_err();
    assert!(matches!(err, OAuthError::MissingScope { .. }), "{err:?}");
}

#[test]
fn azp_checks() {
    let azp_policy = || JwtPolicy {
        trusted_authorized_parties: vec!["https://client.example.org/oidc/".into()],
        ..policy()
    };

    // Quirk preserved from C: a token without azp passes even with trusted_azp set.
    assert!(verifier(azp_policy()).verify(&sign(&base_claims())).is_ok());

    let mut claims = base_claims();
    claims["azp"] = json!("https://client.example.org/oidc/");
    assert!(verifier(azp_policy()).verify(&sign(&claims)).is_ok());

    claims["azp"] = json!("https://evil.example.org/");
    let err = verifier(azp_policy()).verify(&sign(&claims)).unwrap_err();
    assert!(matches!(err, OAuthError::InvalidAuthorizedParty { .. }), "{err:?}");
}

#[test]
fn missing_uid_claim_is_rejected() {
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("preferred_username");
    let err = verifier(policy()).verify(&sign(&claims)).unwrap_err();
    assert!(matches!(err, OAuthError::MissingUidClaim { .. }), "{err:?}");
}

#[test]
fn garbage_tokens_are_parse_errors() {
    let v = verifier(policy());
    assert_eq!(v.verify("").unwrap_err(), OAuthError::ParseError);
    assert_eq!(v.verify("not-a-jwt").unwrap_err(), OAuthError::ParseError);
    assert_eq!(v.verify("aaaa.bbbb.cccc.dddd").unwrap_err(), OAuthError::ParseError);
    assert_eq!(v.verify(&"x".repeat(64)).unwrap_err(), OAuthError::ParseError);
}

fn base64_url(data: &[u8]) -> String {
    // Minimal base64url (no padding) to avoid a test-only dependency.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}
