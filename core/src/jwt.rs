// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::{HashMap, HashSet}, fmt, time::{SystemTime, UNIX_EPOCH}};

use jsonwebtoken::{
    decode, decode_header,
    errors::ErrorKind,
    jwk::Jwk,
    Algorithm, DecodingKey, Validation,
};
use serde_json::Value;

const MIN_JWT_LEN: usize = 16;

// When no oauthbearer_allowed_alg option is configured: asymmetric JWS algorithms
// supported by jsonwebtoken 8.3 are accepted, HMAC algorithms are not.
const LEGACY_ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthError {
    MissingUidClaim { claim: String },
    DisallowedUsername { username: String },
    ParseError,
    InvalidIssuer { found: Option<String> },
    InvalidAudience,
    MissingScope { scope: String },
    InvalidAuthorizedParty { found: Option<String> },
    ClaimExpired,
    InvalidSignature,
    UnknownSigningKey { kid: Option<String> },
    ConfigError(String),
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUidClaim { claim } => write!(f, "token contains no non-empty {claim} claim"),
            Self::DisallowedUsername { username } => write!(f, "username {username:?} is disallowed"),
            Self::ParseError => f.write_str("there was an error parsing the JWT"),
            Self::InvalidIssuer { found } => write!(f, "invalid or missing issuer: {found:?}"),
            Self::InvalidAudience => f.write_str("invalid or missing audience"),
            Self::MissingScope { scope } => write!(f, "required scope {scope:?} is missing"),
            Self::InvalidAuthorizedParty { found } => write!(f, "invalid authorized party: {found:?}"),
            Self::ClaimExpired => f.write_str("token is expired or not yet valid"),
            Self::InvalidSignature => f.write_str("JWT signature is invalid"),
            Self::UnknownSigningKey { kid } => write!(f, "JWT signing key is unknown: {kid:?}"),
            Self::ConfigError(msg) => write!(f, "JWT configuration error: {msg}"),
        }
    }
}

impl std::error::Error for OAuthError {}

#[derive(Debug, Clone)]
struct JwkMeta {
    alg: Option<String>,
    use_: Option<String>,
    key_ops: Vec<String>,
    kty: String,
    crv: Option<String>,
}

#[derive(Clone)]
struct SigningKey {
    key: DecodingKey,
    meta: JwkMeta,
}

#[derive(Debug, Clone)]
pub struct JwtPolicy {
    pub uid_attr: String,
    pub grace: i64,
    pub trusted_issuer: String,
    pub trusted_audiences: Vec<String>,
    pub trusted_authorized_parties: Vec<String>,
    pub required_scopes: Vec<String>,

    // case-insensitive deny-list applied to the resolved uid claim.
    pub disallowed_usernames: Vec<String>,

    // None means the historical/default allow-list above. Some(...) means the
    // administrator explicitly selected the complete allow-list.
    pub allowed_algorithms: Option<Vec<Algorithm>>,

    // Always subtracted from either the configured or historical allow-list.
    pub disallowed_algorithms: Vec<Algorithm>,
}

#[derive(Clone)]
pub struct JwtVerifier {
    policy: JwtPolicy,
    keys: HashMap<String, SigningKey>,
}

impl JwtVerifier {
    pub fn from_jwks_json(policy: JwtPolicy, jwks_json: &str) -> Result<Self, OAuthError> {
        if policy.trusted_audiences.is_empty() {
            return Err(OAuthError::ConfigError("no trusted audiences configured".into()));
        }
        if policy.trusted_issuer.is_empty() {
            return Err(OAuthError::ConfigError("no trusted issuer configured".into()));
        }
        if policy.allowed_algorithms.as_ref().is_some_and(Vec::is_empty) {
            return Err(OAuthError::ConfigError(
                "oauthbearer_allowed_alg was configured but contains no algorithms".into(),
            ));
        }

        let raw: Value = serde_json::from_str(jwks_json)
            .map_err(|e| OAuthError::ConfigError(format!("invalid JWKS JSON: {e}")))?;
        let raw_keys = raw.get("keys").and_then(Value::as_array)
            .ok_or_else(|| OAuthError::ConfigError("JWKS has no keys array".into()))?;
        if raw_keys.is_empty() {
            return Err(OAuthError::ConfigError("JWKS contains no keys".into()));
        }

        let mut seen_kids = HashSet::new();
        let mut keys = HashMap::new();

        for raw_key in raw_keys {
            let Some(obj) = raw_key.as_object() else {
                return Err(OAuthError::ConfigError("JWKS key is not an object".into()));
            };
            let Some(kid) = obj.get("kid").and_then(Value::as_str) else {
                // We select keys by kid. A key without kid cannot be used by this verifier.
                continue;
            };
            if !seen_kids.insert(kid.to_owned()) {
                return Err(OAuthError::ConfigError(format!("duplicate JWK kid {kid:?}")));
            }

            let meta = JwkMeta {
                alg: obj.get("alg").and_then(Value::as_str).map(str::to_owned),
                use_: obj.get("use").and_then(Value::as_str).map(str::to_owned),
                key_ops: obj.get("key_ops")
                    .and_then(Value::as_array)
                    .map(|v| v.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                    .unwrap_or_default(),
                kty: obj.get("kty").and_then(Value::as_str).unwrap_or("").to_owned(),
                crv: obj.get("crv").and_then(Value::as_str).map(str::to_owned),
            };

            // A JWKS may legitimately contain encryption keys alongside signing
            // keys. Ignore those instead of rejecting the complete JWKS.
            if meta.use_.as_deref().is_some_and(|v| v != "sig") {
                continue;
            }
            if !meta.key_ops.is_empty() && !meta.key_ops.iter().any(|v| v == "verify") {
                continue;
            }

            // If alg is present and jsonwebtoken does not support it as JWS,
            // this is not a usable signing key for this verifier. This is what
            // makes RSA-OAEP (a JWE algorithm) harmless at JWKS load time.
            if meta.alg.as_deref().is_some_and(|v| parse_algorithm_name(v).is_none()) {
                continue;
            }

            // jsonwebtoken 8.3's JWK deserializer models `alg` as its JWS-only
            // KeyAlgorithm enum. Strip common metadata that we validate ourselves
            // so unrelated/unknown JOSE metadata cannot make the whole JWKS fail.
            // The remaining key parameters still go through jsonwebtoken's JWK
            // parser. Unsupported kty values are therefore skipped generically;
            // RSA, EC, OKP (and any other kty supported by this jsonwebtoken
            // version) are not hard-coded here.
            let mut key_for_jsonwebtoken = raw_key.clone();
            if let Some(map) = key_for_jsonwebtoken.as_object_mut() {
                map.remove("alg");
                map.remove("use");
                map.remove("key_ops");
            }

            let jwk: Jwk = match serde_json::from_value(key_for_jsonwebtoken) {
                Ok(jwk) => jwk,
                Err(_) => continue,
            };
            let key = match DecodingKey::from_jwk(&jwk) {
                Ok(key) => key,
                Err(_) => continue,
            };

            keys.insert(kid.to_owned(), SigningKey { key, meta });
        }

        if keys.is_empty() {
            return Err(OAuthError::ConfigError(
                "JWKS contains no usable signature verification keys".into(),
            ));
        }

        Ok(Self { policy, keys })
    }

    pub fn verify(&self, token: &str) -> Result<String, OAuthError> {
        if token.len() < MIN_JWT_LEN || token.as_bytes().iter().filter(|&&b| b == b'.').count() != 2 {
            return Err(OAuthError::ParseError);
        }

        // Header decoding is intentionally done before verification only to select the JWK.
        let header = decode_header(token).map_err(|_| OAuthError::ParseError)?;
        if !self.algorithm_allowed(header.alg) {
            return Err(OAuthError::InvalidSignature);
        }

        let kid = header.kid.as_deref()
            .ok_or_else(|| OAuthError::UnknownSigningKey { kid: None })?;
        let signing_key = self.keys.get(kid)
            .ok_or_else(|| OAuthError::UnknownSigningKey { kid: Some(kid.to_owned()) })?;

        self.check_jwk_metadata(&signing_key.meta, header.alg)?;

        // jsonwebtoken 8.3 normally validates exp automatically. Disable registered-claim
        // validation here so we can preserve the original C validation order and error classes.
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;

        let claims = match decode::<Value>(token, &signing_key.key, &validation) {
            Ok(data) => data.claims,
            Err(e) => {
                return Err(match e.kind() {
                    ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => OAuthError::InvalidSignature,
                    ErrorKind::Json(_) | ErrorKind::Base64(_) | ErrorKind::InvalidToken => OAuthError::ParseError,
                    _ => OAuthError::InvalidSignature,
                });
            }
        };

        self.check_issuer(&claims)?;
        self.check_audience(&claims)?;
        self.check_authorized_party(&claims)?;
        self.check_validity_dates(&claims)?;
        self.check_required_scopes(&claims)?;
        let uid = self.extract_uid(&claims)?;
        self.check_username(&uid)?;
        Ok(uid)
    }

    fn algorithm_allowed(&self, alg: Algorithm) -> bool {
        let allowed = self.policy.allowed_algorithms.as_deref()
            .unwrap_or(LEGACY_ALLOWED_ALGORITHMS);
        allowed.contains(&alg) && !self.policy.disallowed_algorithms.contains(&alg)
    }

    fn check_jwk_metadata(&self, meta: &JwkMeta, alg: Algorithm) -> Result<(), OAuthError> {
        if meta.use_.as_deref().is_some_and(|v| v != "sig") {
            return Err(OAuthError::InvalidSignature);
        }
        if !meta.key_ops.is_empty() && !meta.key_ops.iter().any(|v| v == "verify") {
            return Err(OAuthError::InvalidSignature);
        }
        if let Some(expected) = meta.alg.as_deref() {
            if parse_algorithm_name(expected) != Some(alg) {
                return Err(OAuthError::InvalidSignature);
            }
        }
        if !algorithm_matches_key_type(alg, &meta.kty, meta.crv.as_deref()) {
            return Err(OAuthError::InvalidSignature);
        }
        Ok(())
    }

    fn check_issuer(&self, claims: &Value) -> Result<(), OAuthError> {
        let found = claims.get("iss").and_then(Value::as_str);
        if found == Some(self.policy.trusted_issuer.as_str()) {
            Ok(())
        } else {
            Err(OAuthError::InvalidIssuer { found: found.map(str::to_owned) })
        }
    }

    fn check_audience(&self, claims: &Value) -> Result<(), OAuthError> {
        let valid = match claims.get("aud") {
            Some(Value::String(aud)) => self.policy.trusted_audiences.iter().any(|expected| expected == aud),
            Some(Value::Array(audiences)) => audiences.iter().filter_map(Value::as_str)
                .any(|aud| self.policy.trusted_audiences.iter().any(|expected| expected == aud)),
            _ => false,
        };
        if valid { Ok(()) } else { Err(OAuthError::InvalidAudience) }
    }

    fn check_authorized_party(&self, claims: &Value) -> Result<(), OAuthError> {
        // Preserve the C semantics: azp is optional, and with no trusted_azp entries it is ignored.
        if self.policy.trusted_authorized_parties.is_empty() {
            return Ok(());
        }
        let Some(azp) = claims.get("azp") else {
            return Ok(());
        };
        let Some(azp) = azp.as_str() else {
            return Err(OAuthError::InvalidAuthorizedParty { found: None });
        };
        if self.policy.trusted_authorized_parties.iter().any(|expected| expected == azp) {
            Ok(())
        } else {
            Err(OAuthError::InvalidAuthorizedParty { found: Some(azp.to_owned()) })
        }
    }

    fn check_validity_dates(&self, claims: &Value) -> Result<(), OAuthError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| OAuthError::ConfigError("system time is before UNIX epoch".into()))?
            .as_secs() as i64;
        let grace = self.policy.grace.max(0);

        let nbf = numeric_date(claims.get("nbf"))?;
        let iat = numeric_date(claims.get("iat"))?;
        let exp = numeric_date(claims.get("exp"))?;

        if nbf.is_some_and(|v| v > now.saturating_add(grace))
            || iat.is_some_and(|v| v > now.saturating_add(grace))
            || exp.is_some_and(|v| v < now.saturating_sub(grace))
        {
            return Err(OAuthError::ClaimExpired);
        }
        Ok(())
    }

    fn check_required_scopes(&self, claims: &Value) -> Result<(), OAuthError> {
        let scope = claims.get("scope").and_then(Value::as_str).unwrap_or("");
        for required in &self.policy.required_scopes {
            if !scope.split_ascii_whitespace().any(|present| present == required) {
                return Err(OAuthError::MissingScope { scope: required.clone() });
            }
        }
        Ok(())
    }

    fn check_username(&self, username: &str) -> Result<(), OAuthError> {
        if self
            .policy
            .disallowed_usernames
            .iter()
            .any(|value| value.eq_ignore_ascii_case(username))
        {
            Err(OAuthError::DisallowedUsername {
                username: username.to_owned(),
            })
        } else {
            Ok(())
        }
    }

    fn extract_uid(&self, claims: &Value) -> Result<String, OAuthError> {
        claims.get(&self.policy.uid_attr)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| OAuthError::MissingUidClaim { claim: self.policy.uid_attr.clone() })
    }
}

fn numeric_date(value: Option<&Value>) -> Result<Option<i64>, OAuthError> {
    let Some(value) = value else { return Ok(None) };
    if let Some(v) = value.as_i64() { return Ok(Some(v)); }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).map(Some).map_err(|_| OAuthError::ClaimExpired);
    }
    if let Some(v) = value.as_f64() {
        if v.is_finite() && v >= i64::MIN as f64 && v <= i64::MAX as f64 {
            return Ok(Some(v.round() as i64));
        }
    }
    Err(OAuthError::ClaimExpired)
}

fn algorithm_matches_key_type(alg: Algorithm, kty: &str, crv: Option<&str>) -> bool {
    match kty {
        "RSA" => matches!(alg,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 |
            Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512
        ),
        "EC" => match alg {
            Algorithm::ES256 => crv.is_none() || crv == Some("P-256"),
            Algorithm::ES384 => crv.is_none() || crv == Some("P-384"),
            _ => false,
        },
        "OKP" => alg == Algorithm::EdDSA && (crv.is_none() || crv == Some("Ed25519")),
        "oct" => matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512),
        _ => false,
    }
}

pub fn parse_algorithm_name(value: &str) -> Option<Algorithm> {
    match value {
        "HS256" => Some(Algorithm::HS256),
        "HS384" => Some(Algorithm::HS384),
        "HS512" => Some(Algorithm::HS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

pub fn algorithm_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::EdDSA => "EdDSA",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> JwtPolicy {
        JwtPolicy {
            uid_attr: "uid".into(),
            grace: 3,
            trusted_issuer: "issuer".into(),
            trusted_audiences: vec!["ldap".into()],
            trusted_authorized_parties: vec![],
            required_scopes: vec![],
            disallowed_usernames: vec![],
            allowed_algorithms: None,
            disallowed_algorithms: vec![],
        }
    }

    #[test]
    fn jwks_ignores_rsa_oaep_encryption_key() {
        let jwks = r#"{
            "keys": [
                {"kty":"RSA","kid":"enc","use":"enc","alg":"RSA-OAEP","n":"AQ","e":"AQAB"},
                {"kty":"RSA","kid":"sig","use":"sig","alg":"RS256","n":"AQ","e":"AQAB"}
            ]
        }"#;
        let verifier = JwtVerifier::from_jwks_json(test_policy(), jwks).unwrap();
        assert!(verifier.keys.contains_key("sig"));
        assert!(!verifier.keys.contains_key("enc"));
    }

    #[test]
    fn legacy_algorithm_policy_is_preserved() {
        let mut policy = test_policy();
        policy.disallowed_algorithms = vec![Algorithm::PS256];
        let verifier = JwtVerifier {
            policy,
            keys: HashMap::new(),
        };
        assert!(verifier.algorithm_allowed(Algorithm::RS256));
        assert!(!verifier.algorithm_allowed(Algorithm::HS256));
        assert!(!verifier.algorithm_allowed(Algorithm::PS256));
    }

    #[test]
    fn explicit_allow_list_replaces_legacy_list() {
        let mut policy = test_policy();
        policy.allowed_algorithms = Some(vec![Algorithm::PS256]);
        let verifier = JwtVerifier {
            policy,
            keys: HashMap::new(),
        };
        assert!(verifier.algorithm_allowed(Algorithm::PS256));
        assert!(!verifier.algorithm_allowed(Algorithm::RS256));
    }

    #[test]
    fn disallowed_username_is_rejected() {
        let mut policy = test_policy();
        policy.disallowed_usernames = vec!["root".into(), "Administrator".into()];
        let verifier = JwtVerifier {
            policy,
            keys: HashMap::new(),
        };

        assert!(verifier.check_username("alice").is_ok());
        assert_eq!(
            verifier.check_username("root"),
            Err(OAuthError::DisallowedUsername { username: "root".into() })
        );
        assert_eq!(
            verifier.check_username("Root"),
            Err(OAuthError::DisallowedUsername { username: "Root".into() })
        );
    }

    #[test]
    fn scopes_are_space_delimited() {
        let scope = "openid profile email";
        assert!(scope.split_ascii_whitespace().any(|v| v == "openid"));
        assert!(!scope.split_ascii_whitespace().any(|v| v == "open"));
    }
}
