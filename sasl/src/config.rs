// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;

use jsonwebtoken::Algorithm;

use crudeoauth_core::jwt::{parse_algorithm_name, JwtPolicy, JwtVerifier, OAuthError};

use crate::ffi::Utils;

pub struct ServerConfig {
    pub tls_required: bool,
    pub verifier: JwtVerifier,
}

impl ServerConfig {
    pub fn from_sasl(utils: &Utils) -> Result<Self, String> {

        let uid_attr = get_opt(utils, "oauthbearer_userid")?
            .filter(|v| !v.is_empty()).unwrap_or_else(|| "preferred_username".into());
        let grace = get_opt(utils, "oauthbearer_grace")?
            .as_deref().unwrap_or("3").parse::<i64>()
            .map_err(|e| format!("invalid oauthbearer_grace: {e}"))?;
        let no_tls = get_opt(utils, "oauthbearer_no_tls")?
            .as_deref() == Some("1");

        let trusted_audiences = get_indexed(utils, "oauthbearer_trusted_aud")?;
        let trusted_authorized_parties = get_indexed(utils, "oauthbearer_trusted_azp")?;
        let required_scopes = get_indexed(utils, "oauthbearer_required_scope")?;
        let disallowed_usernames = get_list_option(utils, "oauthbearer_disallowed_username")?;

        // Optional algorithm policy. Numbered options match the existing SASL
        // configuration style. For convenience, an unnumbered comma/space
        // separated form is accepted when no numbered entries exist.
        //
        // Omitted allowed_alg => preserve historical behavior.
        // disallowed_alg is always subtracted from the effective allow-list.
        let allowed_names = get_list_option(utils, "oauthbearer_allowed_alg")?;
        let disallowed_names = get_list_option(utils, "oauthbearer_disallowed_alg")?;
        let allowed_algorithms = if allowed_names.is_empty() {
            None
        } else {
            Some(parse_algorithms("oauthbearer_allowed_alg", allowed_names)?)
        };
        let disallowed_algorithms = parse_algorithms(
            "oauthbearer_disallowed_alg",
            disallowed_names,
        )?;

        let trusted_issuer = get_opt(utils, "oauthbearer_trusted_iss0")?
            .filter(|v| !v.is_empty()).ok_or("No trusted issuer configured")?;
        let jwks_filename = get_opt(utils, "oauthbearer_trusted_jwks0")?
            .filter(|v| !v.is_empty()).ok_or("No JWKS configured")?;
        let jwks_json = fs::read_to_string(&jwks_filename)
            .map_err(|e| format!("failed to read JWKS {jwks_filename:?}: {e}"))?;

        let policy = JwtPolicy {
            uid_attr,
            grace,
            trusted_issuer,
            trusted_audiences,
            trusted_authorized_parties,
            required_scopes,
            disallowed_usernames,
            allowed_algorithms,
            disallowed_algorithms,
        };
        let verifier = JwtVerifier::from_jwks_json(policy, &jwks_json)
            .map_err(|e| match e { OAuthError::ConfigError(v) => v, other => other.to_string() })?;

        Ok(Self { tls_required: !no_tls, verifier })
    }
}

fn parse_algorithms(option: &str, values: Vec<String>) -> Result<Vec<Algorithm>, String> {
    let mut result = Vec::new();
    for value in values {
        let alg = parse_algorithm_name(&value)
            .ok_or_else(|| format!("invalid {option} value {value:?}"))?;
        if !result.contains(&alg) {
            result.push(alg);
        }
    }
    Ok(result)
}

fn get_list_option(utils: &Utils, name: &str) -> Result<Vec<String>, String> {
    let indexed = get_indexed(utils, name)?;
    if !indexed.is_empty() {
        return Ok(indexed);
    }

    let Some(value) = get_opt(utils, name)? else {
        return Ok(Vec::new());
    };

    Ok(value
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect())
}

fn get_indexed(utils: &Utils, prefix: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for index in 0usize.. {
        let name = format!("{prefix}{index}");
        match get_opt(utils, &name)? {
            Some(v) if !v.is_empty() => values.push(v),
            Some(_) => return Err(format!("empty SASL option {name}")),
            None => break,
        }
    }
    Ok(values)
}

fn get_opt(utils: &Utils, option: &str) -> Result<Option<String>, String> {
    utils.option(option)
}
