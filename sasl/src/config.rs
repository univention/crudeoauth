// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

use std::{ffi::{CStr, CString}, fs};

use jsonwebtoken::Algorithm;
use sasl2_sys::prelude::sasl_utils_t;

use crudeoauth_core::jwt::{parse_algorithm_name, JwtPolicy, JwtVerifier, OAuthError};

const PLUGIN_NAME: &[u8] = b"OAUTHBEARER\0";

pub struct ServerConfig {
    pub tls_required: bool,
    pub verifier: JwtVerifier,
}

impl ServerConfig {
    pub unsafe fn from_sasl(utils: *const sasl_utils_t) -> Result<Self, String> {
        if utils.is_null() {
            return Err("NULL sasl_utils".into());
        }

        let uid_attr = unsafe { get_opt(utils, "oauthbearer_userid")? }
            .filter(|v| !v.is_empty()).unwrap_or_else(|| "preferred_username".into());
        let grace = unsafe { get_opt(utils, "oauthbearer_grace")? }
            .as_deref().unwrap_or("3").parse::<i64>()
            .map_err(|e| format!("invalid oauthbearer_grace: {e}"))?;
        let no_tls = unsafe { get_opt(utils, "oauthbearer_no_tls")? }
            .as_deref() == Some("1");

        let trusted_audiences = unsafe { get_indexed(utils, "oauthbearer_trusted_aud")? };
        let trusted_authorized_parties = unsafe { get_indexed(utils, "oauthbearer_trusted_azp")? };
        let required_scopes = unsafe { get_indexed(utils, "oauthbearer_required_scope")? };
        let disallowed_usernames = unsafe { get_list_option(utils, "oauthbearer_disallowed_username")? };

        // Optional algorithm policy. Numbered options match the existing SASL
        // configuration style. For convenience, an unnumbered comma/space
        // separated form is accepted when no numbered entries exist.
        //
        // Omitted allowed_alg => preserve historical behavior.
        // disallowed_alg is always subtracted from the effective allow-list.
        let allowed_names = unsafe { get_list_option(utils, "oauthbearer_allowed_alg")? };
        let disallowed_names = unsafe { get_list_option(utils, "oauthbearer_disallowed_alg")? };
        let allowed_algorithms = if allowed_names.is_empty() {
            None
        } else {
            Some(parse_algorithms("oauthbearer_allowed_alg", allowed_names)?)
        };
        let disallowed_algorithms = parse_algorithms(
            "oauthbearer_disallowed_alg",
            disallowed_names,
        )?;

        let trusted_issuer = unsafe { get_opt(utils, "oauthbearer_trusted_iss0")? }
            .filter(|v| !v.is_empty()).ok_or("No trusted issuer configured")?;
        let jwks_filename = unsafe { get_opt(utils, "oauthbearer_trusted_jwks0")? }
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

unsafe fn get_list_option(utils: *const sasl_utils_t, name: &str) -> Result<Vec<String>, String> {
    let indexed = unsafe { get_indexed(utils, name)? };
    if !indexed.is_empty() {
        return Ok(indexed);
    }

    let Some(value) = (unsafe { get_opt(utils, name)? }) else {
        return Ok(Vec::new());
    };

    Ok(value
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect())
}

unsafe fn get_indexed(utils: *const sasl_utils_t, prefix: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for index in 0usize.. {
        let name = format!("{prefix}{index}");
        match unsafe { get_opt(utils, &name)? } {
            Some(v) if !v.is_empty() => values.push(v),
            Some(_) => return Err(format!("empty SASL option {name}")),
            None => break,
        }
    }
    Ok(values)
}

unsafe fn get_opt(utils: *const sasl_utils_t, option: &str) -> Result<Option<String>, String> {
    let getopt = unsafe { (*utils).getopt }.ok_or("sasl_utils.getopt is NULL")?;
    let option = CString::new(option).map_err(|_| "invalid SASL option name")?;
    let mut value = std::ptr::null();
    let rc = unsafe {
        getopt(
            (*utils).getopt_context,
            PLUGIN_NAME.as_ptr().cast(),
            option.as_ptr(),
            &mut value,
            std::ptr::null_mut(),
        )
    };
    if rc != 0 || value.is_null() {
        return Ok(None);
    }
    Ok(Some(unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned()))
}
