// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;

use crudeoauth_core::config::PolicyOptions;
use crudeoauth_core::jwt::{JwtPolicy, JwtVerifier, OAuthError};

use crate::ffi::Utils;

pub struct ServerConfig {
    pub tls_required: bool,
    pub verifier: JwtVerifier,
}

impl ServerConfig {
    pub(crate) fn from_sasl(utils: &Utils) -> Result<Self, String> {
        let options = PolicyOptions::read(|name| utils.option(name))?;
        let no_tls = utils.option("oauthbearer_no_tls")?
            .as_deref() == Some("1");

        let trusted_issuer = options.trusted_issuer.ok_or("No trusted issuer configured")?;
        let jwks_filename = options.jwks_path.ok_or("No JWKS configured")?;
        let jwks_json = fs::read_to_string(&jwks_filename)
            .map_err(|e| format!("failed to read JWKS {jwks_filename:?}: {e}"))?;

        let policy = JwtPolicy {
            uid_attr: options.uid_attr,
            grace: options.grace,
            trusted_issuer,
            trusted_audiences: options.trusted_audiences,
            trusted_authorized_parties: options.trusted_authorized_parties,
            required_scopes: options.required_scopes,
            disallowed_usernames: options.disallowed_usernames,
            allowed_algorithms: options.allowed_algorithms,
            disallowed_algorithms: options.disallowed_algorithms,
        };
        let verifier = JwtVerifier::from_jwks_json(policy, &jwks_json)
            .map_err(|e| match e { OAuthError::ConfigError(v) => v, other => other.to_string() })?;

        Ok(Self { tls_required: !no_tls, verifier })
    }
}
