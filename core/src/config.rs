// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Interpretation of the `oauthbearer_*` SASL options, shared by the SASL
//! plugin (Cyrus getopt) and the PAM module (`config=` file).

use jsonwebtoken::Algorithm;

use crate::jwt::parse_algorithm_name;

pub struct PolicyOptions {
    pub uid_attr: String,
    pub grace: i64,
    pub trusted_issuer: Option<String>,
    pub jwks_path: Option<String>,
    pub trusted_audiences: Vec<String>,
    pub trusted_authorized_parties: Vec<String>,
    pub required_scopes: Vec<String>,
    pub disallowed_usernames: Vec<String>,
    pub allowed_algorithms: Option<Vec<Algorithm>>,
    pub disallowed_algorithms: Vec<Algorithm>,
}

impl PolicyOptions {
    /// `get` looks up one option; `Ok(None)` means unset.
    pub fn read(get: impl Fn(&str) -> Result<Option<String>, String>) -> Result<Self, String> {
        let uid_attr = get("oauthbearer_userid")?
            .filter(|v| !v.is_empty()).unwrap_or_else(|| "preferred_username".into());
        let grace = get("oauthbearer_grace")?
            .as_deref().unwrap_or("3").parse::<i64>()
            .map_err(|e| format!("invalid oauthbearer_grace: {e}"))?;

        // Numbered options match the existing SASL configuration style. The
        // list options also accept an unnumbered comma/space separated form
        // when no numbered entries exist.
        //
        // Omitted allowed_alg => preserve historical behavior.
        // disallowed_alg is always subtracted from the effective allow-list.
        let allowed_names = get_list_option(&get, "oauthbearer_allowed_alg")?;
        let allowed_algorithms = if allowed_names.is_empty() {
            None
        } else {
            Some(parse_algorithms("oauthbearer_allowed_alg", allowed_names)?)
        };
        let disallowed_algorithms = parse_algorithms(
            "oauthbearer_disallowed_alg",
            get_list_option(&get, "oauthbearer_disallowed_alg")?,
        )?;

        Ok(Self {
            uid_attr,
            grace,
            trusted_issuer: get("oauthbearer_trusted_iss0")?.filter(|v| !v.is_empty()),
            jwks_path: get("oauthbearer_trusted_jwks0")?.filter(|v| !v.is_empty()),
            trusted_audiences: get_indexed(&get, "oauthbearer_trusted_aud")?,
            trusted_authorized_parties: get_indexed(&get, "oauthbearer_trusted_azp")?,
            required_scopes: get_indexed(&get, "oauthbearer_required_scope")?,
            disallowed_usernames: get_list_option(&get, "oauthbearer_disallowed_username")?,
            allowed_algorithms,
            disallowed_algorithms,
        })
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

fn get_list_option(
    get: &impl Fn(&str) -> Result<Option<String>, String>,
    name: &str,
) -> Result<Vec<String>, String> {
    let indexed = get_indexed(get, name)?;
    if !indexed.is_empty() {
        return Ok(indexed);
    }

    let value = match get(name)? {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };

    Ok(value
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect())
}

fn get_indexed(
    get: &impl Fn(&str) -> Result<Option<String>, String>,
    prefix: &str,
) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for index in 0usize.. {
        let name = format!("{prefix}{index}");
        match get(&name)? {
            Some(v) if !v.is_empty() => values.push(v),
            Some(_) => return Err(format!("empty SASL option {name}")),
            None => break,
        }
    }
    Ok(values)
}
