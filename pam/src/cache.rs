// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Process-global verifier cache, keyed by the PAM stack arguments and
//! revalidated against the JWKS file's mtime/size.

use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use crudeoauth_core::jwt::{JwtPolicy, JwtVerifier};

pub(crate) enum CacheError {
    Read(String),
    Build(String),
}

struct Entry {
    mtime: Option<SystemTime>,
    len: u64,
    verifier: Arc<JwtVerifier>,
}

static CACHE: OnceLock<Mutex<HashMap<Vec<String>, Entry>>> = OnceLock::new();

pub(crate) fn verifier(
    raw_args: &[String],
    jwks_path: &str,
    make_policy: impl FnOnce() -> JwtPolicy,
) -> Result<Arc<JwtVerifier>, CacheError> {
    let meta = fs::metadata(jwks_path)
        .map_err(|e| CacheError::Read(format!("failed to read JWKS {jwks_path:?}: {e}")))?;
    let mtime = meta.modified().ok();
    let len = meta.len();

    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(entry) = cache.get(raw_args) {
        if entry.mtime == mtime && entry.len == len {
            return Ok(Arc::clone(&entry.verifier));
        }
    }

    let jwks_json = fs::read_to_string(jwks_path)
        .map_err(|e| CacheError::Read(format!("failed to read JWKS {jwks_path:?}: {e}")))?;
    let verifier = Arc::new(
        JwtVerifier::from_jwks_json(make_policy(), &jwks_json)
            .map_err(|e| CacheError::Build(e.to_string()))?,
    );
    cache.insert(
        raw_args.to_vec(),
        Entry { mtime, len, verifier: Arc::clone(&verifier) },
    );
    Ok(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> JwtPolicy {
        JwtPolicy {
            uid_attr: "preferred_username".into(),
            grace: 3,
            trusted_issuer: "https://sso.example.org/realms/master".into(),
            trusted_audiences: vec!["ldaps://example.org/".into()],
            trusted_authorized_parties: vec![],
            required_scopes: vec![],
            disallowed_usernames: vec![],
            allowed_algorithms: None,
            disallowed_algorithms: vec![],
        }
    }

    #[test]
    fn caches_until_the_jwks_file_changes() {
        let jwks = include_str!("../../core/tests/fixtures/jwks.json");
        let path = std::env::temp_dir().join(format!("crudeoauth-cache-test-{}", std::process::id()));
        let path_str = path.to_str().unwrap();
        fs::write(&path, jwks).unwrap();

        let args = vec!["jwks=x".to_owned()];
        let first = verifier(&args, path_str, policy).ok().unwrap();
        let second = verifier(&args, path_str, policy).ok().unwrap();
        assert!(Arc::ptr_eq(&first, &second), "expected a cache hit");

        // Same content, different size: must rebuild.
        fs::write(&path, format!("{jwks} ")).unwrap();
        let third = verifier(&args, path_str, policy).ok().unwrap();
        assert!(!Arc::ptr_eq(&first, &third), "expected a rebuild after file change");

        // Different arguments: separate entry.
        let other_args = vec!["jwks=y".to_owned()];
        let fourth = verifier(&other_args, path_str, policy).ok().unwrap();
        assert!(!Arc::ptr_eq(&third, &fourth));

        fs::remove_file(&path).unwrap();
    }
}
