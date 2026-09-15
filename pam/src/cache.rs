// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Process-global cache of the parsed configuration, keyed by the PAM stack
//! arguments and revalidated against the `config=` file. Each configuration
//! owns the verifier built from it, revalidated against the JWKS file.

use std::collections::HashMap;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

use crudeoauth_core::jwt::{JwtPolicy, JwtVerifier};

use crate::PamArgs;

pub(crate) enum CacheError {
    Read(String),
    Build(String),
}

pub(crate) struct Config {
    pub(crate) args: PamArgs,
    verifier: Mutex<Option<(Option<Stamp>, Arc<JwtVerifier>)>>,
}

struct Entry {
    stamp: Option<Stamp>,
    config: Arc<Config>,
}

static CACHE: Lazy<Mutex<HashMap<Vec<String>, Entry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn config(raw_args: &[String]) -> Result<Arc<Config>, String> {
    let path = crate::config_path(raw_args)?;
    let current = path
        .map(|path| {
            fs::metadata(path)
                .map(|meta| Stamp::of(&meta))
                .map_err(|e| format!("failed to stat config file {path:?}: {e}"))
        })
        .transpose()?;

    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(entry) = cache.get(raw_args) {
        let fresh = match current {
            Some(current) => entry.stamp == Some(current),
            None => true,
        };
        if fresh {
            return Ok(Arc::clone(&entry.config));
        }
    }

    let (args, stamp) = match path {
        Some(path) => {
            let (args, meta) = crate::read_config_file(path)?;
            (args, Stamp::settled(&meta))
        }
        None => (crate::parse_inline_args(raw_args)?, None),
    };
    let config = Arc::new(Config { args, verifier: Mutex::new(None) });
    cache.insert(raw_args.to_vec(), Entry { stamp, config: Arc::clone(&config) });
    Ok(config)
}

impl Config {
    pub(crate) fn verifier(&self) -> Result<Arc<JwtVerifier>, CacheError> {
        let (iss, jwks_path) = match (&self.args.iss, &self.args.jwks) {
            (Some(iss), Some(jwks_path)) => (iss, jwks_path),
            _ => return Err(CacheError::Read("iss and/or jwks missing".into())),
        };
        let read_error = |e| CacheError::Read(format!("failed to read JWKS {jwks_path:?}: {e}"));
        let current = Stamp::of(&fs::metadata(jwks_path).map_err(read_error)?);

        let mut slot = self.verifier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some((stamp, verifier)) = &*slot {
            if *stamp == Some(current) {
                return Ok(Arc::clone(verifier));
            }
        }

        let mut file = File::open(jwks_path).map_err(read_error)?;
        let meta = file.metadata().map_err(read_error)?;
        let mut jwks_json = String::new();
        file.read_to_string(&mut jwks_json).map_err(read_error)?;
        let verifier = Arc::new(
            JwtVerifier::from_jwks_json(self.policy(iss), &jwks_json)
                .map_err(|e| CacheError::Build(e.to_string()))?,
        );
        *slot = Some((Stamp::settled(&meta), Arc::clone(&verifier)));
        Ok(verifier)
    }

    fn policy(&self, trusted_issuer: &str) -> JwtPolicy {
        let args = &self.args;
        JwtPolicy {
            uid_attr: args.userid.clone(),
            grace: args.grace,
            trusted_issuer: trusted_issuer.into(),
            trusted_audiences: args.trusted_aud.clone(),
            trusted_authorized_parties: args.trusted_azp.clone(),
            required_scopes: args.required_scope.clone(),
            disallowed_usernames: args.disallowed_usernames.clone(),
            allowed_algorithms: args.allowed_algorithms.clone(),
            disallowed_algorithms: args.disallowed_algorithms.clone(),
        }
    }
}

/// Identifies one version of a file. ctime catches rewrites that preserve
/// mtime and size, and inode/device catch replacement by rename.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

/// A write within one timestamp tick of reading leaves the stamp unchanged,
/// so a stamp this recent cannot prove the file still matches what was read.
const SETTLE_TIME: Duration = Duration::from_secs(2);

impl Stamp {
    fn of(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }

    /// The stamp to cache, or `None` to force a reread next time.
    fn settled(meta: &Metadata) -> Option<Self> {
        let (secs, nsecs) = (meta.ctime(), meta.ctime_nsec());
        let changed = UNIX_EPOCH
            + Duration::from_secs(u64::try_from(secs).ok()?)
            + Duration::from_nanos(u64::try_from(nsecs).ok()?);
        let age = SystemTime::now().duration_since(changed).ok()?;
        (age >= SETTLE_TIME).then(|| Self::of(meta))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    const JWKS: &str = include_str!("../../core/tests/fixtures/jwks.json");

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("crudeoauth-cache-test-{}-{name}", std::process::id()))
    }

    /// ctime cannot be set, so waiting is the only way to age a file.
    fn settle() {
        std::thread::sleep(SETTLE_TIME);
    }

    fn inline_args(jwks: &PathBuf) -> Vec<String> {
        vec![
            "iss=https://sso.example.org/realms/master".into(),
            format!("jwks={}", jwks.display()),
            "trusted_aud=ldaps://example.org/".into(),
        ]
    }

    #[test]
    fn caches_until_the_jwks_file_changes() {
        let path = temp_path("jwks");
        fs::write(&path, JWKS).unwrap();
        settle();

        let args = inline_args(&path);
        let config = config(&args).ok().unwrap();
        assert!(Arc::ptr_eq(&config, &super::config(&args).ok().unwrap()));
        let first = config.verifier().ok().unwrap();
        let second = config.verifier().ok().unwrap();
        assert!(Arc::ptr_eq(&first, &second), "expected a cache hit");

        fs::write(&path, format!("{JWKS} ")).unwrap();
        let third = config.verifier().ok().unwrap();
        assert!(!Arc::ptr_eq(&first, &third), "expected a rebuild after file change");

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn recently_changed_files_are_reread() {
        let path = temp_path("fresh-jwks");
        fs::write(&path, JWKS).unwrap();

        let config = config(&inline_args(&path)).ok().unwrap();
        let first = config.verifier().ok().unwrap();
        let second = config.verifier().ok().unwrap();
        assert!(!Arc::ptr_eq(&first, &second), "expected no cache hit before settling");

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn config_file_changes_replace_the_policy() {
        let path = temp_path("config");
        let write = |aud: &str| {
            fs::write(
                &path,
                format!(
                    "oauthbearer_trusted_iss0: issuer\noauthbearer_trusted_jwks0: keys.json\noauthbearer_trusted_aud0: {aud}\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        };
        let args = vec![format!("config={}", path.display())];

        write("first");
        settle();
        let first = config(&args).ok().unwrap();
        assert!(Arc::ptr_eq(&first, &config(&args).ok().unwrap()), "expected a cache hit");

        // Same size as before, so only the stamp's time fields differ.
        write("secnd");
        let second = config(&args).ok().unwrap();
        assert_eq!(second.args.trusted_aud, vec!["secnd".to_owned()]);
        assert!(!Arc::ptr_eq(&second, &config(&args).ok().unwrap()), "expected a reread");

        fs::remove_file(&path).unwrap();
    }
}
