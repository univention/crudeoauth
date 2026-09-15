// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! PAM module: validates an OAuth 2.0 access token supplied as the PAM
//! authentication token (or prompted via the conversation) and grants access
//! when the token's username claim matches the PAM user.
//!
//! Configuration is passed as arguments in the PAM stack definition:
//!   config=, userid=, grace=, iss=, jwks=, trusted_aud=, trusted_azp=,
//!   required_scope=, only_from=, allowed_alg=, disallowed_alg=,
//!   disallowed_username=
//! (trusted_aud/trusted_azp/required_scope may be given multiple times.)
//!
//! Structure: `ffi` wraps the PAM ABI in the safe `PamHandle`; the module
//! logic (`authenticate`) is safe Rust; the `unsafe extern "C"` entry points
//! below only validate raw arguments, build the wrappers, guard against
//! panics and dispatch.

mod cache;
mod ffi;

use std::fs;
use std::io::Read;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::os::unix::fs::MetadataExt;

use crudeoauth_core::config::PolicyOptions;
use crudeoauth_core::jwt::parse_algorithm_name;
use ffi::{
    account_exists, slog, PamHandle, PAM_AUTHTOK, PAM_AUTH_ERR, PAM_IGNORE, PAM_OPEN_ERR,
    PAM_RHOST, PAM_SUCCESS, PAM_SYSTEM_ERR, PAM_TRY_AGAIN,
};
pub use ffi::pam_handle_t;

struct PamArgs {
    userid: String,
    grace: i64,
    iss: Option<String>,
    jwks: Option<String>,
    trusted_aud: Vec<String>,
    trusted_azp: Vec<String>,
    required_scope: Vec<String>,
    only_from: Vec<Vec<String>>,
    disallowed_usernames: Vec<String>,
    allowed_algorithms: Option<Vec<jsonwebtoken::Algorithm>>,
    disallowed_algorithms: Vec<jsonwebtoken::Algorithm>,
}

/// The `config=` path, if the arguments select a configuration file.
fn config_path(raw: &[String]) -> Result<Option<&str>, String> {
    let config_paths: Vec<&str> = raw.iter()
        .filter_map(|arg| arg.strip_prefix("config="))
        .collect();
    if config_paths.len() > 1 {
        return Err("multiple config options given".into());
    }
    if !config_paths.is_empty() && raw.iter().any(|arg| !arg.starts_with("config=")) {
        return Err("config cannot be combined with inline options".into());
    }
    Ok(config_paths.first().copied())
}

fn parse_inline_args(raw: &[String]) -> Result<PamArgs, String> {
    let mut args = default_args();
    for arg in raw {
        let (key, value) = match arg.split_once('=') {
            Some(value) => value,
            None => continue,
        };
        apply_option(&mut args, key, value)?;
    }
    Ok(args)
}

fn default_args() -> PamArgs {
    PamArgs {
        userid: "preferred_username".into(),
        grace: 3,
        iss: None,
        jwks: None,
        trusted_aud: Vec::new(),
        trusted_azp: Vec::new(),
        required_scope: Vec::new(),
        only_from: Vec::new(),
        disallowed_usernames: Vec::new(),
        allowed_algorithms: None,
        disallowed_algorithms: Vec::new(),
    }
}

/// Returns the parsed file together with the metadata of the opened file, so
/// the cache compares against the version that was actually read.
fn read_config_file(path: &str) -> Result<(PamArgs, fs::Metadata), String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("failed to open config file {path:?}: {e}"))?;
    let metadata = file.metadata()
        .map_err(|e| format!("failed to stat config file {path:?}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("config path {path:?} is not a regular file"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!("config file {path:?} is writable by group or others"));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("failed to read config file {path:?}: {e}"))?;
    Ok((parse_config(&contents, path)?, metadata))
}

/// Parses a SASL configuration file the way Cyrus `sasl_config_init()` does:
/// only whole lines are comments, keys are lowercased and the first
/// occurrence of a key wins.
fn parse_config(contents: &str, path: &str) -> Result<PamArgs, String> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let invalid = || format!("invalid config line {} in {path:?}", line_number + 1);
        let (key, value) = line.split_once(':').ok_or_else(invalid)?;
        let value = value.trim();
        if value.is_empty()
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(invalid());
        }
        entries.push((key.to_ascii_lowercase(), value.into()));
    }
    let get = |name: &str| {
        Ok(entries.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone()))
    };

    let options = PolicyOptions::read(get)?;
    Ok(PamArgs {
        userid: options.uid_attr,
        grace: options.grace,
        iss: options.trusted_issuer,
        jwks: options.jwks_path,
        trusted_aud: options.trusted_audiences,
        trusted_azp: options.trusted_authorized_parties,
        required_scope: options.required_scopes,
        only_from: Vec::new(),
        disallowed_usernames: options.disallowed_usernames,
        allowed_algorithms: options.allowed_algorithms,
        disallowed_algorithms: options.disallowed_algorithms,
    })
}

fn apply_option(args: &mut PamArgs, key: &str, value: &str) -> Result<(), String> {
    match key {
        "userid" => args.userid = value.into(),
        "grace" => args.grace = value.parse().map_err(|e| format!("invalid grace: {e}"))?,
        "iss" => set_once(&mut args.iss, value, "iss")?,
        "jwks" => set_once(&mut args.jwks, value, "jwks")?,
        "trusted_aud" => args.trusted_aud.push(value.into()),
        "trusted_azp" => args.trusted_azp.push(value.into()),
        "required_scope" => args.required_scope.push(value.into()),
        "only_from" => args.only_from.push(
            value.split(',').filter(|host| !host.is_empty()).map(str::to_owned).collect(),
        ),
        "disallowed_username" => args.disallowed_usernames.push(value.into()),
        "allowed_alg" => add_algorithm(&mut args.allowed_algorithms, value, "allowed_alg")?,
        "disallowed_alg" => add_disallowed_algorithm(&mut args.disallowed_algorithms, value)?,
        _ => {}
    }
    Ok(())
}

fn set_once(slot: &mut Option<String>, value: &str, name: &str) -> Result<(), String> {
    if slot.replace(value.into()).is_some() {
        Err(format!("multiple {name} values given"))
    } else {
        Ok(())
    }
}

fn add_algorithm(
    slot: &mut Option<Vec<jsonwebtoken::Algorithm>>,
    value: &str,
    name: &str,
) -> Result<(), String> {
    let algorithm = parse_algorithm_name(value)
        .ok_or_else(|| format!("invalid {name} value {value:?}"))?;
    let values = slot.get_or_insert_with(Vec::new);
    if !values.contains(&algorithm) {
        values.push(algorithm);
    }
    Ok(())
}

fn add_disallowed_algorithm(
    values: &mut Vec<jsonwebtoken::Algorithm>,
    value: &str,
) -> Result<(), String> {
    let algorithm = parse_algorithm_name(value)
        .ok_or_else(|| format!("invalid disallowed_alg value {value:?}"))?;
    if !values.contains(&algorithm) {
        values.push(algorithm);
    }
    Ok(())
}

fn only_from_allows(lists: &[Vec<String>], host: &str) -> bool {
    lists.iter().all(|hosts| hosts.iter().any(|allowed| allowed == host))
}

fn authenticate(pam: &PamHandle, raw_args: &[String]) -> c_int {
    let config = match cache::config(raw_args) {
        Ok(v) => v,
        Err(e) => {
            slog(libc::LOG_ERR, &e);
            return PAM_SYSTEM_ERR;
        }
    };
    let args = &config.args;

    // Each only_from list restricts the OAuth check to its hosts.
    if !args.only_from.is_empty() {
        let rhost = pam.item_str(PAM_RHOST).unwrap_or(None);
        if !rhost.map_or(false, |h| only_from_allows(&args.only_from, &h)) {
            return PAM_IGNORE;
        }
    }

    let user = match pam.user() {
        Ok(v) => v,
        Err(rc) => {
            slog(libc::LOG_ERR, &format!("pam_get_user() failed: {}", pam.strerror(rc)));
            return if rc == PAM_SUCCESS { PAM_AUTH_ERR } else { rc };
        }
    };
    let user_name = user.to_string_lossy();

    match account_exists(&user) {
        Ok(true) => {}
        Ok(false) => slog(libc::LOG_WARNING, &format!("inexistant user {user_name}")),
        Err(rc) => {
            if rc == PAM_TRY_AGAIN {
                slog(libc::LOG_ERR, &format!("getpwnam_r({user_name}) failed"));
            }
            return rc;
        }
    }

    let token = match pam.item_str(PAM_AUTHTOK) {
        Err(rc) => {
            slog(
                libc::LOG_ERR,
                &format!("pam_get_item(PAM_AUTHTOK) failed: {}", pam.strerror(rc)),
            );
            return rc;
        }
        Ok(Some(token)) => token,
        Ok(None) => {
            let prompt = unsafe { CStr::from_bytes_with_nul_unchecked(b"Access Token: \0") };
            let token = match pam.converse_secret(prompt) {
                Ok(v) => v,
                Err(rc) => return rc,
            };
            // Later stack modules must see the answer byte for byte.
            pam.set_authtok(&token);
            match token.into_string() {
                Ok(token) => token,
                Err(_) => {
                    slog(libc::LOG_ERR, "access token is not valid UTF-8");
                    return PAM_AUTH_ERR;
                }
            }
        }
    };

    let verifier = match config.verifier() {
        Ok(v) => v,
        Err(cache::CacheError::Read(e)) => {
            slog(libc::LOG_ERR, &e);
            return PAM_OPEN_ERR;
        }
        Err(cache::CacheError::Build(e)) => {
            slog(libc::LOG_ERR, &format!("JWT verifier setup failed: {e}"));
            return PAM_SYSTEM_ERR;
        }
    };

    let oauth_user = match verifier.verify(&token) {
        Ok(v) => v,
        Err(e) => {
            slog(libc::LOG_ERR, &format!("token rejected: {e}"));
            return PAM_AUTH_ERR;
        }
    };
    if oauth_user.as_bytes() != user.to_bytes() {
        slog(
            libc::LOG_INFO,
            &format!("oauth token user \"{oauth_user}\", requested user \"{user_name}\""),
        );
        return PAM_AUTH_ERR;
    }

    PAM_SUCCESS
}

/// A panic must not unwind into libpam; report PAM_SYSTEM_ERR instead.
fn guard(f: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        slog(libc::LOG_ERR, "pam_oauthbearer: internal panic");
        PAM_SYSTEM_ERR
    })
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guard(|| {
        let pam = match unsafe { PamHandle::from_raw(pamh) } {
            Some(pam) => pam,
            None => return PAM_SYSTEM_ERR,
        };
        let args = unsafe { ffi::collect_args(argc, argv) };
        authenticate(&pam, &args)
    })
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::{config_path, only_from_allows, parse_config, parse_inline_args, read_config_file};

    #[test]
    fn only_from_preserves_all_hosts() {
        let args = parse_inline_args(&["only_from=host-a,host-b".into()]).unwrap();
        assert_eq!(args.only_from, vec![vec!["host-a".to_owned(), "host-b".to_owned()]]);
    }

    #[test]
    fn only_from_skips_empty_entries() {
        let args = parse_inline_args(&["only_from=a,,b,".into()]).unwrap();
        assert_eq!(args.only_from, vec![vec!["a".to_owned(), "b".to_owned()]]);
        assert!(!only_from_allows(&args.only_from, ""));
    }

    #[test]
    fn empty_only_from_allows_no_host() {
        let args = parse_inline_args(&["only_from=".into()]).unwrap();
        assert!(!only_from_allows(&args.only_from, ""));
        assert!(!only_from_allows(&args.only_from, "a"));
    }

    #[test]
    fn every_only_from_argument_must_match() {
        let args = parse_inline_args(&["only_from=a,b".into(), "only_from=b,c".into()]).unwrap();
        assert!(only_from_allows(&args.only_from, "b"));
        assert!(!only_from_allows(&args.only_from, "a"));
        assert!(!only_from_allows(&args.only_from, "c"));
    }

    #[test]
    fn config_file_uses_sasl_options() {
        let path = std::env::temp_dir().join(format!(
            "crudeoauth-pam-config-{}",
            std::process::id()
        ));
        fs::write(
            &path,
            "oauthbearer_userid: uid\noauthbearer_grace: 7\noauthbearer_trusted_iss0: issuer\noauthbearer_trusted_jwks0: keys.json\noauthbearer_trusted_aud0: audience\noauthbearer_trusted_aud1: second\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let (args, _) = read_config_file(path.to_str().unwrap()).unwrap();
        assert_eq!(args.userid, "uid");
        assert_eq!(args.grace, 7);
        assert_eq!(args.iss.as_deref(), Some("issuer"));
        assert_eq!(args.jwks.as_deref(), Some("keys.json"));
        assert_eq!(args.trusted_aud, vec!["audience".to_owned(), "second".to_owned()]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn config_file_writable_by_others_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "crudeoauth-pam-config-{}-insecure",
            std::process::id()
        ));
        fs::write(&path, "oauthbearer_trusted_aud0: audience\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o602)).unwrap();

        let result = read_config_file(path.to_str().unwrap());
        assert!(result.err().unwrap().contains("writable by group or others"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn config_file_accepts_unindexed_list_options() {
        let args = parse_config(
            "oauthbearer_disallowed_username: root, admin\noauthbearer_disallowed_alg: HS256\n",
            "test",
        )
        .unwrap();
        assert_eq!(args.disallowed_usernames, vec!["root".to_owned(), "admin".to_owned()]);
        assert_eq!(args.disallowed_algorithms, vec![jsonwebtoken::Algorithm::HS256]);
    }

    #[test]
    fn config_file_follows_cyrus_line_rules() {
        let args = parse_config(
            "# comment\nOAuthBearer_Trusted_Iss0: https://first/#frag\noauthbearer_trusted_iss0: second\n",
            "test",
        )
        .unwrap();
        assert_eq!(args.iss.as_deref(), Some("https://first/#frag"));
    }

    #[test]
    fn config_file_stops_at_the_first_missing_index() {
        let args = parse_config(
            "oauthbearer_trusted_aud0: a\noauthbearer_trusted_aud2: c\n",
            "test",
        )
        .unwrap();
        assert_eq!(args.trusted_aud, vec!["a".to_owned()]);
    }

    #[test]
    fn config_file_rejects_empty_values() {
        assert!(parse_config("oauthbearer_trusted_iss0:\n", "test").is_err());
    }

    #[test]
    fn config_cannot_be_combined_with_inline_options() {
        assert!(config_path(&["config=/x".into(), "iss=y".into()]).is_err());
        assert!(config_path(&["config=/x".into(), "config=/y".into()]).is_err());
    }
}
