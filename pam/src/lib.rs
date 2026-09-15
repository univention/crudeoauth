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
use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::os::unix::fs::MetadataExt;

use crudeoauth_core::jwt::{parse_algorithm_name, JwtPolicy};
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
    only_from: Vec<String>,
    disallowed_usernames: Vec<String>,
    allowed_algorithms: Option<Vec<jsonwebtoken::Algorithm>>,
    disallowed_algorithms: Vec<jsonwebtoken::Algorithm>,
}

fn parse_args(raw: &[String]) -> Result<PamArgs, String> {
    let config_paths: Vec<&str> = raw.iter()
        .filter_map(|arg| arg.strip_prefix("config="))
        .collect();
    if config_paths.len() > 1 {
        return Err("multiple config options given".into());
    }
    if let Some(path) = config_paths.first() {
        if raw.iter().any(|arg| !arg.starts_with("config=")) {
            return Err("config cannot be combined with inline options".into());
        }
        return parse_config_file(path);
    }

    let mut args = default_args();
    for arg in raw {
        let Some((key, value)) = arg.split_once('=') else {
            continue;
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

fn parse_config_file(path: &str) -> Result<PamArgs, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("failed to stat config file {path:?}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("config path {path:?} is not a regular file"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!("config file {path:?} is writable by group or others"));
    }
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file {path:?}: {e}"))?;
    let mut args = default_args();
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.split_once('#').map_or(line, |(value, _)| value).trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!("invalid config line {} in {path:?}", line_number + 1));
        };
        apply_config_option(&mut args, key.trim(), value.trim())?;
    }
    Ok(args)
}

fn apply_option(args: &mut PamArgs, key: &str, value: &str) -> Result<(), String> {
    match key {
        "config" => Err("config cannot be combined with inline options".into()),
        "userid" => args.userid = value.into(),
        "grace" => args.grace = value.parse().map_err(|e| format!("invalid grace: {e}"))?,
        "iss" => set_once(&mut args.iss, value, "iss")?,
        "jwks" => set_once(&mut args.jwks, value, "jwks")?,
        "trusted_aud" => args.trusted_aud.push(value.into()),
        "trusted_azp" => args.trusted_azp.push(value.into()),
        "required_scope" => args.required_scope.push(value.into()),
        "only_from" => args.only_from.extend(value.split(',').map(str::to_owned)),
        "disallowed_username" => args.disallowed_usernames.push(value.into()),
        "allowed_alg" => add_algorithm(&mut args.allowed_algorithms, value, "allowed_alg")?,
        "disallowed_alg" => add_disallowed_algorithm(&mut args.disallowed_algorithms, value)?,
        _ => {}
    }
    Ok(())
}

fn apply_config_option(args: &mut PamArgs, key: &str, value: &str) -> Result<(), String> {
    let option = match key {
        "oauthbearer_userid" => "userid",
        "oauthbearer_grace" => "grace",
        "oauthbearer_trusted_iss0" => "iss",
        "oauthbearer_trusted_jwks0" => "jwks",
        "oauthbearer_trusted_aud0" => "trusted_aud",
        "oauthbearer_trusted_azp0" => "trusted_azp",
        "oauthbearer_required_scope0" => "required_scope",
        "oauthbearer_disallowed_username0" => "disallowed_username",
        "oauthbearer_allowed_alg0" => "allowed_alg",
        "oauthbearer_disallowed_alg0" => "disallowed_alg",
        _ => return apply_indexed_config_option(args, key, value),
    };
    apply_option(args, option, value)
}

fn apply_indexed_config_option(args: &mut PamArgs, key: &str, value: &str) -> Result<(), String> {
    let options = [
        ("oauthbearer_trusted_aud", "trusted_aud"),
        ("oauthbearer_trusted_azp", "trusted_azp"),
        ("oauthbearer_required_scope", "required_scope"),
        ("oauthbearer_disallowed_username", "disallowed_username"),
        ("oauthbearer_allowed_alg", "allowed_alg"),
        ("oauthbearer_disallowed_alg", "disallowed_alg"),
    ];
    for (prefix, option) in options {
        if indexed_key(key, prefix) {
            return apply_option(args, option, value);
        }
    }
    Ok(())
}

fn indexed_key(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix).is_some_and(|suffix| suffix.parse::<usize>().is_ok())
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

fn authenticate(pam: &PamHandle, raw_args: &[String]) -> c_int {
    let args = match parse_args(raw_args) {
        Ok(v) => v,
        Err(e) => {
            slog(libc::LOG_ERR, &e);
            return PAM_SYSTEM_ERR;
        }
    };

    // A configured only_from list restricts the OAuth check to those hosts.
    if !args.only_from.is_empty() {
        let rhost = pam.item_str(PAM_RHOST).unwrap_or(None);
        if !rhost.is_some_and(|h| args.only_from.iter().any(|allowed| *allowed == h)) {
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

    match account_exists(&user) {
        Ok(true) => {}
        Ok(false) => slog(libc::LOG_WARNING, &format!("inexistant user {user}")),
        Err(rc) => {
            if rc == PAM_TRY_AGAIN {
                slog(libc::LOG_ERR, &format!("getpwnam_r({user}) failed"));
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
            let token = match pam.converse_secret(c"Access Token: ") {
                Ok(v) => v,
                Err(rc) => return rc,
            };
            pam.set_authtok(&token);
            token
        }
    };

    let (Some(iss), Some(jwks)) = (args.iss, args.jwks) else {
        slog(libc::LOG_ERR, "iss and/or jwks missing");
        return PAM_OPEN_ERR;
    };
    let make_policy = || JwtPolicy {
        uid_attr: args.userid,
        grace: args.grace,
        trusted_issuer: iss,
        trusted_audiences: args.trusted_aud,
        trusted_authorized_parties: args.trusted_azp,
        required_scopes: args.required_scope,
        disallowed_usernames: args.disallowed_usernames,
        allowed_algorithms: args.allowed_algorithms,
        disallowed_algorithms: args.disallowed_algorithms,
    };
    let config_path = raw_args.iter().find_map(|arg| arg.strip_prefix("config="));
    let verifier = match cache::verifier(raw_args, &jwks, config_path, make_policy) {
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
    if oauth_user != user {
        slog(
            libc::LOG_INFO,
            &format!("oauth token user \"{oauth_user}\", requested user \"{user}\""),
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guard(|| {
        let Some(pam) = (unsafe { PamHandle::from_raw(pamh) }) else {
            return PAM_SYSTEM_ERR;
        };
        let args = unsafe { ffi::collect_args(argc, argv) };
        authenticate(&pam, &args)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
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

    use super::parse_args;

    #[test]
    fn only_from_preserves_all_hosts() {
        let args = parse_args(&["only_from=host-a,host-b".into()]).unwrap();
        assert_eq!(args.only_from, vec!["host-a".to_owned(), "host-b".to_owned()]);
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

        let args = parse_args(&[format!("config={}", path.display())]).unwrap();
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

        let result = parse_args(&[format!("config={}", path.display())]);
        assert!(result.err().unwrap().contains("writable by group or others"));
        let _ = fs::remove_file(path);
    }
}
