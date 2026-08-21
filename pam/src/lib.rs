// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! PAM module: validates an OAuth 2.0 access token supplied as the PAM
//! authentication token (or prompted via the conversation) and grants access
//! when the token's username claim matches the PAM user.
//!
//! Configuration is passed as arguments in the PAM stack definition:
//!   userid=, grace=, iss=, jwks=, trusted_aud=, trusted_azp=,
//!   required_scope=, only_from=
//! (trusted_aud/trusted_azp/required_scope may be given multiple times.)
//!
//! Structure: `ffi` wraps the PAM ABI in the safe `PamHandle`; the module
//! logic (`authenticate`) is safe Rust; the `unsafe extern "C"` entry points
//! below only validate raw arguments, build the wrappers, guard against
//! panics and dispatch.

mod ffi;

use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crudeoauth_core::jwt::{JwtPolicy, JwtVerifier};
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
}

fn parse_args(raw: &[String]) -> Result<PamArgs, String> {
    let mut args = PamArgs {
        userid: "preferred_username".into(),
        grace: 3,
        iss: None,
        jwks: None,
        trusted_aud: Vec::new(),
        trusted_azp: Vec::new(),
        required_scope: Vec::new(),
        only_from: Vec::new(),
    };
    for arg in raw {
        let Some((key, value)) = arg.split_once('=') else {
            continue;
        };
        match key {
            "userid" => args.userid = value.into(),
            "grace" => {
                args.grace = value.parse().map_err(|e| format!("invalid grace: {e}"))?;
            }
            "iss" => {
                if args.iss.replace(value.into()).is_some() {
                    return Err("multiple iss given".into());
                }
            }
            "jwks" => {
                if args.jwks.replace(value.into()).is_some() {
                    return Err("multiple jwks given".into());
                }
            }
            "trusted_aud" => args.trusted_aud.push(value.into()),
            "trusted_azp" => args.trusted_azp.push(value.into()),
            "required_scope" => args.required_scope.push(value.into()),
            "only_from" => args.only_from.extend(value.split(',').map(str::to_owned)),
            _ => {}
        }
    }
    Ok(args)
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
    let jwks_json = match std::fs::read_to_string(&jwks) {
        Ok(v) => v,
        Err(e) => {
            slog(libc::LOG_ERR, &format!("failed to read JWKS {jwks:?}: {e}"));
            return PAM_OPEN_ERR;
        }
    };
    let policy = JwtPolicy {
        uid_attr: args.userid,
        grace: args.grace,
        trusted_issuer: iss,
        trusted_audiences: args.trusted_aud,
        trusted_authorized_parties: args.trusted_azp,
        required_scopes: args.required_scope,
        disallowed_usernames: vec![],
        allowed_algorithms: None,
        disallowed_algorithms: vec![],
    };
    let verifier = match JwtVerifier::from_jwks_json(policy, &jwks_json) {
        Ok(v) => v,
        Err(e) => {
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
