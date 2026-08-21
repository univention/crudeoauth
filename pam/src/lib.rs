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

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{null, null_mut};

use crudeoauth_core::jwt::{JwtPolicy, JwtVerifier};

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_OPEN_ERR: c_int = 1;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_TRY_AGAIN: c_int = 24;
pub const PAM_IGNORE: c_int = 25;

const PAM_RHOST: c_int = 4;
const PAM_CONV: c_int = 5;
const PAM_AUTHTOK: c_int = 6;

const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
pub struct pam_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct pam_message {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

#[repr(C)]
pub struct pam_response {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

#[repr(C)]
pub struct pam_conv {
    pub conv: Option<
        unsafe extern "C" fn(
            c_int,
            *mut *const pam_message,
            *mut *mut pam_response,
            *mut c_void,
        ) -> c_int,
    >,
    pub appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_get_item(pamh: *mut pam_handle_t, item_type: c_int, item: *mut *const c_void)
        -> c_int;
    fn pam_set_item(pamh: *mut pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_strerror(pamh: *mut pam_handle_t, errnum: c_int) -> *const c_char;
}

fn slog(pri: c_int, msg: &str) {
    let Ok(msg) = CString::new(msg) else { return };
    unsafe { libc::syslog(pri, c"%s".as_ptr(), msg.as_ptr()) };
}

fn pam_error(pamh: *mut pam_handle_t, rc: c_int) -> String {
    let p = unsafe { pam_strerror(pamh, rc) };
    if p.is_null() {
        format!("PAM error {rc}")
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

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

fn parse_args(argc: c_int, argv: *const *const c_char) -> Result<PamArgs, String> {
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
    if argv.is_null() {
        return Ok(args);
    }
    for i in 0..argc.max(0) as usize {
        let arg = unsafe { *argv.add(i) };
        if arg.is_null() {
            continue;
        }
        let arg = unsafe { CStr::from_ptr(arg) }.to_string_lossy();
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

unsafe fn get_item_str(pamh: *mut pam_handle_t, item_type: c_int) -> Result<Option<String>, c_int> {
    let mut item: *const c_void = null();
    let rc = unsafe { pam_get_item(pamh, item_type, &mut item) };
    if rc != PAM_SUCCESS {
        return Err(rc);
    }
    if item.is_null() {
        return Ok(None);
    }
    Ok(Some(unsafe { CStr::from_ptr(item.cast()) }.to_string_lossy().into_owned()))
}

/// Ask the application for the access token via the conversation.
unsafe fn converse_for_token(pamh: *mut pam_handle_t) -> Result<String, c_int> {
    let mut convptr: *const c_void = null();
    let rc = unsafe { pam_get_item(pamh, PAM_CONV, &mut convptr) };
    if rc != PAM_SUCCESS {
        slog(libc::LOG_ERR, &format!("pam_get_item(PAM_CONV) failed: {}", pam_error(pamh, rc)));
        return Err(rc);
    }
    let conv = convptr.cast::<pam_conv>();
    let Some(conv_fn) = (unsafe { conv.as_ref() }).and_then(|c| c.conv) else {
        return Err(PAM_CONV_ERR);
    };

    let msg = pam_message { msg_style: PAM_PROMPT_ECHO_OFF, msg: c"Access Token: ".as_ptr() };
    let mut msgp: *const pam_message = &msg;
    let mut resp: *mut pam_response = null_mut();
    let rc = unsafe { conv_fn(1, &mut msgp, &mut resp, (*conv).appdata_ptr) };
    if rc != PAM_SUCCESS {
        slog(libc::LOG_ERR, &format!("PAM conv error: {}", pam_error(pamh, rc)));
        return Err(rc);
    }
    if resp.is_null() {
        return Err(PAM_CONV_ERR);
    }
    let answer = unsafe { (*resp).resp };
    let token = if answer.is_null() {
        None
    } else {
        let token = unsafe { CStr::from_ptr(answer) }.to_string_lossy().into_owned();
        unsafe {
            libc::memset(answer.cast(), 0, libc::strlen(answer));
            libc::free(answer.cast());
        }
        Some(token)
    };
    unsafe { libc::free(resp.cast()) };
    token.ok_or(PAM_CONV_ERR)
}

unsafe fn authenticate(
    pamh: *mut pam_handle_t,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = match parse_args(argc, argv) {
        Ok(v) => v,
        Err(e) => {
            slog(libc::LOG_ERR, &e);
            return PAM_SYSTEM_ERR;
        }
    };

    // A configured only_from list restricts the OAuth check to those hosts.
    if !args.only_from.is_empty() {
        let rhost = unsafe { get_item_str(pamh, PAM_RHOST) }.unwrap_or(None);
        if !rhost.is_some_and(|h| args.only_from.iter().any(|allowed| *allowed == h)) {
            return PAM_IGNORE;
        }
    }

    let mut userptr: *const c_char = null();
    let rc = unsafe { pam_get_user(pamh, &mut userptr, null()) };
    if rc != PAM_SUCCESS || userptr.is_null() {
        slog(libc::LOG_ERR, &format!("pam_get_user() failed: {}", pam_error(pamh, rc)));
        return if rc == PAM_SUCCESS { PAM_AUTH_ERR } else { rc };
    }
    let user = unsafe { CStr::from_ptr(userptr) }.to_string_lossy().into_owned();

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut pwbuf = [0u8; 1024];
    let mut pwres: *mut libc::passwd = null_mut();
    let Ok(user_c) = CString::new(user.as_str()) else {
        return PAM_AUTH_ERR;
    };
    let rc = unsafe {
        libc::getpwnam_r(user_c.as_ptr(), &mut pwd, pwbuf.as_mut_ptr().cast(), pwbuf.len(), &mut pwres)
    };
    if rc != 0 {
        slog(libc::LOG_ERR, &format!("getpwnam_r({user}) failed"));
        return PAM_TRY_AGAIN;
    }
    if pwres.is_null() {
        slog(libc::LOG_WARNING, &format!("inexistant user {user}"));
    }

    let token = match unsafe { get_item_str(pamh, PAM_AUTHTOK) } {
        Err(rc) => {
            slog(libc::LOG_ERR, &format!("pam_get_item(PAM_AUTHTOK) failed: {}", pam_error(pamh, rc)));
            return rc;
        }
        Ok(Some(token)) => token,
        Ok(None) => {
            let token = match unsafe { converse_for_token(pamh) } {
                Ok(v) => v,
                Err(rc) => return rc,
            };
            if let Ok(token_c) = CString::new(token.as_str()) {
                unsafe { pam_set_item(pamh, PAM_AUTHTOK, token_c.as_ptr().cast()) };
            }
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| unsafe { authenticate(pamh, argc, argv) })).unwrap_or_else(
        |_| {
            slog(libc::LOG_ERR, "pam_oauthbearer: internal panic");
            PAM_SYSTEM_ERR
        },
    )
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
