// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Full-stack PAM tests: a generated service file in a private confdir makes
//! the real libpam dlopen the built cdylib and dispatch pam_sm_authenticate;
//! the conversation callback supplies a token signed with the fixture key.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

const ISSUER: &str = "https://sso.example.org/realms/master";
const AUDIENCE: &str = "ldaps://example.org/";

#[repr(C)]
struct pam_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
struct pam_message {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct pam_response {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct pam_conv {
    conv: Option<
        unsafe extern "C" fn(
            c_int,
            *mut *const pam_message,
            *mut *mut pam_response,
            *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const pam_conv,
        confdir: *const c_char,
        pamh: *mut *mut pam_handle_t,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut pam_handle_t, status: c_int) -> c_int;
}

/// Answers every echo-off prompt with the token passed as appdata.
unsafe extern "C" fn conv_cb(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata: *mut c_void,
) -> c_int {
    let token = unsafe { CStr::from_ptr(appdata.cast()) };
    let responses = unsafe {
        libc::calloc(num_msg.max(0) as usize, size_of::<pam_response>()).cast::<pam_response>()
    };
    for i in 0..num_msg.max(0) as usize {
        let m = unsafe { &**msg.add(i) };
        if m.msg_style == PAM_PROMPT_ECHO_OFF {
            unsafe { (*responses.add(i)).resp = libc::strdup(token.as_ptr()) };
        }
    }
    unsafe { *resp = responses };
    PAM_SUCCESS
}

fn module_path() -> PathBuf {
    // target/debug/deps/pam_auth-<hash> -> target/debug/libcrudeoauth.so
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().unwrap().parent().unwrap().join("libpam_oauthbearer.so");
    assert!(path.exists(), "cdylib not found at {path:?}");
    path
}

fn write_confdir(service: &str) -> PathBuf {
    let confdir = module_path().parent().unwrap().join("pam-test-confdir");
    std::fs::create_dir_all(&confdir).unwrap();
    let jwks = concat!(env!("CARGO_MANIFEST_DIR"), "/../core/tests/fixtures/jwks.json");
    std::fs::write(
        confdir.join(service),
        format!(
            "auth required {} iss={ISSUER} jwks={jwks} trusted_aud={AUDIENCE}\n",
            module_path().display()
        ),
    )
    .unwrap();
    confdir
}

fn sign_token(username: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "preferred_username": username,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(include_bytes!("../../core/tests/fixtures/test_rsa.pem")).unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn run_pam_auth(service: &str, pam_user: &str, token: &str) -> c_int {
    let confdir = write_confdir(service);
    let service_c = CString::new(service).unwrap();
    let user_c = CString::new(pam_user).unwrap();
    let confdir_c = CString::new(confdir.to_str().unwrap()).unwrap();
    let token_c = CString::new(token).unwrap();
    let conv = pam_conv { conv: Some(conv_cb), appdata_ptr: token_c.as_ptr() as *mut c_void };

    unsafe {
        let mut pamh: *mut pam_handle_t = null_mut();
        let rc = pam_start_confdir(
            service_c.as_ptr(),
            user_c.as_ptr(),
            &conv,
            confdir_c.as_ptr(),
            &mut pamh,
        );
        assert_eq!(rc, PAM_SUCCESS, "pam_start_confdir");
        assert!(!pamh.is_null());
        let rc = pam_authenticate(pamh, 0);
        pam_end(pamh, rc);
        rc
    }
}

#[test]
fn matching_token_authenticates() {
    let token = sign_token("crudetest");
    assert_eq!(run_pam_auth("crudeoauth-ok", "crudetest", &token), PAM_SUCCESS);
}

#[test]
fn user_mismatch_is_rejected() {
    let token = sign_token("crudetest");
    assert_eq!(run_pam_auth("crudeoauth-mismatch", "someoneelse", &token), PAM_AUTH_ERR);
}

#[test]
fn tampered_token_is_rejected() {
    let mut token = sign_token("crudetest");
    let sig_start = token.rfind('.').unwrap() + 1;
    let tail = if token.ends_with("AAAA") { "BBBB" } else { "AAAA" };
    token.replace_range(token.len() - 4.min(token.len() - sig_start).., tail);
    assert_eq!(run_pam_auth("crudeoauth-tampered", "crudetest", &token), PAM_AUTH_ERR);
}

#[test]
fn expired_token_is_rejected() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now - 300,
        "preferred_username": "crudetest",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(include_bytes!("../../core/tests/fixtures/test_rsa.pem")).unwrap();
    let token = encode(&header, &claims, &key).unwrap();
    assert_eq!(run_pam_auth("crudeoauth-expired", "crudetest", &token), PAM_AUTH_ERR);
}
