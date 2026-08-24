// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! In-process integration tests for the client mechanism: register the plugin
//! with the real libsasl2 via sasl_client_add_plugin and drive it through
//! sasl_client_start/_step, both with value callbacks and with the
//! sasl_interact prompt cycle (the path libldap uses).

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void, CStr};
use std::mem::offset_of;
use std::ptr::{null, null_mut};
use std::sync::Once;

use crudeoauth_core::rfc7628::parse_client_response;
use sasl2_sys::sasl::{
    sasl_callback_t, sasl_client_init, sasl_client_new, sasl_client_start, sasl_client_step,
    sasl_conn_t, sasl_dispose, sasl_interact_t, sasl_secret_t, SASL_CB_LIST_END, SASL_CB_PASS,
    SASL_CB_USER, SASL_CONTINUE, SASL_INTERACT, SASL_OK,
};
use sasl2_sys::saslplug::sasl_client_add_plugin;

const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJmYWtlIjoxfQ.c2lnbmF0dXJl";
const AUTHZID: &str = "u:someuser";

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| unsafe {
        assert_eq!(sasl_client_init(null()), SASL_OK);
        assert_eq!(
            sasl_client_add_plugin(c"oauthbearer".as_ptr(), Some(oauthbearer::sasl_client_plug_init)),
            SASL_OK
        );
    });
}

unsafe extern "C" fn cb_user(
    _context: *mut c_void,
    _id: c_int,
    result: *mut *const c_char,
    len: *mut c_uint,
) -> c_int {
    unsafe {
        *result = c"u:someuser".as_ptr();
        if !len.is_null() {
            *len = AUTHZID.len() as c_uint;
        }
    }
    SASL_OK
}

/// Build a sasl_secret_t (length-prefixed flexible array) holding TOKEN.
fn secret_ptr() -> *mut sasl_secret_t {
    let data = TOKEN.as_bytes();
    let bytes = offset_of!(sasl_secret_t, data) + data.len() + 1;
    let words = bytes.div_ceil(size_of::<c_ulong>());
    let buf: &'static mut [c_ulong] = Vec::leak(vec![0; words]);
    let p = buf.as_mut_ptr().cast::<u8>();
    unsafe {
        p.cast::<c_ulong>().write(data.len() as c_ulong);
        p.add(offset_of!(sasl_secret_t, data))
            .copy_from_nonoverlapping(data.as_ptr(), data.len());
    }
    p.cast()
}

unsafe extern "C" fn cb_pass(
    _conn: *mut sasl_conn_t,
    _context: *mut c_void,
    _id: c_int,
    psecret: *mut *mut sasl_secret_t,
) -> c_int {
    unsafe { *psecret = secret_ptr() };
    SASL_OK
}

type AnyCb = unsafe extern "C" fn() -> c_int;

fn value_callbacks() -> [sasl_callback_t; 3] {
    unsafe {
        [
            sasl_callback_t {
                id: SASL_CB_USER,
                proc_: Some(std::mem::transmute::<
                    unsafe extern "C" fn(*mut c_void, c_int, *mut *const c_char, *mut c_uint) -> c_int,
                    AnyCb,
                >(cb_user)),
                context: null_mut(),
            },
            sasl_callback_t {
                id: SASL_CB_PASS,
                proc_: Some(std::mem::transmute::<
                    unsafe extern "C" fn(
                        *mut sasl_conn_t,
                        *mut c_void,
                        c_int,
                        *mut *mut sasl_secret_t,
                    ) -> c_int,
                    AnyCb,
                >(cb_pass)),
                context: null_mut(),
            },
            sasl_callback_t { id: SASL_CB_LIST_END, proc_: None, context: null_mut() },
        ]
    }
}

/// NULL-proc entries: the application wants sasl_interact prompting.
fn interact_callbacks() -> [sasl_callback_t; 3] {
    [
        sasl_callback_t { id: SASL_CB_USER, proc_: None, context: null_mut() },
        sasl_callback_t { id: SASL_CB_PASS, proc_: None, context: null_mut() },
        sasl_callback_t { id: SASL_CB_LIST_END, proc_: None, context: null_mut() },
    ]
}

unsafe fn new_conn(callbacks: *const sasl_callback_t) -> *mut sasl_conn_t {
    let mut conn: *mut sasl_conn_t = null_mut();
    let rc = unsafe {
        sasl_client_new(c"ldap".as_ptr(), c"server.example.org".as_ptr(), null(), null(), callbacks, 0, &mut conn)
    };
    assert_eq!(rc, SASL_OK);
    conn
}

#[test]
fn client_emits_initial_response_from_callbacks() {
    init();
    let callbacks = value_callbacks();
    unsafe {
        let mut conn = new_conn(callbacks.as_ptr());
        let mut prompts: *mut sasl_interact_t = null_mut();
        let mut out: *const c_char = null();
        let mut outlen: c_uint = 0;
        let mut mech: *const c_char = null();

        let rc = sasl_client_start(conn, c"OAUTHBEARER".as_ptr(), &mut prompts, &mut out, &mut outlen, &mut mech);
        assert_eq!(rc, SASL_CONTINUE);
        assert_eq!(CStr::from_ptr(mech).to_str().unwrap(), "OAUTHBEARER");

        let msg = std::slice::from_raw_parts(out.cast::<u8>(), outlen as usize);
        let parsed = parse_client_response(msg).unwrap();
        assert_eq!(parsed.token, TOKEN);
        assert_eq!(parsed.authzid.as_deref(), Some(AUTHZID));

        // Server rejects: RFC 7628 error JSON in, single %x01 out, mech done.
        let error_json = r#"{"status":"invalid_token"}"#;
        let rc = sasl_client_step(
            conn,
            error_json.as_ptr().cast(),
            error_json.len() as c_uint,
            &mut prompts,
            &mut out,
            &mut outlen,
        );
        assert_eq!(rc, SASL_OK);
        let msg = std::slice::from_raw_parts(out.cast::<u8>(), outlen as usize);
        assert_eq!(msg, b"\x01");

        sasl_dispose(&mut conn);
    }
}

#[test]
fn client_prompts_when_no_value_callbacks() {
    init();
    let callbacks = interact_callbacks();
    unsafe {
        let mut conn = new_conn(callbacks.as_ptr());
        let mut prompts: *mut sasl_interact_t = null_mut();
        let mut out: *const c_char = null();
        let mut outlen: c_uint = 0;
        let mut mech: *const c_char = null();

        let rc = sasl_client_start(conn, c"OAUTHBEARER".as_ptr(), &mut prompts, &mut out, &mut outlen, &mut mech);
        assert_eq!(rc, SASL_INTERACT);
        assert!(!prompts.is_null());

        // Fill the prompts like libldap's interact loop would.
        let mut p = prompts;
        let mut seen = 0;
        while (*p).id != SASL_CB_LIST_END {
            match (*p).id {
                SASL_CB_USER => {
                    (*p).result = AUTHZID.as_ptr().cast();
                    (*p).len = AUTHZID.len() as c_uint;
                }
                SASL_CB_PASS => {
                    (*p).result = TOKEN.as_ptr().cast();
                    (*p).len = TOKEN.len() as c_uint;
                }
                other => panic!("unexpected prompt id {other}"),
            }
            seen += 1;
            p = p.add(1);
        }
        assert_eq!(seen, 2);

        let rc = sasl_client_start(conn, c"OAUTHBEARER".as_ptr(), &mut prompts, &mut out, &mut outlen, &mut mech);
        assert_eq!(rc, SASL_CONTINUE, "start after filling prompts");

        let msg = std::slice::from_raw_parts(out.cast::<u8>(), outlen as usize);
        let parsed = parse_client_response(msg).unwrap();
        assert_eq!(parsed.token, TOKEN);
        assert_eq!(parsed.authzid.as_deref(), Some(AUTHZID));

        sasl_dispose(&mut conn);
    }
}
