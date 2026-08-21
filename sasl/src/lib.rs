// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

mod config;

use std::{
    ffi::{c_char, c_void, CStr, CString},
    os::raw::c_uint,
    ptr::{null, null_mut},
};

use config::ServerConfig;
use crudeoauth_core::rfc7628::{build_client_response, parse_client_response};
use sasl2_sys::{
    prelude::{
        sasl_client_params, sasl_client_plug_t, sasl_out_params, sasl_out_params_t,
        sasl_server_params, sasl_server_plug, sasl_server_plug_t, sasl_utils, sasl_utils_t,
        SASL_CLIENT_PLUG_VERSION, SASL_FEAT_ALLOWS_PROXY, SASL_FEAT_WANT_CLIENT_FIRST,
        SASL_SERVER_PLUG_VERSION,
    },
    sasl::{
        sasl_interact, sasl_interact_t, sasl_secret_t, SASL_BADAUTH, SASL_BADPARAM,
        SASL_BADPROT, SASL_BADVERS, SASL_CB_LIST_END, SASL_CB_PASS, SASL_CB_USER,
        SASL_CONTINUE, SASL_CU_AUTHID, SASL_CU_AUTHZID, SASL_ENCRYPT, SASL_FAIL,
        SASL_INTERACT, SASL_LOG_ERR, SASL_LOG_NOTE, SASL_NOMEM, SASL_NOUSER, SASL_OK,
        SASL_SEC_NOANONYMOUS, SASL_SEC_NOPLAINTEXT, SASL_SSF_EXTERNAL, SASL_TOOWEAK,
    },
    saslplug::sasl_callback_ft,
};
use std::ffi::{c_int, c_ulong};

// Not exposed by sasl2-sys bindings against system headers; value from <sasl/sasl.h>.
const SASL_CONFIGERR: i32 = -100;

const MAX_CLIENTIN_LEN: usize = 65_536;
const MECH_NAME: &[u8] = b"OAUTHBEARER\0";
const INVALID_TOKEN_JSON: &str = r#"{"status":"invalid_token"}"#;

struct ServerContext {
    config: *const ServerConfig,
    server_out: Option<CString>,
}

unsafe extern "C" fn server_mech_new(
    glob_context: *mut c_void,
    params: *mut sasl_server_params,
    _challenge: *const i8,
    _challen: u32,
    conn_context: *mut *mut c_void,
) -> i32 {
    if params.is_null() || conn_context.is_null() || glob_context.is_null() {
        return SASL_BADPARAM;
    }
    let ctx = Box::new(ServerContext {
        config: glob_context.cast(),
        server_out: None,
    });
    unsafe { *conn_context = Box::into_raw(ctx).cast(); }
    SASL_OK
}

unsafe extern "C" fn server_mech_step(
    conn_context: *mut c_void,
    params: *mut sasl_server_params,
    client_in: *const c_char,
    client_in_len: u32,
    server_out: *mut *const i8,
    server_out_len: *mut u32,
    oparams: *mut sasl_out_params_t,
) -> i32 {
    if conn_context.is_null() || params.is_null() || server_out.is_null()
        || server_out_len.is_null() || oparams.is_null()
    {
        return SASL_BADPARAM;
    }
    let params = unsafe { &mut *params };
    if params.utils.is_null() {
        return SASL_BADPARAM;
    }
    let utils = unsafe { &*params.utils };
    let ctx = unsafe { &mut *(conn_context.cast::<ServerContext>()) };
    let config = unsafe { &*ctx.config };

    unsafe {
        *server_out = null();
        *server_out_len = 0;
    }

    if config.tls_required {
        let Some(getprop) = utils.getprop else {
            set_error(params.utils, "sasl_utils.getprop is NULL");
            return SASL_FAIL;
        };
        let mut ssf_ptr: *const c_void = null();
        let rc = unsafe { getprop(utils.conn, SASL_SSF_EXTERNAL as i32, &mut ssf_ptr) };
        if rc != SASL_OK {
            set_error(params.utils, "could not get SASL_SSF_EXTERNAL");
            return SASL_BADPARAM;
        }
        let ssf = if ssf_ptr.is_null() { 0 } else { unsafe { *(ssf_ptr.cast::<c_uint>()) } };
        if ssf < 256 {
            set_error(params.utils, "TLS required");
            return SASL_ENCRYPT;
        }
    }

    if client_in_len as usize > MAX_CLIENTIN_LEN {
        set_error(params.utils, "client data too big");
        return SASL_BADPROT;
    }
    if client_in.is_null() && client_in_len != 0 {
        set_error(params.utils, "NULL client input");
        return SASL_BADPARAM;
    }

    let input = if client_in_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(client_in.cast::<u8>(), client_in_len as usize) }
    };

    // RFC 7628 section 3.2.3: client's one-byte response completes an error exchange.
    if input == b"\x01" {
        finish_oparams(oparams);
        return SASL_BADAUTH;
    }

    let response = match parse_client_response(input) {
        Ok(v) => v,
        Err(e) => {
            set_error(params.utils, &format!("invalid OAUTHBEARER client response: {e}"));
            return SASL_BADPROT;
        }
    };

    let authcid = match config.verifier.verify(&response.token) {
        Ok(v) => v,
        Err(e) => {
            log_msg(params.utils, SASL_LOG_NOTE, &format!("OAUTHBEARER token rejected: {e}"));
            set_error(params.utils, &e.to_string());
            ctx.server_out = CString::new(INVALID_TOKEN_JSON).ok();
            if let Some(out) = &ctx.server_out {
                unsafe {
                    *server_out = out.as_ptr();
                    *server_out_len = out.as_bytes().len() as u32;
                }
            }
            return SASL_CONTINUE;
        }
    };

    let Some(canon_user) = params.canon_user else {
        set_error(params.utils, "canon_user callback is NULL");
        return SASL_FAIL;
    };
    let authcid = match CString::new(authcid) {
        Ok(v) => v,
        Err(_) => {
            set_error(params.utils, "authcid contains NUL");
            return SASL_NOUSER;
        }
    };

    let rc = if let Some(authzid) = response.authzid.as_deref().filter(|v| !v.is_empty()) {
        let authzid = match CString::new(authzid) {
            Ok(v) => v,
            Err(_) => {
                set_error(params.utils, "authzid contains NUL");
                return SASL_BADPROT;
            }
        };
        let rc = unsafe {
            canon_user(utils.conn, authzid.as_ptr(), authzid.as_bytes().len() as u32, SASL_CU_AUTHZID, oparams)
        };
        if rc != SASL_OK {
            rc
        } else {
            unsafe {
                canon_user(utils.conn, authcid.as_ptr(), authcid.as_bytes().len() as u32, SASL_CU_AUTHID, oparams)
            }
        }
    } else {
        unsafe {
            canon_user(
                utils.conn,
                authcid.as_ptr(),
                authcid.as_bytes().len() as u32,
                SASL_CU_AUTHID | SASL_CU_AUTHZID,
                oparams,
            )
        }
    };

    if rc != SASL_OK {
        set_error(params.utils, &format!("canon_user failed ({rc})"));
        return rc;
    }

    finish_oparams(oparams);
    SASL_OK
}

unsafe extern "C" fn server_mech_dispose(conn_context: *mut c_void, _utils: *const sasl_utils_t) {
    if !conn_context.is_null() {
        unsafe { drop(Box::from_raw(conn_context.cast::<ServerContext>())); }
    }
}

unsafe extern "C" fn server_mech_free(glob_context: *mut c_void, _utils: *const sasl_utils_t) {
    if !glob_context.is_null() {
        unsafe { drop(Box::from_raw(glob_context.cast::<ServerConfig>())); }
    }
}

fn make_server_plugin(config: Box<ServerConfig>) -> sasl_server_plug_t {
    sasl_server_plug_t {
        mech_name: MECH_NAME.as_ptr().cast(),
        max_ssf: 0,
        security_flags: SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
        features: SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY,
        glob_context: Box::into_raw(config).cast(),
        mech_new: Some(server_mech_new),
        mech_step: Some(server_mech_step),
        mech_dispose: Some(server_mech_dispose),
        mech_free: Some(server_mech_free),
        setpass: None,
        user_query: None,
        idle: None,
        mech_avail: None,
        spare_fptr2: None,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sasl_server_plug_init(
    utils: *const sasl_utils,
    maxvers: i32,
    outvers: *mut i32,
    pluglist: *mut *mut sasl_server_plug,
    plugcount: *mut i32,
) -> i32 {
    if utils.is_null() || outvers.is_null() || pluglist.is_null() || plugcount.is_null() {
        return SASL_BADPARAM;
    }
    if maxvers < SASL_SERVER_PLUG_VERSION as i32 {
        log_msg(utils, SASL_LOG_ERR, "OAUTHBEARER server plugin version mismatch");
        return SASL_BADVERS;
    }

    let config = match unsafe { ServerConfig::from_sasl(utils) } {
        Ok(v) => Box::new(v),
        Err(e) => {
            log_msg(utils, SASL_LOG_ERR, &format!("OAUTHBEARER configuration failed: {e}"));
            return SASL_CONFIGERR;
        }
    };
    let plugin = Box::new(make_server_plugin(config));
    log_msg(utils, SASL_LOG_NOTE, "OAUTHBEARER loaded JWKS and initialized verifier");

    unsafe {
        *outvers = SASL_SERVER_PLUG_VERSION as i32;
        *pluglist = Box::into_raw(plugin);
        *plugcount = 1;
    }
    SASL_OK
}

// Client side: obtains the access token via SASL_CB_PASS and an optional
// authzid via SASL_CB_USER (through callbacks or the sasl_interact prompt
// cycle), then emits the RFC 7628 initial response. The JWT verifier is
// server-only; the client treats the token as opaque.
const MAX_SERVERIN_LEN: u32 = 65_536;

struct ClientContext {
    output: Vec<u8>,
}

enum CbValue {
    Value(Option<Vec<u8>>),
    NeedPrompt,
    Fail(i32),
}

unsafe fn find_prompt(
    prompt_need: *mut *mut sasl_interact_t,
    id: c_ulong,
) -> Option<*mut sasl_interact_t> {
    if prompt_need.is_null() || unsafe { *prompt_need }.is_null() {
        return None;
    }
    let mut p = unsafe { *prompt_need };
    loop {
        let entry = unsafe { &*p };
        if entry.id == SASL_CB_LIST_END {
            return None;
        }
        if entry.id == id {
            return Some(p);
        }
        p = unsafe { p.add(1) };
    }
}

/// Fetch an optional simple value (SASL_CB_USER): prompt results take
/// precedence, then the registered callback; a NULL-proc callback entry means
/// the application wants to be prompted.
unsafe fn get_simple(
    utils: &sasl_utils_t,
    id: c_ulong,
    prompt_need: *mut *mut sasl_interact_t,
) -> CbValue {
    if let Some(p) = unsafe { find_prompt(prompt_need, id) } {
        let entry = unsafe { &*p };
        if entry.result.is_null() {
            return CbValue::Value(None);
        }
        let bytes = if entry.len > 0 {
            unsafe { std::slice::from_raw_parts(entry.result.cast::<u8>(), entry.len as usize) }
                .to_vec()
        } else {
            unsafe { CStr::from_ptr(entry.result.cast()) }.to_bytes().to_vec()
        };
        return CbValue::Value(Some(bytes));
    }

    let Some(getcallback) = utils.getcallback else {
        return CbValue::Fail(SASL_FAIL);
    };
    let mut proc_: sasl_callback_ft = None;
    let mut context: *mut c_void = null_mut();
    match unsafe { getcallback(utils.conn, id, &mut proc_, &mut context) } {
        SASL_OK => {
            let Some(proc_) = proc_ else {
                return CbValue::Fail(SASL_FAIL);
            };
            let cb: unsafe extern "C" fn(
                *mut c_void,
                c_int,
                *mut *const c_char,
                *mut c_uint,
            ) -> c_int = unsafe { std::mem::transmute(proc_) };
            let mut result: *const c_char = null();
            let rc = unsafe { cb(context, id as c_int, &mut result, null_mut()) };
            if rc != SASL_OK {
                return CbValue::Fail(rc);
            }
            if result.is_null() {
                return CbValue::Value(None);
            }
            CbValue::Value(Some(unsafe { CStr::from_ptr(result) }.to_bytes().to_vec()))
        }
        SASL_FAIL => CbValue::Value(None), // no callback registered; the value is optional
        SASL_INTERACT => CbValue::NeedPrompt,
        other => CbValue::Fail(other),
    }
}

/// Fetch the access token (SASL_CB_PASS). Unlike get_simple the value is
/// required, so a missing callback is an error.
unsafe fn get_password(utils: &sasl_utils_t, prompt_need: *mut *mut sasl_interact_t) -> CbValue {
    if let Some(p) = unsafe { find_prompt(prompt_need, SASL_CB_PASS) } {
        let entry = unsafe { &*p };
        if entry.result.is_null() {
            return CbValue::Fail(SASL_BADPARAM);
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(entry.result.cast::<u8>(), entry.len as usize) }
                .to_vec();
        return CbValue::Value(Some(bytes));
    }

    let Some(getcallback) = utils.getcallback else {
        return CbValue::Fail(SASL_FAIL);
    };
    let mut proc_: sasl_callback_ft = None;
    let mut context: *mut c_void = null_mut();
    match unsafe { getcallback(utils.conn, SASL_CB_PASS, &mut proc_, &mut context) } {
        SASL_OK => {
            let Some(proc_) = proc_ else {
                return CbValue::Fail(SASL_FAIL);
            };
            let cb: unsafe extern "C" fn(
                *mut sasl2_sys::sasl::sasl_conn_t,
                *mut c_void,
                c_int,
                *mut *mut sasl_secret_t,
            ) -> c_int = unsafe { std::mem::transmute(proc_) };
            let mut secret: *mut sasl_secret_t = null_mut();
            let rc = unsafe { cb(utils.conn, context, SASL_CB_PASS as c_int, &mut secret) };
            if rc != SASL_OK {
                return CbValue::Fail(rc);
            }
            if secret.is_null() {
                return CbValue::Value(None);
            }
            let s = unsafe { &*secret };
            let bytes =
                unsafe { std::slice::from_raw_parts(s.data.as_ptr(), s.len as usize) }.to_vec();
            CbValue::Value(Some(bytes))
        }
        SASL_INTERACT => CbValue::NeedPrompt,
        other => CbValue::Fail(other),
    }
}

/// Allocate a SASL_CB_LIST_END-terminated prompt array via the SASL allocator
/// (the application and libsasl free it with the same allocator).
unsafe fn make_prompts(
    utils: &sasl_utils_t,
    prompt_need: *mut *mut sasl_interact_t,
    want_user: bool,
    want_pass: bool,
) -> i32 {
    if prompt_need.is_null() {
        return SASL_FAIL;
    }
    let Some(malloc) = utils.malloc else {
        return SASL_FAIL;
    };
    let count = usize::from(want_user) + usize::from(want_pass) + 1;
    let arr = unsafe { malloc(count * std::mem::size_of::<sasl_interact_t>()) }
        .cast::<sasl_interact_t>();
    if arr.is_null() {
        return SASL_NOMEM;
    }

    let mut i = 0;
    let mut push = |id: c_ulong, challenge: &'static CStr, prompt: &'static CStr| {
        unsafe {
            arr.add(i).write(sasl_interact {
                id,
                challenge: challenge.as_ptr(),
                prompt: prompt.as_ptr(),
                defresult: null(),
                result: null(),
                len: 0,
            });
        }
        i += 1;
    };
    if want_user {
        push(SASL_CB_USER, c"Authorization Name", c"Please enter an authorization name");
    }
    if want_pass {
        push(SASL_CB_PASS, c"Access Token", c"Please enter Access Token (as JWT)");
    }
    push(SASL_CB_LIST_END, c"", c"");

    unsafe { *prompt_need = arr };
    SASL_INTERACT
}

unsafe extern "C" fn client_mech_new(
    _glob_context: *mut c_void,
    _params: *mut sasl_client_params,
    conn_context: *mut *mut c_void,
) -> i32 {
    if conn_context.is_null() { return SASL_BADPARAM; }
    let ctx = Box::new(ClientContext { output: Vec::new() });
    unsafe { *conn_context = Box::into_raw(ctx).cast(); }
    SASL_OK
}

unsafe extern "C" fn client_mech_step(
    context: *mut c_void,
    c_params: *mut sasl_client_params,
    server_in: *const i8,
    server_in_len: u32,
    prompt_need: *mut *mut sasl_interact,
    client_out: *mut *const i8,
    client_out_len: *mut u32,
    oparams: *mut sasl_out_params,
) -> i32 {
    if context.is_null()
        || c_params.is_null()
        || client_out.is_null()
        || client_out_len.is_null()
        || oparams.is_null()
    {
        return SASL_BADPARAM;
    }
    let params = unsafe { &mut *c_params };
    if params.utils.is_null() {
        return SASL_BADPARAM;
    }
    let utils = unsafe { &*params.utils };
    let ctx = unsafe { &mut *context.cast::<ClientContext>() };

    if server_in_len > MAX_SERVERIN_LEN {
        set_error(params.utils, "server data too big");
        return SASL_BADPROT;
    }

    if server_in_len != 0 {
        // RFC 7628 3.2.2: the server rejected the token with a JSON error.
        // Complete the error message sequence (3.2.3) with a single %x01.
        let msg = if server_in.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(server_in.cast::<u8>(), server_in_len as usize) }
        };
        set_error(
            params.utils,
            &format!("Authentication failed ({})", String::from_utf8_lossy(msg)),
        );
        ctx.output.clear();
        ctx.output.push(0x01);
        unsafe {
            *client_out = ctx.output.as_ptr().cast();
            *client_out_len = 1;
        }
        finish_oparams(oparams);
        return SASL_OK;
    }

    unsafe {
        *client_out = null();
        *client_out_len = 0;
    }

    if params.props.min_ssf > params.external_ssf {
        set_error(params.utils, "SSF too weak for the OAUTHBEARER plugin");
        return SASL_TOOWEAK;
    }

    let user = unsafe { get_simple(utils, SASL_CB_USER, prompt_need) };
    let pass = unsafe { get_password(utils, prompt_need) };

    // The prompt results are harvested; release the array we allocated in the
    // previous round before possibly requesting a new one.
    if !prompt_need.is_null() && !unsafe { *prompt_need }.is_null() {
        if let Some(free) = utils.free {
            unsafe { free((*prompt_need).cast()) };
        }
        unsafe { *prompt_need = null_mut() };
    }

    let want_user = matches!(user, CbValue::NeedPrompt);
    let want_pass = matches!(pass, CbValue::NeedPrompt);
    if want_user || want_pass {
        return unsafe { make_prompts(utils, prompt_need, want_user, want_pass) };
    }

    let authzid = match user {
        CbValue::Value(v) => v,
        CbValue::Fail(rc) => return rc,
        CbValue::NeedPrompt => unreachable!(),
    };
    let token = match pass {
        CbValue::Value(Some(v)) => v,
        CbValue::Value(None) => {
            set_error(params.utils, "Bad parameter (no Access Token)");
            return SASL_BADPARAM;
        }
        CbValue::Fail(rc) => return rc,
        CbValue::NeedPrompt => unreachable!(),
    };
    let Ok(token) = std::str::from_utf8(&token) else {
        set_error(params.utils, "Access Token is not valid UTF-8");
        return SASL_BADPARAM;
    };

    let Some(canon_user) = params.canon_user else {
        set_error(params.utils, "canon_user callback is NULL");
        return SASL_FAIL;
    };
    let authzid = match authzid.filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => match String::from_utf8(v) {
            Ok(s) => Some(s),
            Err(_) => {
                set_error(params.utils, "authzid is not valid UTF-8");
                return SASL_BADPARAM;
            }
        },
    };

    // The real identity is derived from the token by the server; use the
    // "anonymous" placeholder for the client-side authcid like the C plugin.
    let anonymous = c"anonymous";
    let rc = unsafe { canon_user(utils.conn, anonymous.as_ptr(), 0, SASL_CU_AUTHID, oparams) };
    if rc != SASL_OK {
        return rc;
    }
    let rc = if let Some(authzid) = &authzid {
        let Ok(authzid_c) = CString::new(authzid.as_str()) else {
            set_error(params.utils, "authzid contains NUL");
            return SASL_BADPARAM;
        };
        unsafe { canon_user(utils.conn, authzid_c.as_ptr(), 0, SASL_CU_AUTHZID, oparams) }
    } else {
        unsafe { canon_user(utils.conn, anonymous.as_ptr(), 0, SASL_CU_AUTHZID, oparams) }
    };
    if rc != SASL_OK {
        return rc;
    }

    ctx.output = build_client_response(authzid.as_deref(), token);
    unsafe {
        *client_out = ctx.output.as_ptr().cast();
        *client_out_len = ctx.output.len() as u32;
    }
    SASL_CONTINUE
}

unsafe extern "C" fn client_mech_dispose(context: *mut c_void, _utils: *const sasl_utils) {
    if !context.is_null() {
        unsafe { drop(Box::from_raw(context.cast::<ClientContext>())); }
    }
}

fn make_client_plugin() -> sasl_client_plug_t {
    sasl_client_plug_t {
        mech_name: MECH_NAME.as_ptr().cast(),
        max_ssf: 0,
        security_flags: SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
        features: SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY,
        required_prompts: null(),
        glob_context: null_mut(),
        mech_new: Some(client_mech_new),
        mech_step: Some(client_mech_step),
        mech_dispose: Some(client_mech_dispose),
        mech_free: None,
        idle: None,
        spare_fptr2: None,
        spare_fptr1: None,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sasl_client_plug_init(
    utils: *const sasl_utils_t,
    maxvers: i32,
    outvers: *mut i32,
    pluglist: *mut *mut sasl_client_plug_t,
    plugcount: *mut i32,
) -> i32 {
    if utils.is_null() || outvers.is_null() || pluglist.is_null() || plugcount.is_null() {
        return SASL_BADPARAM;
    }
    if maxvers < SASL_CLIENT_PLUG_VERSION as i32 {
        log_msg(utils, SASL_LOG_ERR, "OAUTHBEARER client plugin version mismatch");
        return SASL_BADVERS;
    }
    unsafe {
        *outvers = SASL_CLIENT_PLUG_VERSION as i32;
        *pluglist = Box::into_raw(Box::new(make_client_plugin()));
        *plugcount = 1;
    }
    SASL_OK
}

fn finish_oparams(oparams: *mut sasl_out_params_t) {
    if oparams.is_null() { return; }
    unsafe {
        (*oparams).doneflag = 1;
        (*oparams).mech_ssf = 0;
        (*oparams).maxoutbuf = 0;
        (*oparams).encode_context = null_mut();
        (*oparams).encode = None;
        (*oparams).decode_context = null_mut();
        (*oparams).decode = None;
        (*oparams).param_version = 0;
    }
}

fn log_msg(utils: *const sasl_utils_t, level: i32, message: &str) {
    if utils.is_null() { return; }
    let Ok(message) = CString::new(message) else { return; };
    let Some(log) = (unsafe { (*utils).log }) else { return; };
    unsafe { log((*utils).conn, level, b"%s\0".as_ptr().cast(), message.as_ptr()); }
}

fn set_error(utils: *const sasl_utils_t, message: &str) {
    if utils.is_null() { return; }
    let Ok(message) = CString::new(message) else { return; };
    let Some(seterror) = (unsafe { (*utils).seterror }) else { return; };
    unsafe { seterror((*utils).conn, 0, b"%s\0".as_ptr().cast(), message.as_ptr()); }
}

#[allow(dead_code)]
fn cstr(ptr: *const c_char) -> Option<&'static CStr> {
    if ptr.is_null() { None } else { Some(unsafe { CStr::from_ptr(ptr) }) }
}
