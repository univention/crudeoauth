// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Cyrus SASL OAUTHBEARER mechanism (server and client).
//!
//! Structure: `ffi` wraps the raw plugin ABI in safe types; the mechanism
//! logic (`server_step`/`client_step`) is safe Rust; the `unsafe extern "C"`
//! functions below only validate raw arguments, build the wrappers, guard
//! against panics and dispatch.

mod config;
mod ffi;

use std::ffi::{c_char, c_uint, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;

use config::ServerConfig;
use crudeoauth_core::rfc7628::{build_client_response, parse_client_response};
use ffi::{CanonUser, CbValue, OutBuf, OutParams, Prompts, Utils};
use sasl2_sys::{
    prelude::{
        sasl_client_params, sasl_client_plug_t, sasl_out_params, sasl_out_params_t,
        sasl_server_params, sasl_server_plug, sasl_server_plug_t, sasl_utils, sasl_utils_t,
        SASL_CLIENT_PLUG_VERSION, SASL_FEAT_ALLOWS_PROXY, SASL_FEAT_WANT_CLIENT_FIRST,
        SASL_SERVER_PLUG_VERSION,
    },
    sasl::{
        sasl_interact, SASL_BADAUTH, SASL_BADPARAM, SASL_BADPROT, SASL_BADVERS, SASL_CB_USER,
        SASL_CONTINUE, SASL_CU_AUTHID, SASL_CU_AUTHZID, SASL_ENCRYPT, SASL_FAIL, SASL_LOG_ERR,
        SASL_LOG_NOTE, SASL_NOUSER, SASL_OK, SASL_SEC_NOANONYMOUS, SASL_SEC_NOPLAINTEXT,
        SASL_TOOWEAK,
    },
};

// Not exposed by sasl2-sys bindings against system headers; value from <sasl/sasl.h>.
const SASL_CONFIGERR: i32 = -100;

const MAX_CLIENTIN_LEN: usize = 65_536;
const MAX_SERVERIN_LEN: u32 = 65_536;
const MECH_NAME: &[u8] = b"OAUTHBEARER\0";
const INVALID_TOKEN_JSON: &str = r#"{"status":"invalid_token"}"#;

/// A panic must not unwind into libsasl2; report SASL_FAIL instead.
fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(SASL_FAIL)
}

// ---------------------------------------------------------------------------
// Server mechanism
// ---------------------------------------------------------------------------

struct ServerContext {
    config: *const ServerConfig,
    server_out: Option<CString>,
}

fn server_step(
    utils: &Utils,
    config: &ServerConfig,
    ctx: &mut ServerContext,
    input: &[u8],
    canon: Option<CanonUser>,
    out: &mut OutBuf,
    oparams: &mut OutParams,
) -> i32 {
    out.clear();

    if config.tls_required {
        let ssf = match utils.external_ssf() {
            Ok(v) => v,
            Err(e) => {
                utils.set_error(&e);
                return SASL_BADPARAM;
            }
        };
        if ssf < 256 {
            utils.set_error("TLS required");
            return SASL_ENCRYPT;
        }
    }

    if input.len() > MAX_CLIENTIN_LEN {
        utils.set_error("client data too big");
        return SASL_BADPROT;
    }

    // RFC 7628 section 3.2.3: client's one-byte response completes an error exchange.
    if input == b"\x01" {
        oparams.finish();
        return SASL_BADAUTH;
    }

    let response = match parse_client_response(input) {
        Ok(v) => v,
        Err(e) => {
            utils.set_error(&format!("invalid OAUTHBEARER client response: {e}"));
            return SASL_BADPROT;
        }
    };

    let authcid = match config.verifier.verify(&response.token) {
        Ok(v) => v,
        Err(e) => {
            utils.log(SASL_LOG_NOTE, &format!("OAUTHBEARER token rejected: {e}"));
            utils.set_error(&e.to_string());
            ctx.server_out = CString::new(INVALID_TOKEN_JSON).ok();
            if let Some(json) = &ctx.server_out {
                out.publish(json.as_bytes());
            }
            return SASL_CONTINUE;
        }
    };

    let Some(canon) = canon else {
        utils.set_error("canon_user callback is NULL");
        return SASL_FAIL;
    };
    let Ok(authcid) = CString::new(authcid) else {
        utils.set_error("authcid contains NUL");
        return SASL_NOUSER;
    };

    let rc = if let Some(authzid) = response.authzid.as_deref().filter(|v| !v.is_empty()) {
        let Ok(authzid) = CString::new(authzid) else {
            utils.set_error("authzid contains NUL");
            return SASL_BADPROT;
        };
        let rc = canon.apply(&authzid, SASL_CU_AUTHZID, oparams);
        if rc != SASL_OK { rc } else { canon.apply(&authcid, SASL_CU_AUTHID, oparams) }
    } else {
        canon.apply(&authcid, SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams)
    };
    if rc != SASL_OK {
        utils.set_error(&format!("canon_user failed ({rc})"));
        return rc;
    }

    oparams.finish();
    SASL_OK
}

unsafe extern "C" fn server_mech_new(
    glob_context: *mut c_void,
    params: *mut sasl_server_params,
    _challenge: *const c_char,
    _challen: u32,
    conn_context: *mut *mut c_void,
) -> i32 {
    guard(|| {
        if params.is_null() || conn_context.is_null() || glob_context.is_null() {
            return SASL_BADPARAM;
        }
        let ctx = Box::new(ServerContext { config: glob_context.cast(), server_out: None });
        unsafe { *conn_context = Box::into_raw(ctx).cast() };
        SASL_OK
    })
}

unsafe extern "C" fn server_mech_step(
    conn_context: *mut c_void,
    params: *mut sasl_server_params,
    client_in: *const c_char,
    client_in_len: u32,
    server_out: *mut *const c_char,
    server_out_len: *mut u32,
    oparams: *mut sasl_out_params_t,
) -> i32 {
    guard(|| {
        if conn_context.is_null() || params.is_null() {
            return SASL_BADPARAM;
        }
        let params = unsafe { &mut *params };
        let (Some(utils), Some(mut out), Some(mut oparams)) = (
            unsafe { Utils::from_raw(params.utils) },
            unsafe { OutBuf::from_raw(server_out, server_out_len) },
            unsafe { OutParams::from_raw(oparams) },
        ) else {
            return SASL_BADPARAM;
        };
        let ctx = unsafe { &mut *conn_context.cast::<ServerContext>() };
        let config = unsafe { &*ctx.config };
        if client_in.is_null() && client_in_len != 0 {
            utils.set_error("NULL client input");
            return SASL_BADPARAM;
        }
        let input = if client_in_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(client_in.cast::<u8>(), client_in_len as usize) }
        };
        let canon = unsafe { CanonUser::from_parts(params.canon_user, utils.conn()) };

        server_step(&utils, config, ctx, input, canon, &mut out, &mut oparams)
    })
}

unsafe extern "C" fn server_mech_dispose(conn_context: *mut c_void, _utils: *const sasl_utils_t) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !conn_context.is_null() {
            drop(unsafe { Box::from_raw(conn_context.cast::<ServerContext>()) });
        }
    }));
}

unsafe extern "C" fn server_mech_free(glob_context: *mut c_void, _utils: *const sasl_utils_t) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !glob_context.is_null() {
            drop(unsafe { Box::from_raw(glob_context.cast::<ServerConfig>()) });
        }
    }));
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
    guard(|| {
        if outvers.is_null() || pluglist.is_null() || plugcount.is_null() {
            return SASL_BADPARAM;
        }
        let Some(utils) = (unsafe { Utils::from_raw(utils) }) else {
            return SASL_BADPARAM;
        };
        if maxvers < SASL_SERVER_PLUG_VERSION as i32 {
            utils.log(SASL_LOG_ERR, "OAUTHBEARER server plugin version mismatch");
            return SASL_BADVERS;
        }

        let config = match ServerConfig::from_sasl(&utils) {
            Ok(v) => Box::new(v),
            Err(e) => {
                utils.log(SASL_LOG_ERR, &format!("OAUTHBEARER configuration failed: {e}"));
                return SASL_CONFIGERR;
            }
        };
        let plugin = Box::new(make_server_plugin(config));
        utils.log(SASL_LOG_NOTE, "OAUTHBEARER loaded JWKS and initialized verifier");

        unsafe {
            *outvers = SASL_SERVER_PLUG_VERSION as i32;
            *pluglist = Box::into_raw(plugin);
            *plugcount = 1;
        }
        SASL_OK
    })
}

// ---------------------------------------------------------------------------
// Client mechanism
// ---------------------------------------------------------------------------

// The client obtains the access token via SASL_CB_PASS and an optional
// authzid via SASL_CB_USER (through callbacks or the sasl_interact prompt
// cycle), then emits the RFC 7628 initial response. The JWT verifier is
// server-only; the client treats the token as opaque.

struct ClientContext {
    output: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn client_step(
    utils: &Utils,
    ctx: &mut ClientContext,
    server_in: &[u8],
    is_final: bool,
    ssf_too_weak: bool,
    mut prompts: Prompts,
    canon: Option<CanonUser>,
    out: &mut OutBuf,
    oparams: &mut OutParams,
) -> i32 {
    if server_in.len() as u32 > MAX_SERVERIN_LEN {
        utils.set_error("server data too big");
        return SASL_BADPROT;
    }

    if is_final {
        // RFC 7628 3.2.2: the server rejected the token with a JSON error.
        // Complete the error message sequence (3.2.3) with a single %x01.
        utils.set_error(&format!(
            "Authentication failed ({})",
            String::from_utf8_lossy(server_in)
        ));
        ctx.output.clear();
        ctx.output.push(0x01);
        out.publish(&ctx.output);
        oparams.finish();
        return SASL_OK;
    }

    out.clear();

    if ssf_too_weak {
        utils.set_error("SSF too weak for the OAUTHBEARER plugin");
        return SASL_TOOWEAK;
    }

    let user = utils.get_simple(&prompts, SASL_CB_USER);
    let pass = utils.get_password(&prompts);

    // The prompt results are harvested; release the array we allocated in the
    // previous round before possibly requesting a new one.
    prompts.release(utils);

    let want_user = matches!(user, CbValue::NeedPrompt);
    let want_pass = matches!(pass, CbValue::NeedPrompt);
    if want_user || want_pass {
        return prompts.request(utils, want_user, want_pass);
    }

    let authzid = match user {
        CbValue::Value(v) => v,
        CbValue::Fail(rc) => return rc,
        CbValue::NeedPrompt => unreachable!(),
    };
    let token = match pass {
        CbValue::Value(Some(v)) => v,
        CbValue::Value(None) => {
            utils.set_error("Bad parameter (no Access Token)");
            return SASL_BADPARAM;
        }
        CbValue::Fail(rc) => return rc,
        CbValue::NeedPrompt => unreachable!(),
    };
    let Ok(token) = std::str::from_utf8(&token) else {
        utils.set_error("Access Token is not valid UTF-8");
        return SASL_BADPARAM;
    };

    let Some(canon) = canon else {
        utils.set_error("canon_user callback is NULL");
        return SASL_FAIL;
    };
    let authzid = match authzid.filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => match String::from_utf8(v) {
            Ok(s) => Some(s),
            Err(_) => {
                utils.set_error("authzid is not valid UTF-8");
                return SASL_BADPARAM;
            }
        },
    };

    // The real identity is derived from the token by the server; use the
    // "anonymous" placeholder for the client-side authcid like the C plugin.
    let anonymous = c"anonymous";
    let rc = canon.apply(anonymous, SASL_CU_AUTHID, oparams);
    if rc != SASL_OK {
        return rc;
    }
    let rc = if let Some(authzid) = &authzid {
        let Ok(authzid_c) = CString::new(authzid.as_str()) else {
            utils.set_error("authzid contains NUL");
            return SASL_BADPARAM;
        };
        canon.apply(&authzid_c, SASL_CU_AUTHZID, oparams)
    } else {
        canon.apply(anonymous, SASL_CU_AUTHZID, oparams)
    };
    if rc != SASL_OK {
        return rc;
    }

    ctx.output = build_client_response(authzid.as_deref(), token);
    out.publish(&ctx.output);
    SASL_CONTINUE
}

unsafe extern "C" fn client_mech_new(
    _glob_context: *mut c_void,
    _params: *mut sasl_client_params,
    conn_context: *mut *mut c_void,
) -> i32 {
    guard(|| {
        if conn_context.is_null() {
            return SASL_BADPARAM;
        }
        let ctx = Box::new(ClientContext { output: Vec::new() });
        unsafe { *conn_context = Box::into_raw(ctx).cast() };
        SASL_OK
    })
}

unsafe extern "C" fn client_mech_step(
    context: *mut c_void,
    c_params: *mut sasl_client_params,
    server_in: *const c_char,
    server_in_len: u32,
    prompt_need: *mut *mut sasl_interact,
    client_out: *mut *const c_char,
    client_out_len: *mut u32,
    oparams: *mut sasl_out_params,
) -> i32 {
    guard(|| {
        if context.is_null() || c_params.is_null() {
            return SASL_BADPARAM;
        }
        let params = unsafe { &mut *c_params };
        let (Some(utils), Some(mut out), Some(mut oparams)) = (
            unsafe { Utils::from_raw(params.utils) },
            unsafe { OutBuf::from_raw(client_out, client_out_len as *mut c_uint) },
            unsafe { OutParams::from_raw(oparams) },
        ) else {
            return SASL_BADPARAM;
        };
        let ctx = unsafe { &mut *context.cast::<ClientContext>() };
        let server_in = if server_in.is_null() || server_in_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(server_in.cast::<u8>(), server_in_len as usize) }
        };
        let prompts = unsafe { Prompts::from_raw(prompt_need) };
        let canon = unsafe { CanonUser::from_parts(params.canon_user, utils.conn()) };
        let ssf_too_weak = params.props.min_ssf > params.external_ssf;

        client_step(
            &utils,
            ctx,
            server_in,
            server_in_len != 0,
            ssf_too_weak,
            prompts,
            canon,
            &mut out,
            &mut oparams,
        )
    })
}

unsafe extern "C" fn client_mech_dispose(context: *mut c_void, _utils: *const sasl_utils) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !context.is_null() {
            drop(unsafe { Box::from_raw(context.cast::<ClientContext>()) });
        }
    }));
}

fn make_client_plugin() -> sasl_client_plug_t {
    sasl_client_plug_t {
        mech_name: MECH_NAME.as_ptr().cast(),
        max_ssf: 0,
        security_flags: SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
        features: SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY,
        required_prompts: std::ptr::null(),
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
    guard(|| {
        if outvers.is_null() || pluglist.is_null() || plugcount.is_null() {
            return SASL_BADPARAM;
        }
        let Some(utils) = (unsafe { Utils::from_raw(utils) }) else {
            return SASL_BADPARAM;
        };
        if maxvers < SASL_CLIENT_PLUG_VERSION as i32 {
            utils.log(SASL_LOG_ERR, "OAUTHBEARER client plugin version mismatch");
            return SASL_BADVERS;
        }
        unsafe {
            *outvers = SASL_CLIENT_PLUG_VERSION as i32;
            *pluglist = Box::into_raw(Box::new(make_client_plugin()));
            *plugcount = 1;
        }
        SASL_OK
    })
}
