// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! The OAUTHBEARER server mechanism: parses the RFC 7628 client response,
//! validates the bearer token and canonicalizes the resulting identity.

use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::config::ServerConfig;
use crate::ffi::{CanonUser, OutBuf, OutParams, Utils};
use crate::{guard, MECH_NAME, SASL_CONFIGERR};
use crudeoauth_core::rfc7628::parse_client_response;
use sasl2_sys::{
    prelude::{
        sasl_out_params_t, sasl_server_params, sasl_server_plug, sasl_server_plug_t,
        sasl_utils, sasl_utils_t, SASL_FEAT_ALLOWS_PROXY, SASL_FEAT_WANT_CLIENT_FIRST,
        SASL_SERVER_PLUG_VERSION,
    },
    sasl::{
        SASL_BADAUTH, SASL_BADPARAM, SASL_BADPROT, SASL_BADVERS, SASL_CONTINUE,
        SASL_CU_AUTHID, SASL_CU_AUTHZID, SASL_ENCRYPT, SASL_FAIL, SASL_LOG_ERR,
        SASL_LOG_NOTE, SASL_NOUSER, SASL_OK, SASL_SEC_NOANONYMOUS, SASL_SEC_NOPLAINTEXT,
    },
};

const MAX_CLIENTIN_LEN: usize = 65_536;
const INVALID_TOKEN_JSON: &str = r#"{"status":"invalid_token"}"#;

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
