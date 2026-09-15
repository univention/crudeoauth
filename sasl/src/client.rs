// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! The OAUTHBEARER client mechanism: obtains the access token via
//! SASL_CB_PASS and an optional authzid via SASL_CB_USER (through callbacks
//! or the sasl_interact prompt cycle), then emits the RFC 7628 initial
//! response. The JWT verifier is server-only; the client treats the token as
//! opaque.

use std::ffi::{c_char, c_uint, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;

use crate::ffi::{CanonUser, CbValue, OutBuf, OutParams, Prompts, Utils};
use crate::{guard, MECH_NAME};
use crudeoauth_core::rfc7628::build_client_response;
use sasl2_sys::{
    prelude::{
        sasl_client_params, sasl_client_plug_t, sasl_out_params, sasl_utils, sasl_utils_t,
        SASL_CLIENT_PLUG_VERSION, SASL_FEAT_ALLOWS_PROXY, SASL_FEAT_WANT_CLIENT_FIRST,
    },
    sasl::{
        sasl_interact, SASL_BADPARAM, SASL_BADPROT, SASL_BADVERS, SASL_CB_USER,
        SASL_CONTINUE, SASL_CU_AUTHID, SASL_CU_AUTHZID, SASL_FAIL, SASL_LOG_ERR, SASL_OK,
        SASL_SEC_NOANONYMOUS, SASL_SEC_NOPLAINTEXT, SASL_TOOWEAK,
    },
};

const MAX_SERVERIN_LEN: u32 = 65_536;

struct ClientContext {
    output: Vec<u8>,
}

/// One client step, translated out of the raw ABI by client_mech_step.
struct ClientStep<'a> {
    utils: Utils<'a>,
    ctx: &'a mut ClientContext,
    server_in: &'a [u8],
    is_final: bool,
    ssf_too_weak: bool,
    prompts: Prompts<'a>,
    canon: Option<CanonUser<'a>>,
    out: OutBuf<'a>,
    oparams: OutParams<'a>,
}

impl ClientStep<'_> {
    fn run(mut self) -> i32 {
        if self.server_in.len() as u32 > MAX_SERVERIN_LEN {
            self.utils.set_error("server data too big");
            return SASL_BADPROT;
        }

        if self.is_final {
            // RFC 7628 3.2.2: the server rejected the token with a JSON error.
            // Complete the error message sequence (3.2.3) with a single %x01.
            self.utils.set_error(&format!(
                "Authentication failed ({})",
                String::from_utf8_lossy(self.server_in)
            ));
            self.ctx.output.clear();
            self.ctx.output.push(0x01);
            self.out.publish(&self.ctx.output);
            self.oparams.finish();
            return SASL_OK;
        }

        self.out.clear();

        if self.ssf_too_weak {
            self.utils.set_error("SSF too weak for the OAUTHBEARER plugin");
            return SASL_TOOWEAK;
        }

        let user = self.utils.get_simple(&self.prompts, SASL_CB_USER);
        let pass = self.utils.get_password(&self.prompts);

        // The prompt results are harvested; release the array we allocated in
        // the previous round before possibly requesting a new one.
        self.prompts.release(&self.utils);

        let want_user = matches!(user, CbValue::NeedPrompt);
        let want_pass = matches!(pass, CbValue::NeedPrompt);
        if want_user || want_pass {
            return self.prompts.request(&self.utils, want_user, want_pass);
        }

        let authzid = match user {
            CbValue::Value(v) => v,
            CbValue::Fail(rc) => return rc,
            CbValue::NeedPrompt => unreachable!(),
        };
        let token = match pass {
            CbValue::Value(Some(v)) => v,
            CbValue::Value(None) => {
                self.utils.set_error("Bad parameter (no Access Token)");
                return SASL_BADPARAM;
            }
            CbValue::Fail(rc) => return rc,
            CbValue::NeedPrompt => unreachable!(),
        };
        let Ok(token) = std::str::from_utf8(&token) else {
            self.utils.set_error("Access Token is not valid UTF-8");
            return SASL_BADPARAM;
        };

        let Some(canon) = self.canon else {
            self.utils.set_error("canon_user callback is NULL");
            return SASL_FAIL;
        };
        let authzid = match authzid.filter(|v| !v.is_empty()) {
            None => None,
            Some(v) => match String::from_utf8(v) {
                Ok(s) => Some(s),
                Err(_) => {
                    self.utils.set_error("authzid is not valid UTF-8");
                    return SASL_BADPARAM;
                }
            },
        };

        // The real identity is derived from the token by the server; use the
        // "anonymous" placeholder for the client-side authcid like the C plugin.
        let anonymous = c"anonymous";
        let rc = canon.apply(anonymous, SASL_CU_AUTHID, &mut self.oparams);
        if rc != SASL_OK {
            return rc;
        }
        let rc = if let Some(authzid) = &authzid {
            let Ok(authzid_c) = CString::new(authzid.as_str()) else {
                self.utils.set_error("authzid contains NUL");
                return SASL_BADPARAM;
            };
            canon.apply(&authzid_c, SASL_CU_AUTHZID, &mut self.oparams)
        } else {
            canon.apply(anonymous, SASL_CU_AUTHZID, &mut self.oparams)
        };
        if rc != SASL_OK {
            return rc;
        }

        self.ctx.output = build_client_response(authzid.as_deref(), token);
        self.out.publish(&self.ctx.output);
        SASL_CONTINUE
    }
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
        let (Some(utils), Some(out), Some(oparams)) = (
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

        ClientStep {
            utils,
            ctx,
            server_in,
            is_final: server_in_len != 0,
            ssf_too_weak,
            prompts,
            canon,
            out,
            oparams,
        }
        .run()
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
