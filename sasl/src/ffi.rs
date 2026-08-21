// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Safe boundary around the cyrus SASL plugin ABI.
//!
//! Every raw pointer dereference and transmute of this crate lives in this
//! module. The mechanism logic in lib.rs is safe Rust operating on these
//! wrapper types; the `unsafe extern "C"` entry points construct them from
//! the raw arguments and nothing else.

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void, CStr, CString};
use std::marker::PhantomData;
use std::ptr::{null, null_mut};

use sasl2_sys::{
    prelude::{sasl_out_params_t, sasl_utils_t},
    sasl::{
        sasl_conn_t, sasl_interact, sasl_interact_t, sasl_secret_t, SASL_BADPARAM,
        SASL_CB_LIST_END, SASL_CB_PASS, SASL_FAIL, SASL_INTERACT, SASL_NOMEM, SASL_OK,
        SASL_SSF_EXTERNAL,
    },
    saslplug::sasl_callback_ft,
};

const PLUGIN_NAME: &CStr = c"OAUTHBEARER";

/// Outcome of asking the application for a value (callback or prompt cycle).
pub(crate) enum CbValue {
    Value(Option<Vec<u8>>),
    NeedPrompt,
    Fail(i32),
}

/// The `sasl_utils_t` service table: logging, error reporting, configuration
/// options, allocator and application callbacks.
pub(crate) struct Utils<'a> {
    raw: &'a sasl_utils_t,
}

impl<'a> Utils<'a> {
    /// # Safety
    /// `ptr` must be NULL or point to a `sasl_utils_t` valid for `'a`.
    pub(crate) unsafe fn from_raw(ptr: *const sasl_utils_t) -> Option<Utils<'a>> {
        unsafe { ptr.as_ref() }.map(|raw| Utils { raw })
    }

    pub(crate) fn log(&self, level: i32, message: &str) {
        let Ok(message) = CString::new(message) else { return };
        let Some(log) = self.raw.log else { return };
        unsafe { log(self.raw.conn, level, c"%s".as_ptr(), message.as_ptr()) };
    }

    pub(crate) fn set_error(&self, message: &str) {
        let Ok(message) = CString::new(message) else { return };
        let Some(seterror) = self.raw.seterror else { return };
        unsafe { seterror(self.raw.conn, 0, c"%s".as_ptr(), message.as_ptr()) };
    }

    /// Look up a configuration option (sasl getopt). `Ok(None)` means unset.
    pub(crate) fn option(&self, name: &str) -> Result<Option<String>, String> {
        let getopt = self.raw.getopt.ok_or("sasl_utils.getopt is NULL")?;
        let name = CString::new(name).map_err(|_| "invalid SASL option name")?;
        let mut value: *const c_char = null();
        let rc = unsafe {
            getopt(self.raw.getopt_context, PLUGIN_NAME.as_ptr(), name.as_ptr(), &mut value, null_mut())
        };
        if rc != 0 || value.is_null() {
            return Ok(None);
        }
        Ok(Some(unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned()))
    }

    /// The external (TLS) security strength factor of the connection.
    pub(crate) fn external_ssf(&self) -> Result<u32, String> {
        let getprop = self.raw.getprop.ok_or("sasl_utils.getprop is NULL")?;
        let mut prop: *const c_void = null();
        let rc = unsafe { getprop(self.raw.conn, SASL_SSF_EXTERNAL as c_int, &mut prop) };
        if rc != SASL_OK {
            return Err("could not get SASL_SSF_EXTERNAL".into());
        }
        Ok(if prop.is_null() { 0 } else { unsafe { *(prop.cast::<c_uint>()) } })
    }

    /// Fetch an optional simple value (e.g. SASL_CB_USER): prompt results take
    /// precedence, then the registered callback; a NULL-proc callback entry
    /// means the application wants to be prompted.
    pub(crate) fn get_simple(&self, prompts: &Prompts, id: c_ulong) -> CbValue {
        if let Some(entry) = prompts.find(id) {
            let entry = unsafe { &*entry };
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

        let Some(getcallback) = self.raw.getcallback else {
            return CbValue::Fail(SASL_FAIL);
        };
        let mut proc_: sasl_callback_ft = None;
        let mut context: *mut c_void = null_mut();
        match unsafe { getcallback(self.raw.conn, id, &mut proc_, &mut context) } {
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

    /// Fetch the password/token (SASL_CB_PASS). Unlike get_simple the value is
    /// required, so a missing callback is an error.
    pub(crate) fn get_password(&self, prompts: &Prompts) -> CbValue {
        if let Some(entry) = prompts.find(SASL_CB_PASS) {
            let entry = unsafe { &*entry };
            if entry.result.is_null() {
                return CbValue::Fail(SASL_BADPARAM);
            }
            let bytes =
                unsafe { std::slice::from_raw_parts(entry.result.cast::<u8>(), entry.len as usize) }
                    .to_vec();
            return CbValue::Value(Some(bytes));
        }

        let Some(getcallback) = self.raw.getcallback else {
            return CbValue::Fail(SASL_FAIL);
        };
        let mut proc_: sasl_callback_ft = None;
        let mut context: *mut c_void = null_mut();
        match unsafe { getcallback(self.raw.conn, SASL_CB_PASS, &mut proc_, &mut context) } {
            SASL_OK => {
                let Some(proc_) = proc_ else {
                    return CbValue::Fail(SASL_FAIL);
                };
                let cb: unsafe extern "C" fn(
                    *mut sasl_conn_t,
                    *mut c_void,
                    c_int,
                    *mut *mut sasl_secret_t,
                ) -> c_int = unsafe { std::mem::transmute(proc_) };
                let mut secret: *mut sasl_secret_t = null_mut();
                let rc = unsafe { cb(self.raw.conn, context, SASL_CB_PASS as c_int, &mut secret) };
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

    pub(crate) fn conn(&self) -> *mut sasl_conn_t {
        self.raw.conn
    }

    fn free(&self, ptr: *mut c_void) {
        if let Some(free) = self.raw.free {
            unsafe { free(ptr) };
        }
    }

    fn malloc(&self, size: usize) -> *mut c_void {
        match self.raw.malloc {
            Some(malloc) => unsafe { malloc(size) },
            None => null_mut(),
        }
    }
}

/// The `sasl_interact_t` prompt array slot shared with the application.
pub(crate) struct Prompts<'a> {
    slot: *mut *mut sasl_interact_t,
    _marker: PhantomData<&'a mut sasl_interact_t>,
}

impl<'a> Prompts<'a> {
    /// # Safety
    /// `slot` must be NULL or a valid prompt-array slot for `'a`, holding
    /// either NULL or a SASL_CB_LIST_END-terminated array.
    pub(crate) unsafe fn from_raw(slot: *mut *mut sasl_interact_t) -> Prompts<'a> {
        Prompts { slot, _marker: PhantomData }
    }

    fn find(&self, id: c_ulong) -> Option<*const sasl_interact_t> {
        if self.slot.is_null() || unsafe { *self.slot }.is_null() {
            return None;
        }
        let mut p = unsafe { *self.slot };
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

    /// Release a previously requested prompt array through the SASL allocator.
    pub(crate) fn release(&mut self, utils: &Utils) {
        if !self.slot.is_null() && !unsafe { *self.slot }.is_null() {
            utils.free(unsafe { *self.slot }.cast());
            unsafe { *self.slot = null_mut() };
        }
    }

    /// Allocate a SASL_CB_LIST_END-terminated prompt array via the SASL
    /// allocator (the application and libsasl free it with the same
    /// allocator) and hand it to the application.
    pub(crate) fn request(&mut self, utils: &Utils, want_user: bool, want_pass: bool) -> i32 {
        if self.slot.is_null() {
            return SASL_FAIL;
        }
        let count = usize::from(want_user) + usize::from(want_pass) + 1;
        let arr = utils.malloc(count * std::mem::size_of::<sasl_interact_t>())
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
            push(
                sasl2_sys::sasl::SASL_CB_USER,
                c"Authorization Name",
                c"Please enter an authorization name",
            );
        }
        if want_pass {
            push(SASL_CB_PASS, c"Access Token", c"Please enter Access Token (as JWT)");
        }
        push(SASL_CB_LIST_END, c"", c"");

        unsafe { *self.slot = arr };
        SASL_INTERACT
    }
}

/// The mechanism's output parameters (`sasl_out_params_t`).
pub(crate) struct OutParams<'a> {
    raw: &'a mut sasl_out_params_t,
}

impl<'a> OutParams<'a> {
    /// # Safety
    /// `ptr` must be NULL or point to a `sasl_out_params_t` valid for `'a`.
    pub(crate) unsafe fn from_raw(ptr: *mut sasl_out_params_t) -> Option<OutParams<'a>> {
        unsafe { ptr.as_mut() }.map(|raw| OutParams { raw })
    }

    /// Mark the mechanism finished: no security layer, no output encoding.
    pub(crate) fn finish(&mut self) {
        self.raw.doneflag = 1;
        self.raw.mech_ssf = 0;
        self.raw.maxoutbuf = 0;
        self.raw.encode_context = null_mut();
        self.raw.encode = None;
        self.raw.decode_context = null_mut();
        self.raw.decode = None;
        self.raw.param_version = 0;
    }

    fn as_mut_ptr(&mut self) -> *mut sasl_out_params_t {
        self.raw
    }
}

/// The framework's canon_user callback bound to this connection.
pub(crate) struct CanonUser<'a> {
    f: unsafe extern "C" fn(
        *mut sasl_conn_t,
        *const c_char,
        c_uint,
        c_uint,
        *mut sasl_out_params_t,
    ) -> c_int,
    conn: *mut sasl_conn_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CanonUser<'a> {
    /// # Safety
    /// `f`, if Some, must be the connection's canon_user callback and `conn`
    /// the matching `sasl_conn_t`, both valid for `'a`.
    pub(crate) unsafe fn from_parts(
        f: Option<
            unsafe extern "C" fn(
                *mut sasl_conn_t,
                *const c_char,
                c_uint,
                c_uint,
                *mut sasl_out_params_t,
            ) -> c_int,
        >,
        conn: *mut sasl_conn_t,
    ) -> Option<CanonUser<'a>> {
        f.map(|f| CanonUser { f, conn, _marker: PhantomData })
    }

    /// Canonicalize `name` into the out params under the given SASL_CU flags.
    pub(crate) fn apply(&self, name: &CStr, flags: c_uint, out: &mut OutParams) -> i32 {
        unsafe {
            (self.f)(
                self.conn,
                name.as_ptr(),
                name.to_bytes().len() as c_uint,
                flags,
                out.as_mut_ptr(),
            )
        }
    }
}

/// A mechanism output buffer slot (`serverout`/`clientout` plus length).
pub(crate) struct OutBuf<'a> {
    ptr: &'a mut *const c_char,
    len: &'a mut c_uint,
}

impl<'a> OutBuf<'a> {
    /// # Safety
    /// Both pointers must be non-NULL and valid for `'a`.
    pub(crate) unsafe fn from_raw(ptr: *mut *const c_char, len: *mut c_uint) -> Option<OutBuf<'a>> {
        if ptr.is_null() || len.is_null() {
            return None;
        }
        Some(OutBuf { ptr: unsafe { &mut *ptr }, len: unsafe { &mut *len } })
    }

    pub(crate) fn clear(&mut self) {
        *self.ptr = null();
        *self.len = 0;
    }

    /// Publish `data` as the mechanism output. The cyrus ABI requires the
    /// data to stay allocated until the next step on this connection or its
    /// disposal — callers pass buffers owned by the connection context.
    pub(crate) fn publish(&mut self, data: &[u8]) {
        *self.ptr = data.as_ptr().cast();
        *self.len = data.len() as c_uint;
    }
}
