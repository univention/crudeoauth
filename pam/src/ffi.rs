// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Safe boundary around the Linux-PAM module ABI (and the libc calls the
//! module needs). Every raw pointer dereference of this crate lives in this
//! module; the module logic in lib.rs is safe Rust operating on `PamHandle`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::marker::PhantomData;
use std::ptr::{null, null_mut};

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_OPEN_ERR: c_int = 1;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_TRY_AGAIN: c_int = 24;
pub const PAM_IGNORE: c_int = 25;

pub(crate) const PAM_RHOST: c_int = 4;
const PAM_CONV: c_int = 5;
pub(crate) const PAM_AUTHTOK: c_int = 6;

const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
pub struct pam_handle_t {
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

pub(crate) fn slog(pri: c_int, msg: &str) {
    let Ok(msg) = CString::new(msg) else { return };
    unsafe { libc::syslog(pri, c"%s".as_ptr(), msg.as_ptr()) };
}

/// Copy the PAM stack arguments into owned strings.
///
/// # Safety
/// `argv` must be NULL or point to `argc` valid C strings.
pub(crate) unsafe fn collect_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let mut args = Vec::new();
    if argv.is_null() {
        return args;
    }
    for i in 0..argc.max(0) as usize {
        let arg = unsafe { *argv.add(i) };
        if !arg.is_null() {
            args.push(unsafe { CStr::from_ptr(arg) }.to_string_lossy().into_owned());
        }
    }
    args
}

/// Whether a local account with this name exists. `Err(rc)` carries the PAM
/// return code for a lookup failure.
pub(crate) fn account_exists(user: &str) -> Result<bool, c_int> {
    let Ok(user) = CString::new(user) else {
        return Err(PAM_AUTH_ERR);
    };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 1024];
    let mut result: *mut libc::passwd = null_mut();
    let rc = unsafe {
        libc::getpwnam_r(user.as_ptr(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result)
    };
    if rc != 0 {
        return Err(PAM_TRY_AGAIN);
    }
    Ok(!result.is_null())
}

/// A PAM handle for the duration of one module call.
pub(crate) struct PamHandle<'a> {
    raw: *mut pam_handle_t,
    _marker: PhantomData<&'a mut pam_handle_t>,
}

impl<'a> PamHandle<'a> {
    /// # Safety
    /// `raw` must be NULL or the valid handle libpam passed to the module
    /// entry point, usable for `'a`.
    pub(crate) unsafe fn from_raw(raw: *mut pam_handle_t) -> Option<PamHandle<'a>> {
        if raw.is_null() { None } else { Some(PamHandle { raw, _marker: PhantomData }) }
    }

    pub(crate) fn strerror(&self, rc: c_int) -> String {
        let p = unsafe { pam_strerror(self.raw, rc) };
        if p.is_null() {
            format!("PAM error {rc}")
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    }

    /// The (possibly conversation-prompted) target user. `Err` carries the
    /// libpam return code; PAM_SUCCESS in it means a NULL user was returned.
    pub(crate) fn user(&self) -> Result<String, c_int> {
        let mut user: *const c_char = null();
        let rc = unsafe { pam_get_user(self.raw, &mut user, null()) };
        if rc != PAM_SUCCESS || user.is_null() {
            return Err(rc);
        }
        Ok(unsafe { CStr::from_ptr(user) }.to_string_lossy().into_owned())
    }

    pub(crate) fn item_str(&self, item_type: c_int) -> Result<Option<String>, c_int> {
        let mut item: *const c_void = null();
        let rc = unsafe { pam_get_item(self.raw, item_type, &mut item) };
        if rc != PAM_SUCCESS {
            return Err(rc);
        }
        if item.is_null() {
            return Ok(None);
        }
        Ok(Some(unsafe { CStr::from_ptr(item.cast()) }.to_string_lossy().into_owned()))
    }

    /// Store the token as PAM_AUTHTOK for later stack modules (best effort).
    pub(crate) fn set_authtok(&self, value: &str) {
        if let Ok(value) = CString::new(value) {
            unsafe { pam_set_item(self.raw, PAM_AUTHTOK, value.as_ptr().cast()) };
        }
    }

    /// Ask the application for a secret via the conversation (echo off). The
    /// response buffer is zeroized and freed as the PAM contract requires.
    pub(crate) fn converse_secret(&self, prompt: &CStr) -> Result<String, c_int> {
        let mut convptr: *const c_void = null();
        let rc = unsafe { pam_get_item(self.raw, PAM_CONV, &mut convptr) };
        if rc != PAM_SUCCESS {
            slog(
                libc::LOG_ERR,
                &format!("pam_get_item(PAM_CONV) failed: {}", self.strerror(rc)),
            );
            return Err(rc);
        }
        let conv = convptr.cast::<pam_conv>();
        let Some(conv_fn) = (unsafe { conv.as_ref() }).and_then(|c| c.conv) else {
            return Err(PAM_CONV_ERR);
        };

        let msg = pam_message { msg_style: PAM_PROMPT_ECHO_OFF, msg: prompt.as_ptr() };
        let mut msgp: *const pam_message = &msg;
        let mut resp: *mut pam_response = null_mut();
        let rc = unsafe { conv_fn(1, &mut msgp, &mut resp, (*conv).appdata_ptr) };
        if rc != PAM_SUCCESS {
            slog(libc::LOG_ERR, &format!("PAM conv error: {}", self.strerror(rc)));
            return Err(rc);
        }
        if resp.is_null() {
            return Err(PAM_CONV_ERR);
        }
        let answer = unsafe { (*resp).resp };
        let secret = if answer.is_null() {
            None
        } else {
            let secret = unsafe { CStr::from_ptr(answer) }.to_string_lossy().into_owned();
            unsafe {
                libc::memset(answer.cast(), 0, libc::strlen(answer));
                libc::free(answer.cast());
            }
            Some(secret)
        };
        unsafe { libc::free(resp.cast()) };
        secret.ok_or(PAM_CONV_ERR)
    }
}
