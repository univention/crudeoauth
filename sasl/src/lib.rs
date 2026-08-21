// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Cyrus SASL OAUTHBEARER mechanism plugin.
//!
//! Structure: `ffi` wraps the raw plugin ABI in safe types; `server` and
//! `client` hold the two mechanisms, each with safe step logic and thin
//! `unsafe extern "C"` entry points that only validate raw arguments, build
//! the wrappers, guard against panics and dispatch.

mod client;
mod config;
mod ffi;
mod server;

use std::panic::{catch_unwind, AssertUnwindSafe};

pub use client::sasl_client_plug_init;
pub use server::sasl_server_plug_init;

// Not exposed by sasl2-sys bindings against system headers; value from <sasl/sasl.h>.
pub(crate) const SASL_CONFIGERR: i32 = -100;

pub(crate) const MECH_NAME: &[u8] = b"OAUTHBEARER\0";

/// A panic must not unwind into libsasl2; report SASL_FAIL instead.
pub(crate) fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(sasl2_sys::sasl::SASL_FAIL)
}
