// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared OAUTHBEARER logic: JWT validation policy and RFC 7628 message
//! framing. Pure safe Rust; the SASL and PAM FFI live in their own crates.

pub mod jwt;
pub mod rfc7628;
