// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    // libpam dlcloses modules at pam_end. Keep the module mapped so the
    // process-global verifier cache survives across PAM sessions.
    println!("cargo:rustc-link-arg-cdylib=-Wl,-z,nodelete");
}
