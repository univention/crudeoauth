// SPDX-FileCopyrightText: 2026 Univention GmbH
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

const KVSEP: u8 = 0x01;
const BEARER: &[u8] = b"Bearer ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    pub authzid: Option<String>,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rfc7628Error {
    InvalidUtf8,
    InvalidGs2Header,
    InvalidSaslName,
    MissingAuth,
    InvalidKeyValue,
    MissingTerminator,
    NotBearer,
}

impl fmt::Display for Rfc7628Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub fn parse_client_response(input: &[u8]) -> Result<ClientResponse, Rfc7628Error> {
    let first_sep = input.iter().position(|&b| b == KVSEP).ok_or(Rfc7628Error::InvalidGs2Header)?;
    let gs2 = &input[..first_sep];

    let authzid = if gs2 == b"n,," {
        None
    } else if gs2.starts_with(b"n,a=") && gs2.ends_with(b",") {
        let encoded = std::str::from_utf8(&gs2[4..gs2.len() - 1]).map_err(|_| Rfc7628Error::InvalidUtf8)?;
        Some(decode_saslname(encoded)?)
    } else {
        return Err(Rfc7628Error::InvalidGs2Header);
    };

    if !input.ends_with(&[KVSEP, KVSEP]) {
        return Err(Rfc7628Error::MissingTerminator);
    }

    let mut auth = None;
    for field in input[first_sep + 1..input.len() - 1].split(|&b| b == KVSEP) {
        if field.is_empty() { continue; }
        let eq = field.iter().position(|&b| b == b'=').ok_or(Rfc7628Error::InvalidKeyValue)?;
        let key = &field[..eq];
        let value = &field[eq + 1..];
        if key == b"auth" {
            auth = Some(value);
        }
    }

    let auth = auth.ok_or(Rfc7628Error::MissingAuth)?;
    if auth.len() < BEARER.len() || !auth[..BEARER.len()].eq_ignore_ascii_case(BEARER) {
        return Err(Rfc7628Error::NotBearer);
    }
    let token = std::str::from_utf8(&auth[BEARER.len()..]).map_err(|_| Rfc7628Error::InvalidUtf8)?;
    if token.is_empty() {
        return Err(Rfc7628Error::NotBearer);
    }

    Ok(ClientResponse { authzid, token: token.to_owned() })
}

pub fn build_client_response(authzid: Option<&str>, token: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(token.len() + authzid.map_or(16, |v| v.len() + 20));
    if let Some(authzid) = authzid.filter(|v| !v.is_empty()) {
        out.extend_from_slice(b"n,a=");
        out.extend_from_slice(encode_saslname(authzid).as_bytes());
        out.extend_from_slice(b",");
    } else {
        out.extend_from_slice(b"n,,");
    }
    out.push(KVSEP);
    out.extend_from_slice(b"auth=Bearer ");
    out.extend_from_slice(token.as_bytes());
    out.extend_from_slice(&[KVSEP, KVSEP]);
    out
}

fn decode_saslname(input: &str) -> Result<String, Rfc7628Error> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'=' if bytes.get(i + 1..i + 3) == Some(b"2C") => { out.push(b','); i += 3; }
            b'=' if bytes.get(i + 1..i + 3) == Some(b"3D") => { out.push(b'='); i += 3; }
            b'=' => return Err(Rfc7628Error::InvalidSaslName),
            b => { out.push(b); i += 1; }
        }
    }
    String::from_utf8(out).map_err(|_| Rfc7628Error::InvalidUtf8)
}

fn encode_saslname(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            ',' => out.push_str("=2C"),
            '=' => out.push_str("=3D"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let msg = build_client_response(Some("a,b=c"), "aaa.bbb.ccc");
        let parsed = parse_client_response(&msg).unwrap();
        assert_eq!(parsed.authzid.as_deref(), Some("a,b=c"));
        assert_eq!(parsed.token, "aaa.bbb.ccc");
    }
}
