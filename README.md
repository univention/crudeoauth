# crudeoauth - PAM and SASL OAUTHBEARER authentication

`crudeoauth` provides a PAM module and a Cyrus SASL plugin for
authentication with OAuth 2.0 bearer access tokens. The SASL
implementation uses the OAUTHBEARER mechanism defined by [RFC
7628](https://datatracker.ietf.org/doc/html/rfc7628).

The server-side verifier accepts signed JWT access tokens, verifies
their signatures against locally configured JWKS files, and applies
configurable claim and security policy checks. The implementation uses
the Rust [`jsonwebtoken`](https://docs.rs/jsonwebtoken/) crate.

The artifacts can be used:

-   by user-facing services to validate OAuth 2.0 access tokens through
    PAM;
-   by SASL clients to send an OAuth 2.0 access token with OAUTHBEARER;
    and
-   by protected resources such as OpenLDAP to accept OAUTHBEARER SASL
    binds and validate the presented access token.

In UCS, for example, a user-facing service can be the Univention
Management Console and the protected resource can be OpenLDAP `slapd`.

## Token validation

The verifier:

-   parses the JWT and requires a signing-key identifier (`kid`);
-   selects the corresponding key only from configured JWKS files;
-   verifies the JWT signature;
-   checks the configured issuer and audience;
-   optionally checks the authorized party (`azp`);
-   checks `nbf`, `iat`, and `exp` when present, with a configurable
    clock-skew grace period;
-   optionally requires OAuth scopes;
-   extracts the configured username claim;
-   optionally rejects configured usernames, case-insensitively; and
-   applies an explicit JWT signature-algorithm policy.

JWKS files may contain keys that are unrelated to access-token
signatures. Unsupported keys and keys intended for encryption are
ignored instead of making the complete JWKS unusable. In particular,
`RSA-OAEP` is a JWE key-management algorithm, not a JWT signature
algorithm, and is not accepted as a JWT signing algorithm.

The token's JWK metadata, when present, must be compatible with
signature verification. The verifier does not use token-provided key
URLs or embedded keys as trust sources.

The implementation has been tested with Keycloak 26.7.x. The verifier
checks the `aud` claim; depending on the Keycloak client configuration,
an appropriate audience may need to be added to the access token.

## Debian packages

The repository contains Debian packaging in `debian/`. It can be used to
build:

-   `libpam-oauthbearer`
-   `libsasl2-modules-oauthbearer`

## SASL configuration

The SASL server plugin is configured through the Cyrus SASL
configuration file, for example `/etc/ldap/sasl2/slapd.conf` for
OpenLDAP on Debian.

Example:

``` text
mech_list: ... OAUTHBEARER
oauthbearer_grace: 3
oauthbearer_userid: preferred_username
oauthbearer_trusted_jwks0: /usr/share/oidc/authorization-server.jwks
oauthbearer_trusted_iss0: https://sso.example.org/realms/master
oauthbearer_trusted_aud0: ldaps://example.org/

# Optional restrictions:
# oauthbearer_trusted_azp0: https://client.example.org/oidc/
# oauthbearer_required_scope0: openid
# oauthbearer_disallowed_username0: root
# oauthbearer_allowed_alg0: RS256
# oauthbearer_disallowed_alg0: RS512

# TLS is required by default:
# oauthbearer_no_tls: 0
```

Options with numeric suffixes can be repeated using consecutive indices
(`0`, `1`, ...).

### SASL options

`oauthbearer_grace`
:   Clock-skew tolerance in seconds for `nbf`, `iat`, and `exp`. The
    default is 3 seconds. This is a clock-skew allowance, not a maximum
    token lifetime or maximum token age.

`oauthbearer_userid`
:   Claim used for the SASL `authcid`. The default is
    `preferred_username`.

`oauthbearer_trusted_jwksN`
:   Path to a trusted JWKS file.

`oauthbearer_trusted_issN`
:   Trusted issuer (`iss`).

`oauthbearer_trusted_audN`
:   Trusted audience (`aud`). At least one trusted audience is required.

`oauthbearer_trusted_azpN`
:   Optional trusted authorized party (`azp`).

`oauthbearer_required_scopeN`
:   Optional required OAuth scope. Multiple configured entries mean that
    all configured scopes are required.

`oauthbearer_disallowed_usernameN`
:   Optional username deny-list. Matching is case-insensitive. This is
    useful for preventing identities such as `root` from being produced
    by the configured username claim.

`oauthbearer_allowed_algN`
:   Optional signature-algorithm allow-list. If omitted, the built-in
    algorithm policy is retained. Configuring one or more values
    replaces that default allow-list.

`oauthbearer_disallowed_algN`
:   Optional signature-algorithm deny-list. It is applied after the
    default or configured allow-list, so a denied algorithm is never
    accepted.

`oauthbearer_no_tls`
:   Set to `1` to disable the server plugin's TLS requirement. Bearer
    tokens should normally only be sent over an encrypted connection.

Supported configurable signature algorithm names are `RS256`, `RS384`,
`RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, and `EdDSA`.
Symmetric `HS*` algorithms are not part of the default asymmetric-key
policy.

### OpenLDAP identity mapping

The username extracted from the token becomes the SASL `authcid`. An
optional RFC 7628 `authzid` can be supplied and is subject to the
authorization rules of the SASL consumer.

After a successful SASL bind, OpenLDAP exposes an OAUTHBEARER SASL
identity such as:

``` text
uid=username,cn=oauthbearer,cn=auth
```

It can be mapped into the directory with the usual `authz-regexp`, for
example:

``` text
authz-regexp
    uid=([^,]*),cn=oauthbearer,cn=auth
    ldap:///dc=example,dc=org??sub?uid=$1
```

## PAM configuration

`pam_oauthbearer.so`, provided by `libpam-oauthbearer`, performs the
same JWT and policy validation for PAM authentication.

Example:

``` text
auth sufficient pam_oauthbearer.so grace=3 userid=preferred_username \
    iss=https://sso.example.org/realms/master \
    jwks=/usr/share/oidc/authorization-server.jwks \
    trusted_aud=ldaps://example.org/ \
    trusted_azp=https://client.example.org/oidc/ \
    required_scope=openid \
    allowed_alg=RS256 \
    disallowed_username=root
```

The corresponding PAM options are `grace`, `userid`, `iss`, `jwks`,
`trusted_aud`, `trusted_azp`, `required_scope`, `allowed_alg`,
`disallowed_alg`, and `disallowed_username`. Repeat options that accept
multiple values.

See `pam_oauthbearer(5)` and `sasl_oauthbearer(5)` for details.

## Security considerations

Bearer tokens are credentials: possession is sufficient for
authentication. Transport encryption should therefore remain enabled.

Keep the trusted issuer and audience configuration as narrow as
possible. `trusted_azp` and `required_scope` can provide additional
restrictions when they match the authorization model of the identity
provider.

The algorithm allow-list is optional. If it is omitted, the built-in
policy is used. `disallowed_alg` can be used to remove individual
algorithms from either the built-in or configured allow-list without
restating the complete policy.

The username deny-list is evaluated after the configured username claim
is extracted and is case-insensitive. Consider denying privileged local
account names that must never be supplied by the identity provider.

JWKS data is loaded as trust configuration. Keys that cannot be used for
the requested signature algorithm, encryption-only keys, and unsupported
key types are not used for verification.

## Developer notes

The Rust code is split into:

-   `core/src/jwt.rs`: JWT/JWKS parsing, signature verification, and
    fine-grained token policy checks.
-   `core/src/rfc7628.rs`: OAUTHBEARER GS2/RFC 7628 parsing and construction.
-   `sasl/src/lib.rs`: Cyrus SASL FFI/plugin glue.
-   `sasl/config.rs`: Cyrus SASL configuration loading and one-time JWKS
    loading.
-   `pam/src/lib.rs`: PAM module.

The verifier performs the application policy checks itself rather than
relying on `jsonwebtoken` to decide issuer, audience, time, scope,
authorized-party, algorithm, or username policy. This keeps the
authentication errors and policy behavior under `crudeoauth` control.
