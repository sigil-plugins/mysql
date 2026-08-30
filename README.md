# wasm.mysql

`wasm.mysql` is Sigil's bounded MySQL and SingleStore protocol component. It
exports the exact experimental `sigil:sql/driver@0.1.0` interface and imports
only `sigil:host/net@1.0.0`, its read-only `net-policy` companion, its value
types, and `sigil:host/secrets@1.0.0`.

Sigil owns endpoint resolution, TCP, TLS verification, timeouts, byte quotas,
secret grants, cancellation, and teardown. The component implements MySQL
Classic Protocol framing, operator-selected plaintext or TLS-upgrade
negotiation, `caching_sha2_password`, `mysql_native_password`, and single-result
`COM_QUERY`. It never receives a raw host, port, DNS, socket, TLS name, trust
root, clock, filesystem, process, stdio, or ambient WASI capability.

The driver reads only the frozen TLS mode for its granted logical endpoint.
For `tls = "upgrade"`, it requires the server's SSL capability, sends the MySQL
SSLRequest, and asks Sigil to verify and upgrade the stream before credentials.
For explicit deploy-local `tls = "disabled"`, it omits SSLRequest and may use
the challenge-response `mysql_native_password` exchange without sending the
password itself. It rejects `tls = "direct"`, unknown routes, auth switches,
and any cleartext `caching_sha2_password` full-auth request. A server flag can
never downgrade an operator-required TLS upgrade. Disabled mode provides no
transport confidentiality and is appropriate only for Sigil's explicitly
permitted deploy-local routes.

Password-derived SHA-1 and SHA-256 digest intermediates use optimizer-resistant
zeroization. The release gate inspects the optimized core Wasm and requires all
six fixed-size wipes to remain reachable from the exported `connect` path.

The v0.1 driver deliberately does not implement prepared statements, binary
protocol, multi-statements/results, `LOCAL INFILE`, retry, or reconnect.

## Build

Prerequisites are Rust 1.95.0 with `wasm32-unknown-unknown`, `wasm-tools`
1.252.0, `just` 1.57.0, `b3sum` 1.8.3, Python 3.11+, and zstd 1.5.7.

```sh
just check
just dist
```

`just sdk-drift` checks the vendored build inputs against the immutable SDK
revision recorded in `SDK.lock`. `just reproducible` performs two isolated
builds and compares both the component and canonical package bytes.

Version 0.1.2 is the first keyless-provenance release. The unprivileged
`prepare-release` workflow builds its package and canonical release manifest
once from `main`. After explicit digest approval, the protected
`publish-release` workflow stages and reads back exactly three assets, creates
one GitHub OIDC/Sigstore package attestation, and publishes an immutable tag and
release. It has no long-lived signing secret and never resumes or replaces a
partial version.

Version 0.1.3 is an unpublished release candidate adding the additive
`sigil:host/net-policy@1.0.0` contract and SingleStore-compatible
`mysql_native_password`. It requires Sigil 0.33.1 or newer; a compatible Sigil
release has not yet been published. Its deterministic fixtures cover the exact
SingleStoreDB Dev 0.2.35 greeting as well as the existing MySQL 8.4
`caching_sha2_password` path.

## Lua shape

```lua
local mysql = require("wasm.mysql")
local connection, err = mysql.connect({
  endpoint = "database",
  ["username-secret"] = "MYSQL_USER",
  ["password-secret"] = "MYSQL_PASSWORD",
  database = "app",
})
local result, query_err = connection:query("select marker from lane")
connection:close()
```

Secrets are named, never passed as values. Infrastructure and authority faults
remain outer Sigil plugin failures even if guest code attempts to catch or
relabel them.

The hyphenated option keys are the exact WIT record field names. A successful
`connect` or `query` is returned as `(value, nil)`; a typed driver error is
returned as `(nil, error)`. `close()` is idempotent and post-close queries
return the stable `closed` class without reconnecting.
