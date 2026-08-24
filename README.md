# wasm.mysql

`wasm.mysql` is Sigil's bounded MySQL 8.4 protocol component. It exports the
exact experimental `sigil:sql/driver@0.1.0` interface and imports only
`sigil:host/net@1.0.0`, its value types, and `sigil:host/secrets@1.0.0`.

Sigil owns endpoint resolution, TCP, TLS verification, timeouts, byte quotas,
secret grants, cancellation, and teardown. The component implements MySQL
Classic Protocol framing, TLS-upgrade negotiation, `caching_sha2_password`, and
single-result `COM_QUERY`. It never receives a raw host, port, DNS, socket,
clock, filesystem, process, stdio, or ambient WASI capability.

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
