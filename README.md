# wasm.mysql

`wasm.mysql` is Sigil's bounded MySQL and SingleStore protocol component. It
exports the exact experimental `sigil:sql/driver@0.2.0` interface and imports
only `sigil:host/net@1.0.0`, its read-only `net-policy` companion, its value
types, and `sigil:host/secrets@1.0.0`.

Sigil owns endpoint resolution, TCP, TLS verification, timeouts, byte quotas,
secret grants, cancellation, and teardown. The component implements MySQL
Classic Protocol framing, operator-selected plaintext or TLS-upgrade
negotiation, `caching_sha2_password`, `mysql_native_password`, and stateful,
single-result `COM_QUERY`. One returned connection resource is one server
session, so temporary tables and other session state survive alternating
`exec` and `query` calls. It never receives a raw host, port, DNS, socket, TLS
name, trust root, clock, filesystem, process, stdio, or ambient WASI capability.

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

The v0.2 driver returns signed and unsigned integers as integers, finite
floating-point values as numbers, exact decimal and temporal lexemes as
strings, SQL NULL as its own tagged value, and binary columns as byte strings.
It returns ordered column metadata with every row set, and complete affected
row, last-insert-id, and warning metadata from command responses. Caller row
and byte limits only lower the driver's fixed ceilings. A breached bound or
malformed, contradictory, or truncated response closes the session and never
returns a partial result. Complete server errors and a `query`/`exec` result
kind mismatch are nonterminal; transport, timeout, protocol, encoding, and
limit errors are terminal. The driver never retries, reconnects, or replays a
statement.

The frozen v0.1 releases deliberately do not implement prepared statements,
binary protocol, multi-statements/results, `LOCAL INFILE`, retry, or reconnect.
Version 0.2 retains those exclusions while replacing the v0.1 combined result
variant with row-only `query` and separate `exec` methods.

## Build

Prerequisites are Rust 1.95.0 with `wasm32-unknown-unknown`, `wasm-tools`
1.252.0, `just` 1.57.0, `b3sum` 1.8.3, Python 3.11+, and zstd 1.5.7.

```sh
just check
just dist
SIGIL=/path/to/sigil SIGIL_CHECKOUT=/path/to/sigil-source just sigil-check
```

`just sdk-drift` checks the vendored build inputs against the immutable SDK
revision recorded in `SDK.lock`. `just reproducible` performs two isolated
builds and compares both the component and canonical package bytes.
`just sigil-check` loads the packed component through Sigil's production store
and Lua bridge, then drives it against a deterministic MySQL protocol peer.
`just live-acceptance` runs the same production path against pinned
SingleStoreDB Dev and stock MySQL 8 images, plus hostile protocol peers; see
[`conformance/live/README.md`](conformance/live/README.md) for its prerequisites,
exact identities, matrix, and evidence layout.

Version 0.1.2 is the first keyless-provenance release. The unprivileged
`prepare-release` workflow builds its package and canonical release manifest
once from `main`. After explicit digest approval, the protected
`publish-release` workflow stages and reads back exactly three assets, creates
one GitHub OIDC/Sigstore package attestation, and publishes an immutable tag and
release. It has no long-lived signing secret and never resumes or replaces a
partial version.

Version 0.2.0 is an unpublished source candidate. It includes the additive
`sigil:host/net-policy@1.0.0` contract, SingleStore-compatible
`mysql_native_password`, and the typed SQL 0.2 session contract. It requires
Sigil 0.33.1 or newer; Sigil 0.33.1 is public, but this plugin candidate has no
official package asset. Do not use `sigil plugin install mysql@0.2.0` or add
that identity to a project lock until a separately authorized release is
published and verified. Build-from-source packages are for isolated validation
only.
Its deterministic fixtures cover the exact SingleStoreDB Dev 0.2.35 greeting,
the existing MySQL 8.4 `caching_sha2_password` path, repeated calls on one
session, typed boundary values, exact command metadata, and fail-closed limits.

| Public 0.1.2 | Unpublished 0.2.0 source candidate |
|---|---|
| `query` returns a row-or-command variant | row-only `query` plus command-only `exec` |
| NULL, text, and bytes cells | tagged signed, unsigned, floating, exact decimal, temporal, text, bytes, and NULL |
| fixed result ceilings | `max-rows` and `max-result-bytes` may lower, never raise, fixed and host ceilings |
| MySQL 8.4 `caching_sha2_password` | also supports SingleStore's MySQL 5.7 dialect and `mysql_native_password` |

## Lua shape

```lua
local mysql = require("wasm.mysql")
local connection, err = mysql.connect({
  endpoint = "database",
  ["username-secret"] = "MYSQL_USER",
  ["password-secret"] = "MYSQL_PASSWORD",
  database = "app",
  ["max-rows"] = 1000,
  ["max-result-bytes"] = 8 * 1024 * 1024,
})
expect(connection ~= nil, err and err.message)
local rows, query_err = connection:query(
  "select unix_timestamp(ts), amount, nullable_note from lane"
)
expect(rows ~= nil, query_err and query_err.message)
expect(rows.rows[1].cells[1].tag == "signed")
expect(rows.rows[1].cells[2].tag == "decimal")
expect(rows.rows[1].cells[3].tag == "null")
local command, exec_err = connection:exec("update lane set seen = 1")
expect(command ~= nil, exec_err and exec_err.message)
expect(command["affected-rows"] == 1)
expect(command.warnings == 0)
connection:close()
```

Secrets are named, never passed as values. Infrastructure and authority faults
remain outer Sigil plugin failures even if guest code attempts to catch or
relabel them.

The hyphenated option keys are the exact WIT record field names. Optional
`max-rows` and `max-result-bytes` values are additional caller ceilings. A
successful `connect`, `query`, or `exec` is returned as `(value, nil)`; a typed
driver error is returned as `(nil, error)`. `query` accepts exactly one row-set
response, while `exec` accepts exactly one command response. `close()` is
idempotent and post-close calls return the stable `closed` class without
reconnecting.
