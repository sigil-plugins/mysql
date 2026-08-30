# Pinned live acceptance

This gate proves the unpublished MySQL SQL 0.2 candidate through Sigil's real
plugin store, lock, component host, and Lua resource bridge. It uses a
rootless Podman or Docker runner on Linux and never publishes an artifact.

## Exact inputs

- Candidate commit:
  `e9659bb2c4b04d83c63391422867b1eb0c7f0901`
- `plugin.wasm` SHA-256:
  `571501479e22ba02b47adb8e61b51006ca4d70200a6fb518db0a18e80cce80d3`
- `plugin.wasm` BLAKE3:
  `d876478d14a9b1c89fff63ea54ed31cc3d225dfe04476c409fd02eed2c1585bf`
- `dist/mysql-0.2.0.sigil-plugin.tar.zst` SHA-256:
  `47e039e312b2ada199a6fa47a30a1c9f9bdb99f1891bc5ef7b11cfbc85b37bdd`
- `dist/mysql-0.2.0.sigil-plugin.tar.zst` BLAKE3:
  `b95ae75bb3f6384d04a1f3127a568972ac2f6d462a0ae0e3715ff749aed93fd9`
- SingleStoreDB Dev 0.2.35 Linux/amd64 manifest:
  `ghcr.io/singlestore-labs/singlestoredb-dev@sha256:603b0ac0c7992becab334534a3ec1b37bac1a630b3e09cb50369fa222c72c269`
- MySQL 8.4.6 Linux/amd64 manifest:
  `docker.io/library/mysql@sha256:c296d65ee6ab3ce2f608c1d1b2bdd3c08b087a5834101d76a6db2e00875216cc`

The script rejects changed candidate digests before starting either service.
It runs SingleStore with four CPUs because that image's free license rejects a
larger visible CPU count.

`just signal-cleanup-check` exercises the shared trap dispatcher in isolated
subprocesses. It proves ordinary exit status preservation, distinct 130/143
statuses for INT/TERM, exactly one cleanup call, and managed-resource absence.

## Run

Prerequisites are the normal build toolchain, Python 3.11 or newer, a
compatible Sigil binary and its exact source checkout, and either Podman or
Docker. Then run:

```sh
SIGIL=/absolute/path/to/sigil \
SIGIL_CHECKOUT=/absolute/path/to/sigil-source \
just live-acceptance
```

`OCI_ENGINE=podman` or `OCI_ENGINE=docker` selects a runner explicitly. The
script gives every container a unique name, publishes SQL only on an ephemeral
loopback port, and stops and removes every container plus every volume created
for it in the exit trap. `KEEP_LIVE_SCRATCH=1` retains the temporary Sigil
project for diagnosis; it does not retain service state.

Sigil 0.33.0 already contains the SQL 0.2 host contract but predates this
candidate's declared 0.33.1 floor. For that one version only, the harness
lowers the floor in a scratch manifest so it can exercise the production host.
The candidate component and package are hashed before that scratch operation,
and neither checked-in artifact is changed.

## Matrix

The real services cover the advertised `mysql_native_password` and
`caching_sha2_password` handshakes, successful authentication, database
selection, repeated `query` and `exec` calls on one session, temporary-table
continuity and fresh-session isolation, typed signed/unsigned integers,
decimal, finite floating point, SQL NULL, UTF-8 text, bytes, temporal lexemes,
and ten-digit `UNIX_TIMESTAMP` seconds. They also cover affected rows,
last-insert ID, warnings, vendor code and SQLSTATE, a nonterminal server error,
a delayed first response under a longer deadline, caller row/result-byte
ceilings, the fixed packet ceiling, idempotent close, and resource reuse.

SingleStore returns a typed `authentication` error with vendor code 1045 and
SQLSTATE 28000 for a bad native-password response. On the deliberately
plaintext MySQL lane, a bad `caching_sha2_password` token requests full
authentication; the component returns `unsupported` rather than transmitting
the password without TLS. Correct credentials use the cache-primed fast-auth
path.

Separate scenarios prove a one-second operator timeout, socket-loss
`transport`, malformed metadata `protocol`, invalid integer `encoding`, and
signed `TINYINT` overflow `protocol`, and oversized packet `limit`. The
hostile peer records the exact statement trace, requires EOF after every
terminal error, and rejects reconnection or replay.
A one-KiB host wire ceiling is checked both through the lossy JSON
`plugin_infrastructure` projection and the human diagnostic's exact
`PLUGIN_RESOURCE_LIMIT`; the report must contain only the successful connect
assertion, never partial row output.

Each run writes ignored evidence under `target/live-acceptance/run.*`, including
image pull identities, raw handshake probes, auth-plugin evidence, JSON
reports, hostile-peer traces, service logs, candidate identities, elapsed
times, the one-line `cleanup-count.txt`, container and volume inventories
before and after teardown, and `teardown.txt`. A successful teardown file ends
with:

```text
all live acceptance containers and volumes removed
```
