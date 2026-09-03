# Pinned live acceptance

This gate proves the public MySQL 0.2.1 release through Sigil's real
plugin store, lock, component host, and Lua resource bridge. It uses a
rootless Podman or Docker runner on Linux and never publishes an artifact.

## Exact inputs

- Release commit:
  `f62d41387bd27c671f734a4ba6171d619f810614`
- `plugin.wasm` SHA-256:
  `968704493a62e07d8011bbbe4ce2d8f178b30dc0b1bc1e379c2a2e41263d9125`
- `plugin.wasm` BLAKE3:
  `9f59fe036ccf1651ac932f52a3fe6b66ebf039f5c77ded844ab95647060e7e17`
- `dist/mysql-0.2.1.sigil-plugin.tar.zst` SHA-256:
  `c5d8daf3e824fe3f9329f7938f125504a35df0ff4bb368dadae562a12448e436`
- `dist/mysql-0.2.1.sigil-plugin.tar.zst` BLAKE3:
  `5ff1772bf8cbee0756fcfcc4d61169fbb258d9deafffe0579386631eeff880fb`
- SingleStoreDB Dev 0.2.35 Linux/amd64 manifest:
  `ghcr.io/singlestore-labs/singlestoredb-dev@sha256:603b0ac0c7992becab334534a3ec1b37bac1a630b3e09cb50369fa222c72c269`
- MySQL 8.0.29 Linux/amd64 manifest:
  `docker.io/library/mysql@sha256:44f98f4dd825a945d2a6a4b7b2f14127b5d07c5aaa07d9d232c2b58936fb76dc`

The script rejects changed release digests before starting either service.
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
release's declared 0.33.1 floor. The harness lowers that floor only in a
scratch manifest when testing 0.33.0. SemVer excludes prereleases from a stable
lower-bound comparator, so the harness similarly pins a supplied prerelease
binary's exact version in scratch. The release component and package are
hashed before either operation, and neither checked-in artifact is changed.

## Matrix

The real services cover SingleStore's initial `mysql_native_password` greeting
and three stock MySQL 8.0.29 paths: a cold `caching_sha2_password` cache, an
auth switch to a `mysql_native_password` user, and another cold caching login
after `FLUSH PRIVILEGES`. Each path proves successful authentication, database
selection, repeated `query` and `exec` calls on one session, temporary-table
continuity and fresh-session isolation, typed signed/unsigned integers,
decimal, finite floating point, SQL NULL, UTF-8 text, bytes, temporal lexemes,
and ten-digit `UNIX_TIMESTAMP` seconds. They also cover affected rows,
last-insert ID, warnings, vendor code and SQLSTATE, a nonterminal server error,
a delayed first response under a longer deadline, caller row/result-byte
ceilings, the fixed packet ceiling, idempotent close, and resource reuse.

Every dialect and authentication plugin returns a typed `authentication` error
with vendor code 1045 and SQLSTATE 28000 for a wrong password. On the
deliberately plaintext MySQL lane, cold `caching_sha2_password` authentication
requests the server public key and sends an RSA-OAEP ciphertext seeded by the
explicit entropy grant; no cache-prime login is performed. The native MySQL
user proves the server-directed auth-switch response rather than only an
initial native greeting.

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
reports, hostile-peer traces, service logs, release identities, elapsed
times, the one-line `cleanup-count.txt`, container and volume inventories
before and after teardown, and `teardown.txt`. A successful teardown file ends
with:

```text
all live acceptance containers and volumes removed
```
