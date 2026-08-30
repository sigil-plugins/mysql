#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 /path/to/sigil-binary [/path/to/sigil-checkout]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
SIGIL="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
readonly SIGIL
SIGIL_CHECKOUT="${2:-${SIGIL_CHECKOUT:-}}"
if [[ ! -x "$SIGIL" ]]; then
  echo "sigil binary is not executable: $SIGIL" >&2
  exit 2
fi
if [[ -z "$SIGIL_CHECKOUT" || ! -f "$SIGIL_CHECKOUT/Cargo.toml" ]]; then
  echo "an exact Sigil source checkout is required for compatibility seeding" >&2
  exit 2
fi
SIGIL_CHECKOUT="$(cd "$SIGIL_CHECKOUT" && pwd -P)"
readonly SIGIL_CHECKOUT
if ! grep -Eq '^name = "sigil"$' "$SIGIL_CHECKOUT/Cargo.toml"; then
  echo "not a Sigil source checkout: $SIGIL_CHECKOUT" >&2
  exit 2
fi

if [[ -n "${OCI_ENGINE:-}" ]]; then
  ENGINE="$OCI_ENGINE"
elif command -v podman >/dev/null 2>&1; then
  ENGINE=podman
elif command -v docker >/dev/null 2>&1; then
  ENGINE=docker
else
  echo "Podman or Docker is required for live acceptance" >&2
  exit 2
fi
readonly ENGINE

SINGLESTORE_IMAGE="ghcr.io/singlestore-labs/singlestoredb-dev@sha256:603b0ac0c7992becab334534a3ec1b37bac1a630b3e09cb50369fa222c72c269"
MYSQL_IMAGE="docker.io/library/mysql@sha256:c296d65ee6ab3ce2f608c1d1b2bdd3c08b087a5834101d76a6db2e00875216cc"
EXPECTED_COMPONENT_SHA256="571501479e22ba02b47adb8e61b51006ca4d70200a6fb518db0a18e80cce80d3"
EXPECTED_PACKAGE_SHA256="47e039e312b2ada199a6fa47a30a1c9f9bdb99f1891bc5ef7b11cfbc85b37bdd"
EXPECTED_COMPONENT_BLAKE3="d876478d14a9b1c89fff63ea54ed31cc3d225dfe04476c409fd02eed2c1585bf"
EXPECTED_PACKAGE_BLAKE3="b95ae75bb3f6384d04a1f3127a568972ac2f6d462a0ae0e3715ff749aed93fd9"
readonly SINGLESTORE_IMAGE MYSQL_IMAGE EXPECTED_COMPONENT_SHA256 EXPECTED_PACKAGE_SHA256
readonly EXPECTED_COMPONENT_BLAKE3 EXPECTED_PACKAGE_BLAKE3

SINGLESTORE_PASSWORD="sigil-live-root-2026"
MYSQL_ROOT_SECRET="sigil-mysql-root-2026"
MYSQL_USER_PASSWORD="sigil-mysql-user-2026"
BAD_PASSWORD="definitely-wrong"
readonly SINGLESTORE_PASSWORD MYSQL_ROOT_SECRET MYSQL_USER_PASSWORD BAD_PASSWORD

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sigil-mysql-live.XXXXXXXX")"
mkdir -p "$ROOT/target/live-acceptance"
EVIDENCE="$(mktemp -d "$ROOT/target/live-acceptance/run.XXXXXXXX")"
readonly SCRATCH EVIDENCE
suffix="$$"
singlestore_name="sigil-mysql-live-singlestore-$suffix"
mysql_name="sigil-mysql-live-mysql-$suffix"
readonly singlestore_name mysql_name
started_containers=()
peer_pids=()
attached_volumes=()

remember_volume() {
  local candidate=$1
  local existing
  for existing in "${attached_volumes[@]}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return 0
    fi
  done
  attached_volumes+=("$candidate")
}

inventory_container() {
  local name=$1
  local phase=$2
  local identity_file="$EVIDENCE/$name.$phase.identity.txt"
  local mounts_file="$EVIDENCE/$name.$phase.mounts.json"
  local volumes_file="$EVIDENCE/$name.$phase.volumes.txt"
  "$ENGINE" container inspect --format \
    'id={{.Id}} name={{.Name}} image={{.Image}}' "$name" >"$identity_file"
  "$ENGINE" container inspect --format '{{json .Mounts}}' "$name" >"$mounts_file"
  python3 - "$mounts_file" "$volumes_file" <<'PY'
import json
from pathlib import Path
import sys

mounts = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(mounts, list):
    raise SystemExit("container inspection has no mount inventory")
volumes = []
for mount in mounts:
    if mount.get("Type") == "volume":
        name = mount.get("Name")
        if not isinstance(name, str) or not name:
            raise SystemExit("volume mount has no stable name")
        volumes.append(name)
Path(sys.argv[2]).write_text(
    "".join(f"{name}\n" for name in sorted(set(volumes))), encoding="utf-8"
)
PY
  while IFS= read -r volume; do
    if [[ -n "$volume" ]]; then
      remember_volume "$volume"
    fi
  done <"$volumes_file"
}

cleanup() {
  local status=$?
  local name volume
  set +e
  : >"$EVIDENCE/teardown.txt"
  for pid in "${peer_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" >>"$EVIDENCE/teardown.txt" 2>&1
      wait "$pid" >>"$EVIDENCE/teardown.txt" 2>&1
    fi
  done
  : >"$EVIDENCE/managed-containers.before-cleanup.txt"
  for name in "${started_containers[@]}"; do
    if "$ENGINE" container inspect "$name" >/dev/null 2>&1; then
      echo "$name present" >>"$EVIDENCE/managed-containers.before-cleanup.txt"
      if ! inventory_container "$name" before-cleanup \
        >>"$EVIDENCE/teardown.txt" 2>&1; then
        echo "failed to inventory live acceptance container: $name" \
          >>"$EVIDENCE/teardown.txt"
        status=1
      fi
    else
      echo "$name absent" >>"$EVIDENCE/managed-containers.before-cleanup.txt"
    fi
  done
  : >"$EVIDENCE/managed-volumes.before-cleanup.txt"
  for volume in "${attached_volumes[@]}"; do
    if "$ENGINE" volume inspect "$volume" >/dev/null 2>&1; then
      echo "$volume present" >>"$EVIDENCE/managed-volumes.before-cleanup.txt"
    else
      echo "$volume absent" >>"$EVIDENCE/managed-volumes.before-cleanup.txt"
    fi
  done
  for name in "${started_containers[@]}"; do
    if "$ENGINE" container inspect "$name" >/dev/null 2>&1; then
      "$ENGINE" stop --time 15 "$name" >>"$EVIDENCE/teardown.txt" 2>&1
      "$ENGINE" rm --volumes "$name" >>"$EVIDENCE/teardown.txt" 2>&1
    fi
  done
  : >"$EVIDENCE/managed-containers.after.txt"
  for name in "${started_containers[@]}"; do
    if "$ENGINE" container inspect "$name" >/dev/null 2>&1; then
      echo "$name present" >>"$EVIDENCE/managed-containers.after.txt"
      echo "live acceptance container remains after teardown: $name" \
        >>"$EVIDENCE/teardown.txt"
      status=1
    else
      echo "$name absent" >>"$EVIDENCE/managed-containers.after.txt"
    fi
  done
  : >"$EVIDENCE/managed-volumes.after.txt"
  for volume in "${attached_volumes[@]}"; do
    if "$ENGINE" volume inspect "$volume" >/dev/null 2>&1; then
      if ! grep -Fx "$volume" "$EVIDENCE/engine-volumes.before.txt" >/dev/null; then
        "$ENGINE" volume rm "$volume" >>"$EVIDENCE/teardown.txt" 2>&1
      fi
    fi
    if "$ENGINE" volume inspect "$volume" >/dev/null 2>&1; then
      echo "$volume present" >>"$EVIDENCE/managed-volumes.after.txt"
      echo "live acceptance volume remains after teardown: $volume" \
        >>"$EVIDENCE/teardown.txt"
      status=1
    else
      echo "$volume absent" >>"$EVIDENCE/managed-volumes.after.txt"
    fi
  done
  "$ENGINE" volume ls --format '{{.Name}}' | sort \
    >"$EVIDENCE/engine-volumes.after.txt"
  if [[ "$status" -eq 0 ]]; then
    echo "all live acceptance containers and volumes removed" \
      >>"$EVIDENCE/teardown.txt"
  fi
  if [[ "${KEEP_LIVE_SCRATCH:-0}" == 1 ]]; then
    printf 'scratch retained: %s\n' "$SCRATCH" >&2
  else
    rm -r -- "$SCRATCH"
  fi
  printf 'evidence: %s\n' "$EVIDENCE" >&2
  exit "$status"
}
trap cleanup EXIT INT TERM

"$ENGINE" volume ls --format '{{.Name}}' | sort \
  >"$EVIDENCE/engine-volumes.before.txt"
: >"$EVIDENCE/managed-containers.before.txt"
for name in "$singlestore_name" "$mysql_name"; do
  if "$ENGINE" container inspect "$name" >/dev/null 2>&1; then
    echo "$name present" >>"$EVIDENCE/managed-containers.before.txt"
    echo "managed container name already exists: $name" >&2
    exit 1
  fi
  echo "$name absent" >>"$EVIDENCE/managed-containers.before.txt"
done

wait_for_exec() {
  local name=$1
  local password=$2
  local client=$3
  local user=$4
  for _attempt in $(seq 1 180); do
    if MYSQL_PWD="$password" "$ENGINE" exec --env MYSQL_PWD "$name" \
      "$client" -u"$user" -Nse "SELECT @@version" >"$EVIDENCE/$name.version" 2>/dev/null; then
      return 0
    fi
    if [[ "$("$ENGINE" inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" != true ]]; then
      "$ENGINE" logs "$name" >"$EVIDENCE/$name.log" 2>&1
      return 1
    fi
    sleep 1
  done
  "$ENGINE" logs "$name" >"$EVIDENCE/$name.log" 2>&1
  return 1
}

published_port() {
  local name=$1
  local mapping
  mapping="$("$ENGINE" port "$name" 3306/tcp | tail -n 1)"
  [[ "$mapping" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || {
    echo "unexpected published port: $mapping" >&2
    return 1
  }
  printf '%s\n' "${BASH_REMATCH[1]}"
}

run_sigil() {
  (
    cd "$SCRATCH/project"
    SIGIL_DATA_DIR="$SCRATCH/data" \
      SIGIL_CACHE_DIR="$SCRATCH/cache" \
      "$SIGIL" "$@"
  )
}

run_live_scenario() {
  local dialect=$1
  local port=$2
  local user=$3
  local password=$4
  local report="$EVIDENCE/$dialect.report.json"
  local started elapsed
  started=$(date +%s)
  MYSQL_DIALECT="$dialect" MYSQL_USER="$user" MYSQL_PASSWORD="$password" \
  MYSQL_BAD_PASSWORD="$BAD_PASSWORD" \
    run_sigil run scenarios/mysql-session.lua \
      --endpoint "database=http://127.0.0.1:$port" \
      --env MYSQL_DIALECT --env MYSQL_USER --env MYSQL_PASSWORD --env MYSQL_BAD_PASSWORD \
      --json >"$report"
  elapsed=$(($(date +%s) - started))
  printf '%s\n' "$elapsed" >"$EVIDENCE/$dialect.elapsed-seconds"
  python3 - "$report" "$dialect" "$elapsed" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["status"] != "passed" or report["total"] != 1 or report["failed"] != 0:
    raise SystemExit(f"{sys.argv[2]} live scenario failed: {report!r}")
if int(sys.argv[3]) < 2:
    raise SystemExit(f"{sys.argv[2]} delayed query returned before two seconds")
PY
}

run_pass_scenario() {
  local label=$1
  local scenario=$2
  local port=$3
  local user=$4
  local password=$5
  local report="$EVIDENCE/$label.report.json"
  MYSQL_USER="$user" MYSQL_PASSWORD="$password" MYSQL_BAD_PASSWORD="$BAD_PASSWORD" \
    run_sigil run "scenarios/$scenario" \
      --endpoint "database=http://127.0.0.1:$port" \
      --env MYSQL_USER --env MYSQL_PASSWORD --env MYSQL_BAD_PASSWORD \
      --json >"$report" \
      2>"$EVIDENCE/$label.stderr.txt"
  python3 - "$report" "$label" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["status"] != "passed" or report["total"] != 1 or report["failed"] != 0:
    raise SystemExit(f"{sys.argv[2]} scenario failed: {report!r}")
PY
}

set_network_option() {
  local name=$1
  local old=$2
  local new=$3
  python3 - "$SCRATCH/project/.sigil/sigil.toml" "$name" "$old" "$new" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
name, old, new = sys.argv[2:]
text = path.read_text(encoding="utf-8")
needle = f'{name} = "{old}"'
replacement = f'{name} = "{new}"'
if text.count(needle) != 1:
    raise SystemExit(f"expected exactly one config entry: {needle}")
path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY
}

start_fault_peer() {
  local mode=$1
  local ready="$EVIDENCE/$mode.peer.port"
  local result="$EVIDENCE/$mode.peer.json"
  local log="$EVIDENCE/$mode.peer.log"
  rm -f -- "$ready" "$result"
  python3 "$ROOT/scripts/live-fault-mysql.py" "$mode" "$ready" "$result" \
    >"$log" 2>&1 &
  PEER_PID=$!
  peer_pids+=("$PEER_PID")
  for _attempt in $(seq 1 100); do
    if [[ -s "$ready" ]]; then
      PEER_PORT="$(<"$ready")"
      [[ "$PEER_PORT" =~ ^[0-9]+$ ]] || {
        echo "fault peer returned invalid port: $PEER_PORT" >&2
        return 1
      }
      return 0
    fi
    if ! kill -0 "$PEER_PID" 2>/dev/null; then
      wait "$PEER_PID"
      return 1
    fi
    sleep 0.05
  done
  echo "fault peer did not become ready: $mode" >&2
  return 1
}

if [[ "$(git -C "$ROOT" rev-parse e9659bb2c4b04d83c63391422867b1eb0c7f0901)" != \
  e9659bb2c4b04d83c63391422867b1eb0c7f0901 ]]; then
  echo "merged SQL 0.2 candidate commit is unavailable" >&2
  exit 1
fi
if ! git -C "$ROOT" merge-base --is-ancestor \
  e9659bb2c4b04d83c63391422867b1eb0c7f0901 HEAD; then
  echo "live acceptance workspace does not descend from the merged SQL 0.2 candidate" >&2
  exit 1
fi
echo "$EXPECTED_COMPONENT_SHA256  $ROOT/plugin.wasm" | sha256sum --check --strict
echo "$EXPECTED_PACKAGE_SHA256  $ROOT/dist/mysql-0.2.0.sigil-plugin.tar.zst" |
  sha256sum --check --strict
echo "$EXPECTED_COMPONENT_BLAKE3  $ROOT/plugin.wasm" | b3sum --check
echo "$EXPECTED_PACKAGE_BLAKE3  $ROOT/dist/mysql-0.2.0.sigil-plugin.tar.zst" |
  b3sum --check

"$ENGINE" pull "$SINGLESTORE_IMAGE" >"$EVIDENCE/singlestore.pull.txt"
"$ENGINE" pull "$MYSQL_IMAGE" >"$EVIDENCE/mysql.pull.txt"

ROOT_PASSWORD="$SINGLESTORE_PASSWORD" "$ENGINE" run -d \
  --name "$singlestore_name" --cpus=4 --env ROOT_PASSWORD \
  -p 127.0.0.1::3306 "$SINGLESTORE_IMAGE" \
  >"$EVIDENCE/singlestore.container-id"
started_containers+=("$singlestore_name")
inventory_container "$singlestore_name" started

MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_SECRET" \
MYSQL_DATABASE=app \
MYSQL_USER=sigil \
MYSQL_PASSWORD="$MYSQL_USER_PASSWORD" \
  "$ENGINE" run -d --name "$mysql_name" \
    --env MYSQL_ROOT_PASSWORD --env MYSQL_DATABASE --env MYSQL_USER --env MYSQL_PASSWORD \
    -p 127.0.0.1::3306 "$MYSQL_IMAGE" \
    >"$EVIDENCE/mysql.container-id"
started_containers+=("$mysql_name")
inventory_container "$mysql_name" started

wait_for_exec "$singlestore_name" "$SINGLESTORE_PASSWORD" memsql root
wait_for_exec "$mysql_name" "$MYSQL_ROOT_SECRET" mysql root

MYSQL_PWD="$SINGLESTORE_PASSWORD" "$ENGINE" exec --env MYSQL_PWD "$singlestore_name" \
  memsql -uroot -e "CREATE DATABASE IF NOT EXISTS app"
MYSQL_PWD="$MYSQL_USER_PASSWORD" "$ENGINE" exec --env MYSQL_PWD "$mysql_name" \
  mysql -usigil app -Nse "SELECT CURRENT_USER(), @@version" \
  >"$EVIDENCE/mysql.cache-prime.txt"
MYSQL_PWD="$MYSQL_ROOT_SECRET" "$ENGINE" exec --env MYSQL_PWD "$mysql_name" \
  mysql -uroot -Nse \
    "SELECT user, host, plugin FROM mysql.user WHERE user = 'sigil' ORDER BY host" \
  >"$EVIDENCE/mysql.auth-plugin.txt"
grep -F $'sigil\t%\tcaching_sha2_password' "$EVIDENCE/mysql.auth-plugin.txt" >/dev/null

singlestore_port="$(published_port "$singlestore_name")"
mysql_port="$(published_port "$mysql_name")"
python3 "$ROOT/scripts/probe-mysql-handshake.py" 127.0.0.1 "$singlestore_port" \
  >"$EVIDENCE/singlestore.handshake.json"
python3 "$ROOT/scripts/probe-mysql-handshake.py" 127.0.0.1 "$mysql_port" \
  >"$EVIDENCE/mysql.handshake.json"
grep -F '"auth_plugin": "mysql_native_password"' \
  "$EVIDENCE/singlestore.handshake.json" >/dev/null
grep -F '"auth_plugin": "caching_sha2_password"' \
  "$EVIDENCE/mysql.handshake.json" >/dev/null

mkdir -p "$SCRATCH/package/dist" "$SCRATCH/seeder/src" \
  "$SCRATCH/project/.sigil" "$SCRATCH/project/scenarios"
cp "$ROOT/plugin.toml" "$SCRATCH/package/plugin.toml"
cp "$ROOT/plugin.wasm" "$SCRATCH/package/plugin.wasm"
python3 - "$SCRATCH/package/plugin.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
replacements = {
    'source = "github:sigil-plugins/mysql"': 'source = "github:conformance/mysql"',
}
for old, new in replacements.items():
    if text.count(old) != 1:
        raise SystemExit(f"candidate manifest field differs: {old}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
PY
if [[ "$($SIGIL --version)" == "sigil 0.33.0" ]]; then
  python3 - "$SCRATCH/package/plugin.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = 'sigil = ">=0.33.1, <1.0.0"'
if text.count(old) != 1:
    raise SystemExit("candidate Sigil version floor differs")
path.write_text(text.replace(old, 'sigil = ">=0.33.0, <1.0.0"'), encoding="utf-8")
PY
fi
"$SIGIL" plugin validate "$SCRATCH/package/plugin.toml" \
  >"$EVIDENCE/plugin.validate.txt"
"$SIGIL" plugin inspect "$SCRATCH/package/plugin.toml" \
  >"$EVIDENCE/plugin.inspect.txt"
"$SIGIL" plugin pack "$SCRATCH/package/plugin.toml" \
  --output-dir "$SCRATCH/package/dist" >/dev/null

python3 - \
  "$ROOT/tools/sigil-compat-seed/Cargo.toml.in" \
  "$SIGIL_CHECKOUT" \
  "$SCRATCH/seeder/Cargo.toml" <<'PY'
from pathlib import Path
import sys

template = Path(sys.argv[1]).read_text(encoding="utf-8")
checkout = sys.argv[2].replace("\\", "\\\\").replace('"', '\\"')
Path(sys.argv[3]).write_text(
    template.replace("@SIGIL_CHECKOUT@", checkout), encoding="utf-8"
)
PY
cp "$ROOT/tools/sigil-compat-seed/main.rs" "$SCRATCH/seeder/src/main.rs"
cargo generate-lockfile --quiet --manifest-path "$SCRATCH/seeder/Cargo.toml" --offline
CARGO_TARGET_DIR="$ROOT/target/sigil-compat-seed" \
  cargo run --quiet --locked --offline \
    --manifest-path "$SCRATCH/seeder/Cargo.toml" -- \
    "$SCRATCH/data" \
    "$SCRATCH/package/dist/mysql-0.2.0.sigil-plugin.tar.zst" \
    github:conformance/mysql mysql 0.2.0 mysql-live-0.2.0

cp "$ROOT/conformance/live/sigil.toml" "$SCRATCH/project/.sigil/sigil.toml"
for scenario in "$ROOT"/conformance/live/*.sigil.lua; do
  name="$(basename "$scenario" .sigil.lua)"
  cp "$scenario" "$SCRATCH/project/scenarios/$name.lua"
done
run_sigil plugin lock >"$EVIDENCE/plugin.lock.txt"

run_live_scenario singlestore "$singlestore_port" root "$SINGLESTORE_PASSWORD"
run_live_scenario mysql84 "$mysql_port" sigil "$MYSQL_USER_PASSWORD"

start_fault_peer typed
run_pass_scenario protocol-faults mysql-protocol-faults.lua \
  "$PEER_PORT" root "$SINGLESTORE_PASSWORD"
wait "$PEER_PID"
python3 - "$EVIDENCE/typed.peer.json" <<'PY'
import json
from pathlib import Path
import sys

actual = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "connections": 4,
    "queries": [
        "SELECT malformed_metadata",
        "SELECT invalid_integer",
        "SELECT integer_overflow",
        "SELECT oversized_packet",
    ],
    "terminal_eof": 4,
}
if actual != expected:
    raise SystemExit(f"typed fault peer evidence differs: {actual!r}")
PY

start_fault_peer transport
run_pass_scenario transport mysql-transport.lua \
  "$PEER_PORT" root "$SINGLESTORE_PASSWORD"
wait "$PEER_PID"
python3 - "$EVIDENCE/transport.peer.json" <<'PY'
import json
from pathlib import Path
import sys

actual = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "connections": 1,
    "queries": ["SELECT socket_loss"],
    "reconnects": 0,
}
if actual != expected:
    raise SystemExit(f"transport peer evidence differs: {actual!r}")
PY

set_network_option io_timeout 5s 1s
run_pass_scenario timeout mysql-timeout.lua \
  "$mysql_port" sigil "$MYSQL_USER_PASSWORD"
set_network_option io_timeout 1s 5s

set_network_option max_bytes 32MiB 1KiB
set +e
MYSQL_USER=sigil MYSQL_PASSWORD="$MYSQL_USER_PASSWORD" MYSQL_BAD_PASSWORD="$BAD_PASSWORD" \
  run_sigil run scenarios/mysql-host-limit.lua \
    --endpoint "database=http://127.0.0.1:$mysql_port" \
    --env MYSQL_USER --env MYSQL_PASSWORD --env MYSQL_BAD_PASSWORD --json \
    >"$EVIDENCE/host-limit.report.json" \
    2>"$EVIDENCE/host-limit.stderr.txt"
host_limit_status=$?
set -e
if [[ "$host_limit_status" -eq 0 ]]; then
  echo "host-owned max_bytes breach unexpectedly passed" >&2
  exit 1
fi
python3 - "$EVIDENCE/host-limit.report.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["status"] != "failed" or report["total"] != 1 or report["failed"] != 1:
    raise SystemExit(f"host limit did not fail closed: {report!r}")
scenario = report["scenarios"][0]
if scenario.get("failure_class") != "plugin_infrastructure":
    raise SystemExit(f"host limit classification differs: {report!r}")
expects = scenario.get("expects", [])
if len(expects) != 1 or expects[0].get("passed") is not True:
    raise SystemExit(f"host limit returned guest-visible partial output: {report!r}")
PY
set +e
MYSQL_USER=sigil MYSQL_PASSWORD="$MYSQL_USER_PASSWORD" MYSQL_BAD_PASSWORD="$BAD_PASSWORD" \
  run_sigil run scenarios/mysql-host-limit.lua \
    --endpoint "database=http://127.0.0.1:$mysql_port" \
    --env MYSQL_USER --env MYSQL_PASSWORD --env MYSQL_BAD_PASSWORD \
    >"$EVIDENCE/host-limit.human.txt" 2>&1
host_limit_human_status=$?
set -e
if [[ "$host_limit_human_status" -eq 0 ]] || \
  ! grep -F "PLUGIN_RESOURCE_LIMIT" "$EVIDENCE/host-limit.human.txt" >/dev/null; then
  echo "host-owned max_bytes failure did not expose PLUGIN_RESOURCE_LIMIT" >&2
  exit 1
fi
set_network_option max_bytes 1KiB 32MiB

"$ENGINE" logs "$singlestore_name" >"$EVIDENCE/singlestore.log" 2>&1
"$ENGINE" logs "$mysql_name" >"$EVIDENCE/mysql.log" 2>&1
printf '%s\n' \
  "candidate_commit=e9659bb2c4b04d83c63391422867b1eb0c7f0901" \
  "component_sha256=$EXPECTED_COMPONENT_SHA256" \
  "component_blake3=$EXPECTED_COMPONENT_BLAKE3" \
  "package_sha256=$EXPECTED_PACKAGE_SHA256" \
  "package_blake3=$EXPECTED_PACKAGE_BLAKE3" \
  "singlestore_image=$SINGLESTORE_IMAGE" \
  "singlestore_image_id=$($ENGINE image inspect --format '{{.Id}}' "$SINGLESTORE_IMAGE")" \
  "mysql_image=$MYSQL_IMAGE" \
  "mysql_image_id=$($ENGINE image inspect --format '{{.Id}}' "$MYSQL_IMAGE")" \
  "sigil_version=$($SIGIL --version)" \
  "sigil_source_commit=$(git -C "$SIGIL_CHECKOUT" rev-parse HEAD)" \
  "engine=$($ENGINE --version)" \
  >"$EVIDENCE/identities.txt"

echo "pinned SingleStore and MySQL 8 real-component acceptance passed"
