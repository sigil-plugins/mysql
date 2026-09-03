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
if [[ ! -x "$SIGIL" ]]; then
  echo "sigil binary is not executable: $SIGIL" >&2
  exit 2
fi

SIGIL_CHECKOUT="${2:-${SIGIL_CHECKOUT:-}}"
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

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sigil-mysql-compat.XXXXXXXX")"
readonly SCRATCH
SOURCE="github:conformance/mysql"
readonly SOURCE
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -r -- "$SCRATCH"
}
trap cleanup EXIT

run_sigil() {
  (
    cd "$SCRATCH/project"
    SIGIL_DATA_DIR="$SCRATCH/data" \
      SIGIL_CACHE_DIR="$SCRATCH/cache" \
      "$SIGIL" "$@"
  )
}

mkdir -p "$SCRATCH/package/dist"
cp "$ROOT/plugin.toml" "$SCRATCH/package/plugin.toml"
cp "$ROOT/plugin.wasm" "$SCRATCH/package/plugin.wasm"

# Give the throwaway package a non-official source identity. Production store
# verification requires the package claim and seeded acquisition to agree.
python3 - "$SCRATCH/package/plugin.toml" "$SOURCE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = 'source = "github:sigil-plugins/mysql"'
new = f'source = "{sys.argv[2]}"'
if text.count(old) != 1:
    raise SystemExit("candidate repository source differs")
path.write_text(text.replace(old, new), encoding="utf-8")
PY

# The compatibility host source already implements this candidate ABI while
# its unreleased development binary still identifies itself as 0.33.0. Lower
# only the scratch package's host-version declaration in that exact case. The
# source manifest remains >=0.33.1 and its exact value is separately asserted.
sigil_version="$($SIGIL --version)"
scratch_requirement=""
if [[ "$sigil_version" == "sigil 0.33.0" ]]; then
  scratch_requirement=">=0.33.0, <1.0.0"
elif [[ "$sigil_version" == sigil\ *-* ]]; then
  scratch_requirement="=${sigil_version#sigil }"
fi
if [[ -n "$scratch_requirement" ]]; then
  python3 - "$SCRATCH/package/plugin.toml" "$scratch_requirement" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
requirement = sys.argv[2]
text = path.read_text(encoding="utf-8")
old = 'sigil = ">=0.33.1, <1.0.0"'
if text.count(old) != 1:
    raise SystemExit("candidate Sigil version floor differs")
path.write_text(text.replace(old, f'sigil = "{requirement}"'), encoding="utf-8")
PY
fi

grep -F 'sigil = ">=0.33.1, <1.0.0"' "$ROOT/plugin.toml" >/dev/null
"$SIGIL" plugin validate "$SCRATCH/package/plugin.toml"
"$SIGIL" plugin inspect "$SCRATCH/package/plugin.toml" >"$SCRATCH/inspect.txt"
grep -F 'sigil:sql/driver@0.2.0' "$SCRATCH/inspect.txt" >/dev/null
grep -F '[method]connection.exec' "$SCRATCH/inspect.txt" >/dev/null
grep -F 'requested capabilities: network, secrets, entropy' "$SCRATCH/inspect.txt" >/dev/null

"$SIGIL" plugin pack "$SCRATCH/package/plugin.toml" \
  --output-dir "$SCRATCH/package/dist"
archive="$SCRATCH/package/dist/mysql-0.2.1.sigil-plugin.tar.zst"
test -f "$archive"
"$SIGIL" plugin validate "$archive"

mkdir -p "$SCRATCH/seeder/src"
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
    "$SCRATCH/data" "$archive" "$SOURCE" mysql 0.2.1 mysql-conformance-0.2.1

mkdir -p "$SCRATCH/project/.sigil" "$SCRATCH/project/scenarios"
cp "$ROOT/conformance/sigil.toml" "$SCRATCH/project/.sigil/sigil.toml"
cp "$ROOT/conformance/mysql-v02.sigil.lua" \
  "$SCRATCH/project/scenarios/mysql-v02.lua"

run_sigil plugin lock >/dev/null
stub="$SCRATCH/project/.sigil/types/wasm/mysql.lua"
test -f "$stub"
grep -F '["query"]' "$stub" >/dev/null
grep -F '["exec"]' "$stub" >/dev/null

ready="$SCRATCH/mysql.port"
python3 "$ROOT/scripts/mock-mysql.py" "$ready" >"$SCRATCH/mysql.log" 2>&1 &
server_pid=$!
for _attempt in $(seq 1 100); do
  [[ -s "$ready" ]] && break
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$SCRATCH/mysql.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$ready" ]]; then
  echo "mock MySQL server did not become ready" >&2
  exit 1
fi
port="$(<"$ready")"

if ! MYSQL_USER=root MYSQL_PASSWORD=secret \
  run_sigil run scenarios/mysql-v02.lua \
    --endpoint "database=http://127.0.0.1:$port" \
    --env MYSQL_USER --env MYSQL_PASSWORD --json >"$SCRATCH/run.json"; then
  python3 -m json.tool "$SCRATCH/run.json" >&2 || true
  cat "$SCRATCH/mysql.log" >&2
  exit 1
fi

python3 - "$SCRATCH/run.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["status"] != "passed" or report["total"] != 1 or report["failed"] != 0:
    raise SystemExit(f"MySQL compatibility scenario failed: {report!r}")
PY

wait "$server_pid"
server_pid=""
test ! -s "$SCRATCH/mysql.log"
echo "real MySQL component and Lua bridge compatibility passed"
