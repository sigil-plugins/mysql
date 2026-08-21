#!/usr/bin/env bash
set -euo pipefail

root="$(pwd -P)"
temporary="$(mktemp -d)"
if [[ -z "$temporary" || ! -d "$temporary" || -L "$temporary" ]]; then
  echo "failed to create an isolated temporary directory" >&2
  exit 1
fi
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

for run in one two; do
  CARGO_TARGET_DIR="$temporary/target-$run" cargo build --release --target wasm32-unknown-unknown --locked
  wasm-tools component new \
    "$temporary/target-$run/wasm32-unknown-unknown/release/sigil_plugin_mysql.wasm" \
    -o "$temporary/plugin-$run.wasm"
done

cmp --silent "$temporary/plugin-one.wasm" "$temporary/plugin-two.wasm"
sha256sum "$temporary/plugin-one.wasm" "$temporary/plugin-two.wasm"
python3 scripts/pack.py plugin.toml dist >/dev/null
first_package="$(sha256sum dist/mysql-0.1.0-rc.1.sigil-plugin.tar.zst)"
python3 scripts/pack.py plugin.toml dist >/dev/null
test "$first_package" = "$(sha256sum dist/mysql-0.1.0-rc.1.sigil-plugin.tar.zst)"
test "$root" = "$(pwd -P)"
echo "two isolated component builds and repeated canonical packages are byte-identical"
