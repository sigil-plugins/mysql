#!/usr/bin/env bash
set -euo pipefail

root="$(pwd -P)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
version="$(python3 -c 'import tomllib; print(tomllib.load(open("plugin.toml", "rb"))["version"])')"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "plugin.toml version is not canonical SemVer" >&2
  exit 1
fi
rustflags="${RUSTFLAGS:-} --remap-path-prefix=${root}=/workspace --remap-path-prefix=${cargo_home}=/cargo"
rustflags="${rustflags# }"
temporary="$(mktemp -d)"
if [[ -z "$temporary" || ! -d "$temporary" || -L "$temporary" ]]; then
  echo "failed to create an isolated temporary directory" >&2
  exit 1
fi
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

for run in one two; do
  CARGO_TARGET_DIR="$temporary/target-$run" RUSTFLAGS="$rustflags" \
    cargo build --release --target wasm32-unknown-unknown --locked
  wasm-tools component new \
    "$temporary/target-$run/wasm32-unknown-unknown/release/sigil_plugin_mysql.wasm" \
    -o "$temporary/plugin-$run.wasm"
done

cmp --silent "$temporary/plugin-one.wasm" "$temporary/plugin-two.wasm"
if wasm-tools print "$temporary/plugin-one.wasm" | grep -F -e "$root" -e "$cargo_home" >/dev/null; then
  echo "component contains a host-specific source path" >&2
  exit 1
fi
sha256sum "$temporary/plugin-one.wasm" "$temporary/plugin-two.wasm"
for run in one two; do
  mkdir "$temporary/source-$run"
  cp plugin.toml "$temporary/source-$run/plugin.toml"
  cp "$temporary/plugin-$run.wasm" "$temporary/source-$run/plugin.wasm"
  python3 scripts/pack.py \
    "$temporary/source-$run/plugin.toml" \
    "$temporary/dist-$run" >/dev/null
done
cmp --silent \
  "$temporary/dist-one/mysql-${version}.sigil-plugin.tar.zst" \
  "$temporary/dist-two/mysql-${version}.sigil-plugin.tar.zst"
sha256sum "$temporary/dist-one/mysql-${version}.sigil-plugin.tar.zst" \
  "$temporary/dist-two/mysql-${version}.sigil-plugin.tar.zst"
test "$root" = "$(pwd -P)"
echo "two isolated component builds and repeated canonical packages are byte-identical"
