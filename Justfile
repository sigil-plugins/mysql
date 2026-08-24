set shell := ["bash", "-euo", "pipefail", "-c"]

wasm_tools := env_var_or_default("WASM_TOOLS", "wasm-tools")
python := env_var_or_default("PYTHON", "python3")

build:
    root="$(pwd -P)"; cargo_home="${CARGO_HOME:-$HOME/.cargo}"; rustflags="${RUSTFLAGS:-} --remap-path-prefix=${root}=/workspace --remap-path-prefix=${cargo_home}=/cargo"; RUSTFLAGS="${rustflags# }" cargo build --release --target wasm32-unknown-unknown --locked
    {{wasm_tools}} component new target/wasm32-unknown-unknown/release/sigil_plugin_mysql.wasm -o plugin.wasm
    {{wasm_tools}} validate --features all plugin.wasm
    {{wasm_tools}} component targets wit --world sigil:mysql/mysql@0.1.0 plugin.wasm

sdk-drift:
    ./scripts/check-sdk-lock.sh

check: sdk-drift
    cargo fmt --all -- --check
    cargo test --locked
    cargo clippy --all-targets --locked -- -D warnings
    just build

dist: check
    {{python}} scripts/pack.py plugin.toml dist

release-dist source_commit: check
    {{python}} scripts/pack.py plugin.toml dist --source-commit "{{source_commit}}"

reproducible:
    ./scripts/reproducible.sh
