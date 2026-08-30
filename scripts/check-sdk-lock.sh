#!/usr/bin/env bash
set -euo pipefail

repository="$(sed -n 's/^repository = "\([^"]*\)"$/\1/p' SDK.lock)"
commit="$(sed -n 's/^commit = "\([0-9a-f]*\)"$/\1/p' SDK.lock)"
expected_host="$(sed -n 's/^host_wit_sha256 = "\([0-9a-f]*\)"$/\1/p' SDK.lock)"
expected_sql="$(sed -n 's/^sql_wit_sha256 = "\([0-9a-f]*\)"$/\1/p' SDK.lock)"

if [[ -n "${SDK_CHECKOUT:-}" ]]; then
  checkout="$SDK_CHECKOUT"
  temporary=""
else
  temporary="$(mktemp -d)"
  checkout="$temporary/sdk"
  git clone --quiet "https://github.com/${repository#github:}.git" "$checkout"
  git -C "$checkout" checkout --quiet --detach "$commit"
fi

cleanup() {
  if [[ -n "$temporary" && -d "$temporary" && ! -L "$temporary" ]]; then
    rm -rf -- "$temporary"
  fi
}
trap cleanup EXIT

test "$(git -C "$checkout" rev-parse HEAD)" = "$commit"
echo "$expected_host  $checkout/wit/sigil-host/1.0.0/host.wit" | sha256sum --check --strict
echo "$expected_sql  $checkout/wit/sigil-sql/0.2.0/sql.wit" | sha256sum --check --strict
cmp --silent "$checkout/wit/sigil-host/1.0.0/host.wit" wit/deps/sigil-host/host.wit
cmp --silent "$checkout/wit/sigil-sql/0.2.0/sql.wit" wit/deps/sigil-sql/sql.wit
echo "SDK revision and vendored WIT are exact"
