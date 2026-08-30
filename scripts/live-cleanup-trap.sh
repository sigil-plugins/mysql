#!/usr/bin/env bash

# Shared trap dispatcher for live acceptance. The caller supplies one cleanup
# callback accepting the requested exit status and returning the final status.

sigil_cleanup_started=0
sigil_cleanup_callback=

sigil_dispatch_cleanup() {
  local requested_status=$1
  if [[ "$sigil_cleanup_started" -ne 0 ]]; then
    return 0
  fi
  sigil_cleanup_started=1

  # EXIT must not dispatch a second time, and a second signal must not
  # interrupt resource cleanup half-way through.
  trap - EXIT
  trap '' INT TERM
  set +e
  "$sigil_cleanup_callback" "$requested_status"
  local final_status=$?
  exit "$final_status"
}

sigil_install_cleanup_traps() {
  if [[ $# -ne 1 ]] || ! declare -F "$1" >/dev/null; then
    echo "cleanup trap requires one callback function" >&2
    return 2
  fi
  sigil_cleanup_callback=$1
  trap 'sigil_dispatch_cleanup "$?"' EXIT
  trap 'sigil_dispatch_cleanup 130' INT
  trap 'sigil_dispatch_cleanup 143' TERM
}
