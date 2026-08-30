#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sigil-live-cleanup-test.XXXXXXXX")"
readonly TEST_ROOT

cleanup_test_root() {
  rm -r -- "$TEST_ROOT"
}
trap cleanup_test_root EXIT

run_case() {
  local mode=$1
  local expected_status=$2
  local case_dir="$TEST_ROOT/$mode"
  mkdir -p "$case_dir"
  : >"$case_dir/container.present"
  : >"$case_dir/volume.present"

  set +e
  PROBE_DIR="$case_dir" PROBE_MODE="$mode" \
  TRAP_LIBRARY="$ROOT/scripts/live-cleanup-trap.sh" \
    bash -c '
      set -euo pipefail
      source "$TRAP_LIBRARY"
      probe_cleanup() {
        local requested_status=$1
        printf "%s\n" "$requested_status" >>"$PROBE_DIR/cleanup-count.txt"
        rm -f -- "$PROBE_DIR/container.present" "$PROBE_DIR/volume.present"
        [[ ! -e "$PROBE_DIR/container.present" ]]
        [[ ! -e "$PROBE_DIR/volume.present" ]]
        return "$requested_status"
      }
      sigil_install_cleanup_traps probe_cleanup
      case "$PROBE_MODE" in
        INT|TERM) kill -s "$PROBE_MODE" "$BASHPID" ;;
        EXIT) exit 37 ;;
        *) exit 98 ;;
      esac
      exit 99
    '
  local actual_status=$?
  set -e

  if [[ "$actual_status" -ne "$expected_status" ]]; then
    echo "$mode cleanup exited $actual_status, expected $expected_status" >&2
    return 1
  fi
  if [[ "$(wc -l <"$case_dir/cleanup-count.txt")" -ne 1 ]]; then
    echo "$mode cleanup did not run exactly once" >&2
    return 1
  fi
  if [[ "$(<"$case_dir/cleanup-count.txt")" != "$expected_status" ]]; then
    echo "$mode cleanup received the wrong status" >&2
    return 1
  fi
  if [[ -e "$case_dir/container.present" || -e "$case_dir/volume.present" ]]; then
    echo "$mode cleanup left a managed resource present" >&2
    return 1
  fi
}

run_case TERM 143
run_case INT 130
run_case EXIT 37
echo "INT, TERM, and ordinary EXIT dispatch cleanup exactly once with exact status"
