#!/usr/bin/env bash
# Fast self-smoke for the shared smoke assertion helpers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="smoke-assertions-smoke"
sample_output=$'alpha\nbeta'

expect_failure() {
  local name="$1"
  local expected_fragment="$2"
  shift 2

  local stderr status
  set +e
  stderr="$("$@" 2>&1 >/dev/null)"
  status=$?
  set -e

  if [[ "$status" != "1" ]]; then
    echo "$label: $name expected exit status 1, got $status" >&2
    printf '%s\n' "$stderr" >&2
    exit 1
  fi

  if ! grep -Fq -- "$expected_fragment" <<<"$stderr"; then
    echo "$label: $name missing expected stderr fragment:" >&2
    echo "  $expected_fragment" >&2
    echo "$label: $name actual stderr:" >&2
    printf '%s\n' "$stderr" >&2
    exit 1
  fi
}

require_exact_line "$label" "$sample_output" "alpha"
require_exact_output "$label" "$sample_output" "$sample_output"
require_absent_substring "$label" "$sample_output" "gamma"
require_line_count "$label" "$sample_output" "2"
require_exit_status "$label" "2" "2" "$sample_output"

expect_failure "missing exact line" \
  "$label: missing expected line:" \
  require_exact_line "$label" "$sample_output" "gamma"

expect_failure "output mismatch" \
  "$label: output mismatch" \
  require_exact_output "$label" "$sample_output" $'beta\nalpha'

expect_failure "forbidden substring" \
  "$label: forbidden output found: beta" \
  require_absent_substring "$label" "$sample_output" "beta"

expect_failure "line count mismatch" \
  "$label: expected exactly 3 output lines, got 2" \
  require_line_count "$label" "$sample_output" "3"

expect_failure "exit status mismatch" \
  "$label: expected exit status 2, got 1" \
  require_exit_status "$label" "1" "2" "$sample_output"

echo "smoke-assertions-smoke: OK"
