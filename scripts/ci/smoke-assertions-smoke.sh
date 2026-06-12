#!/usr/bin/env bash
# Fast self-smoke for the shared smoke assertion helpers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="smoke-assertions-smoke"
sample_output=$'alpha\nbeta'
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mneme-smoke-assertions.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
sentinel_target="$scratch/cargo-target"

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

lane_choices="$(validation_lane_choices_from_source "$label")"
target_lane_choices="$(validation_lane_choices_for_target "$label" "$sentinel_target")"
require_exact_output "$label" "$target_lane_choices" "$lane_choices"
full_sublanes="$(validation_lane_sublanes_before "$label" "$lane_choices" "full-preflight")"
require_exact_output "$label" "$full_sublanes" "quick crypto tamper merge determinism bounds p3-local"

multiline_lane_list="$scratch/multiline-lane-list.sh"
printf '%s\n' "printf '%s\n' 'quick|full-preflight' 'full'" > "$multiline_lane_list"

invalid_token_lane_list="$scratch/invalid-token-lane-list.sh"
printf '%s\n' "printf '%s\n' 'quick||full-preflight'" > "$invalid_token_lane_list"

underscore_runtime_lane_list="$scratch/underscore-runtime-lane-list.sh"
printf '%s\n' "printf '%s\n' 'quick|bad_lane|full-preflight'" > "$underscore_runtime_lane_list"

duplicate_runtime_lane_list="$scratch/duplicate-runtime-lane-list.sh"
printf '%s\n' "printf '%s\n' 'quick|quick|full-preflight'" > "$duplicate_runtime_lane_list"

malformed_validation_lane="$scratch/malformed-validation-lane.sh"
printf '%s\n' 'VALIDATION_LANES=quick crypto' > "$malformed_validation_lane"

duplicate_validation_lane="$scratch/duplicate-validation-lane.sh"
{
  printf '%s\n' 'VALIDATION_LANES=(quick full-preflight full)'
  printf '%s\n' 'VALIDATION_LANES=(quick full)'
} > "$duplicate_validation_lane"

empty_token_validation_lane="$scratch/empty-token-validation-lane.sh"
printf '%s\n' 'VALIDATION_LANES=(quick  full-preflight full)' > "$empty_token_validation_lane"

underscore_token_validation_lane="$scratch/underscore-token-validation-lane.sh"
printf '%s\n' 'VALIDATION_LANES=(quick bad_lane full-preflight full)' > "$underscore_token_validation_lane"

duplicate_token_validation_lane="$scratch/duplicate-token-validation-lane.sh"
printf '%s\n' 'VALIDATION_LANES=(quick quick full-preflight full)' > "$duplicate_token_validation_lane"

if [[ -e "$sentinel_target" ]]; then
  echo "$label: lane helper created target dir" >&2
  exit 1
fi

expect_failure "malformed validation lane source" \
  "$label: cannot parse VALIDATION_LANES" \
  validation_lane_choices_from_source "$label" "$malformed_validation_lane"

expect_failure "duplicate validation lane source" \
  "$label: expected exactly one VALIDATION_LANES declaration" \
  validation_lane_choices_from_source "$label" "$duplicate_validation_lane"

expect_failure "empty validation lane token" \
  "$label: invalid VALIDATION_LANES tokens" \
  validation_lane_choices_from_source "$label" "$empty_token_validation_lane"

expect_failure "underscore validation lane token" \
  "$label: invalid VALIDATION_LANES tokens" \
  validation_lane_choices_from_source "$label" "$underscore_token_validation_lane"

expect_failure "duplicate validation lane token" \
  "$label: duplicate VALIDATION_LANES token: quick" \
  validation_lane_choices_from_source "$label" "$duplicate_token_validation_lane"

expect_failure "multi-line target lane choices" \
  "$label: expected exactly 1 output lines, got 2" \
  validation_lane_choices_for_target "$label" "$sentinel_target" "$multiline_lane_list"

expect_failure "invalid target lane choices" \
  "$label: invalid validation lane choices: quick||full-preflight" \
  validation_lane_choices_for_target "$label" "$sentinel_target" "$invalid_token_lane_list"

expect_failure "underscore target lane choice" \
  "$label: invalid validation lane choices: quick|bad_lane|full-preflight" \
  validation_lane_choices_for_target "$label" "$sentinel_target" "$underscore_runtime_lane_list"

expect_failure "duplicate target lane choices" \
  "$label: duplicate validation lane choice: quick" \
  validation_lane_choices_for_target "$label" "$sentinel_target" "$duplicate_runtime_lane_list"

expect_failure "invalid sublane choices" \
  "$label: invalid validation lane choices: quick||full-preflight" \
  validation_lane_sublanes_before "$label" "quick||full-preflight" "full-preflight"

expect_failure "duplicate sublane choices" \
  "$label: duplicate validation lane choice: quick" \
  validation_lane_sublanes_before "$label" "quick|quick|full-preflight" "full-preflight"

expect_failure "missing full-preflight sentinel" \
  "$label: quick|full did not produce full-preflight sentinel" \
  validation_lane_sublanes_before "$label" "quick|full" "full-preflight"

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
