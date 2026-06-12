#!/usr/bin/env bash
# Fast fail-closed checks for validation-lane metadata before display output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="validation-lane-metadata-smoke"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mneme-validation-lane-metadata.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fixture_dir="$scratch/scripts/ci"
mkdir -p "$fixture_dir"
cp scripts/ci/lib.sh "$fixture_dir/lib.sh"

make_fixture() {
  local fixture="$1"
  local validation_lanes="$2"

  sed "s/^VALIDATION_LANES=.*/VALIDATION_LANES=$validation_lanes/" \
    scripts/ci/validation-lane.sh > "$fixture"
  chmod +x "$fixture"
}

expect_metadata_failure() {
  local name="$1"
  local expected_fragment="$2"
  local fixture="$3"
  shift 3

  local output status
  set +e
  output="$(bash "$fixture" "$@" 2>&1)"
  status=$?
  set -e

  require_exit_status "$label" "$status" "1" "$output"
  require_exact_line "$label" "$output" "$expected_fragment"
  require_line_count "$label" "$output" "1"
  require_absent_substring "$label" "$output" "Usage: scripts/ci/validation-lane.sh"
  require_absent_substring "$label" "$output" "Unknown lane:"
}

duplicate_lane_fixture="$fixture_dir/duplicate-validation-lane.sh"
invalid_lane_fixture="$fixture_dir/invalid-validation-lane.sh"
missing_sentinel_fixture="$fixture_dir/missing-sentinel-validation-lane.sh"
first_sentinel_fixture="$fixture_dir/first-sentinel-validation-lane.sh"

make_fixture "$duplicate_lane_fixture" "(quick quick full-preflight full)"
make_fixture "$invalid_lane_fixture" "(quick BAD full-preflight full)"
make_fixture "$missing_sentinel_fixture" "(quick crypto full)"
make_fixture "$first_sentinel_fixture" "(full-preflight full)"

expect_metadata_failure "duplicate --list lane metadata" \
  "MNEME validation-lane metadata invalid: duplicate VALIDATION_LANES token: quick" \
  "$duplicate_lane_fixture" --list

expect_metadata_failure "invalid --help lane metadata" \
  "MNEME validation-lane metadata invalid: invalid VALIDATION_LANES token: BAD" \
  "$invalid_lane_fixture" --help

expect_metadata_failure "missing sentinel unknown-lane metadata" \
  "MNEME validation-lane metadata invalid: VALIDATION_LANES missing full-preflight sentinel" \
  "$missing_sentinel_fixture" __mneme_unknown_lane__

expect_metadata_failure "empty sublane plan metadata" \
  "MNEME validation-lane metadata invalid: VALIDATION_LANES produced no full sublanes" \
  "$first_sentinel_fixture" --list

echo "validation-lane-metadata-smoke: OK"
