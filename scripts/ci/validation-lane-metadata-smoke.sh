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
fixture_target_dir="$scratch/cargo-target"
fixture_lib_marker="$scratch/fixture-lib-sourced"
mkdir -p "$fixture_dir"

install_fixture_lib() {
  cp scripts/ci/lib.sh "$fixture_dir/lib.sh"
  cat >> "$fixture_dir/lib.sh" <<'EOF'
if [[ -n "${MNEME_VALIDATION_LANE_FIXTURE_LIB_MARKER:-}" ]]; then
  printf '%s\n' "${BASH_SOURCE[0]}" > "$MNEME_VALIDATION_LANE_FIXTURE_LIB_MARKER"
fi
EOF
}

require_fixture_lib_sourced() {
  local output="$1"

  if [[ ! -f "$fixture_lib_marker" ]]; then
    echo "$label: fixture did not source copied lib.sh" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  require_exact_output "$label" "$(cat "$fixture_lib_marker")" "$fixture_dir/lib.sh"
}

install_fixture_lib

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
  rm -rf "$fixture_target_dir"
  rm -f "$fixture_lib_marker"
  set +e
  output="$(CARGO_TARGET_DIR="$fixture_target_dir" MNEME_VALIDATION_LANE_FIXTURE_LIB_MARKER="$fixture_lib_marker" bash "$fixture" "$@" 2>&1)"
  status=$?
  set -e

  require_fixture_lib_sourced "$output"
  if [[ -e "$fixture_target_dir" ]]; then
    echo "$label: $name created CARGO_TARGET_DIR during metadata rejection" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  require_exit_status "$label" "$status" "1" "$output"
  require_exact_line "$label" "$output" "$expected_fragment"
  require_line_count "$label" "$output" "1"
  require_absent_substring "$label" "$output" "Usage: scripts/ci/validation-lane.sh"
  require_absent_substring "$label" "$output" "Unknown lane:"
}

duplicate_lane_fixture="$fixture_dir/duplicate-validation-lane.sh"
invalid_lane_fixture="$fixture_dir/invalid-validation-lane.sh"
underscore_lane_fixture="$fixture_dir/underscore-validation-lane.sh"
missing_sentinel_fixture="$fixture_dir/missing-sentinel-validation-lane.sh"
first_sentinel_fixture="$fixture_dir/first-sentinel-validation-lane.sh"
empty_lanes_fixture="$fixture_dir/empty-validation-lane.sh"

make_fixture "$duplicate_lane_fixture" "(quick quick full-preflight full)"
make_fixture "$invalid_lane_fixture" "(quick BAD full-preflight full)"
make_fixture "$underscore_lane_fixture" "(quick bad_lane full-preflight full)"
make_fixture "$missing_sentinel_fixture" "(quick crypto full)"
make_fixture "$first_sentinel_fixture" "(full-preflight full)"
make_fixture "$empty_lanes_fixture" "()"

expect_metadata_failure "empty lane metadata" \
  "MNEME validation-lane metadata invalid: VALIDATION_LANES is empty" \
  "$empty_lanes_fixture" --list

expect_metadata_failure "duplicate --list lane metadata" \
  "MNEME validation-lane metadata invalid: duplicate VALIDATION_LANES token: quick" \
  "$duplicate_lane_fixture" --list

expect_metadata_failure "invalid --help lane metadata" \
  "MNEME validation-lane metadata invalid: invalid VALIDATION_LANES token: BAD" \
  "$invalid_lane_fixture" --help

expect_metadata_failure "underscore token lane metadata" \
  "MNEME validation-lane metadata invalid: invalid VALIDATION_LANES token: bad_lane" \
  "$underscore_lane_fixture" --list

expect_metadata_failure "missing sentinel unknown-lane metadata" \
  "MNEME validation-lane metadata invalid: VALIDATION_LANES missing full-preflight sentinel" \
  "$missing_sentinel_fixture" __mneme_unknown_lane__

expect_metadata_failure "empty sublane plan metadata" \
  "MNEME validation-lane metadata invalid: VALIDATION_LANES produced no full sublanes" \
  "$first_sentinel_fixture" --list

echo "validation-lane-metadata-smoke: OK"
