#!/usr/bin/env bash
# Fast non-executing contract check for validation-lane list output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="validation-lane-list-smoke"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mneme-validation-lane-list.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

sentinel_target="$scratch/cargo-target"

output="$(CARGO_TARGET_DIR="$sentinel_target" bash scripts/ci/validation-lane.sh --list)"
expected_output="$(validation_lane_choices_from_source "$label")"

require_exact_output "$label" "$output" "$expected_output"
require_line_count "$label" "$output" "1"

if [[ -e "$sentinel_target" ]]; then
  echo "validation-lane-list-smoke: --list created target dir" >&2
  exit 1
fi

echo "validation-lane-list-smoke: OK"
