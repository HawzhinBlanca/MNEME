#!/usr/bin/env bash
# Fast fail-closed contract check for validation-lane unknown-lane handling.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="validation-lane-unknown-smoke"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mneme-validation-lane-unknown.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

sentinel_target="$scratch/cargo-target"

set +e
output="$(CARGO_TARGET_DIR="$sentinel_target" bash scripts/ci/validation-lane.sh __mneme_unknown_lane__ 2>&1)"
status=$?
set -e

expected="Unknown lane: __mneme_unknown_lane__ (expected quick|crypto|tamper|merge|determinism|full-preflight|full)"

require_exit_status "$label" "$status" "2" "$output"
require_exact_line "$label" "$output" "$expected"
require_line_count "$label" "$output" "1"

if [[ -e "$sentinel_target" ]]; then
  echo "validation-lane-unknown-smoke: unknown lane created target dir" >&2
  exit 1
fi

echo "validation-lane-unknown-smoke: OK"
