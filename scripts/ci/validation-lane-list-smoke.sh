#!/usr/bin/env bash
# Fast executable contract check for validation-lane --list.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="validation-lane-list-smoke"
expected_output="quick|crypto|tamper|merge|determinism|full-preflight|full"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mneme-validation-lane-list.XXXXXX")"
sentinel_target="$scratch/cargo-target"

cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT

output="$(CARGO_TARGET_DIR="$sentinel_target" bash scripts/ci/validation-lane.sh --list)"

require_exact_output "$label" "$output" "$expected_output"
require_line_count "$label" "$output" "1"

if [[ -e "$sentinel_target" ]]; then
  echo "validation-lane-list-smoke: --list created target dir: $sentinel_target" >&2
  exit 1
fi

echo "validation-lane-list-smoke: OK"
