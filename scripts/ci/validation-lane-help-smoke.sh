#!/usr/bin/env bash
# Fast non-executing contract check for validation-lane help output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="validation-lane-help-smoke"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mneme-validation-lane-help.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

sentinel_target="$scratch/cargo-target"
short_sentinel_target="$scratch/short-cargo-target"

output="$(CARGO_TARGET_DIR="$sentinel_target" bash scripts/ci/validation-lane.sh --help)"
short_output="$(CARGO_TARGET_DIR="$short_sentinel_target" bash scripts/ci/validation-lane.sh -h)"

expected_output="$(cat <<'EOF'
Usage: scripts/ci/validation-lane.sh <quick|crypto|tamper|merge|determinism|full-preflight|full>
       scripts/ci/validation-lane.sh --list
       scripts/ci/validation-lane.sh --help
EOF
)"

require_exact_output "$label" "$output" "$expected_output"
require_exact_output "$label" "$short_output" "$expected_output"
require_line_count "$label" "$output" "3"
require_line_count "$label" "$short_output" "3"

if [[ -e "$sentinel_target" ]]; then
  echo "validation-lane-help-smoke: --help created target dir" >&2
  exit 1
fi

if [[ -e "$short_sentinel_target" ]]; then
  echo "validation-lane-help-smoke: -h created target dir" >&2
  exit 1
fi

echo "validation-lane-help-smoke: OK"
