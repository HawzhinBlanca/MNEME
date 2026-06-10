#!/usr/bin/env bash
# Aggregate cheap validation-lane contract checks for the quick lane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="validation-contract-smoke"
expected_output="$(cat <<'EOF'
smoke-assertions-smoke: OK
validation-lane-list-smoke: OK
validation-lane-help-smoke: OK
ui-server-smoke: OK
full-preflight-smoke: OK
validation-lane-unknown-smoke: OK
EOF
)"

output="$(
  bash scripts/ci/smoke-assertions-smoke.sh
  bash scripts/ci/validation-lane-list-smoke.sh
  bash scripts/ci/validation-lane-help-smoke.sh
  bash scripts/ci/ui-server-smoke.sh
  bash scripts/ci/full-preflight-smoke.sh
  bash scripts/ci/validation-lane-unknown-smoke.sh
)"

require_exact_output "$label" "$output" "$expected_output"
printf '%s\n' "$output"

echo "validation-contract-smoke: OK"
