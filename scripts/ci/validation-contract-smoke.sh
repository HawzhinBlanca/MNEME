#!/usr/bin/env bash
# Aggregate cheap validation-lane contract checks for the quick lane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

bash scripts/ci/smoke-assertions-smoke.sh
bash scripts/ci/full-preflight-smoke.sh
bash scripts/ci/validation-lane-unknown-smoke.sh

echo "validation-contract-smoke: OK"
