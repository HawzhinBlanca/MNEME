#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
echo "MNEME Phase IV cost report — PIOP prover NOT_MEASURED"
if [[ "${MNEME_P4_RUN_FLAT_BENCH:-1}" == "1" && -f scripts/piop-flat-prototype/Cargo.toml ]]; then
  (cd scripts/piop-flat-prototype && cargo run --release --quiet --bin piop-flat-microbench) || echo piop_flat_status=BUILD_FAILED
fi
echo "phase-iv-cost-report: OK" >&2
