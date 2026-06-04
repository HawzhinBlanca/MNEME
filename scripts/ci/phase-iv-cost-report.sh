#!/usr/bin/env bash
# Phase IV P4-4 — cost / bench reporting harness (planning only).
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NO PRODUCTION NUMBERS — This script emits a planning report only.          ║
# ║  It does NOT run PIOP provers, does NOT claim SLA compliance, and must not  ║
# ║  be cited as benchmark evidence. Lab numbers belong in Step 4 prototypes.   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   bash scripts/ci/phase-iv-cost-report.sh              # stdout report
#   MNEME_P4_REPORT_DIR=out/p4-cost bash scripts/ci/phase-iv-cost-report.sh
#
# Optional hooks (when implemented):
#   MNEME_P4_RUN_RECALL_BENCH=1  — invoke scripts/ci/bench-recall-optional.sh (Phase I SLA only)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

REPORT_DIR="${MNEME_P4_REPORT_DIR:-}"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

emit() {
  if [[ -n "$REPORT_DIR" ]]; then
    mkdir -p "$REPORT_DIR"
    tee -a "$REPORT_DIR/phase-iv-cost-report.txt"
  else
    cat
  fi
}

{
  echo "MNEME Phase IV — Cost-to-Default Planning Report"
  echo "generated_utc: $STAMP"
  echo "honesty: NO PRODUCTION NUMBERS — planning artifact only"
  echo ""
  echo "## Scope"
  echo "- Target: verified-by-default tier (prove + verify within ~10% of recall SLA — not measured here)."
  echo "- Phase I recall verify bench: scripts/ci/bench-recall-optional.sh (existing; optional hook)."
  echo "- PIOP / global exact-NN: UNIMPLEMENTED (piop_research returns UnsupportedVersion)."
  echo ""
  echo "## Planned measurement slots (fill in Step 4 prototype only)"
  echo "| metric | status | notes |"
  echo "|---|---|---|"
  echo "| piop_prover_secs | NOT_MEASURED | requires out-of-TCB prototype crate |"
  echo "| piop_verifier_secs | NOT_MEASURED | separate verifier; not in mneme-verify TCB |"
  echo "| piop_proof_bytes | NOT_MEASURED | |V|, dim, hardware must be labeled |"
  echo "| recall_verify_10k_ms | OPTIONAL | set MNEME_P4_RUN_RECALL_BENCH=1 to run existing bench |"
  echo "| sidecar_commit_overhead | NOT_MEASURED | commitment-bridge spike (Step 3) |"
  echo ""
  echo "## References"
  echo "- docs/PHASE_IV_TASK_SPEC.md (P4-4)"
  echo "- docs/research/PHASE_IV_A_PIOP_SPIKE.md"
  echo "- docs/research/PHASE_IV_A_PIOP_TOOLCHAIN_MATRIX.md"
} | emit

if [[ "${MNEME_P4_RUN_RECALL_BENCH:-0}" == "1" ]]; then
  echo "" | emit
  echo "## Phase I recall bench hook (not PIOP)" | emit
  bash scripts/ci/bench-recall-optional.sh 2>&1 | emit || true
fi

echo "phase-iv-cost-report: OK (planning report emitted; no production numbers claimed)" >&2
