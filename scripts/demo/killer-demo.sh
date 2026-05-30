#!/usr/bin/env bash
# §21 killer demo — offline, M4 Max / local-first.
#
# Two-agent narrative (blueprint §21):
#   Agent-A: conventional vector-DB memory (no integrity / no tiers)
#   Agent-B: MNEME store kernel (fail-closed recall_verified)
#   A-DB: storage tamper — A obeys, B rejects with ObjectTampered
#   A-INJ: tool poison — A obeys, B blocks at min_tier=Trusted
#
# Artifacts:
#   out/demo/12-killer-demo.log   — §21 narrative transcript
#   out/demo/14-killer-bypass.log — bypass attempt matrix
#
# Usage: scripts/demo/killer-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
mneme_ci_init "$ROOT" demo-killer

DEMO_LOG="${MNEME_KILLER_DEMO_LOG:-$ROOT/out/demo/12-killer-demo.log}"
BYPASS_LOG="${MNEME_KILLER_BYPASS_LOG:-$ROOT/out/demo/14-killer-bypass.log}"
mkdir -p "$(dirname "$DEMO_LOG")" "$(dirname "$BYPASS_LOG")"

run_demo_tests() {
  local filter="$1"
  local log_path="$2"
  : >"$log_path"
  {
    echo "==> §21 killer demo (offline store kernel)"
    echo "    Agent-A: conventional vector-DB (helpers::ConventionalVectorDb)"
    echo "    Agent-B: MNEME recall_verified fail-closed kernel"
    echo "    filter: $filter"
    echo "    started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    RUST_TEST_THREADS=1 cargo test -p mneme-store --test e2e "$filter" -- --nocapture
  } 2>&1 | tee -a "$log_path"
}

echo "==> §21 killer demo — build check"
if ! cargo check -p mneme-store --quiet 2>/dev/null; then
  echo "killer-demo: mneme-store does not build — demo cannot run (§21 acceptance artifact blocked)." >&2
  exit 1
fi

echo "==> §21 narrative (Agent-A vs Agent-B)"
run_demo_tests "killer_demo_agent_a_vs_agent_b" "$DEMO_LOG"
run_demo_tests "e2e_killer_demo_storage_tamper_rejected_at_read" "$DEMO_LOG"
run_demo_tests "e2e_quarantine_entry_blocked_from_trusted_recall" "$DEMO_LOG"
run_demo_tests "e2e_promote_requires_promote_capability" "$DEMO_LOG"

echo "==> bypass attempts"
run_demo_tests "e2e_bypass_" "$BYPASS_LOG"

echo
echo "killer-demo: OK (§21 Agent-A vs Agent-B + A-DB/A-INJ + bypass harness)"
echo "  transcript: $DEMO_LOG"
echo "  bypass:     $BYPASS_LOG"
