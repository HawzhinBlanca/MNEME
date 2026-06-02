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

append_e2e_filter() {
  local log_path="$1"
  local filter="$2"
  {
    echo "--- filter: $filter ---"
    RUST_TEST_THREADS=1 cargo test -p mneme-store --test e2e "$filter" -- --nocapture
    echo
  } 2>&1 | tee -a "$log_path"
}

echo "==> §21 killer demo — build check"
if ! cargo check -p mneme-store --quiet 2>/dev/null; then
  echo "killer-demo: mneme-store does not build — demo cannot run (§21 acceptance artifact blocked)." >&2
  exit 1
fi

echo "==> §21 narrative + store kernel checks"
{
  echo "==> §21 killer demo transcript"
  echo "    Agent-A: conventional vector-DB (helpers::ConventionalVectorDb)"
  echo "    Agent-B: MNEME recall_verified fail-closed kernel"
  echo "    started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
} >"$DEMO_LOG"

for filter in \
  killer_demo_agent_a_vs_agent_b \
  e2e_killer_demo_storage_tamper_rejected_at_read \
  e2e_quarantine_entry_blocked_from_trusted_recall \
  e2e_promote_requires_promote_capability; do
  append_e2e_filter "$DEMO_LOG" "$filter"
done

echo "==> bypass attempts"
{
  echo "==> §21 bypass attempts"
  echo "    started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
} >"$BYPASS_LOG"
append_e2e_filter "$BYPASS_LOG" e2e_bypass_

echo
echo "killer-demo: OK (§21 Agent-A vs Agent-B + A-DB/A-INJ + bypass harness)"
echo "  transcript: $DEMO_LOG"
echo "  bypass:     $BYPASS_LOG"
