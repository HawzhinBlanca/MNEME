#!/usr/bin/env bash
# §21 killer demo — offline, M4 Max / local-first (A-DB storage tamper + A-INJ quarantine).
#
# Runs blueprint-aligned store e2e tests that prove:
#   A-DB: out-of-band storage tamper rejected at read (ObjectTampered)
#   A-INJ: quarantine-tier poison blocked from min_tier=Trusted recall
#
# Usage: scripts/demo/killer-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
mneme_ci_init "$ROOT" demo-killer

echo "==> §21 killer demo (offline store kernel)"
echo "    A-DB path: e2e_killer_demo_storage_tamper_rejected_at_read"
echo "    A-INJ path: e2e_quarantine_entry_blocked_from_trusted_recall"
echo

if ! cargo check -p mneme-store --quiet 2>/dev/null; then
  echo "killer-demo: mneme-store does not build — demo cannot run (§21 acceptance artifact blocked)." >&2
  exit 1
fi

cargo test -p mneme-store --test e2e \
  e2e_killer_demo_storage_tamper_rejected_at_read \
  -- --nocapture
cargo test -p mneme-store --test e2e \
  e2e_quarantine_entry_blocked_from_trusted_recall \
  -- --nocapture
cargo test -p mneme-store --test e2e \
  e2e_promote_requires_promote_capability \
  -- --nocapture

echo
echo "killer-demo: OK (A-DB tamper fail-closed + A-INJ tier gate demonstrated via e2e tests)"
