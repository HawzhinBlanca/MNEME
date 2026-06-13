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

echo "==> Building mneme CLI binary (with optional root_pace_log feature)"
cargo build -p mneme-cli --bin mneme --features root_pace_log
# mneme_ci_init exports CARGO_TARGET_DIR (out/agent-targets/ci-demo-killer); resolve the
# binary from there rather than the default ./target so the demo runs the binary it just
# built (with the feature), not a stale default-target one.
MNEME_BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/mneme"
[[ -x "$MNEME_BIN" ]] || { echo "killer-demo: built binary missing at $MNEME_BIN" >&2; exit 1; }

echo "==> Running end-to-end memory narrative (remember -> recall -> ROBR receipt -> forget+ForgetProof -> hash-chained root pace-log -> Agent Card)"
STORE_DIR="out/demo/store_e2e"
rm -rf "$STORE_DIR"
mkdir -p "out/demo"

# 1. Initialize store
"$MNEME_BIN" init "$STORE_DIR" \
  --operator-seed 1111111111111111111111111111111111111111111111111111111111111111

# 2. Remember memory
"$MNEME_BIN" remember "$STORE_DIR" \
  --namespace user --name "secret-crd" \
  --body "confidential-agent-data" \
  --operator-seed 1111111111111111111111111111111111111111111111111111111111111111

# 3. Recall memory (verified)
"$MNEME_BIN" recall "$STORE_DIR" \
  -q "secret-crd" --key "secret-crd" --namespace user --min-tier trusted \
  --operator-seed 1111111111111111111111111111111111111111111111111111111111111111

# 4. Generate ROBR receipt
echo "recalled confidential agent data successfully" > out/demo/output_tokens.txt
"$MNEME_BIN" robr "$STORE_DIR" \
  --keys "secret-crd" \
  --namespace user \
  --min-tier quarantine \
  --prompt "Retrieve the secret-crd memory" \
  --weight-measurement "0000000000000000000000000000000000000000000000000000000000000099" \
  --sampling "model=gpt-4;temp=0" \
  --output-file out/demo/output_tokens.txt \
  --out out/demo/robr_receipt.bin \
  --operator-seed 1111111111111111111111111111111111111111111111111111111111111111

# 5. Offline verify ROBR receipt
"$MNEME_BIN" verify-robr out/demo/robr_receipt.bin

# 6. Forget the memory, emitting the FCC proof
"$MNEME_BIN" forget "$STORE_DIR" \
  --key "user/secret-crd" \
  --mode shred \
  --emit-proof out/demo/forget_proof.cbor \
  --operator-seed 1111111111111111111111111111111111111111111111111111111111111111

# 7. Verify the hash-chained root pace-log (NOT an RFC6962 transparency log: no
#    inclusion/consistency proofs, single-operator. A derived, rebuildable artifact.)
"$MNEME_BIN" pace verify "$STORE_DIR/meta/root-pace.log"

# 8. Generate A2A Agent Card
"$MNEME_BIN" agent-card "$STORE_DIR" \
  --attestation-endpoint "http://localhost:7845/v1/attest" \
  --out out/demo/agent.jws \
  --operator-seed 1111111111111111111111111111111111111111111111111111111111111111

# 9. Verify Agent Card
"$MNEME_BIN" verify-card out/demo/agent.jws

echo
echo "killer-demo: OK (§21 Agent-A vs Agent-B + A-DB/A-INJ + bypass harness + end-to-end memory narrative)"
echo "  transcript: $DEMO_LOG"
echo "  bypass:     $BYPASS_LOG"

