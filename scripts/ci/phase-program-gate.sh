#!/usr/bin/env bash
# MNEME phase program gate (Phase I–IV scaffolding).
# Usage:
#   PHASE_GATE_LEVEL=quick|tamper|full scripts/ci/phase-program-gate.sh
# Behavior:
#   * Prints checklists from the Phase specs + phase-program manifest (if present)
#   * Runs staged validation lanes: quick → tamper → full (selected via PHASE_GATE_LEVEL)
#   * Runs Phase I targeted tests: zkANN, cognition certificate, bi-temporal recall,
#     provenance-scoped recall, CLI certify/verify, crossref cognition cert vectors
#   * Exits non-zero on any failure with a clear phase label
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-phase-gate}"

LEVEL="${PHASE_GATE_LEVEL:-quick}"
SPEC_PHASE_I="$ROOT/docs/PHASE_I_TASK_SPEC.md"
SPEC_PHASE_II="$ROOT/docs/PHASE_II_TASK_SPEC.md"
SPEC_PHASE_III="$ROOT/docs/PHASE_III_TASK_SPEC.md"
MANIFEST="$ROOT/docs/phase-program/manifest.yaml"

section() {
  echo
  echo "=== $1 ==="
}

print_checkboxes() {
  local file="$1"
  local label="$2"
  if [[ -f "$file" ]]; then
    section "$label checklist ($file)"
    grep -n "^- \\[.*\\]" "$file" || echo "(no checkboxes found)"
  else
    echo "WARN: checklist file missing: $file" >&2
  fi
}

print_manifest() {
  if [[ -f "$MANIFEST" ]]; then
    section "Phase-program manifest ($MANIFEST)"
    awk '/^phase:/ {phase=$0} /^id:/ {id=$0} /^status:/ {status=$0} /^evidence:/ {print phase; print id; print status; print "evidence:"; next} {if ($0 ~ /^  - path:/) print $0}' "$MANIFEST" || cat "$MANIFEST"
  else
    echo "NOTE: manifest not found at $MANIFEST (create it to record evidence)."
  fi
}

run_step() {
  local label="$1"
  shift
  echo
  echo ">>> $label"
  if "$@"; then
    echo ">>> $label: OK"
  else
    echo ">>> $label: FAIL" >&2
    exit 1
  fi
}

run_validation_lane() {
  local lane="$1"
  run_step "validation-lane ($lane)" bash scripts/ci/validation-lane.sh "$lane"
}

run_phase_one_targets() {
  section "Phase I targeted tests"
  run_step "zkANN dominance + audit (mneme-index, pedersen_schnorr_zk)" \
    cargo test -p mneme-index --features pedersen_schnorr_zk -- zkann --nocapture
  run_step "Cognition certificate (mneme-index)" \
    cargo test -p mneme-index --features pedersen_schnorr_zk -- cognition_cert --nocapture
  run_step "Bi-temporal recall (mneme-store recall_verified_at)" \
    cargo test -p mneme-store recall_verified_at -- --nocapture
  run_step "Provenance-scoped recall (mneme-store provenance_scoped)" \
    cargo test -p mneme-store provenance_scoped -- --nocapture
  run_step "CLI certify (mneme-cli)" \
    cargo test -p mneme-cli certify -- --nocapture
  run_step "CLI verify-cert (mneme-cli)" \
    cargo test -p mneme-cli verify_cert -- --nocapture
  run_step "Crossref cognition cert vectors" \
    bash scripts/ci/cross-implementation-vectors.sh
}

run_phase_two_three_four_redteam() {
  section "Phase II/III/IV red-team (new surfaces)"
  run_step "Output binding forgery (mneme-core + mneme-gate)" \
    bash -c 'cargo test -p mneme-core output:: -- --nocapture && cargo test -p mneme-gate forgery -- --nocapture'
  run_step "Phase II strict context gate (context_gate feature)" \
    bash -c 'cargo test -p mneme-gate gate_closed_by_default -- --nocapture && cargo test -p mneme-index --features context_gate cognition_cert_v2_strict -- --nocapture && cargo test -p mneme-store --features context_gate --test phase_ii_context_gate -- --nocapture'
  run_step "ActionReceipt + ForgetProof (mneme-account, phase_iii_verify + gate-off)" \
    bash -c 'cargo test -p mneme-account --features phase_iii_verify redteam -- --nocapture && cargo test -p mneme-account --features phase_iii_verify redteam_forget -- --nocapture && cargo test -p mneme-account --features phase_iii_verify --test prove_forget -- --nocapture && cargo test -p mneme-account --features phase_iii_bind_action --test bind_action -- --nocapture && cargo test -p mneme-account --test fail_closed -- --nocapture'
  run_step "Store bind_external_action (gate-off + phase_iii_bind)" \
    bash -c 'cargo test -p mneme-store --test phase_iii_bind bind_external_action_fail_closed -- --nocapture && cargo test -p mneme-store --features phase_iii_bind --test phase_iii_bind -- --nocapture'
  run_step "Store mandatory ActionReceipt policy (phase_iii_require_action)" \
    cargo test -p mneme-store --features phase_iii_bind,phase_iii_require_action --test phase_iii_policy -- --nocapture
  run_step "Store ForgetProof on forget (phase_iii_prove_forget)" \
    cargo test -p mneme-store --features phase_iii_prove_forget --test phase_iii_forget -- --nocapture
  run_step "MCP ActionReceipt bind (phase_iii_bind)" \
    cargo test -p mneme-mcp --features phase_iii_bind --test phase_iii_mcp -- --nocapture
  run_step "Federation cert forgery (mneme-index)" \
    cargo test -p mneme-index forgery -- --nocapture
}

section "Phase program gate (level=$LEVEL)"
print_checkboxes "$SPEC_PHASE_I" "Phase I"
print_checkboxes "$SPEC_PHASE_II" "Phase II"
print_checkboxes "$SPEC_PHASE_III" "Phase III"
print_manifest

case "$LEVEL" in
  quick)
    run_validation_lane quick
    ;;
  tamper)
    run_validation_lane quick
    run_validation_lane tamper
    ;;
  full)
    run_validation_lane full
    ;;
  *)
    echo "Unknown PHASE_GATE_LEVEL: $LEVEL (expected quick|tamper|full)" >&2
    exit 2
    ;;
esac

run_phase_one_targets

run_phase_two_three_four_redteam

echo
echo "phase-program-gate ($LEVEL): OK"
