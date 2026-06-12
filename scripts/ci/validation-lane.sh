#!/usr/bin/env bash
# MNEME validation ladder (blueprint §18).
#
# Usage: scripts/ci/validation-lane.sh <quick|crypto|tamper|merge|determinism|bounds|p3-local|full-preflight|full>
# Fuzz: full → fuzz-meaningful.sh (≥30s/target, 7 targets); quick uses kill-resume only.
#       Standalone smoke: scripts/ci/fuzz-smoke.sh (-runs=16).
# Parallel agents: set CARGO_TARGET_DIR=out/agent-targets/ci-harness (or per-lane default applies).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VALIDATION_LANES=(quick crypto tamper merge determinism bounds p3-local full-preflight full)
VALIDATION_LANE_TOKEN_PATTERN='[a-z0-9][a-z0-9-]*'

validation_lane_metadata_fail_closed() {
  local message="$1"
  echo "MNEME validation-lane metadata invalid: $message" >&2
  exit 1
}

validation_lane_choices() {
  local IFS='|'
  echo "${VALIDATION_LANES[*]}"
}

validate_validation_lanes() {
  local lane
  local seen_lane
  local validation_lane_token_pattern
  local seen_validation_lanes=()
  local saw_full_preflight=0
  local full_sublane_count=0

  if [[ "${#VALIDATION_LANES[@]}" -eq 0 ]]; then
    validation_lane_metadata_fail_closed "VALIDATION_LANES is empty"
  fi

  validation_lane_token_pattern="^${VALIDATION_LANE_TOKEN_PATTERN}$"
  for lane in "${VALIDATION_LANES[@]}"; do
    if [[ ! "$lane" =~ $validation_lane_token_pattern ]]; then
      validation_lane_metadata_fail_closed "invalid VALIDATION_LANES token: $lane"
    fi

    if [[ "${#seen_validation_lanes[@]}" -gt 0 ]]; then
      for seen_lane in "${seen_validation_lanes[@]}"; do
        if [[ "$lane" == "$seen_lane" ]]; then
          validation_lane_metadata_fail_closed "duplicate VALIDATION_LANES token: $lane"
        fi
      done
    fi
    seen_validation_lanes+=("$lane")

    if [[ "$lane" == "full-preflight" ]]; then
      saw_full_preflight=1
    elif [[ "$saw_full_preflight" == "0" ]]; then
      full_sublane_count=$((full_sublane_count + 1))
    fi
  done

  if [[ "$saw_full_preflight" != "1" ]]; then
    validation_lane_metadata_fail_closed "VALIDATION_LANES missing full-preflight sentinel"
  fi
  if [[ "$full_sublane_count" -eq 0 ]]; then
    validation_lane_metadata_fail_closed "VALIDATION_LANES produced no full sublanes"
  fi
}

validation_lane_usage() {
  echo "Usage: scripts/ci/validation-lane.sh <$(validation_lane_choices)>"
  echo "       scripts/ci/validation-lane.sh --list"
  echo "       scripts/ci/validation-lane.sh --help"
}

validation_lane_is_known() {
  local candidate="$1"
  local lane
  for lane in "${VALIDATION_LANES[@]}"; do
    if [[ "$candidate" == "$lane" ]]; then
      return 0
    fi
  done
  return 1
}

validate_validation_lanes

if [[ "${1:-}" == "--list" ]]; then
  validation_lane_choices
  exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  validation_lane_usage
  exit 0
fi

LANE="${1:-quick}"

if ! validation_lane_is_known "$LANE"; then
  echo "Unknown lane: $LANE (expected $(validation_lane_choices))" >&2
  exit 2
fi

fail_closed() {
  local suite="$1"
  local section="$2"
  echo "MNEME validation-lane ($LANE): ${suite} not wired (${section}) — failing closed." >&2
  exit 1
}

FULL_SUBLANES=()
for lane in "${VALIDATION_LANES[@]}"; do
  if [[ "$lane" == "full-preflight" ]]; then
    break
  fi
  FULL_SUBLANES+=("$lane")
done
if [[ "${#FULL_SUBLANES[@]}" -eq 0 ]]; then
  fail_closed "full sublane plan" "VALIDATION_LANES produced no full sublanes"
fi
if [[ "${#FULL_SUBLANES[@]}" -eq "${#VALIDATION_LANES[@]}" ]]; then
  fail_closed "full sublane plan" "VALIDATION_LANES missing full-preflight sentinel"
fi

print_local_cross_host_honesty_boundary() {
  echo "validation-lane ($LANE): Section 17.7 cross-host two-machine determinism is NOT proven by this lane (single host)."
  echo "validation-lane ($LANE): to prove it, set MNEME_SECOND_HOST and run scripts/ci/determinism-two-machine.sh on a distinct physical host."
}

print_full_preflight_plan() {
  echo "validation-lane (full-preflight): planned sublanes: ${FULL_SUBLANES[*]}"
  echo "validation-lane (full-preflight): heavy checks are NOT executed by this lane."
  print_local_cross_host_honesty_boundary
}

run_full_sublanes() {
  local sublane
  for sublane in "${FULL_SUBLANES[@]}"; do
    bash "$0" "$sublane"
  done
}

if [[ "$LANE" != "full-preflight" ]]; then
  mneme_ci_init "$ROOT" "$LANE"
fi

case "$LANE" in
  quick)
    python3 scripts/ci/claims_lint.py
    cargo fmt --all -- --check
    # Wave 0/1 + store kernel on quick lane (§18, §19 v0).
    cargo clippy -p mneme-core -p mneme-crypto -p mneme-smt -p mneme-dag \
      -p mneme-root -p mneme-cap -p mneme-verify -p mneme-store \
      --lib --tests -- -D warnings
    bash scripts/ci/verify-tcb-guard.sh
    cargo test -p mneme-verify --test tcb_budget -- --nocapture
    cargo test -p mneme-core -p mneme-crypto -p mneme-smt -p mneme-dag \
      -p mneme-root -p mneme-cap -p mneme-verify --lib -- --nocapture
    bash scripts/ci/kill-resume-smoke.sh
    bash scripts/ci/mcp-smoke.sh
    bash scripts/ci/validation-contract-smoke.sh
    bash scripts/ci/vcp-integration-smoke.sh
    bash scripts/ci/vcp-c2-smoke.sh
    ;;

  p3-local)
    echo "validation-lane ($LANE): P3 local scaffolds — NOT external KMS/TEE/SSH proof (see docs/P3_LOCAL_SCAFFOLDS.md)"
    bash scripts/ci/convergence-two-host.sh --local-smoke
    bash scripts/kms/conformance-local.sh
    bash scripts/ci/attestation-policy-local.sh
    bash scripts/ci/formal-obligations-local.sh
    ;;

  crypto)
    cargo test -p mneme-crypto -p mneme-smt -- --nocapture
    if cargo metadata --format-version 1 --no-deps \
      | grep -q '"name":"mneme-index"'; then
      cargo test -p mneme-index -- --nocapture 2>/dev/null \
        || echo "mneme-index: no tests yet (Wave 2 scaffold)"
    fi
    bash scripts/ci/crypto-fault-injection-smoke.sh
    bash scripts/ci/kill-resume-smoke.sh
    ;;

  tamper)
    if [[ -x scripts/validate_reliability.sh ]]; then
      exec scripts/validate_reliability.sh tamper
    fi
    fail_closed "tamper suite (150+ cases)" "§17.2 / §18 tamper"
    ;;

  merge)
    if [[ -x scripts/validate_reliability.sh ]]; then
      exec scripts/validate_reliability.sh merge
    fi
    fail_closed "CRDT merge property tests" "§18 merge / §9.4"
    ;;

  determinism)
    if [[ -x scripts/validate_reliability.sh ]]; then
      exec scripts/validate_reliability.sh determinism
    fi
    fail_closed "determinism foundation-gate" "§17.7 / §18 determinism"
    ;;

  bounds)
    echo "validation-lane ($LANE): Pillar B floor audit — Ω(log n / log log n) honesty (see docs/theory/PRICE_OF_VERIFIABLE_COGNITION.md)"
    cargo test -p mneme-core --test cognition_floor_audit -- --nocapture
    cargo test -p mneme-smt --test recall_floor -- --nocapture
    cargo test -p mneme-index --test exact_dominance_floor -- --nocapture
    ;;

  full-preflight)
    print_full_preflight_plan
    ;;

  full)
    # One target dir for the whole full ladder (sub-lanes inherit CARGO_TARGET_DIR).
    mneme_ci_ensure_target_dir "$ROOT" full
    export MNEME_CI_LANE=full
    mneme_ci_clean_foundation_gate_dirs "$ROOT"
    run_full_sublanes
    bash scripts/ci/determinism-local-second-host.sh
    # F-B: the full lane runs ONLY the same-host dual-workspace reproducibility
    # check. It is explicitly NOT the §17.7 cross-host milestone, which stays
    # UNPROVEN until run with MNEME_SECOND_HOST=<distinct host> (and, for a strict
    # release gate, MNEME_STRICT_CROSS_HOST=1 to force fail-closed without a peer).
    print_local_cross_host_honesty_boundary
    bash scripts/ci/determinism-two-machine.sh
    bash scripts/ci/cross-implementation-vectors.sh
    cargo test --workspace -- --nocapture
    bash scripts/ci/bench-recall-optional.sh
    # §17.4 sustained fuzz (≥30s/target, seeded corpus); 16-run smoke is quick-only.
    bash scripts/ci/fuzz-meaningful.sh
    bash scripts/ci/check-test-vectors.sh
    # Re-materialize report after workspace/fuzz (prior ci-foundation-gate tree may be gone).
    cargo run -p mneme-cli -- determinism foundation-gate \
      --out "$ROOT/out/ci-foundation-gate" \
      --timestamp "1970-01-01T00:00:00Z"
    bash scripts/ci/check-foundation-digests.sh
    # B5: agent-session sim over live MCP stdio; see mcp-agent-sim.sh.
    bash scripts/ci/mcp-agent-sim.sh
    ;;

  *)
    echo "Unknown lane: $LANE (expected $(validation_lane_choices))" >&2
    exit 2
    ;;
esac

echo "validation-lane ($LANE): OK"
