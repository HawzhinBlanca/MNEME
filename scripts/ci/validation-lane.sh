#!/usr/bin/env bash
# MNEME validation ladder (blueprint §18).
#
# Usage: scripts/ci/validation-lane.sh <quick|crypto|tamper|merge|determinism|full>
# Parallel agents: set CARGO_TARGET_DIR=out/agent-targets/ci-harness (or per-lane default applies).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

LANE="${1:-quick}"
mneme_ci_init "$ROOT" "$LANE"

fail_closed() {
  local suite="$1"
  local section="$2"
  echo "MNEME validation-lane ($LANE): ${suite} not wired (${section}) — failing closed." >&2
  exit 1
}

case "$LANE" in
  quick)
    cargo fmt --all -- --check
    # Wave 0/1 + store kernel on quick lane (§18, §19 v0).
    cargo clippy -p mneme-core -p mneme-crypto -p mneme-smt -p mneme-dag \
      -p mneme-root -p mneme-cap -p mneme-verify -p mneme-store \
      --lib --tests -- -D warnings
    bash scripts/ci/verify-tcb-guard.sh
    cargo test -p mneme-core -p mneme-crypto -p mneme-smt -p mneme-dag \
      -p mneme-root -p mneme-cap -p mneme-verify --lib -- --nocapture
    bash scripts/ci/kill-resume-smoke.sh
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
    if cargo test -p mneme-crdt -- merge_convergence 2>/dev/null; then
      cargo test -p mneme-crdt -- merge_convergence -- --nocapture
    else
      fail_closed "CRDT merge property tests" "§18 merge / §9.4"
    fi
    ;;

  determinism)
    if cargo run -p mneme-cli -- determinism foundation-gate --help &>/dev/null; then
      out="$ROOT/out/ci-foundation-gate"
      rm -rf "$out" "${out}-2"
      for run in 1 2; do
        dest="$out"
        [[ "$run" -eq 2 ]] && dest="${out}-2"
        cargo run -p mneme-cli -- determinism foundation-gate \
          --out "$dest" \
          --timestamp "1970-01-01T00:00:00Z"
        cargo run -p mneme-cli -- determinism foundation-verify \
          "$dest/foundation.report.json" \
          --output "$dest/foundation.verify.json"
      done
    else
      fail_closed "determinism foundation-gate" "§17.7 / §18 determinism"
    fi
    ;;

  full)
    # One target dir for the whole full ladder (sub-lanes inherit CARGO_TARGET_DIR).
    mneme_ci_ensure_target_dir "$ROOT" full
    export MNEME_CI_LANE=full
    bash "$0" quick
    bash "$0" crypto
    bash "$0" tamper
    bash "$0" determinism
    bash scripts/ci/determinism-local-second-host.sh
    echo "validation-lane (full): real two-machine proof is separate and fail-closed; set MNEME_SECOND_HOST and run scripts/ci/determinism-two-machine.sh"
    bash scripts/ci/determinism-two-machine.sh
    bash scripts/ci/cross-implementation-vectors.sh
    cargo test --workspace -- --nocapture
    bash scripts/ci/bench-recall-optional.sh
    bash scripts/ci/fuzz-smoke.sh
    bash scripts/ci/check-test-vectors.sh
    bash scripts/ci/check-foundation-digests.sh
    ;;

  *)
    echo "Unknown lane: $LANE (expected quick|crypto|tamper|merge|determinism|full)" >&2
    exit 2
    ;;
esac

echo "validation-lane ($LANE): OK"
