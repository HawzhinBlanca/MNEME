#!/usr/bin/env bash
# Reliability harness (blueprint §17–§18): tamper, determinism, merge lanes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LANE="${1:-tamper}"

# shellcheck source=scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"
mneme_ci_init "$ROOT" "$LANE"

fail_closed() {
  local reason="$1"
  echo "validate_reliability ($LANE): ${reason} — failing closed." >&2
  exit 1
}

require_store() {
  if ! cargo check -p mneme-store --quiet 2>/dev/null; then
    fail_closed "mneme-store does not build"
  fi
}

case "$LANE" in
  tamper)
    require_store
    echo "==> store generative tamper (≥120 executed cases)"
    cargo test -p mneme-store --test tamper_suite tamper_suite_generative -- --nocapture
    echo "==> verify tamper suites (key + semantic + cap + checkpoint + tombstone)"
    cargo test -p mneme-verify --test tamper_suite -- --nocapture
    cargo test -p mneme-verify --test tamper_semantic -- --nocapture
    cargo test -p mneme-verify --test tamper_cap -- --nocapture
    cargo test -p mneme-verify --test tamper_checkpoint -- --nocapture
    cargo test -p mneme-verify --test tamper_tombstone -- --nocapture
    echo "==> complete-kNN generative tamper (≥150 cases)"
    cargo test -p mneme-index --test complete_knn_tamper -- --nocapture
    echo "==> complete-kNN JL conservative invariant"
    cargo test -p mneme-index --test complete_knn_jl -- --nocapture
    ;;

  determinism)
    if ! cargo run -p mneme-cli -- determinism foundation-gate --help &>/dev/null; then
      fail_closed "mneme-cli determinism foundation-gate not available"
    fi
    out="$ROOT/out/ci-foundation-gate"
    rm -rf "$out" "${out}-2"
    for run in 1 2; do
      echo "==> determinism foundation-gate run ${run}/2"
      dest="$out"
      [[ "$run" -eq 2 ]] && dest="${out}-2"
      cargo run -p mneme-cli -- determinism foundation-gate \
        --out "$dest" \
        --timestamp "1970-01-01T00:00:00Z"
      cargo run -p mneme-cli -- determinism foundation-verify \
        "$dest/foundation.report.json" \
        --output "$dest/foundation.verify.json"
    done
    ;;

  merge)
    if cargo test -p mneme-crdt -- merge_convergence 2>/dev/null; then
      cargo test -p mneme-crdt -- merge_convergence -- --nocapture
    else
      fail_closed "CRDT merge_convergence tests not wired (§18 merge)"
    fi
    ;;

  *)
    echo "Unknown lane: $LANE (expected tamper|determinism|merge)" >&2
    exit 2
    ;;
esac

echo "validate_reliability ($LANE): OK"
