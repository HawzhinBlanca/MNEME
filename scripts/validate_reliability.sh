#!/usr/bin/env bash
# Reliability harness (blueprint §17–§18): tamper, determinism, merge lanes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LANE="${1:-tamper}"
export CARGO_TERM_COLOR=always
export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"

fail_closed() {
  local reason="$1"
  echo "validate_reliability ($LANE): ${reason} — failing closed." >&2
  exit 1
}

require_store() {
  if ! cargo check -p mneme-store --features internal_test_support --quiet 2>/dev/null; then
    fail_closed "mneme-store does not build"
  fi
}

case "$LANE" in
  tamper)
    require_store
    echo "==> store generative tamper (≥120 executed cases)"
    cargo test -p mneme-store --features internal_test_support --test tamper_suite tamper_suite_generative -- --nocapture
    echo "==> verify tamper suites (key + cap; semantic is experimental)"
    cargo test -p mneme-verify --test tamper_suite -- --nocapture
    if [[ "${MNEME_EXPERIMENTAL_SEMANTIC:-0}" == "1" ]]; then
      cargo test -p mneme-verify --features experimental_semantic --test tamper_semantic -- --nocapture
    else
      echo "==> skipping semantic tamper suite (set MNEME_EXPERIMENTAL_SEMANTIC=1)"
    fi
    cargo test -p mneme-verify --test tamper_cap -- --nocapture
    ;;

  determinism)
    if ! cargo run -p mneme-cli --features operator_tools -- determinism foundation-gate --help &>/dev/null; then
      fail_closed "mneme-cli determinism foundation-gate not available"
    fi
    out="$ROOT/out/ci-foundation-gate"
    rm -rf "$out" "${out}-2"
    for run in 1 2; do
      echo "==> determinism foundation-gate run ${run}/2"
      dest="$out"
      [[ "$run" -eq 2 ]] && dest="${out}-2"
      cargo run -p mneme-cli --features operator_tools -- determinism foundation-gate \
        --out "$dest" \
        --timestamp "1970-01-01T00:00:00Z"
      cargo run -p mneme-cli --features operator_tools -- determinism foundation-verify \
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
