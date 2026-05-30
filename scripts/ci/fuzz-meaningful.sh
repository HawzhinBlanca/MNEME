#!/usr/bin/env bash
# Sustained cargo-fuzz lane (blueprint §17.4, READINESS B6): ≥30s per target, seeded corpus.
# Full validation-lane uses this; fuzz-smoke.sh remains 16-run quick gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-fuzz-meaningful}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/out/agent-targets/fuzz}"
mkdir -p "$CARGO_TARGET_DIR"

FUZZ_SECS="${MNEME_FUZZ_MAX_TOTAL_TIME:-30}"
FUZZ_TARGETS=(dcbor_parse smt_parse cap_parse receipt_parse index_wire sync_message_parse)

if [[ ! -d fuzz ]] || ! command -v cargo-fuzz &>/dev/null; then
  echo "fuzz-meaningful: fuzz/ targets or cargo-fuzz not present (§17.4) — failing closed." >&2
  exit 1
fi

FUZZ_TOOLCHAIN="${MNEME_FUZZ_TOOLCHAIN:-nightly}"
if ! rustup run "$FUZZ_TOOLCHAIN" rustc -V &>/dev/null; then
  echo "fuzz-meaningful: rustup toolchain '$FUZZ_TOOLCHAIN' required for cargo-fuzz (§17.4)." >&2
  exit 1
fi

ensure_corpus() {
  local target="$1"
  local dir="$ROOT/fuzz/corpus/$target"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
  fi
  if [[ -z "$(find "$dir" -type f 2>/dev/null | head -n 1)" ]]; then
    echo "fuzz-meaningful: seeding empty corpus for $target" >&2
    printf '\x00' >"$dir/seed_minimal"
  fi
}

for target in "${FUZZ_TARGETS[@]}"; do
  ensure_corpus "$target"
  echo "fuzz-meaningful: $target (${FUZZ_SECS}s, corpus=$(find "$ROOT/fuzz/corpus/$target" -type f | wc -l | tr -d ' ') seeds)" >&2
  log="$(mktemp)"
  set +e
  cargo "+${FUZZ_TOOLCHAIN}" fuzz run "$target" -- \
    -max_total_time="$FUZZ_SECS" \
    -print_final_stats=1 \
    2>&1 | tee "$log"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    echo "fuzz-meaningful: $target FAILED (exit $status)" >&2
    exit "$status"
  fi
  # libFuzzer prints "#12345" exec counter in final stats; extract last execs line.
  execs="$(grep -E '^#[0-9]+' "$log" | tail -n 1 | tr -d '#,' || true)"
  if [[ -z "$execs" ]]; then
    execs="$(grep -oE 'stat::number_of_executed_units:[0-9]+' "$log" | tail -n 1 | cut -d: -f2 || true)"
  fi
  echo "fuzz-meaningful: $target execs=${execs:-unknown} time=${FUZZ_SECS}s exit=0"
  rm -f "$log"
done

echo "fuzz-meaningful: OK (${FUZZ_TARGETS[*]}, ${FUZZ_SECS}s/target, CARGO_TARGET_DIR=$CARGO_TARGET_DIR)"
