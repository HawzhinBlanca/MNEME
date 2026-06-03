#!/usr/bin/env bash
# Sustained cargo-fuzz lane (blueprint §17.4, READINESS B6): ≥30s per target, seeded corpus.
# Full validation-lane uses this; fuzz-smoke.sh remains 16-run quick gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/out/agent-targets/fuzz}"
mkdir -p "$CARGO_TARGET_DIR"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-fuzz-meaningful}"

FUZZ_SECS="${MNEME_FUZZ_MAX_TOTAL_TIME:-30}"
FUZZ_TARGETS=(dcbor_parse smt_parse cap_parse receipt_parse index_wire sync_message_parse cognition_cert_parse)
EVIDENCE_DIR="${MNEME_FUZZ_EVIDENCE_DIR:-}"
TOTAL_EXECS=0
CRASHES=0

if [[ ! -d fuzz ]] || ! command -v cargo-fuzz &>/dev/null; then
  echo "fuzz-meaningful: fuzz/ targets or cargo-fuzz not present (§17.4) — failing closed." >&2
  exit 1
fi

FUZZ_TOOLCHAIN="${MNEME_FUZZ_TOOLCHAIN:-nightly}"
if ! rustup run "$FUZZ_TOOLCHAIN" rustc -V &>/dev/null; then
  echo "fuzz-meaningful: rustup toolchain '$FUZZ_TOOLCHAIN' required for cargo-fuzz (§17.4)." >&2
  exit 1
fi

if [[ -n "$EVIDENCE_DIR" ]]; then
  mkdir -p "$EVIDENCE_DIR"
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

extract_execs() {
  local log="$1"
  local execs
  execs="$(grep -oE 'stat::number_of_executed_units: [0-9]+' "$log" | tail -n 1 | grep -oE '[0-9]+$' || true)"
  if [[ -z "$execs" ]]; then
    execs="$(grep -E '^#[0-9]+' "$log" | tail -n 1 | sed -n 's/^#\([0-9][0-9]*\).*/\1/p' || true)"
  fi
  printf '%s' "$execs"
}

SUMMARY="$EVIDENCE_DIR/fuzz-meaningful-summary.txt"
if [[ -n "$EVIDENCE_DIR" ]]; then
  : >"$SUMMARY"
fi

for target in "${FUZZ_TARGETS[@]}"; do
  ensure_corpus "$target"
  seeds="$(find "$ROOT/fuzz/corpus/$target" -type f | wc -l | tr -d ' ')"
  echo "fuzz-meaningful: $target (${FUZZ_SECS}s, corpus=${seeds} seeds)" >&2
  if [[ -n "$EVIDENCE_DIR" ]]; then
    log="$EVIDENCE_DIR/fuzz-${target}.log"
  else
    log="$(mktemp)"
  fi
  set +e
  # Catch a REAL single unbounded allocation (`-malloc_limit_mb`, the bounded-alloc
  # guarantee) but do NOT abort on benign cumulative process RSS (`-rss_limit_mb=0`):
  # over a long run libFuzzer's own coverage maps + corpus grow past the default
  # 2048 MB and would otherwise dump a false-positive `oom-` artifact for whatever
  # input was in flight (confirmed harmless on replay). Both are env-overridable.
  cargo "+${FUZZ_TOOLCHAIN}" fuzz run "$target" -- \
    -max_total_time="$FUZZ_SECS" \
    -print_final_stats=1 \
    -malloc_limit_mb="${MNEME_FUZZ_MALLOC_LIMIT_MB:-2048}" \
    -rss_limit_mb="${MNEME_FUZZ_RSS_LIMIT_MB:-0}" \
    2>&1 | tee "$log"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    echo "fuzz-meaningful: $target FAILED (exit $status)" >&2
    CRASHES=$((CRASHES + 1))
    exit "$status"
  fi
  if grep -qE 'ERROR: libFuzzer: deadly signal|==ABORTING|SUMMARY:.*(crash|oom|timeout)' "$log"; then
    echo "fuzz-meaningful: $target crash detected in log" >&2
    CRASHES=$((CRASHES + 1))
    exit 1
  fi
  execs="$(extract_execs "$log")"
  if [[ -n "$execs" && "$execs" =~ ^[0-9]+$ ]]; then
    TOTAL_EXECS=$((TOTAL_EXECS + execs))
  fi
  line="fuzz-meaningful: $target execs=${execs:-unknown} time=${FUZZ_SECS}s seeds=${seeds} exit=0"
  echo "$line"
  if [[ -n "$EVIDENCE_DIR" ]]; then
    echo "$line" >>"$SUMMARY"
  else
    rm -f "$log"
  fi
done

echo "fuzz-meaningful: total_execs=${TOTAL_EXECS} crashes=${CRASHES} targets=${#FUZZ_TARGETS[@]} secs_per_target=${FUZZ_SECS}"
echo "fuzz-meaningful: OK (${FUZZ_TARGETS[*]}, ${FUZZ_SECS}s/target, CARGO_TARGET_DIR=$CARGO_TARGET_DIR)"
if [[ -n "$EVIDENCE_DIR" ]]; then
  {
    echo "total_execs=${TOTAL_EXECS}"
    echo "crashes=${CRASHES}"
    echo "targets=${#FUZZ_TARGETS[@]}"
    echo "secs_per_target=${FUZZ_SECS}"
    echo "cargo_target_dir=${CARGO_TARGET_DIR}"
    echo "exit=0"
  } >>"$SUMMARY"
fi
