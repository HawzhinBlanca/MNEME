#!/usr/bin/env bash
# Sustained chaos soak — readiness adversarial audit (§17.3 durability).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
mneme_ci_init "$ROOT" "chaos-soak"

REPORT_DIR="${MNEME_CHAOS_REPORT_DIR:-$ROOT/out/readiness/chaos-soak-20260531}"
mkdir -p "$REPORT_DIR"

SOAK_SECS="${MNEME_CHAOS_SOAK_SECS:-360}"
ITERATIONS="${MNEME_CHAOS_ITERATIONS:-40}"
SEED="${MNEME_CHAOS_SEED:-$(date +%s)}"

LOG="$REPORT_DIR/chaos-soak.log"
MATRIX_TSV="$REPORT_DIR/chaos-matrix.tsv"
UNSAFE_LOG="$REPORT_DIR/unsafe-events.log"
SUMMARY="$REPORT_DIR/soak-summary.txt"

export MNEME_CHAOS_ITERATIONS="$ITERATIONS"
export MNEME_CHAOS_SEED="$SEED"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

echo "chaos-soak: target=$CARGO_TARGET_DIR report=$REPORT_DIR soak_secs=$SOAK_SECS iterations=$ITERATIONS seed=$SEED" | tee "$SUMMARY"

# Build once
cargo test -p mneme-store --test chaos chaos_smoke_one_each --no-run 2>&1 | tee -a "$LOG"

start_epoch=$(date +%s)
end_epoch=$((start_epoch + SOAK_SECS))
run=0

: >"$MATRIX_TSV"
echo -e "run\titer\tfault\tinjection\texpected\tactual\tverify\tincomplete\topen\tunsafe\tunsafe_reason" >>"$MATRIX_TSV"
: >"$UNSAFE_LOG"

while [[ $(date +%s) -lt $end_epoch ]]; do
  run=$((run + 1))
  echo "=== chaos soak run $run @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$LOG"
  if cargo test -p mneme-store --test chaos chaos_sustained_soak -- --nocapture 2>&1 | tee -a "$LOG"; then
    echo "run $run: PASS" >>"$SUMMARY"
  else
    echo "run $run: FAIL (see log)" >>"$SUMMARY"
    exit 1
  fi
  grep '^CHAOS_ROW|' "$LOG" | tail -n $((ITERATIONS * 9)) | while IFS='|' read -r _ json; do
    fault=$(echo "$json" | sed -n 's/.*"fault":"\([^"]*\)".*/\1/p')
    iter=$(echo "$json" | sed -n 's/.*"iter":\([0-9]*\).*/\1/p')
    injection=$(echo "$json" | sed -n 's/.*"injection_point":"\([^"]*\)".*/\1/p')
    expected=$(echo "$json" | sed -n 's/.*"expected":"\([^"]*\)".*/\1/p')
    actual=$(echo "$json" | sed -n 's/.*"actual":"\([^"]*\)".*/\1/p')
    verify=$(echo "$json" | sed -n 's/.*"verify_result":"\([^"]*\)".*/\1/p')
    incomplete=$(echo "$json" | sed -n 's/.*"incomplete":\([a-z]*\).*/\1/p')
    open_r=$(echo "$json" | sed -n 's/.*"open_result":"\([^"]*\)".*/\1/p')
    unsafe=$(echo "$json" | sed -n 's/.*"unsafe_state":\([a-z]*\).*/\1/p')
    reason=$(echo "$json" | sed -n 's/.*"unsafe_reason":"\([^"]*\)".*/\1/p')
    echo -e "$run\t$iter\t$fault\t$injection\t$expected\t$actual\t$verify\t$incomplete\t$open_r\t$unsafe\t$reason" >>"$MATRIX_TSV"
    if [[ "$unsafe" == "true" ]]; then
      echo "run=$run iter=$iter fault=$fault reason=$reason" >>"$UNSAFE_LOG"
    fi
  done
done

total_rows=$((run * ITERATIONS * 9))
unsafe_count=$(grep -c '^' "$UNSAFE_LOG" 2>/dev/null || true)
unsafe_count=${unsafe_count:-0}

{
  echo "completed_runs=$run"
  echo "total_fault_rows≈$total_rows"
  echo "unsafe_events=$unsafe_count"
  echo "MTBUS=$([[ "$unsafe_count" -eq 0 ]] && echo NEVER || echo "$unsafe_count events — see unsafe-events.log")"
  echo "log=$LOG"
  echo "matrix=$MATRIX_TSV"
} | tee -a "$SUMMARY"

if [[ "$unsafe_count" -gt 0 ]]; then
  exit 2
fi
