#!/usr/bin/env bash
# Overnight soak: the heavy, normally-skipped validations, run SEQUENTIALLY (benchmarks
# need isolation — concurrent tiers contend on the fsync queue) and RESILIENTLY (one
# failing stage never aborts the run; every stage's rc + duration is recorded). Launch
# detached; read out/overnight/<ts>/SUMMARY.txt in the morning.
set -uo pipefail   # deliberately NOT -e: collect every stage's result

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
[ -z "${ROOT:-}" ] && ROOT="/Users/hawzhin/MNEME"
cd "$ROOT"

TS="$(date +%Y%m%dT%H%M%S)"
OUT="$ROOT/out/overnight/$TS"
mkdir -p "$OUT"
SUMMARY="$OUT/SUMMARY.txt"
export CARGO_TERM_COLOR=never

echo "MNEME overnight soak — started $(date)" | tee "$SUMMARY"
echo "host: $(sysctl -n machdep.cpu.brand_string 2>/dev/null) cores=$(sysctl -n hw.ncpu 2>/dev/null)" | tee -a "$SUMMARY"
echo "HEAD: $(git rev-parse HEAD)" | tee -a "$SUMMARY"
echo "out:  $OUT" | tee -a "$SUMMARY"
echo "----------------------------------------------------------------" | tee -a "$SUMMARY"

PASS=0 FAIL=0
stage() {
  local name="$1"; shift
  local log="$OUT/${name}.log"
  local start; start=$(date +%s)
  echo "[$(date +%H:%M:%S)] START $name" | tee -a "$SUMMARY"
  ( "$@" ) >"$log" 2>&1
  local rc=$?
  local dur=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  printf '[%s] END   %-26s rc=%d dur=%ds log=%s\n' "$(date +%H:%M:%S)" "$name" "$rc" "$dur" "${log#$ROOT/}" | tee -a "$SUMMARY"
}

# 1) Comprehensive correctness ladder: fmt, clippy -Dwarnings, tamper, determinism x2,
#    cross-impl vectors, workspace tests, 10k recall gate, 30s/target fuzz, vectors, mcp-sim.
stage 01-validation-lane-full env CARGO_TARGET_DIR="$OUT/target-full" bash scripts/ci/validation-lane.sh full

# 2) Deep fuzz: 30 min/target x 6 targets (vs the 30s in the lane).
stage 02-deep-fuzz env MNEME_FUZZ_MAX_TOTAL_TIME=1800 bash scripts/ci/fuzz-meaningful.sh

# 3) Durable 1M benchmark (fsync ON — real production write latency at scale; ~3 hr ingest).
stage 03-durable-1m-bench env \
  MNEME_BENCH_SCALE=1000000 MNEME_BENCH_SAMPLES=3000 MNEME_BENCH_WRITE_SAMPLES=40 \
  MNEME_BENCH_STORE_DIR="/tmp/ovn-1m-store" MNEME_BENCH_MERGE_PEER=500 MNEME_BENCH_MERGE_ITERS=1 \
  /usr/bin/time -l cargo test --release -p mneme-store --features bench_support,internal_test_support --test bench_recall bench_scale_ops -- --ignored --nocapture

# 4) Determinism stability: foundation-gate x5, assert byte-identical HEAD digests.
stage 04-determinism-x5 bash -c '
  set -uo pipefail
  prev=""
  for i in 1 2 3 4 5; do
    d="/tmp/ovn-det-$i"; rm -rf "$d"
    cargo run --release -q -p mneme-cli --features operator_tools -- determinism foundation-gate --out "$d" --timestamp "1970-01-01T00:00:00Z" || exit 2
    h=$(shasum -a256 "$d/run-a/roots/HEAD" | cut -d" " -f1)
    echo "run $i HEAD=$h"
    if [ -n "$prev" ] && [ "$h" != "$prev" ]; then echo "DETERMINISM DRIFT at run $i: $h != $prev"; exit 3; fi
    prev="$h"
  done
  echo "determinism stable across 5 runs: $prev"
'

# 5) Concurrent multi-agent merge under contention (larger: 14 threads, base 5000).
stage 05-contention env \
  MNEME_BENCH_CONTENTION_THREADS=14 MNEME_BENCH_CONTENTION_BASE=5000 \
  MNEME_BENCH_CONTENTION_PEER=500 MNEME_BENCH_CONTENTION_MERGES=4 \
  cargo test --release -p mneme-store --features bench_support,internal_test_support,experimental_sync_crdt --test bench_recall bench_concurrent_merge_contention -- --ignored --nocapture

# 6) §21 killer demo + bypass harness.
stage 06-killer-demo bash scripts/demo/killer-demo.sh

echo "----------------------------------------------------------------" | tee -a "$SUMMARY"
echo "OVERNIGHT SOAK COMPLETE — $(date)" | tee -a "$SUMMARY"
echo "stages: PASS=$PASS FAIL=$FAIL" | tee -a "$SUMMARY"
# Surface the headline benchmark + fuzz lines into the summary for a quick morning read.
echo "--- key bench lines ---" | tee -a "$SUMMARY"
grep -hE "BENCH op=(populate|recall_verified|recall_verified_cached|recall_raw|remember|forget|merge)|maximum resident" "$OUT/03-durable-1m-bench.log" 2>/dev/null | tee -a "$SUMMARY"
grep -hE "fuzz-meaningful: total_execs|crashes=" "$OUT/02-deep-fuzz.log" 2>/dev/null | tee -a "$SUMMARY"
grep -hE "BENCH op=merge_contention|merge_contended" "$OUT/05-contention.log" 2>/dev/null | tee -a "$SUMMARY"
echo "[$(date +%H:%M:%S)] summary written to $SUMMARY"
