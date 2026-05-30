#!/usr/bin/env bash
# Perf-budget gate for bench_verify_recall_10k_entries (blueprint §19: verify <1ms @ 10k).
#
# Runs the `#[ignore]`d bench in isolation (release, single-threaded) with a HARD timeout
# that works even when coreutils `timeout`/`gtimeout` is absent (default on macOS). The SMT
# membership `auth_path` is now O(TREE_DEPTH) cached (§5.6/§9.3), so the verify phase is
# genuinely sub-millisecond and this is a REAL gate: a failed assertion (perf regression)
# propagates as a non-zero exit. The generous timeout (default 2400s, ~10x the known ingest
# wall-time) only guards against a wedged process; exceeding it is also treated as a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export CARGO_TARGET_DIR
CARGO_TARGET_DIR="$(mneme_ci_bench_target_dir "$ROOT")"
mkdir -p "$CARGO_TARGET_DIR"

TIMEOUT_SECS="${BENCH_TIMEOUT_SECS:-2400}"

echo "bench-recall: target=${CARGO_TARGET_DIR}"
echo "bench-recall: running bench_verify_recall_10k_entries in isolation (hard timeout=${TIMEOUT_SECS}s, release profile)"

# libtest warns at 60s under parallel scheduling; allow long populate + measure recall only.
export RUST_TEST_TIME_INTEGRATION="${RUST_TEST_TIME_INTEGRATION:-7200000,7200000}"
export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"

# Launch the bench in its own process group so we can reliably kill the whole tree.
set -m
cargo test -p mneme-store --test bench_recall --release \
  bench_verify_recall_10k_entries -- --ignored --nocapture --test-threads=1 &
bench_pid=$!
bench_pgid="$(ps -o pgid= -p "$bench_pid" 2>/dev/null | tr -d ' ')"

waited=0
status=""
while (( waited < TIMEOUT_SECS )); do
  if ! kill -0 "$bench_pid" 2>/dev/null; then
    wait "$bench_pid"
    status=$?
    break
  fi
  sleep 2
  waited=$((waited + 2))
done

if [[ -z "$status" ]]; then
  echo "bench-recall: FAIL - exceeded ${TIMEOUT_SECS}s; killing bench (wedged or pathologically slow)" >&2
  if [[ -n "$bench_pgid" ]]; then
    kill -TERM "-${bench_pgid}" 2>/dev/null || true
    sleep 1
    kill -KILL "-${bench_pgid}" 2>/dev/null || true
  else
    kill -TERM "$bench_pid" 2>/dev/null || true
  fi
  wait "$bench_pid" 2>/dev/null || true
  exit 124
fi

if [[ "$status" -ne 0 ]]; then
  echo "bench-recall: FAIL - bench exited $status (perf regression: verify exceeded the <1ms budget)" >&2
  exit "$status"
fi

echo "bench-recall: OK (within budget)"
