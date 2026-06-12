#!/usr/bin/env bash
# Two-peer anti-entropy demo (§19 12-month): merge disjoint stores via mneme-cli.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
mneme_ci_init "$ROOT" demo-two-peer

OUT="${TMPDIR:-/tmp}/mneme-two-peer-$$"
rm -rf "$OUT"
mkdir -p "$OUT"
SEED="${MNEME_OPERATOR_SEED:-4242424242424242424242424242424242424242424242424242424242424242}"

cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" init "$OUT/a"
cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" init "$OUT/b"

cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" remember "$OUT/a" --namespace peer --name only-a --body "alpha"
cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" remember "$OUT/b" --namespace peer --name only-b --body "beta"

cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" merge "$OUT/a" "$OUT/b"
cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" merge "$OUT/b" "$OUT/a"

recall_a="$(cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" recall "$OUT/a" --namespace peer --key only-b -q only-b --min-tier trusted)"
recall_b="$(cargo run -q -p mneme-cli --features operator_tools -- --operator-seed "$SEED" recall "$OUT/b" --namespace peer --key only-a -q only-a --min-tier trusted)"

if [[ "$recall_a" != *"beta"* || "$recall_b" != *"alpha"* ]]; then
  echo "two-peer-merge: merged stores did not expose peer entries — failing closed." >&2
  exit 1
fi

echo "two-peer-merge: OK (stores under $OUT)"
