#!/usr/bin/env bash
# Full lane: cargo-fuzz smoke (blueprint §17.4, §18 full).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-fuzz}"

if [[ ! -d fuzz ]] || ! command -v cargo-fuzz &>/dev/null; then
  echo "fuzz-smoke: fuzz/ targets or cargo-fuzz not present (§17.4) — failing closed." >&2
  exit 1
fi

FUZZ_TOOLCHAIN="${MNEME_FUZZ_TOOLCHAIN:-nightly}"
if ! rustup run "$FUZZ_TOOLCHAIN" rustc -V &>/dev/null; then
  echo "fuzz-smoke: rustup toolchain '$FUZZ_TOOLCHAIN' required for cargo-fuzz (§17.4)." >&2
  exit 1
fi

for target in dcbor_parse smt_parse cap_parse receipt_parse index_wire sync_message_parse; do
  cargo "+${FUZZ_TOOLCHAIN}" fuzz run "$target" -- -runs=16
done
echo "fuzz-smoke: OK (dcbor_parse smt_parse cap_parse receipt_parse index_wire sync_message_parse)"
