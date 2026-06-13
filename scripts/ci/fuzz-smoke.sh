#!/usr/bin/env bash
# Full lane: cargo-fuzz smoke (blueprint §17.4, §18 full).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/out/agent-targets/fuzz}"
mkdir -p "$CARGO_TARGET_DIR"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-fuzz-smoke}"

if [[ ! -d fuzz ]] || ! command -v cargo-fuzz &>/dev/null; then
  echo "fuzz-smoke: fuzz/ targets or cargo-fuzz not present (§17.4) — failing closed." >&2
  exit 1
fi

FUZZ_TOOLCHAIN="${MNEME_FUZZ_TOOLCHAIN:-nightly}"
if ! rustup run "$FUZZ_TOOLCHAIN" rustc -V &>/dev/null; then
  echo "fuzz-smoke: rustup toolchain '$FUZZ_TOOLCHAIN' required for cargo-fuzz (§17.4)." >&2
  exit 1
fi

# Seed the wire-parser targets with their committed valid vectors so the fuzzer mutates
# from a real, structurally-valid input (far better coverage than the \x00 fallback).
seed_corpus_from_vector() {
  local target="$1" vector="$2"
  local corpus="$ROOT/fuzz/corpus/$target"
  mkdir -p "$corpus"
  if [[ -f "$ROOT/$vector" ]]; then
    cp "$ROOT/$vector" "$corpus/seed_vector_v1"
  fi
}
seed_corpus_from_vector robr_verify proof/vectors/robr_vector_v1.bin
seed_corpus_from_vector forget_proof_verify proof/vectors/forget_proof_vector_v1.cbor
seed_corpus_from_vector pace_log_verify proof/vectors/pace_log_vector_v1.cbor

FUZZ_TARGETS=(dcbor_parse smt_parse cap_parse receipt_parse index_wire sync_message_parse cognition_cert_parse federation_cert_parse federation_cert_verify robr_verify forget_proof_verify pace_log_verify)
for target in "${FUZZ_TARGETS[@]}"; do
  corpus="$ROOT/fuzz/corpus/$target"
  if [[ ! -d "$corpus" ]] || [[ -z "$(find "$corpus" -type f 2>/dev/null | head -n 1)" ]]; then
    mkdir -p "$corpus"
    printf '\x00' >"$corpus/seed_minimal"
  fi
  cargo "+${FUZZ_TOOLCHAIN}" fuzz run "$target" -- -runs=16
done
echo "fuzz-smoke: OK (dcbor_parse smt_parse cap_parse receipt_parse index_wire sync_message_parse cognition_cert_parse federation_cert_parse federation_cert_verify robr_verify forget_proof_verify pace_log_verify)"
