#!/usr/bin/env bash
# MNEME CI harness helpers — parallel-safe Cargo target dirs (coordinator § conflict rules).
#
# Usage (from other scripts/ci/*.sh):
#   # shellcheck source=lib.sh
#   source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
#   mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-quick}"
set -euo pipefail

_MNEME_CI_LIB_LOADED=1

# Repo root from scripts/ci (caller may override MNEME_ROOT).
mneme_ci_root() {
  if [[ -n "${MNEME_ROOT:-}" ]]; then
    printf '%s\n' "$MNEME_ROOT"
    return
  fi
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  printf '%s\n' "$here"
}

# Default under out/agent-targets/ci-<lane>; respects pre-set CARGO_TARGET_DIR.
mneme_ci_default_target_dir() {
  local root="$1"
  local lane="$2"
  printf '%s/out/agent-targets/ci-%s' "$root" "$lane"
}

mneme_ci_ensure_target_dir() {
  local root="$1"
  local lane="${2:-default}"
  if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    export CARGO_TARGET_DIR
    CARGO_TARGET_DIR="$(mneme_ci_default_target_dir "$root" "$lane")"
  fi
  mkdir -p "$CARGO_TARGET_DIR"
}

# Standard env for lane scripts (bounded test threads; optional job cap).
mneme_ci_init() {
  local root="$1"
  local lane="${2:-default}"
  export MNEME_ROOT="$root"
  export MNEME_CI_LANE="$lane"
  export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
  export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"
  export RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"
  if [[ -n "${MNEME_CARGO_BUILD_JOBS:-}" ]]; then
    export CARGO_BUILD_JOBS="$MNEME_CARGO_BUILD_JOBS"
  fi
  mneme_ci_ensure_target_dir "$root" "$lane"
}

# Release bench uses a dedicated target tree (avoids debug/release fights under load).
mneme_ci_bench_target_dir() {
  local root="$1"
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    printf '%s\n' "$CARGO_TARGET_DIR"
    return
  fi
  printf '%s/out/agent-targets/ci-bench-recall\n' "$root"
}

# Remove shared foundation-gate trees so consecutive full lanes cannot read partial run-a/.
mneme_ci_clean_foundation_gate_dirs() {
  local root="$1"
  rm -rf \
    "$root/out/ci-foundation-gate" \
    "$root/out/ci-foundation-gate-2"
}
