#!/usr/bin/env bash
# Local parity with .github/workflows/ci.yml e2e jobs.
# Serialized store/daemon tests share one target; CLI/Node use ci-e2e-cli (parallel-safe).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PROFILE="${MNEME_BUILD_PROFILE:-release}"

run_store_e2e() {
  mneme_ci_init "$ROOT" e2e-store
  echo "==> store kernel e2e (tests/e2e/mod.rs) [target=${CARGO_TARGET_DIR}]"
  cargo test -p mneme-store --features internal_test_support --test e2e -- --nocapture
}

run_daemon_e2e() {
  mneme_ci_init "$ROOT" e2e-daemon
  echo "==> mnemed API e2e (http / grpc / sync shards) [target=${CARGO_TARGET_DIR}]"
  cargo test -p mnemed --test api_integration http_api -- --nocapture
  cargo test -p mnemed --test api_integration grpc_api -- --nocapture
  cargo test -p mnemed --test api_integration sync_ws -- --nocapture
}

run_cli_e2e() {
  mneme_ci_init "$ROOT" e2e-cli
  local bin="$CARGO_TARGET_DIR/$PROFILE/mneme"
  echo "==> build mneme-cli ($PROFILE) [target=${CARGO_TARGET_DIR}]"
  cargo build -p mneme-cli --"$PROFILE"
  echo "==> Rust CLI e2e (cli_e2e.rs)"
  cargo test -p mneme-cli --test cli_e2e -- --nocapture
  echo "==> Node CLI smoke (e2e/cli/*.test.mjs)"
  export MNEME_BIN="$bin"
  if [[ -f package-lock.json ]]; then
    npm ci
  else
    npm install
  fi
  node --test e2e/cli/*.test.mjs
  if [[ -n "${MNEME_UI_BASE_URL:-}" ]]; then
    echo "==> Playwright UI (MNEME_UI_BASE_URL set)"
    npx playwright install chromium --with-deps 2>/dev/null || npx playwright install chromium
    npm run test:e2e:ui
  else
    echo "==> Playwright UI skipped (MNEME_UI_BASE_URL unset — no web UI in v1)"
    npx playwright install chromium 2>/dev/null || true
    npm run test:e2e:ui
  fi
}

# Default: run all e2e phases sequentially (avoids target/lock fights).
run_store_e2e
run_daemon_e2e
run_cli_e2e

echo "E2E harness complete."
