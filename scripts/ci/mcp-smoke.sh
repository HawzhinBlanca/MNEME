#!/usr/bin/env bash
# MCP stdio smoke — four-call JSON-RPC roundtrip with honesty checks (READINESS B5).
# Spawns `mneme-mcp` binary (not in-process dispatch); gates live agent protocol path in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/out/agent-targets/b5-mcp}"
mneme_ci_init "$ROOT" mcp-smoke

if ! cargo check -p mneme-mcp --quiet 2>/dev/null; then
  echo "mcp-smoke: mneme-mcp does not build — failing closed until MCP adoption layer is green (§14.1)." >&2
  exit 1
fi

cargo test -p mneme-mcp --test stdio_roundtrip -- --nocapture
echo "mcp-smoke: stdio record/recall/erase/verify roundtrip + honesty checks OK"
exit 0
