#!/usr/bin/env bash
# MCP agent-session simulation CI (READINESS B5 closure).
#
# Honest scope: simulates a multi-turn agent loop (initialize, tool discovery, remember,
# recall at quarantine, trusted-tier A-INJ gate, forget, recall fail-closed) over live
# `mneme-mcp` stdio — NOT a live Claude/Anthropic API integration. Live LLM agent CI
# requires network credentials and non-deterministic model output; this lane proves the
# adoption protocol path an agent would drive.
#
# Evidence: `cargo test -p mneme-mcp --test agent_session_sim` (1 test, 9 turns).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/out/agent-targets/b5-mcp}"
mneme_ci_init "$ROOT" mcp-agent-sim

if ! cargo check -p mneme-mcp --quiet 2>/dev/null; then
  echo "mcp-agent-sim: mneme-mcp does not build — failing closed (§14.1)." >&2
  exit 1
fi

cargo test -p mneme-mcp --test agent_session_sim -- --nocapture
echo "mcp-agent-sim: agent-session CI OK (stdio multi-turn; not live Claude API)"
exit 0
