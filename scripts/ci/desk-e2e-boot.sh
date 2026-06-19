#!/usr/bin/env bash
# Boot the live MNEME Desk stack for the Playwright browser e2e (playwright.live.config.ts).
# Starts mnemed (with a minted cap), seeds two memories, then runs ui/serve.mjs in the
# foreground on the UI port Playwright waits for. The daemon is killed on teardown.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

DPORT="${MNEME_DESK_DAEMON_PORT:-7848}"
UPORT="${MNEME_DESK_UI_PORT:-3100}"
export MNEME_KMS_MASTER_KEY_HEX="${MNEME_KMS_MASTER_KEY_HEX:-5555555555555555555555555555555555555555555555555555555555555555}"
TMP="$(mktemp -d)"
DPID=""; PROXY=""
cleanup() { kill "$DPID" "$PROXY" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

cargo build -q -p mneme-cli --bin mneme
cargo build -q -p mnemed --bin mnemed
BIN="$ROOT/target/debug/mneme"
DAEMON="$ROOT/target/debug/mnemed"

"$BIN" init "$TMP/store" >/dev/null 2>&1
"$BIN" cap mint "$TMP/store" --read --write --forget --promote --namespace '*' --tier-max trusted --out "$TMP/cap.txt" >/dev/null 2>&1

"$DAEMON" --store "$TMP/store" --http "127.0.0.1:$DPORT" >"$TMP/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$DPORT/v1/health" >/dev/null 2>&1 && break; sleep 0.25; done

AUTH="Authorization: Bearer $(cat "$TMP/cap.txt")"
seed() { curl -s -X POST "http://127.0.0.1:$DPORT/v1/memory" -H "$AUTH" -H 'content-type: application/json' -d "$1" >/dev/null; }
seed '{"namespace":"notes","name":"hello","kind":"episodic","body":"verified-recall-works"}'
seed '{"namespace":"notes","name":"forgetme","kind":"episodic","body":"delete-with-a-receipt"}'
seed '{"namespace":"notes","name":"promoteme","kind":"episodic","body":"raise-my-trust-tier"}'

MNEME_CAP_FILE="$TMP/cap.txt" MNEME_UI_PORT="$UPORT" MNEME_DAEMON="http://127.0.0.1:$DPORT" \
  node "$ROOT/ui/serve.mjs" &
PROXY=$!
wait "$PROXY"
