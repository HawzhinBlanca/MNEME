#!/usr/bin/env bash
# MNEME Desk — one-command local launcher.
#
# Collapses the manual runbook (custody -> store -> capability -> wasm auditor ->
# daemon + same-origin host) into a single command, then stays in the foreground
# and tears everything down cleanly on Ctrl-C.
#
#   scripts/desk/run.sh                 # build, launch, open the browser
#   scripts/desk/run.sh --no-open       # don't open a browser
#   scripts/desk/run.sh --rebuild       # force a fresh cargo + wasm build
#   MNEME_DESK_HOME=~/mneme scripts/desk/run.sh
#
# Honest scope: this makes the Desk ONE-COMMAND RUNNABLE FOR A TECHNICAL USER on
# this machine. It is NOT a packaged consumer installer — there is no app bundle,
# no code-signed binary, and the master key lives in a local file you must protect.
# authenticated != true.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# ── Config (override via env) ────────────────────────────────────────────────
DESK_HOME="${MNEME_DESK_HOME:-$HOME/.mneme/desk}"
STORE="$DESK_HOME/store"
MASTER_FILE="$DESK_HOME/master.key"
CAP_FILE="$DESK_HOME/cap.txt"
DPORT="${MNEME_DESK_DAEMON_PORT:-7845}"
UPORT="${MNEME_DESK_UI_PORT:-8765}"
PROFILE="release"
OPEN_BROWSER=1
REBUILD=0

for arg in "$@"; do
  case "$arg" in
    --no-open) OPEN_BROWSER=0 ;;
    --rebuild) REBUILD=1 ;;
    --debug)   PROFILE="debug" ;;
    -h|--help)
      sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "desk: unknown arg '$arg' (try --help)" >&2; exit 2 ;;
  esac
done

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET_DIR/$PROFILE/mneme"
DAEMON="$TARGET_DIR/$PROFILE/mnemed"
MNEME_PID=""; PROXY_PID=""

log()  { printf '\033[1;34m[desk]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[desk]\033[0m %s\n' "$1" >&2; }

CLEANED=0
cleanup() {
  [ "$CLEANED" = 1 ] && return 0
  CLEANED=1
  echo
  log "shutting down…"
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "$MNEME_PID" ] && kill "$MNEME_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  log "stopped. Your store + receipts persist at $STORE"
}
# Ctrl-C / SIGTERM: clean up and exit 0 (don't fall through to the crash notice).
trap 'cleanup; exit 0' INT TERM
trap cleanup EXIT

# ── 0. operator custody: generate + persist a master key on first run ─────────
mkdir -p "$DESK_HOME"
chmod 700 "$DESK_HOME" 2>/dev/null || true
if [ ! -f "$MASTER_FILE" ]; then
  log "first run: generating an operator master key (sealed-seed custody)"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "$MASTER_FILE"
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$MASTER_FILE"
  fi
  chmod 600 "$MASTER_FILE" 2>/dev/null || true
  warn "master key written to $MASTER_FILE — this is your root of trust; protect it."
fi
export MNEME_KMS_MASTER_KEY_HEX
MNEME_KMS_MASTER_KEY_HEX="$(tr -d ' \n' < "$MASTER_FILE")"

# ── 1. build the binaries ─────────────────────────────────────────────────────
if [ "$REBUILD" = 1 ] || [ ! -x "$BIN" ] || [ ! -x "$DAEMON" ]; then
  log "building mneme + mnemed ($PROFILE)…"
  if [ "$PROFILE" = "release" ]; then
    cargo build --release -q -p mneme-cli -p mnemed
  else
    cargo build -q -p mneme-cli -p mnemed
  fi
fi

# ── 2. create the store (idempotent) ──────────────────────────────────────────
if [ ! -f "$STORE/roots/HEAD" ]; then
  log "creating store at $STORE"
  "$BIN" init "$STORE" >/dev/null
else
  log "reusing store at $STORE"
fi

# ── 3. mint a least-privilege capability for the app ──────────────────────────
log "minting app capability (read/write/forget, all namespaces, tier-max trusted)"
"$BIN" cap mint "$STORE" --read --write --forget --namespace '*' \
  --tier-max trusted --out "$CAP_FILE" >/dev/null
chmod 600 "$CAP_FILE" 2>/dev/null || true

# ── 4. build the in-browser Verify auditor (best-effort) ──────────────────────
if [ "$REBUILD" = 1 ] || [ ! -f "$ROOT/ui/auditor/mneme_verify_wasm_bg.wasm" ]; then
  log "building the in-browser Verify auditor (wasm)…"
  if bash scripts/ci/wasm-auditor.sh >/tmp/mneme-desk-wasm.log 2>&1; then
    log "Verify panel ready (client-side wasm auditor built)"
  else
    warn "wasm auditor build failed (see /tmp/mneme-desk-wasm.log) — the Desk still"
    warn "runs; the in-browser Verify panel will show 'auditor not built'."
  fi
else
  log "reusing in-browser Verify auditor (ui/auditor/)"
fi

# ── 5. start the daemon (loopback only) ───────────────────────────────────────
log "starting mnemed on 127.0.0.1:$DPORT"
"$DAEMON" --store "$STORE" --http "127.0.0.1:$DPORT" >"$DESK_HOME/daemon.log" 2>&1 &
MNEME_PID=$!
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$DPORT/v1/health" >/dev/null 2>&1 && break
  sleep 0.25
done
if ! curl -sf "http://127.0.0.1:$DPORT/v1/health" >/dev/null 2>&1; then
  warn "daemon did not become healthy — see $DESK_HOME/daemon.log"
  exit 1
fi

# ── 6. start the same-origin host (injects the cap server-side) ───────────────
log "starting the Desk host on 127.0.0.1:$UPORT"
MNEME_CAP_FILE="$CAP_FILE" MNEME_UI_PORT="$UPORT" MNEME_DAEMON="http://127.0.0.1:$DPORT" \
  node "$ROOT/ui/serve.mjs" >"$DESK_HOME/host.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$UPORT/index.html" >/dev/null 2>&1 && break
  sleep 0.25
done
if ! curl -sf "http://127.0.0.1:$UPORT/index.html" >/dev/null 2>&1; then
  warn "Desk host did not start — see $DESK_HOME/host.log"
  exit 1
fi

URL="http://127.0.0.1:$UPORT"
echo
log "MNEME Desk is live:  $URL"
log "  store:   $STORE"
log "  logs:    $DESK_HOME/{daemon,host}.log"
log "Press Ctrl-C to stop."

# ── 7. open a browser (best-effort) ───────────────────────────────────────────
if [ "$OPEN_BROWSER" = 1 ]; then
  if command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
  fi
fi

# Stay alive until interrupted; surface a daemon/host crash instead of hanging.
while kill -0 "$MNEME_PID" 2>/dev/null && kill -0 "$PROXY_PID" 2>/dev/null; do
  sleep 1
done
warn "a Desk process exited unexpectedly — check the logs above."
