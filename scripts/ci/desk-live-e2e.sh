#!/usr/bin/env bash
# MNEME Desk — Phase Y0 live end-to-end harness (no browser required).
#
# Boots the real stack (mneme cap mint -> mnemed -> ui/serve.mjs) and asserts the
# full verifiable-recall + forget-with-proof chain over HTTP, including fail-closed
# auth, fail-closed deletion, and least-privilege enforcement. Any failed assertion
# aborts (set -e). A clean run prints "desk-live-e2e: OK".
#
# Usage: scripts/ci/desk-live-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

DPORT="${MNEME_E2E_DAEMON_PORT:-7847}"
UPORT="${MNEME_E2E_UI_PORT:-8767}"
export MNEME_KMS_MASTER_KEY_HEX="${MNEME_KMS_MASTER_KEY_HEX:-5555555555555555555555555555555555555555555555555555555555555555}"
TMP="$(mktemp -d)"
MNEME_PID=""; PROXY_PID=""
cleanup() { kill "$MNEME_PID" "$PROXY_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }
# want_eq <actual> <expected> <message>
want_eq() { if [ "$1" = "$2" ]; then pass "$3 ($1)"; else fail "$3 (got $1, want $2)"; fi; }
# want_grep <haystack> <pattern> <message>
want_grep() { if printf '%s' "$1" | grep -q "$2"; then pass "$3"; else fail "$3 :: $1"; fi; }
# want_status <code> <accepted-regex> <message>
want_status() { if printf '%s' "$1" | grep -qE "$2"; then pass "$3 ($1)"; else fail "$3 (got $1)"; fi; }

echo "desk-live-e2e: build"
cargo build -q -p mneme-cli --bin mneme
cargo build -q -p mnemed --bin mnemed
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET_DIR/debug/mneme"
DAEMON="$TARGET_DIR/debug/mnemed"

echo "desk-live-e2e: provision store + capabilities"
"$BIN" init "$TMP/store" >/dev/null 2>&1
"$BIN" cap mint "$TMP/store" --read --write --forget --namespace '*' --tier-max trusted --out "$TMP/cap.txt" >/dev/null 2>&1
"$BIN" cap mint "$TMP/store" --read --namespace '*' --out "$TMP/ro.txt" >/dev/null 2>&1
if [ -s "$TMP/cap.txt" ] && [ -s "$TMP/ro.txt" ]; then pass "capabilities minted"; else fail "cap mint failed"; fi
RW="Authorization: Bearer $(cat "$TMP/cap.txt")"
RO="Authorization: Bearer $(cat "$TMP/ro.txt")"

echo "desk-live-e2e: start daemon + same-origin host"
"$DAEMON" --store "$TMP/store" --http "127.0.0.1:$DPORT" >"$TMP/daemon.log" 2>&1 &
MNEME_PID=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$DPORT/v1/health" >/dev/null 2>&1 && break; sleep 0.25; done
if curl -sf "http://127.0.0.1:$DPORT/v1/health" >/dev/null 2>&1; then pass "daemon health"; else fail "daemon did not start"; fi

MNEME_CAP_FILE="$TMP/cap.txt" MNEME_UI_PORT="$UPORT" MNEME_DAEMON="http://127.0.0.1:$DPORT" \
  node "$ROOT/ui/serve.mjs" >"$TMP/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$UPORT/index.html" >/dev/null 2>&1 && break; sleep 0.25; done
if curl -sf "http://127.0.0.1:$UPORT/index.html" >/dev/null 2>&1; then pass "host serving ui/"; else fail "host did not start"; fi

UI="http://127.0.0.1:$UPORT"
DAEMON_URL="http://127.0.0.1:$DPORT"

echo "desk-live-e2e: assertions"

# 1. static console is served same-origin (no CORS)
want_grep "$(curl -s "$UI/")" "Verifiable Memory" "static console served"

# 2. fail-closed auth: unauthenticated authed read is rejected
want_eq "$(curl -s -o /dev/null -w '%{http_code}' "$DAEMON_URL/v1/head")" "401" "no-auth /v1/head rejected"

# 3. proxy injects the cap server-side -> signed root
want_grep "$(curl -s "$UI/v1/head")" '"root_hash_hex"' "proxied /v1/head returns signed root"

# 4. remember through the daemon
remember=$(curl -s -X POST "$DAEMON_URL/v1/memory" -H "$RW" -H 'content-type: application/json' \
  -d '{"namespace":"notes","name":"hello","kind":"episodic","body":"verified-recall-works"}')
want_grep "$remember" '"object_id_hex"' "remember notes/hello"

# 5. verified recall through the proxy returns the committed body
want_grep "$(curl -s "$UI/v1/memory/notes/hello?min_tier=quarantine")" 'verified-recall-works' \
  "verified recall returns committed value"

# 6. forget-with-proof emits an offline-verifiable, root-bound ForgetProof
proof=$(curl -s -X DELETE "$UI/v1/forget-proof/notes/hello")
want_grep "$proof" '"proof_cbor_b64"' "forget emits ForgetProof"
want_grep "$proof" '"root_hash_hex"' "ForgetProof bound to a signed root"

# 7. fail-closed deletion: key is tombstoned (410) or absent (404), never the old body
after=$(curl -s -o /dev/null -w '%{http_code}' "$UI/v1/memory/notes/hello?min_tier=quarantine")
body=$(curl -s "$UI/v1/memory/notes/hello?min_tier=quarantine")
if printf '%s' "$body" | grep -q 'verified-recall-works'; then fail "key still recallable after forget"; fi
want_status "$after" '^(410|404)$' "recall after forget is absent/tombstoned"

# 8. prove-absent corroborates the deletion under the signed root
want_grep "$(curl -s "$UI/v1/prove-absent/notes/hello")" '"absent":true' "prove-absent confirms key gone"

# 9. least-privilege (granular): caps are denied ops they were not granted.
keep=$(curl -s -X POST "$DAEMON_URL/v1/memory" -H "$RW" -H 'content-type: application/json' \
  -d '{"namespace":"notes","name":"keep","kind":"episodic","body":"keep-me"}')
keep_oid=$(printf '%s' "$keep" | grep -o '"object_id_hex":"[0-9a-f]*"' | sed 's/.*:"//;s/"//')
if [ "${#keep_oid}" = "64" ]; then pass "seeded notes/keep"; else fail "could not seed notes/keep: $keep"; fi

ro_forget=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$DAEMON_URL/v1/forget-proof/notes/keep" -H "$RO")
want_status "$ro_forget" '^(401|403)$' "read-only cap denied forget"

promote_body="{\"object_id_hex\":\"$keep_oid\",\"to_tier\":\"trusted\"}"
rw_promote=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$DAEMON_URL/v1/memory/promote" -H "$RW" \
  -H 'content-type: application/json' -d "$promote_body")
want_status "$rw_promote" '^(401|403)$' "cap without PROMOTE denied promote"

echo "desk-live-e2e: OK"
