#!/usr/bin/env bash
# §19 / MNEME 2.0 — two-peer canonical §11 sync convergence (offline).
#
# Spins two mnemed instances with divergent stores, runs `mneme sync pull` on each
# side, and asserts matching key_index_root (same as v11_object_sync / sync_client).
#
# Usage: scripts/demo/sync-two-peer-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=../ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
mneme_ci_init "$ROOT" sync-two-peer-demo

OUT="${MNEME_SYNC_DEMO_LOG:-$ROOT/out/demo/sync-two-peer-demo.log}"
mkdir -p "$(dirname "$OUT")"

{
  echo "==> two-peer sync demo"
  echo "    started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  cargo test -p mnemed --test v11_object_sync two_peers_converge -- --nocapture
  echo
  echo "==> OK: canonical §11 WebSocket anti-entropy converges"
} 2>&1 | tee "$OUT"
