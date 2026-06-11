#!/usr/bin/env bash
# P3 local scaffold: CRDT merge / anti-entropy convergence smoke.
#
# HONESTY: this is NOT external two-host CONVERGENCE proof. --local-smoke runs
# in-repo merge tests on one machine. Distinct-host proof still requires
# MNEME_SECOND_HOST and operator SSH credentials.
#
# Usage:
#   scripts/ci/convergence-two-host.sh --local-smoke     # default for p3-local lane
#   MNEME_SECOND_HOST=user@peer scripts/ci/convergence-two-host.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-convergence-two-host}"

LOCAL_SMOKE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --local-smoke)
      LOCAL_SMOKE=1
      shift
      ;;
    -h | --help)
      echo "Usage: $0 [--local-smoke]"
      echo "  --local-smoke   same-host CRDT merge convergence (no SSH)"
      echo "  MNEME_SECOND_HOST=user@peer  optional distinct-host gate (operator credentials)"
      exit 0
      ;;
    *)
      echo "convergence-two-host: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

run_local_smoke() {
  echo "convergence-two-host: mode=LOCAL-SMOKE (same host — NOT external two-host proof)"
  cargo test -p mneme-crdt -- merge_convergence -- --nocapture
  cargo test -p mnemed --test v11_object_sync two_peers_converge -- --nocapture
  echo "convergence-two-host: local smoke OK (in-repo merge + two-peer sync convergence)"
}

run_remote_gate() {
  local remote_root="${MNEME_REMOTE_ROOT:-$ROOT}"
  echo "convergence-two-host: mode=SSH-REMOTE peer=$MNEME_SECOND_HOST"
  echo "  HONESTY: requires a distinct physical host and matching git HEAD — not localhost SSH."

  if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$MNEME_SECOND_HOST" true; then
    echo "convergence-two-host: SSH preflight failed — failing closed." >&2
    exit 1
  fi

  local local_rev remote_rev
  local_rev="$(git -C "$ROOT" rev-parse HEAD)"
  remote_rev="$(ssh -o BatchMode=yes "$MNEME_SECOND_HOST" \
    "git -C '$remote_root' rev-parse HEAD 2>/dev/null" || true)"
  if [[ -n "$remote_rev" && "$local_rev" != "$remote_rev" ]]; then
    echo "convergence-two-host: git HEAD mismatch (local=$local_rev remote=$remote_rev)" >&2
    exit 1
  fi

  cargo test -p mneme-crdt -- merge_convergence -- --nocapture
  ssh -o BatchMode=yes "$MNEME_SECOND_HOST" bash -s <<EOF
set -euo pipefail
cd "$remote_root"
export CARGO_TARGET_DIR="\${CARGO_TARGET_DIR:-$remote_root/target}"
cargo test -p mneme-crdt -- merge_convergence -- --nocapture
EOF
  echo "convergence-two-host: SSH remote merge tests passed (operator-gated — not CI default)"
}

if [[ "$LOCAL_SMOKE" -eq 1 ]]; then
  run_local_smoke
elif [[ -n "${MNEME_SECOND_HOST:-}" ]]; then
  run_remote_gate
else
  echo "convergence-two-host: SKIP — set MNEME_SECOND_HOST for distinct-host gate or pass --local-smoke."
  echo "  This skip is fail-closed honesty: no external convergence proof is claimed without a peer."
  exit 0
fi
