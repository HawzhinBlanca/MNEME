#!/usr/bin/env bash
# Two-machine determinism gate (blueprint §17.7, audit B4).
#
# Mode A — dual-workspace (default when MNEME_SECOND_HOST unset):
#   rsync two isolated trees, independent CARGO_TARGET_DIR per workspace.
#   Closes CI digest reproducibility; does NOT prove cross-host §17.7.
#
# Mode B — remote SSH (full §17.7): set MNEME_SECOND_HOST=user@peer.example
#   Optional MNEME_REMOTE_ROOT when remote checkout path differs from driver ROOT.
#   Localhost SSH is LOCAL-ONLY and must not be reported as cross-host proof.
#
# Usage:
#   scripts/ci/determinism-two-machine.sh
#   MNEME_SECOND_HOST=user@peer.example scripts/ci/determinism-two-machine.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-determinism-two-machine}"

if ! cargo run -p mneme-cli -- determinism foundation-gate --help &>/dev/null; then
  echo "determinism-two-machine: mneme-cli foundation-gate not available — failing closed." >&2
  exit 1
fi

TS="${MNEME_DETERMINISM_TS:-1970-01-01T00:00:00Z}"
PINNED="$ROOT/proof/digests/foundation-gate.v1.json"

is_localhost_ssh_target() {
  local host="$1"
  case "${host#*@}" in
    localhost | 127.0.0.1 | ::1 | "[::1]")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

compare_run_a_digests() {
  local report_a="$1"
  local report_b="$2"
  local label_a="${3:-workspace-a}"
  local label_b="${4:-workspace-b}"
  python3 - "$report_a" "$report_b" "$label_a" "$label_b" <<'PY'
import json, sys

report_a, report_b, label_a, label_b = sys.argv[1:5]
keys = [
    "head_bytes_hex",
    "root_preimage_hex",
    "receipt_digest_hex",
    "absent_proof_digest_hex",
    "semantic_digest_hex",
]

def load_run(path):
    with open(path) as f:
        return json.load(f)["run_a"]

a = load_run(report_a)
b = load_run(report_b)
mismatch = [k for k in keys if a.get(k) != b.get(k)]
if mismatch:
    print(
        f"determinism-two-machine: digest mismatch ({label_a} vs {label_b}): "
        + ", ".join(mismatch),
        file=sys.stderr,
    )
    for k in mismatch:
        print(f"  {k}:", file=sys.stderr)
        print(f"    {label_a}: {a.get(k)}", file=sys.stderr)
        print(f"    {label_b}: {b.get(k)}", file=sys.stderr)
    sys.exit(1)

print(f"determinism-two-machine: OK — run_a digests byte-identical ({label_a} vs {label_b})")
for k in keys:
    print(f"  {k}: {a[k]}")
PY
}

run_ssh_remote() {
  local local_out="$ROOT/out/ci-two-machine-local"
  local remote_out="/tmp/mneme-two-machine-remote"
  local remote_root="${MNEME_REMOTE_ROOT:-$ROOT}"

  echo "determinism-two-machine: mode=SSH-REMOTE peer=$MNEME_SECOND_HOST"
  if is_localhost_ssh_target "$MNEME_SECOND_HOST"; then
    echo "determinism-two-machine: WARNING — MNEME_SECOND_HOST resolves to localhost." >&2
    echo "  This is LOCAL-ONLY and does not satisfy §17.7 cross-host proof." >&2
  fi

  if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$MNEME_SECOND_HOST" true; then
    echo "determinism-two-machine: SSH preflight failed for MNEME_SECOND_HOST=$MNEME_SECOND_HOST" >&2
    echo "  Ensure passwordless SSH (ssh -o BatchMode=yes $MNEME_SECOND_HOST true)." >&2
    echo "  For CI without a peer, unset MNEME_SECOND_HOST to use dual-workspace mode." >&2
    exit 1
  fi

  rm -rf "$local_out"
  cargo run -p mneme-cli -- determinism foundation-gate \
    --out "$local_out" \
    --timestamp "$TS"

  export LOCAL_OUT="$local_out" REMOTE_OUT="$remote_out" TS ROOT
  ssh "$MNEME_SECOND_HOST" bash -s <<EOF
set -euo pipefail
cd "$remote_root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$remote_root/target}"
rm -rf "$REMOTE_OUT"
cargo run -p mneme-cli -- determinism foundation-gate \\
  --out "$REMOTE_OUT" \\
  --timestamp "$TS"
EOF

  local remote_report
  remote_report="$(mktemp "${TMPDIR:-/tmp}/mneme-remote-report.XXXXXX.json")"
  scp "$MNEME_SECOND_HOST:$REMOTE_OUT/foundation.report.json" "$remote_report"

  compare_run_a_digests \
    "$local_out/foundation.report.json" \
    "$remote_report" \
    "local" \
    "$MNEME_SECOND_HOST"

  rm -f "$remote_report"
  bash "$ROOT/scripts/ci/check-foundation-digests.sh" "$local_out/foundation.report.json"

  echo "determinism-two-machine: SSH remote mode complete ($MNEME_SECOND_HOST)"
  echo "  scope: §17.7 cross-host (when peer is a distinct physical host)"
}

run_dual_workspace() {
  local isolation_root ws_a ws_b out_a out_b report_a report_b
  isolation_root="$(mktemp -d "${TMPDIR:-/tmp}/mneme-dual-ws.XXXXXX")"
  ws_a="$isolation_root/workspace-a"
  ws_b="$isolation_root/workspace-b"
  out_a="$ws_a/out/foundation-gate"
  out_b="$ws_b/out/foundation-gate"
  report_a="$out_a/foundation.report.json"
  report_b="$out_b/foundation.report.json"

  echo "determinism-two-machine: mode=CI-DUAL-WORKSPACE (no MNEME_SECOND_HOST)"
  echo "  scope: CI digest reproducibility — NOT §17.7 cross-host proof (see audit B4)"
  echo "  isolation_root: $isolation_root"

  local rsync_excludes=(
    --exclude target/
    --exclude out/
    --exclude .git/
    --exclude out/agent-targets/
  )
  rsync -a "${rsync_excludes[@]}" "$ROOT/" "$ws_a/"
  rsync -a "${rsync_excludes[@]}" "$ROOT/" "$ws_b/"

  run_workspace_gate() {
    local ws="$1"
    local label="$2"
    local out="$3"
    echo "==> $label foundation-gate"
    (
      cd "$ws"
      export CARGO_TARGET_DIR="$ws/target"
      mkdir -p "$CARGO_TARGET_DIR"
      cargo run -p mneme-cli -- determinism foundation-gate \
        --out "$out" \
        --timestamp "$TS"
    )
  }

  run_workspace_gate "$ws_a" "workspace-a" "$out_a"
  run_workspace_gate "$ws_b" "workspace-b" "$out_b"

  compare_run_a_digests "$report_a" "$report_b" "workspace-a" "workspace-b"
  bash "$ROOT/scripts/ci/check-foundation-digests.sh" "$report_a"

  echo "determinism-two-machine: dual-workspace mode complete"
  echo "  workspace-a report: $report_a"
  echo "  workspace-b report: $report_b"
  echo "  isolation_root (retained for inspection): $isolation_root"
}

if [[ -n "${MNEME_SECOND_HOST:-}" ]]; then
  run_ssh_remote
else
  echo "determinism-two-machine: MNEME_SECOND_HOST unset — using dual-workspace isolation."
  echo "  SSH cross-host proof: docs/MNEME_SECOND_HOST.md"
  run_dual_workspace
fi
