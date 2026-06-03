#!/usr/bin/env bash
# Cross-runner determinism (audit B4 honest substitute when no SSH peer).
#
# Proves foundation-gate run_a digests match across distinct GitHub-hosted runners
# (e.g. ubuntu-latest vs macos-latest). Does not replace ops SSH to a dedicated peer
# when one exists — see docs/MNEME_SECOND_HOST.md.
#
# Subcommands:
#   gate [--label LABEL] [--out DIR]
#   compare REPORT_A REPORT_B [LABEL_A LABEL_B]
#
# CI: .github/workflows/determinism-cross-runner.yml
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TS="${MNEME_DETERMINISM_TS:-1970-01-01T00:00:00Z}"
TWO_MACHINE="$ROOT/scripts/ci/determinism-two-machine.sh"

usage() {
  echo "Usage: $(basename "$0") gate [--label LABEL] [--out DIR]" >&2
  echo "       $(basename "$0") compare REPORT_A REPORT_B [LABEL_A LABEL_B]" >&2
  exit 2
}

run_gate() {
  local label="${MNEME_RUNNER_LABEL:-cross-runner}"
  local out="${MNEME_CROSS_RUNNER_OUT:-$ROOT/out/ci-cross-runner/$label}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --label)
        label="$2"
        shift 2
        ;;
      --out)
        out="$2"
        shift 2
        ;;
      *)
        echo "determinism-cross-runner: unknown gate arg: $1" >&2
        usage
        ;;
    esac
  done

  mneme_ci_init "$ROOT" "cross-runner-${label}"

  if ! cargo run -p mneme-cli -- determinism foundation-gate --help &>/dev/null; then
    echo "determinism-cross-runner: foundation-gate unavailable — failing closed." >&2
    exit 1
  fi

  rm -rf "$out"
  echo "determinism-cross-runner: mode=CROSS-RUNNER-GATE label=$label out=$out"
  echo "  runner_os=${RUNNER_OS:-local} runner_arch=${RUNNER_ARCH:-local}"

  cargo run -p mneme-cli -- determinism foundation-gate \
    --out "$out" \
    --timestamp "$TS"

  bash "$ROOT/scripts/ci/check-foundation-digests.sh" "$out/foundation.report.json"

  "$(mneme_ci_python)" - "$out/foundation.report.json" "$out/digest-manifest.json" "$label" <<'PY'
import json, os, sys
from datetime import datetime, timezone

report_path, manifest_path, label = sys.argv[1:4]
with open(report_path) as f:
    report = json.load(f)
run = report["run_a"]
manifest = {
    "mode": "cross-runner-gate",
    "label": label,
    "timestamp_fixture": os.environ.get("MNEME_DETERMINISM_TS", "1970-01-01T00:00:00Z"),
    "runner_os": os.environ.get("RUNNER_OS", "local"),
    "runner_arch": os.environ.get("RUNNER_ARCH", "local"),
    "github_sha": os.environ.get("GITHUB_SHA", ""),
    "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    "digests": {k: run[k] for k in [
        "head_bytes_hex",
        "root_preimage_hex",
        "receipt_digest_hex",
        "absent_proof_digest_hex",
        "semantic_digest_hex",
    ]},
}
with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
print(f"determinism-cross-runner: digest manifest -> {manifest_path}")
PY

  echo "determinism-cross-runner: gate OK ($label)"
}

run_compare() {
  local report_a="$1"
  local report_b="$2"
  local label_a="${3:-runner-a}"
  local label_b="${4:-runner-b}"

  if [[ ! -f "$report_a" || ! -f "$report_b" ]]; then
    echo "determinism-cross-runner: missing report(s)" >&2
    echo "  a=$report_a (exists=$([[ -f $report_a ]] && echo yes || echo no))" >&2
    echo "  b=$report_b (exists=$([[ -f $report_b ]] && echo yes || echo no))" >&2
    exit 1
  fi

  echo "determinism-cross-runner: mode=CROSS-RUNNER-COMPARE"
  echo "  scope: audit B4 — distinct CI runners (not dual-workspace on one host)"
  bash "$TWO_MACHINE" --compare-reports "$report_a" "$report_b" "$label_a" "$label_b"
  bash "$ROOT/scripts/ci/check-foundation-digests.sh" "$report_a"
  echo "determinism-cross-runner: compare OK ($label_a vs $label_b)"
}

cmd="${1:-}"
shift || true

case "$cmd" in
  gate)
    run_gate "$@"
    ;;
  compare)
    [[ $# -ge 2 ]] || usage
    run_compare "$@"
    ;;
  "")
    usage
    ;;
  *)
    echo "determinism-cross-runner: unknown command: $cmd" >&2
    usage
    ;;
esac
