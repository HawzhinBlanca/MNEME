#!/usr/bin/env bash
# Local two-run determinism check (B6 partial): same host, two isolated out dirs.
# Full §17.7 proof still requires MNEME_SECOND_HOST — see docs/MNEME_SECOND_HOST.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-determinism-local}"

TS="${MNEME_DETERMINISM_TS:-1970-01-01T00:00:00Z}"
OUT_A="$ROOT/out/ci-foundation-gate"
OUT_B="$ROOT/out/ci-foundation-gate-2"

if ! cargo run -p mneme-cli -- determinism foundation-gate --help &>/dev/null; then
  echo "determinism-local-second-host: mneme-cli foundation-gate unavailable — failing closed." >&2
  exit 1
fi

rm -rf "$OUT_A" "$OUT_B"
cargo run -p mneme-cli -- determinism foundation-gate --out "$OUT_A" --timestamp "$TS"
cargo run -p mneme-cli -- determinism foundation-gate --out "$OUT_B" --timestamp "$TS"

export OUT_A OUT_B
python3 - <<'PY'
import json, os, sys

def load_run(path):
    with open(path) as f:
        return json.load(f)["run_a"]

a = load_run(os.environ["OUT_A"] + "/foundation.report.json")
b = load_run(os.environ["OUT_B"] + "/foundation.report.json")
keys = [
    "head_bytes_hex",
    "root_preimage_hex",
    "receipt_digest_hex",
    "absent_proof_digest_hex",
    "semantic_digest_hex",
]
mismatch = [k for k in keys if a.get(k) != b.get(k)]
if mismatch:
    print("determinism-local-second-host: mismatch on", ", ".join(mismatch), file=sys.stderr)
    sys.exit(1)
print("determinism-local-second-host: OK (run_a digests identical across two local gates)")
for k in keys:
    print(f"  {k}: {a[k]}")
PY

bash scripts/ci/check-foundation-digests.sh "$OUT_A/foundation.report.json"
