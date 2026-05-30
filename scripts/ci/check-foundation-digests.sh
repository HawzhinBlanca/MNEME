#!/usr/bin/env bash
# Compare latest foundation-gate output to pinned digests (§18, §20.5).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PINNED="$ROOT/proof/digests/foundation-gate.v1.json"
REPORT="${1:-$ROOT/out/ci-foundation-gate/foundation.report.json}"

if [[ ! -f "$PINNED" ]]; then
  echo "check-foundation-digests: no pinned digest file at $PINNED — skipping." >&2
  exit 0
fi
if [[ ! -f "$REPORT" ]]; then
  echo "check-foundation-digests: no report at $REPORT (run determinism lane first)." >&2
  exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
pinned = json.loads(Path("proof/digests/foundation-gate.v1.json").read_text())
run = report["run_a"]
keys = [
    "head_bytes_hex",
    "root_preimage_hex",
    "receipt_digest_hex",
    "absent_proof_digest_hex",
    "semantic_digest_hex",
]
mismatch = [k for k in keys if pinned.get(k) != run.get(k)]
if mismatch:
    print("check-foundation-digests: mismatch on", ", ".join(mismatch), file=sys.stderr)
    sys.exit(1)
print("check-foundation-digests: pinned digests match report run_a")
PY
