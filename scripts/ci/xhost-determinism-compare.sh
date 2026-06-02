#!/usr/bin/env bash
# Cross-host / cross-OS / cross-arch determinism check (§17.7), transport-free.
#
# The cross-host proof does NOT need SSH/rsync: the foundation-gate RunDigest is five
# cryptographic digests over fixed inputs with no path/host/OS/clock data. Run this on
# two independent machines at the SAME commit and compare the five printed lines.
#
#   Host A:  scripts/ci/xhost-determinism-compare.sh            # prints digests
#   Host B:  scripts/ci/xhost-determinism-compare.sh            # prints digests
#   then eyeball / diff the two outputs (or pass --expect <sha> to assert).
#
# Windows peers: run the equivalent one-liner from an "x64 Native Tools" prompt:
#   cargo run -q -p mneme-cli -- determinism foundation-gate --out out\xhost --timestamp 1970-01-01T00:00:00Z
#   powershell -NoProfile -Command "(Get-Content out\xhost\foundation.report.json|ConvertFrom-Json).run_a"
# No MNEME_NO_FSYNC needed: directory fsync is correctly a no-op on Windows (see atomic.rs).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

OUT="${1:-out/xhost-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)}"
rm -rf "$OUT"
cargo run -q -p mneme-cli -- determinism foundation-gate \
  --out "$OUT" --timestamp '1970-01-01T00:00:00Z' >/dev/null

REPORT="$OUT/foundation.report.json"
echo "# host        : $(uname -srm)"
echo "# commit      : $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "# report      : $REPORT"
# Print the five digested fields of run_a, one per line, stable order.
python3 - "$REPORT" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))["run_a"]
for k in ("head_bytes_hex","root_preimage_hex","receipt_digest_hex",
          "absent_proof_digest_hex","semantic_digest_hex"):
    print(f"{k} {a[k]}")
PY
