#!/usr/bin/env bash
# Full lane: Appendix B vector manifests and committed payloads present
# (blueprint §18 full, Appendix B). This fails closed on stale PASS manifests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VECTOR_ROOT="$ROOT/proof/vectors"
REQUIRED_DIRS=(
  objects
  dcbor
  smt
  roots
  receipts
  capabilities
  mst
)

missing=0
for dir in "${REQUIRED_DIRS[@]}"; do
  if [[ ! -d "$VECTOR_ROOT/$dir" ]]; then
    echo "check-test-vectors: missing $VECTOR_ROOT/$dir" >&2
    missing=1
  fi
done

if [[ ! -f "$VECTOR_ROOT/README.md" ]]; then
  echo "check-test-vectors: missing $VECTOR_ROOT/README.md" >&2
  missing=1
fi

if [[ "$missing" -ne 0 ]]; then
  echo "check-test-vectors: Appendix B layout incomplete — failing closed." >&2
  exit 1
fi

python3 - "$VECTOR_ROOT" <<'PY'
import json
import sys
from pathlib import Path

vector_root = Path(sys.argv[1])
required_dirs = ("objects", "dcbor", "smt", "roots", "receipts", "capabilities", "mst")
errors = []


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        errors.append(f"{path}: invalid json ({exc})")
        return {}


def require_payload(path: Path, label: str) -> bool:
    if not path.is_file():
        errors.append(f"{label}: missing {path}")
        return False
    if path.stat().st_size == 0:
        errors.append(f"{label}: empty {path}")
        return False
    return True


def require_pass_manifest(directory: str):
    manifest_path = vector_root / directory / "manifest.json"
    manifest = load_json(manifest_path)
    if manifest.get("status") != "pass":
        errors.append(f"{manifest_path}: status must be 'pass'")
    return manifest


def validate_objects(manifest):
    count = 0
    for entry in manifest.get("vectors", []):
        if require_payload(vector_root / "objects" / entry.get("cbor_file", ""), "objects"):
            count += 1
    root_manifest = load_json(vector_root / "object_id_manifest.json")
    for entry in root_manifest.get("vectors", []):
        require_payload(vector_root / entry.get("cbor_file", ""), "object_id_manifest")
    return count


def validate_dcbor(manifest):
    count = 0
    for entry in manifest.get("vectors", []):
        if require_payload(vector_root / "dcbor" / entry.get("cbor_file", ""), "dcbor"):
            count += 1
    root_manifest = load_json(vector_root / "dcbor_manifest.json")
    for entry in root_manifest.get("cases", []):
        path = vector_root / entry.get("cbor_file", "")
        if require_payload(path, "dcbor_manifest") and "cbor_hex" in entry:
            actual = path.read_bytes().hex()
            if actual != entry["cbor_hex"]:
                errors.append(f"dcbor_manifest: {path} hex mismatch")
    return count


def validate_listed_json(directory: str, manifest):
    count = 0
    for name in manifest.get("vectors", []):
        if require_payload(vector_root / directory / name, directory):
            count += 1
    return count


def validate_roots(manifest):
    count = 0
    for entry in manifest.get("vectors", []):
        if require_payload(vector_root / "roots" / entry.get("cbor_file", ""), "roots"):
            count += 1
    return count


def validate_receipts(manifest):
    count = 0
    for entry in manifest.get("vectors", []):
        if require_payload(vector_root / "receipts" / entry.get("object_cbor_file", ""), "receipts"):
            count += 1
    for name in manifest.get("partial_vectors", []):
        require_payload(vector_root / "receipts" / name, "receipts partial")
    return count


def validate_capabilities(manifest):
    count = 0
    for entry in manifest.get("vectors", []):
        if require_payload(vector_root / "capabilities" / entry.get("cbor_file", ""), "capabilities"):
            count += 1
    return count


validators = {
    "objects": validate_objects,
    "dcbor": validate_dcbor,
    "smt": lambda manifest: validate_listed_json("smt", manifest),
    "roots": validate_roots,
    "receipts": validate_receipts,
    "capabilities": validate_capabilities,
    "mst": lambda manifest: validate_listed_json("mst", manifest),
}

for directory in required_dirs:
    manifest = require_pass_manifest(directory)
    count = validators[directory](manifest)
    if count == 0:
        errors.append(f"{directory}: no committed vector payloads referenced by manifest")
    print(f"check-test-vectors: {directory} PASS ({count} committed vector payloads)")

if errors:
    for err in errors:
        print(f"check-test-vectors: {err}", file=sys.stderr)
    print("check-test-vectors: Appendix B manifests stale or incomplete — failing closed.", file=sys.stderr)
    sys.exit(1)
PY

echo "check-test-vectors: Appendix B manifests and payloads OK"
