#!/usr/bin/env bash
# P3 local scaffold: verifier TCB guard, budget scan, and obligation inventory.
#
# HONESTY: this inventories in-repo proof obligations — NOT a machine-checked Lean
# proof. Formal verification artifacts remain human-gated.
#
# Usage: scripts/ci/formal-obligations-local.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-formal-obligations-local}"

TCB_DIR="$ROOT/crates/mneme-verify/src"
LIB_RS="$TCB_DIR/lib.rs"
BUDGET=500

echo "=== MNEME Formal Obligations (local scaffold) ==="

bash "$ROOT/scripts/ci/verify-tcb-guard.sh"
cargo test -p mneme-verify --test tcb_budget -- --nocapture

if ! grep -q "#\!\[forbid(unsafe_code)\]" "$LIB_RS"; then
  echo "formal-obligations-local: missing #![forbid(unsafe_code)] in $LIB_RS" >&2
  exit 1
fi
echo "[+] #![forbid(unsafe_code)] present in TCB root."

TOTAL_LINES=0
while IFS= read -r file; do
  lines="$(wc -l <"$file" | tr -d ' ')"
  echo "    - $(basename "$file"): ${lines} lines"
  TOTAL_LINES=$((TOTAL_LINES + lines))
done < <(find "$TCB_DIR" -type f -name "*.rs")

echo "[*] Total TCB line count: $TOTAL_LINES / $BUDGET"
if [[ "$TOTAL_LINES" -gt "$BUDGET" ]]; then
  echo "formal-obligations-local: TCB exceeds budget ($TOTAL_LINES > $BUDGET)" >&2
  exit 1
fi
echo "[+] TCB line budget OK."

echo ""
echo "=== Formal Obligations & Invariants (grep inventory) ==="
matches="$(grep -rnE "//\s*(INVARIANT|PROOF-OBLIGATION|HONESTY):" "$TCB_DIR" || true)"
if [[ -z "$matches" ]]; then
  echo "formal-obligations-local: no INVARIANT/PROOF-OBLIGATION/HONESTY markers in TCB src" >&2
  exit 1
fi
while IFS= read -r line; do
  file_path="$(echo "$line" | cut -d: -f1)"
  line_num="$(echo "$line" | cut -d: -f2)"
  content="$(echo "$line" | cut -d: -f3-)"
  file_base="$(basename "$file_path")"
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*\/\/[[:space:]]*//')"
  printf "  [ %-12s : L%-3s ] %s\n" "$file_base" "$line_num" "$trimmed"
done <<<"$matches"

if [[ -d "$ROOT/proof/formal" ]]; then
  echo ""
  echo "[+] proof/formal/ present — operator Lean artifacts (human review required)"
else
  echo ""
  echo "[~] SKIP Lean proof — proof/formal/ absent (human-gated formal methods)"
fi

echo ""
echo "formal-obligations-local: OK (inventory only — not external formal proof)"
