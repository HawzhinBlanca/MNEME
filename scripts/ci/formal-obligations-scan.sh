#!/usr/bin/env bash
# MNEME Formal Obligations Scanner (Phase III Local Scaffold).
# Scans the verifier TCB for line budget, unsafe code, and extracts formal invariants.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TCB_DIR="$ROOT/crates/mneme-verify/src"
LIB_RS="$TCB_DIR/lib.rs"
BUDGET=500

echo "=== MNEME Formal Obligations Scanner ==="

# 1. Check unsafe_code forbid
if ! grep -q "#\!\[forbid(unsafe_code)\]" "$LIB_RS"; then
  echo "[-] FAILED: #![forbid(unsafe_code)] is missing in $LIB_RS" >&2
  exit 1
fi
echo "[+] PASSED: #![forbid(unsafe_code)] is present in TCB root."

# 2. Count TCB lines
echo "[*] Scanning TCB files under $TCB_DIR..."
TOTAL_LINES=0
while IFS= read -r file; do
  LINES=$(wc -l "$file" | awk '{print $1}')
  echo "    - $(basename "$file"): $LINES lines"
  TOTAL_LINES=$((TOTAL_LINES + LINES))
done < <(find "$TCB_DIR" -type f -name "*.rs")

echo "[*] Total TCB line count: $TOTAL_LINES / $BUDGET lines"
if [ "$TOTAL_LINES" -gt "$BUDGET" ]; then
  echo "[-] FAILED: TCB line count exceeds budget of $BUDGET lines!" >&2
  exit 1
fi
echo "[+] PASSED: TCB line count compliant with budget."

# 3. Extract formal comments (INVARIANT, PROOF-OBLIGATION, HONESTY)
echo ""
echo "=== Formal Obligations & Invariants ==="
MATCHES=$(grep -rnE "//\s*(INVARIANT|PROOF-OBLIGATION|HONESTY):" "$TCB_DIR" || true)

if [ -z "$MATCHES" ]; then
  echo "    No explicit INVARIANT, PROOF-OBLIGATION, or HONESTY markers found in TCB src."
else
  # Print matches neatly
  while IFS= read -r line; do
    # Extract file name, line number, and content
    FILE_PATH=$(echo "$line" | cut -d: -f1)
    LINE_NUM=$(echo "$line" | cut -d: -f2)
    CONTENT=$(echo "$line" | cut -d: -f3-)
    
    FILE_BASE=$(basename "$FILE_PATH")
    printf "  [ %-12s : L%-3s ] %s\n" "$FILE_BASE" "$LINE_NUM" "$(echo "$CONTENT" | sed 's/^[[:space:]]*\/\/[[:space:]]*//')"
  done <<< "$MATCHES"
fi

echo ""
echo "[+] Scan complete: TCB is valid and invariants are compiled."
exit 0
