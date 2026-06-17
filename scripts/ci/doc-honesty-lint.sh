#!/usr/bin/env bash
# doc-honesty-lint.sh — CI check for the §3 honesty qualifier on key claims.
#
# The §3 honesty boundary requires that broad claims about "verifiable retrieval"
# or "verifiable memory substrate" do not appear unqualified (without citing the
# §3 limitation/authenticity distinction).
#
# Rule: Every tracked *.md file that mentions "verifiable retrieval" or
# "verifiable memory substrate" (case-insensitive) on any line must qualify
# that line with the symbol "§3" (e.g. "verifiable retrieval (§3)") to ensure
# readers are directed to the honesty boundary and don't assume semantic truth
# or exact-NN optimality.
#
# Exit non-zero on any violation. Fail closed.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail=0
note() { printf '%s\n' "$*" >&2; }

while IFS= read -r md; do
  lineno=0
  while IFS= read -r line; do
    lineno=$((lineno + 1))
    
    # Check if the line matches "verifiable retrieval" or "verifiable memory substrate"
    # but does not contain "§3"
    if printf '%s' "$line" | grep -qiE "verifiable retrieval|verifiable memory substrate"; then
      if ! printf '%s' "$line" | grep -q "§3"; then
        note "UNQUALIFIED-CLAIM  $md:$lineno  line contains \"verifiable retrieval\" or \"verifiable memory substrate\" but lacks the §3 qualifier."
        note "  Line: $line"
        fail=1
      fi
    fi
  done < "$md"
done < <(git ls-files '*.md')

if [ "$fail" -ne 0 ]; then
  note ""
  note "doc-honesty-lint: FAILED — found unqualified claims. Add the \"(§3)\" qualifier."
  exit 1
fi

echo "doc-honesty-lint: OK — all key claims in docs carry §3 qualifications."
