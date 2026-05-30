#!/usr/bin/env bash
# Fail closed if mneme-verify TCB contains forbidden patterns (blueprint §10, §17.6).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TCB_DIR="$ROOT/crates/mneme-verify/src"

if [[ ! -d "$TCB_DIR" ]]; then
  echo "TCB guard: mneme-verify not present yet — skip"
  exit 0
fi

FORBIDDEN='unwrap\(|\.unwrap\(|expect\(|panic!|unreachable!|todo!|unimplemented!|\banyhow::'
HITS="$(grep -REn "$FORBIDDEN" "$TCB_DIR" --include='*.rs' 2>/dev/null || true)"

if [[ -n "$HITS" ]]; then
  echo "TCB guard FAILED — forbidden patterns in mneme-verify:"
  echo "$HITS"
  exit 1
fi

# §17.6: slice/array indexing (`ident[..]`) can panic on out-of-bounds. The TCB
# must use `.get(..)` and fail closed instead. Matches an identifier or field
# access immediately followed by `[` and a non-`]` char; this skips array TYPE
# literals (`[u8; 32]`), attributes (`#[..]`), and macros (`vec![..]`). A line
# may opt out with a trailing `// tcb-index-ok` marker when bounds are proven.
INDEX_PATTERN='[A-Za-z_][A-Za-z0-9_.]*\[[^]]'
INDEX_HITS="$(grep -REn "$INDEX_PATTERN" "$TCB_DIR" --include='*.rs' 2>/dev/null \
  | grep -v 'tcb-index-ok' || true)"

if [[ -n "$INDEX_HITS" ]]; then
  echo "TCB guard FAILED — slice-index panic vectors in mneme-verify (use .get()):"
  echo "$INDEX_HITS"
  exit 1
fi

echo "TCB guard: mneme-verify source clean (no forbidden patterns, no slice-index panics)"
