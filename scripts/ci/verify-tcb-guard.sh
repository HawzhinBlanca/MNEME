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

# §17.6: numeric `as`-casts silently truncate/wrap and must not enter the verifier
# (use checked conversions / typed enum mappers). Matches `as u8|u16|.../i*/f*/usize`.
AS_CAST_PATTERN='\bas[[:space:]]+(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64)\b'
AS_CAST_HITS="$(grep -REn "$AS_CAST_PATTERN" "$TCB_DIR" --include='*.rs' 2>/dev/null \
  | grep -v 'tcb-cast-ok' || true)"

if [[ -n "$AS_CAST_HITS" ]]; then
  echo "TCB guard FAILED — numeric as-casts in mneme-verify (use checked conversions):"
  echo "$AS_CAST_HITS"
  exit 1
fi

# Extended trusted surface (§17.6 / TCB_MANIFEST.md): `verify_store` parses the
# on-disk object-keys / key-index sidecars via `mneme-index::key_index_load`, so
# that parser is part of the trusted surface even though it lives outside the
# budgeted `mneme-verify` crate. It is fully-trusted (no test module) and must also
# carry no panic vectors. Linting the whole crate would false-positive on legit
# `as`-casts elsewhere, so we lint exactly this file.
TRUSTED_PARSER="$ROOT/crates/mneme-index/src/key_index_load.rs"
if [[ -f "$TRUSTED_PARSER" ]]; then
  PARSER_HITS="$(grep -En "$FORBIDDEN" "$TRUSTED_PARSER" 2>/dev/null || true)"
  if [[ -n "$PARSER_HITS" ]]; then
    echo "TCB guard FAILED — forbidden patterns in trusted parser key_index_load.rs:"
    echo "$PARSER_HITS"
    exit 1
  fi
  echo "TCB guard: trusted parser key_index_load.rs clean"
fi

echo "TCB guard: mneme-verify source clean (no forbidden patterns, no slice-index panics)"
