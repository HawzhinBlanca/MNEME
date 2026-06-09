#!/usr/bin/env bash
# Fail closed if mneme-verify TCB contains forbidden patterns (blueprint §10, §17.6).
set -euo pipefail

ROOT="${MNEME_GUARD_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
FORBIDDEN='\bunsafe\b|\b(debug_assert|debug_assert_eq|debug_assert_ne|assert|assert_eq|assert_ne)\s*!|\b(dbg|print|println|eprint|eprintln|trace|debug|info|warn|error)\s*!|\b(log|tracing)\s*::|\bunwrap_err\s*\(|\bexpect_err\s*\(|\bunwrap_or(?:_else|_default)?\s*\(|\bmap_or(?:_else)?\s*\(|\bDefault\b|::\s*default\s*\(|\.\s*or_default\s*\(|\b(?:std\s*::\s*)?mem\s*::\s*take\s*\(|\.\s*(ok|err|is_ok|is_err|is_some|is_none|contains_key|contains|filter|filter_map|find_map|flat_map|flatten|next|next_back|last|nth|find|position|rposition|count|all|any|retain|retain_mut|clear|truncate|drain|splice|split_off|sort|sort_by|sort_by_key|sort_unstable|sort_unstable_by|sort_unstable_by_key|dedup|dedup_by|dedup_by_key|reverse|swap_remove|remove|pop)\s*\(|\bmatches\s*!|\b(f32|f64|NAN|INFINITY|NEG_INFINITY)\b|\b[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?(?:f32|f64)?\b|\b[0-9]+(?:f32|f64)\b|\.\s*(partial_cmp|total_cmp|is_nan|is_finite|is_infinite|is_normal|classify)\s*\(|\bunwrap\s*\(|\bexpect\s*\(|\bpanic_any\s*\(|\bresume_unwind\s*\(|\bcatch_unwind\s*\(|\b(SystemTime|Instant)\s*::\s*now\s*\(|\b(?:std\s*::\s*)?env\s*::\s*(args|args_os|current_dir|current_exe|set_current_dir|temp_dir|var|var_os|vars|vars_os)\s*\(|\b(?:(?:std\s*::\s*)?io\s*::\s*)?(stdin|stdout|stderr)\s*\(|\b(?:std\s*::\s*)?process\s*::\s*id\s*\(|\b(?:std\s*::\s*)?thread\s*::\s*current\s*\(|\b(?:std\s*::\s*)?backtrace\s*::\s*Backtrace\s*::\s*(capture|force_capture)\s*\(|\b(env|option_env|include|include_str|include_bytes)\s*!|\b(?:(?:(std|tokio)\s*::\s*)?process\s*::\s*)?Command\s*::\s*new\s*\(|\b(?:(std|tokio)\s*::\s*)?net\s*::\s*(TcpListener|TcpStream|ToSocketAddrs|UdpSocket|UnixListener|UnixStream|lookup_host)\b|\b(reqwest|hyper|ureq|isahc)\s*::|\b(?:std\s*::\s*)?fs\s*::\s*(metadata|symlink_metadata|canonicalize|read_dir|read_link|copy|create_dir|create_dir_all|hard_link|remove_dir|remove_dir_all|remove_file|rename|set_permissions|write)\s*\(|\b(?:File\s*::\s*(create|open)|OpenOptions\s*::\s*new)\s*\(|\.\s*(metadata|symlink_metadata|canonicalize|read_dir|read_link)\s*\(|\b(?:std\s*::\s*)?thread\s*::\s*spawn\s*\(|\b(?:tokio\s*::\s*)?(?:task\s*::\s*)?(spawn|spawn_blocking|spawn_local)\s*\(|\b(?:tokio\s*::\s*task\s*::\s*)?JoinSet\s*::|\b(rand|rand_core|getrandom)\s*::|\b(OsRng|StdRng|SmallRng|ThreadRng)\b|\b(from_entropy|from_os_rng|thread_rng|SystemRandom\s*::\s*new)\s*\(|\bstatic\s+mut\b|\blazy_static\s*!|\b(Once|OnceCell|OnceLock|LazyCell|LazyLock|Mutex|RwLock|Cell|RefCell)\b|\bAtomic(Bool|U8|U16|U32|U64|Usize|I8|I16|I32|I64|Isize|Ptr)\b|\bthread_local\s*!|\b(HashMap|HashSet|DefaultHasher|RandomState|BuildHasher|SipHasher|IndexMap|IndexSet)\b|\b(hashbrown|indexmap)\s*::|\.\s*exists\s*\(|\bPath\s*::\s*exists\s*\(|\b(?:std\s*::\s*)?mem\s*::\s*forget\s*\(|\b(ManuallyDrop|MaybeUninit|NonNull)\b|\b(?:std\s*::\s*)?ptr\s*::|\b(?:Box|String|Vec)\s*::\s*leak\s*\(|\binto_raw(?:_parts)?\s*\(|\bfrom_raw(?:_parts|_parts_mut)?\s*\(|\btransmute(?:_copy)?\s*\(|\bextern\b|\b(libc|nix)\s*::|\b(?:std|core)\s*::\s*arch\s*::|\b(?:asm|global_asm)\s*!|\b(?:std\s*::\s*)?process\s*::\s*(abort|exit)\s*\(|\bpanic\s*!|\bunreachable\s*!|\btodo\s*!|\bunimplemented\s*!|\banyhow::'

rust_code_hits() {
  local pattern allow_marker stop_at_cfg_test
  pattern="$1"
  allow_marker="$2"
  stop_at_cfg_test="$3"
  shift 3

  "$PYTHON_BIN" - "$pattern" "$allow_marker" "$stop_at_cfg_test" "$@" <<'PY'
import os
import re
import sys

pattern = re.compile(sys.argv[1])
allow_marker = sys.argv[2]
stop_at_cfg_test = sys.argv[3] == "1"
roots = sys.argv[4:]
CFG_ATTR_START = re.compile(r"\s*#\[\s*cfg\s*\(")


def rust_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames.sort()
                for filename in sorted(filenames):
                    if filename.endswith(".rs"):
                        yield os.path.join(dirpath, filename)
        elif path.endswith(".rs"):
            yield path


def advance(text, index):
    if index >= len(text):
        return index
    return index + 1


def raw_string_start(text, index):
    if text.startswith("br", index):
        cursor = index + 2
    elif text.startswith("r", index):
        cursor = index + 1
    else:
        return None

    hashes = 0
    while cursor + hashes < len(text) and text[cursor + hashes] == "#":
        hashes += 1
    if cursor + hashes < len(text) and text[cursor + hashes] == '"':
        return cursor + hashes + 1 - index, hashes
    return None


def raw_string_ends_at(text, index, hashes):
    if index >= len(text) or text[index] != '"':
        return False
    return text[index + 1:index + 1 + hashes] == "#" * hashes


def is_hex_digit(ch):
    return ch.isdigit() or ch in "abcdefABCDEF"


def skip_quoted(text, index):
    quote = text[index]
    index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == quote:
            return index + 1
        else:
            index += 1
    return index


def split_top_level_args(expr):
    args = []
    start = 0
    depth = 0
    index = 0
    while index < len(expr):
        ch = expr[index]
        if ch in "\"'":
            index = skip_quoted(expr, index)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(expr[start:index])
            start = index + 1
        index += 1
    args.append(expr[start:])
    return args


def call_inner(expr, name):
    expr = expr.strip()
    if not expr.startswith(name):
        return None
    index = len(name)
    while index < len(expr) and expr[index].isspace():
        index += 1
    if index >= len(expr) or expr[index] != "(":
        return None

    start = index + 1
    depth = 1
    index = start
    while index < len(expr):
        ch = expr[index]
        if ch in "\"'":
            index = skip_quoted(expr, index)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                tail = expr[index + 1:].strip()
                return expr[start:index] if not tail else None
        index += 1
    return None


def cfg_expr_implies_test(expr):
    expr = expr.strip()
    if expr == "test":
        return True

    all_inner = call_inner(expr, "all")
    if all_inner is not None:
        return any(cfg_expr_implies_test(arg) for arg in split_top_level_args(all_inner))

    not_inner = call_inner(expr, "not")
    if not_inner is not None:
        double_negative_inner = call_inner(not_inner, "not")
        if double_negative_inner is not None:
            return cfg_expr_implies_test(double_negative_inner)

    return False


def cfg_test_attr_end(code_line):
    match = CFG_ATTR_START.match(code_line)
    if not match:
        return None

    expr_start = match.end()
    depth = 1
    index = expr_start
    while index < len(code_line):
        ch = code_line[index]
        if ch in "\"'":
            index = skip_quoted(code_line, index)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        index += 1
    else:
        return None

    expr = code_line[expr_start:index]
    index += 1
    while index < len(code_line) and code_line[index].isspace():
        index += 1
    if index >= len(code_line) or code_line[index] != "]":
        return None

    return index + 1 if cfg_expr_implies_test(expr) else None


def skip_one_attribute(code_line, index):
    index, complete, _ = consume_attribute_brackets(code_line, index, 0)
    return index, complete


def consume_attribute_brackets(code_line, index, depth):
    while index < len(code_line):
        ch = code_line[index]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            index += 1
            if depth == 0:
                return index, True, depth
            continue
        index += 1
    return index, False, depth


def consume_pending_attribute_line(code_line, depth):
    index, complete, depth = consume_attribute_brackets(code_line, 0, depth)
    if complete:
        return code_line[index:], 0, code_line[:index]
    return "", depth, code_line


def leading_attribute_stack(code_line):
    index = 0
    has_cfg_test = False
    while True:
        while index < len(code_line) and code_line[index].isspace():
            index += 1
        if not code_line.startswith("#[", index):
            return index, has_cfg_test, True, 0, ""

        attr_start = index
        if cfg_test_attr_end(code_line[index:]) is not None:
            has_cfg_test = True

        next_index, complete, depth = consume_attribute_brackets(code_line, index, 0)
        index = next_index
        if not complete:
            return index, has_cfg_test, False, depth, code_line[attr_start:index]
        continue


def leading_attribute_stack_on_complete_line(code_line):
    index, has_cfg_test, complete, _, _ = leading_attribute_stack(code_line)
    return index, has_cfg_test, complete


def char_literal_len(text, index):
    if text.startswith("b'", index):
        is_byte = True
        cursor = index + 2
    elif text.startswith("'", index):
        is_byte = False
        cursor = index + 1
    else:
        return None

    if cursor >= len(text) or text[cursor] == "'":
        return None

    if text[cursor] != "\\":
        cursor = advance(text, cursor)
    else:
        cursor += 1
        if cursor >= len(text):
            return None
        escape = text[cursor]
        if escape == "x":
            if cursor + 2 >= len(text):
                return None
            if not is_hex_digit(text[cursor + 1]) or not is_hex_digit(text[cursor + 2]):
                return None
            cursor += 3
        elif escape == "u":
            if is_byte or cursor + 1 >= len(text) or text[cursor + 1] != "{":
                return None
            cursor += 2
            digits = 0
            while cursor < len(text) and text[cursor] != "}":
                if not is_hex_digit(text[cursor]):
                    return None
                digits += 1
                if digits > 6:
                    return None
                cursor += 1
            if cursor >= len(text) or text[cursor] != "}" or digits == 0:
                return None
            cursor += 1
        elif escape in "'\"nrt0\\":
            cursor += 1
        else:
            return None

    if cursor < len(text) and text[cursor] == "'":
        return cursor + 1 - index
    return None


def masked_lines(source):
    block_depth = 0
    literal = None
    for line in source.splitlines():
        masked = []
        line_comment = ""
        index = 0
        while index < len(line):
            if block_depth:
                if line.startswith("/*", index):
                    block_depth += 1
                    index += 2
                elif line.startswith("*/", index):
                    block_depth -= 1
                    index += 2
                else:
                    index = advance(line, index)
                masked.append(" ")
                continue

            if literal:
                kind, hashes = literal
                if kind == "normal":
                    if line.startswith("\\", index):
                        index += 1
                        index = advance(line, index)
                    elif line.startswith('"', index):
                        literal = None
                        index += 1
                    else:
                        index = advance(line, index)
                else:
                    if raw_string_ends_at(line, index, hashes):
                        index += 1 + hashes
                        literal = None
                    else:
                        index = advance(line, index)
                masked.append(" ")
                continue

            if line.startswith("//", index):
                line_comment = line[index + 2:]
                break
            if line.startswith("/*", index):
                block_depth += 1
                index += 2
                masked.append(" ")
                continue
            char_len = char_literal_len(line, index)
            if char_len is not None:
                index += char_len
                masked.append(" ")
                continue
            raw_start = raw_string_start(line, index)
            if raw_start is not None:
                prefix_len, hashes = raw_start
                literal = ("raw", hashes)
                index += prefix_len
                masked.append(" ")
                continue
            if line.startswith('"', index):
                literal = ("normal", 0)
                index += 1
                masked.append(" ")
                continue

            masked.append(line[index])
            index = advance(line, index)
        yield "".join(masked), line_comment


def skip_leading_attributes(code_line, index):
    while True:
        while index < len(code_line) and code_line[index].isspace():
            index += 1
        if not code_line.startswith("#[", index):
            return index, True

        index, complete = skip_one_attribute(code_line, index)
        if not complete:
            return index, False


def consume_cfg_test_item_from_start(code_line):
    index, attributes_complete = skip_leading_attributes(code_line, 0)
    if not attributes_complete or not code_line[index:].strip():
        return "", True, True, 0

    depth = 0
    saw_body = False
    while index < len(code_line):
        ch = code_line[index]
        if ch == "{":
            depth += 1
            saw_body = True
        elif ch == "}" and saw_body:
            depth -= 1
            if depth <= 0:
                return code_line[index + 1:], False, False, 0
        elif ch == ";" and not saw_body:
            return code_line[index + 1:], False, False, 0
        index += 1

    if saw_body:
        return "", True, False, depth
    return "", True, True, 0


def consume_pending_cfg_test_line(code_line, waiting_for_body, brace_depth):
    if waiting_for_body:
        return consume_cfg_test_item_from_start(code_line)

    depth = brace_depth
    for index, ch in enumerate(code_line):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth <= 0:
                return code_line[index + 1:], False, False, 0
    return "", True, False, depth


for path in rust_files(roots):
    with open(path, "r", encoding="utf-8") as handle:
        source = handle.read()
    original_lines = source.splitlines()
    skipping_cfg_test_item = False
    waiting_for_cfg_test_body = False
    cfg_test_brace_depth = 0
    pending_leading_attr_depth = 0
    pending_leading_attr_text = ""
    leading_stack_has_cfg_test = False
    for line_number, (code_line, line_comment) in enumerate(masked_lines(source), start=1):
        if stop_at_cfg_test:
            while True:
                if pending_leading_attr_depth:
                    (
                        code_line,
                        pending_leading_attr_depth,
                        consumed_attr_text,
                    ) = consume_pending_attribute_line(
                        code_line,
                        pending_leading_attr_depth,
                    )
                    pending_leading_attr_text += "\n" + consumed_attr_text
                    if pending_leading_attr_depth:
                        break
                    if cfg_test_attr_end(pending_leading_attr_text) is not None:
                        leading_stack_has_cfg_test = True
                    pending_leading_attr_text = ""
                    continue

                if skipping_cfg_test_item:
                    (
                        code_line,
                        skipping_cfg_test_item,
                        waiting_for_cfg_test_body,
                        cfg_test_brace_depth,
                    ) = consume_pending_cfg_test_line(
                        code_line,
                        waiting_for_cfg_test_body,
                        cfg_test_brace_depth,
                    )
                    if skipping_cfg_test_item:
                        break
                    continue

                (
                    attr_end,
                    has_cfg_test,
                    attributes_complete,
                    attr_depth,
                    pending_attr_text,
                ) = leading_attribute_stack(code_line)
                has_cfg_test = leading_stack_has_cfg_test or has_cfg_test
                if not attributes_complete:
                    pending_leading_attr_depth = attr_depth
                    pending_leading_attr_text = pending_attr_text
                    leading_stack_has_cfg_test = has_cfg_test
                    code_line = ""
                    break
                if not has_cfg_test:
                    leading_stack_has_cfg_test = False
                    break

                leading_stack_has_cfg_test = False
                (
                    code_line,
                    skipping_cfg_test_item,
                    waiting_for_cfg_test_body,
                    cfg_test_brace_depth,
                ) = consume_cfg_test_item_from_start(code_line[attr_end:])
                if skipping_cfg_test_item:
                    break
            if skipping_cfg_test_item:
                continue
        if allow_marker and allow_marker in line_comment:
            continue
        if pattern.search(code_line):
            print(f"{path}:{line_number}:{original_lines[line_number - 1].strip()}")
PY
}

run_guard() {
  local root tcb_dir trusted_parser hits index_hits as_cast_hits parser_hits parser_index_hits parser_cast_hits
  local semantic_file semantic_hits semantic_index_hits semantic_cast_hits
  root="${1:-$ROOT}"
  tcb_dir="${MNEME_TCB_DIR:-$root/crates/mneme-verify/src}"
  trusted_parser="${MNEME_TRUSTED_PARSER:-$root/crates/mneme-index/src/key_index_load.rs}"
  local semantic_surface=(
    "$root/crates/mneme-index/src/verify.rs"
    "$root/crates/mneme-index/src/procedure.rs"
    "$root/crates/mneme-index/src/provenance.rs"
    "$root/crates/mneme-index/src/commit.rs"
    "$root/crates/mneme-index/src/semantic_zk.rs"
    "$root/crates/mneme-index/src/zkann.rs"
  )

  if [[ ! -d "$tcb_dir" ]]; then
    echo "TCB guard: mneme-verify not present yet — skip"
    return 0
  fi

  hits="$(rust_code_hits "$FORBIDDEN" "" 0 "$tcb_dir")"

  if [[ -n "$hits" ]]; then
    echo "TCB guard FAILED — forbidden patterns in mneme-verify:"
    echo "$hits"
    return 1
  fi

  # §17.6: slice/array indexing can panic on out-of-bounds. The TCB must use
  # `.get(..)` and fail closed instead. Matches identifier/field indexing with
  # optional whitespace, plus indexing of call/group/prior-index/try results;
  # this skips array TYPE literals (`[u8; 32]`), attributes (`#[..]`), and bare
  # macro calls (`vec![..]`). A line may opt out with a trailing
  # `// tcb-index-ok` marker when bounds are proven.
  INDEX_PATTERN='([A-Za-z_][A-Za-z0-9_.]*|\)|\]|\?)\s*\[[^]]'
  index_hits="$(rust_code_hits "$INDEX_PATTERN" "tcb-index-ok" 0 "$tcb_dir")"

  if [[ -n "$index_hits" ]]; then
    echo "TCB guard FAILED — slice-index panic vectors in mneme-verify (use .get()):"
    echo "$index_hits"
    return 1
  fi

  # §17.6: numeric `as`-casts silently truncate/wrap and must not enter the verifier
  # (use checked conversions / typed enum mappers). Matches `as u8|u16|.../i*/f*/usize`.
  AS_CAST_PATTERN='\bas\s+(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64)\b'
  as_cast_hits="$(rust_code_hits "$AS_CAST_PATTERN" "tcb-cast-ok" 0 "$tcb_dir")"

  if [[ -n "$as_cast_hits" ]]; then
    echo "TCB guard FAILED — numeric as-casts in mneme-verify (use checked conversions):"
    echo "$as_cast_hits"
    return 1
  fi

  # Semantic receipt verification is Tier-2 trusted surface (TCB_MANIFEST.md).
  # It is outside the 500-line orchestration budget, but it must still reject
  # obvious verifier hazards and randomized hash collections. Deterministic
  # sorting/truncation remains allowed here because procedure replay is the
  # semantic verifier's job.
  local SEMANTIC_FORBIDDEN='\bunsafe\b|\b(debug_assert|debug_assert_eq|debug_assert_ne|assert|assert_eq|assert_ne)\s*!|\bunwrap_err\s*\(|\bexpect_err\s*\(|\bunwrap\s*\(|\bexpect\s*\(|\bpanic_any\s*\(|\bresume_unwind\s*\(|\bcatch_unwind\s*\(|\bpanic\s*!|\bunreachable\s*!|\btodo\s*!|\bunimplemented\s*!|\banyhow::|\b(HashMap|HashSet|DefaultHasher|RandomState|BuildHasher|SipHasher|IndexMap|IndexSet)\b|\b(hashbrown|indexmap)\s*::'
  for semantic_file in "${semantic_surface[@]}"; do
    if [[ ! -f "$semantic_file" ]]; then
      continue
    fi
    semantic_hits="$(rust_code_hits "$SEMANTIC_FORBIDDEN" "" 1 "$semantic_file")"
    if [[ -n "$semantic_hits" ]]; then
      echo "TCB guard FAILED — forbidden patterns in semantic trusted surface ${semantic_file#$root/}:"
      echo "$semantic_hits"
      return 1
    fi
    semantic_index_hits="$(rust_code_hits "$INDEX_PATTERN" "tcb-index-ok" 1 "$semantic_file")"
    if [[ -n "$semantic_index_hits" ]]; then
      echo "TCB guard FAILED — slice-index panic vectors in semantic trusted surface ${semantic_file#$root/} (use .get() or justify with tcb-index-ok):"
      echo "$semantic_index_hits"
      return 1
    fi
    semantic_cast_hits="$(rust_code_hits "$AS_CAST_PATTERN" "tcb-cast-ok" 1 "$semantic_file")"
    if [[ -n "$semantic_cast_hits" ]]; then
      echo "TCB guard FAILED — numeric as-casts in semantic trusted surface ${semantic_file#$root/} (use checked conversions):"
      echo "$semantic_cast_hits"
      return 1
    fi
  done
  echo "TCB guard: semantic trusted surface clean"

  # Extended trusted surface (§17.6 / TCB_MANIFEST.md): `verify_store` parses the
  # on-disk object-keys / key-index sidecars via `mneme-index::key_index_load`, so
  # that parser is part of the trusted surface even though it lives outside the
  # budgeted `mneme-verify` crate. Production code remains trusted even after
  # code-visible #[cfg(test)] items; those test-only items may use normal test
  # assertions. Linting the whole crate would
  # false-positive on legit `as`-casts elsewhere, so we lint exactly this file.
  if [[ -f "$trusted_parser" ]]; then
    parser_hits="$(rust_code_hits "$FORBIDDEN" "" 1 "$trusted_parser")"
    if [[ -n "$parser_hits" ]]; then
      echo "TCB guard FAILED — forbidden patterns in trusted parser key_index_load.rs:"
      echo "$parser_hits"
      return 1
    fi
    parser_index_hits="$(rust_code_hits "$INDEX_PATTERN" "tcb-index-ok" 1 "$trusted_parser")"
    if [[ -n "$parser_index_hits" ]]; then
      echo "TCB guard FAILED — slice-index panic vectors in trusted parser key_index_load.rs (use .get()):"
      echo "$parser_index_hits"
      return 1
    fi
    parser_cast_hits="$(rust_code_hits "$AS_CAST_PATTERN" "tcb-cast-ok" 1 "$trusted_parser")"
    if [[ -n "$parser_cast_hits" ]]; then
      echo "TCB guard FAILED — numeric as-casts in trusted parser key_index_load.rs (use checked conversions):"
      echo "$parser_cast_hits"
      return 1
    fi
    echo "TCB guard: trusted parser key_index_load.rs clean"
  fi

  echo "TCB guard: mneme-verify source clean (no forbidden patterns, no slice-index panics)"
}

self_test_tcb_src() {
  printf '%s/crates/mneme-verify/src' "$1"
}

self_test_trusted_parser() {
  printf '%s/crates/mneme-index/src/key_index_load.rs' "$1"
}

reset_tcb_self_test_fixture() {
  local tmp layout src
  tmp="$1"
  layout="${2:-flat}"
  src="$(self_test_tcb_src "$tmp")"
  rm -rf "$src"
  if [[ "$layout" == "nested" ]]; then
    mkdir -p "$src/nested"
  else
    mkdir -p "$src"
  fi
}

write_root_tcb_self_test_fixture() {
  cat >"$(self_test_tcb_src "$1")/lib.rs" <<'RS'
pub fn root_fixture() {}
RS
}

run_self_test_guard() {
  local tmp
  tmp="$1"
  MNEME_TCB_DIR="$(self_test_tcb_src "$tmp")" \
    MNEME_TRUSTED_PARSER="$(self_test_trusted_parser "$tmp")" \
    run_guard "$tmp" 2>&1
}

run_self_test() {
  local tmp out
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mkdir -p "$tmp/crates/mneme-index/src"
  reset_tcb_self_test_fixture "$tmp" nested
  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}
RS
  cat >"$tmp/crates/mneme-index/src/verify.rs" <<'RS'
pub fn semantic_surface_fixture() {}
RS

  cat >"$tmp/crates/mneme-index/src/verify.rs" <<'RS'
use std::collections::HashSet;

pub fn semantic_surface_fixture() {
    let _set = HashSet::<u8>::new();
    panic!("semantic trusted surface must be scanned");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — semantic trusted surface was not scanned"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"semantic trusted surface"* || "$out" != *"HashSet"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — semantic trusted surface hits were not reported"
    echo "$out"
    return 1
  fi
  cat >"$tmp/crates/mneme-index/src/verify.rs" <<'RS'
pub fn semantic_surface_fixture() {}
RS
  echo "TCB guard self-test: semantic trusted surface coverage OK"

  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
#![forbid(unsafe_code)]
// .unwrap( .expect( panic!( unreachable!( todo!( unimplemented!( anyhow:: value as usize data[0]
/* .unwrap( panic!(
   .expect( todo!( value as u64 data[1] */
pub fn docs_only() {
    let _message = "panic!( .expect( anyhow:: value as usize data[0]";
    let _raw = r#".unwrap( todo!( unimplemented!( value as u64 data[1]"#;
}
RS
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
// .unwrap( panic!( value as usize data[0]
pub fn nested_docs_only() {
    let _message = "panic!( value as usize data[0]";
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — comments/strings should not trip the guard"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn byte_raw_and_nested_comments_are_docs_only() {
    let _bytes = br##".unwrap( panic!( todo!( unimplemented!( value as usize data[0]"##;
    /* outer .expect( value as u64 data[1]
       /* inner panic!( anyhow:: data[2] */
       unreachable!( value as i32 data[3]
    */
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — byte raw strings and nested comments should not trip the guard"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner masks byte raw strings and nested block comments OK"

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn escaped_and_multiline_strings_are_docs_only() {
    let _escaped = "escaped quote: \" panic!( .expect( anyhow:: value as usize data[0]";
    let _multiline = "first line .unwrap( value as u64 data[1]
second line todo!( unimplemented!( data[2]
third line unreachable!( value as i32 data[3]";
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — escaped quotes and multiline strings should not trip the guard"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner masks escaped quotes and multiline normal strings OK"

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn quote_char_literal_does_not_hide_following_code() {
    let _quote = '"';
    panic!("real TCB code after quote char must still be scanned");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — quote char literal hid following production panic!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — production panic! after quote char was not reported"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn byte_quote_char_literal_does_not_hide_following_code() {
    let _quote = b'"';
    panic!("real TCB code after byte quote char must still be scanned");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — byte quote char literal hid following production panic!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — production panic! after byte quote char was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner handles char and byte char literals without hiding code OK"

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn lifetime_syntax_does_not_hide_following_code<'a>() { panic!("real TCB code after lifetime must still be scanned"); let _marker: Option<&'a ()> = None; }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — lifetime syntax hid following production panic!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — production panic! after lifetime syntax was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner keeps lifetime syntax from masking production code OK"

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn line_comment_markers_opt_out_when_bounds_are_proven(data: &[u8], value: u64) -> usize {
    let _byte = data[0]; // tcb-index-ok
    value as usize // tcb-cast-ok
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — line-comment opt-out markers should be honored"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn marker_string_does_not_hide_index(data: &[u8]) -> u8 {
    let _marker = "tcb-index-ok"; data[0]
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — string marker hid following production index!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"slice-index panic vectors"* ]]; then
    echo "TCB guard self-test FAILED — production index after string marker was not reported"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/lib.rs" <<'RS'
pub fn marker_string_does_not_hide_cast(value: u64) -> usize {
    let _marker = "tcb-cast-ok"; value as usize
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — string marker hid following production cast!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"numeric as-casts"* ]]; then
    echo "TCB guard self-test FAILED — production cast after string marker was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner only honors opt-out markers in line comments OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_forbidden() {
    panic!("real TCB code must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — real forbidden code was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"panic!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — real panic! hit was not reported"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_unsafe(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — unsafe code was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unsafe"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — unsafe code hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects unsafe code OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_assert(value: u8) -> u8 {
    assert!(value != 0);
    value
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — production assert macro was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"assert!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — production assert macro hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects production assert macros OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_whitespace_macro_invocations(value: u8) -> u8 {
    assert ! (value != 0);
    debug_assert_eq ! (value, value);
    if value == 1 {
        panic ! ("trusted production code must fail closed");
    }
    if value == 2 {
        unreachable ! ("trusted production code must fail closed");
    }
    if value == 3 {
        todo ! ("trusted production code must fail closed");
    }
    if value == 4 {
        unimplemented ! ("trusted production code must fail closed");
    }
    value
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — whitespace macro invocations were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"assert !"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace assert macro hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"debug_assert_eq !"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace debug_assert_eq macro hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"panic !"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace panic macro hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unreachable !"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace unreachable macro hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"todo !"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace todo macro hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unimplemented !"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace unimplemented macro hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects whitespace macro invocations OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_result_error_unwraps() -> (u8, u8) {
    let left = Ok::<u8, u8>(7).unwrap_err();
    let right = Ok::<u8, u8>(9).expect_err("fixture must fail closed");
    (left, right)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — Result unwrap_err/expect_err helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unwrap_err"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Result unwrap_err hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"expect_err"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Result expect_err hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects Result unwrap_err/expect_err OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_fallback_default_helpers(value: Option<u8>) -> (u8, u8, u8, u8, u8) {
    let direct = value.unwrap_or(0);
    let lazy = value.unwrap_or_else(|| 1);
    let defaulted = value.unwrap_or_default();
    let mapped = value.map_or(2, |n| n);
    let mapped_lazy = value.map_or_else(|| 3, |n| n);
    (direct, lazy, defaulted, mapped, mapped_lazy)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — fallback default helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unwrap_or"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — unwrap_or hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unwrap_or_else"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — unwrap_or_else hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unwrap_or_default"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — unwrap_or_default hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"map_or"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — map_or hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"map_or_else"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — map_or_else hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects fallback default helpers OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
#[derive(Default)]
struct ImplicitSidecar {
    entries: std::collections::BTreeMap<String, String>,
}

pub fn real_implicit_default_constructors(
    mut sidecar: ImplicitSidecar,
) -> (ImplicitSidecar, std::collections::BTreeMap<String, String>) {
    let derived: ImplicitSidecar = Default::default();
    let associated = ImplicitSidecar::default();
    sidecar.entries.entry("trusted".to_owned()).or_default();
    let taken = std::mem::take(&mut sidecar.entries);
    (associated, taken)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — implicit default constructors were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Default"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Default hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"::default"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — associated default hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"or_default"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — or_default hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"mem::take"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — mem::take hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects implicit default constructors OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_result_option_conversions() -> (Option<u8>, Option<&'static str>) {
    let value = Ok::<u8, &'static str>(7).ok();
    let error = Err::<u8, &'static str>("trusted errors must stay typed").err();
    (value, error)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — Result-to-Option conversions were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *".ok("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Result::ok hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *".err("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Result::err hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects Result-to-Option conversions OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_result_option_predicate_collapse(value: Option<u8>) -> bool {
    let accepted = Ok::<u8, &'static str>(7).is_ok();
    let rejected = Err::<u8, &'static str>("trusted errors must stay typed").is_err();
    let present = value.is_some();
    let missing = value.is_none();
    let matched = matches!(value, Some(7));
    accepted || rejected || present || missing || matched
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — Result/Option predicate collapse was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"is_ok"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — is_ok hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"is_err"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — is_err hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"is_some"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — is_some hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"is_none"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — is_none hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"matches!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — matches! hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects Result/Option predicate collapse OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_collection_membership_predicates(
    entries: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    tombstones: Vec<[u8; 32]>,
    id: [u8; 32],
) -> bool {
    entries.contains_key(&id) || tombstones.contains(&id)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — collection membership predicates were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"contains_key"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — contains_key hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"contains"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — contains hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects collection membership predicates OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_iterator_elision_helpers(values: Vec<u8>) -> Vec<u8> {
    let first = values
        .iter()
        .find_map(|value| if *value == 7 { Some(*value) } else { None });
    values
        .into_iter()
        .filter(|value| *value != 0)
        .filter_map(|value| if value > 1 { Some(value) } else { None })
        .flat_map(|value| [value])
        .map(Some)
        .flatten()
        .chain(first)
        .collect()
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — iterator elision helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"filter"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — filter hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"filter_map"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — filter_map hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"find_map"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — find_map hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"flat_map"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — flat_map hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"flatten"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — flatten hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects iterator elision helpers OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_iterator_terminal_selection(
    values: Vec<u8>,
) -> (
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<usize>,
    Option<usize>,
    Option<u8>,
) {
    let first = values.iter().next().copied();
    let last = values.iter().last().copied();
    let nth = values.iter().nth(2).copied();
    let found = values.iter().find(|value| **value == 7).copied();
    let position = values.iter().position(|value| *value == 7);
    let reverse_position = values.iter().rposition(|value| *value == 7);
    let mut iter = values.iter();
    let back = iter.next_back().copied();
    (first, last, nth, found, position, reverse_position, back)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — iterator terminal selection helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"next"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — next hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"last"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — last hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"nth"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — nth hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"find"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — find hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"position"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — position hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"rposition"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — rposition hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"next_back"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — next_back hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects iterator terminal selection helpers OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_iterator_aggregate_predicates(values: Vec<u8>) -> bool {
    let nonzero_count = values.iter().count();
    values.iter().all(|value| *value != 0)
        || values.iter().any(|value| *value == 7)
        || nonzero_count == 1
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — iterator aggregate predicates were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"count"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — count hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"all"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — all hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"any"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — any hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects iterator aggregate predicates OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_retain_based_silent_filtering(mut values: Vec<u8>) -> Vec<u8> {
    values.retain(|value| *value != 0);
    values.retain_mut(|value| {
        *value += 1;
        *value != 7
    });
    values
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — retain-based silent filtering was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"retain"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — retain hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"retain_mut"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — retain_mut hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects retain-based silent filtering OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_bulk_collection_mutation(mut values: Vec<u8>) -> Vec<u8> {
    let _dropped: Vec<u8> = values.drain(0..1).collect();
    values.splice(0..0, [9]);
    let _tail = values.split_off(1);
    values.truncate(2);
    values.clear();
    values
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — bulk collection mutation helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"drain"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — drain hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"splice"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — splice hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"split_off"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — split_off hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"truncate"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — truncate hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"clear"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — clear hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects bulk collection mutation OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_collection_reorder_and_dedup(mut values: Vec<u8>) -> Vec<u8> {
    values.sort();
    values.sort_by(|left, right| left.cmp(right));
    values.sort_by_key(|value| *value);
    values.sort_unstable();
    values.sort_unstable_by(|left, right| left.cmp(right));
    values.sort_unstable_by_key(|value| *value);
    values.dedup();
    values.dedup_by(|left, right| left == right);
    values.dedup_by_key(|value| *value);
    values.reverse();
    let _dropped = values.swap_remove(0);
    values
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — collection reorder/dedup helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"sort"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — sort hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"sort_by"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — sort_by hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"sort_by_key"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — sort_by_key hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"sort_unstable"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — sort_unstable hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"sort_unstable_by"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — sort_unstable_by hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"sort_unstable_by_key"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — sort_unstable_by_key hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"dedup"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — dedup hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"dedup_by"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — dedup_by hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"dedup_by_key"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — dedup_by_key hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"reverse"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — reverse hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"swap_remove"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — swap_remove hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects collection reorder/dedup helpers OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_collection_remove_and_pop(
    mut values: Vec<u8>,
    mut entries: std::collections::BTreeMap<String, String>,
    key: String,
) -> Vec<u8> {
    let _entry = entries.remove(&key);
    let _dropped = values.remove(0);
    let _tail = values.pop();
    values
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — collection remove/pop helpers were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"remove"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — remove hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"pop"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — pop hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects collection remove/pop helpers OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_floating_point_hazards(value: f64) -> bool {
    let threshold: f32 = 0.5f32;
    let literal = 1.25;
    let nan = f64::NAN;
    let infinite = f32::INFINITY;
    value.partial_cmp(&literal).is_some()
        || value.total_cmp(&literal).is_eq()
        || value.is_nan()
        || value.is_finite()
        || nan.is_infinite()
        || infinite.is_normal()
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — floating-point hazards were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"f64"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — f64 hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"f32"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — f32 hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"0.5"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — float literal hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"NAN"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — NaN hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"INFINITY"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — infinity hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"partial_cmp"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — partial_cmp hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"total_cmp"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — total_cmp hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"is_nan"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — is_nan hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"is_finite"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — is_finite hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects floating-point hazards OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_whitespace_panic_calls() -> (u8, u8, u8, u8) {
    let left = Ok::<u8, u8>(7).unwrap ();
    let right = Some(8).expect ("fixture must have a value");
    let err_left = Ok::<u8, u8>(9).unwrap_err ();
    let err_right = Ok::<u8, u8>(10).expect_err ("fixture must fail closed");
    (left, right, err_left, err_right)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — whitespace panic-capable calls were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unwrap ()"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace unwrap hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"expect ("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace expect hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"unwrap_err ()"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace unwrap_err hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"expect_err ("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — whitespace expect_err hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects whitespace panic calls OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_panic_any() {
    std::panic::panic_any("trusted production code must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — panic_any was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"panic_any"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — panic_any hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects panic_any OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_resume_unwind() {
    std::panic::resume_unwind(Box::new("trusted production code must fail closed"));
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — resume_unwind was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"resume_unwind"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — resume_unwind hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects resume_unwind OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_catch_unwind() -> u8 {
    let result = std::panic::catch_unwind(|| 7);
    result.unwrap_or(0)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — catch_unwind was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"catch_unwind"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — catch_unwind hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects catch_unwind OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_process_termination() {
    std::process::abort();
    std::process::exit(1);
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — process termination calls were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"process::abort"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — process abort hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"process::exit"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — process exit hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects process termination OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_ambient_time_reads() {
    let _wall = std::time::SystemTime::now();
    let _mono = std::time::Instant::now();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — ambient time reads were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"SystemTime::now"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — SystemTime::now hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Instant::now"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Instant::now hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects ambient time OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_ambient_process_state_reads() {
    let _value = std::env::var("MNEME_TCB_SELF_TEST");
    let _vars = std::env::vars_os();
    let _cwd = std::env::current_dir();
    let _exe = std::env::current_exe();
    let _tmp = std::env::temp_dir();
    let _args = std::env::args_os();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — ambient process-state reads were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env::var"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env::var hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env::vars_os"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env::vars_os hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env::current_dir"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env::current_dir hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env::current_exe"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env::current_exe hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env::temp_dir"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env::temp_dir hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env::args_os"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env::args_os hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects ambient process state OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::io;
use std::process;
use std::thread;

pub fn real_ambient_runtime_probes() {
    let _stdin = std::io::stdin();
    let _stdout = io::stdout();
    let _stderr = io::stderr();
    let _pid = process::id();
    let _thread = thread::current().id();
    let _backtrace = std::backtrace::Backtrace::capture();
    let _forced = std::backtrace::Backtrace::force_capture();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — ambient runtime probes were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"std::io::stdin"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — std::io::stdin hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"io::stdout"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — io::stdout hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"io::stderr"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — io::stderr hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"process::id"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — process::id hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"thread::current"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — thread::current hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Backtrace::capture"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Backtrace::capture hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Backtrace::force_capture"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Backtrace::force_capture hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects ambient runtime probes OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::process::Command;

pub fn real_process_spawning() {
    let _qualified = std::process::Command::new("sh").arg("-c").arg("true").status();
    let _imported = Command::new("sh").arg("-c").arg("true").output();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — process spawning was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"process::Command::new"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — qualified process Command::new hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Command::new"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — imported Command::new hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects process spawning OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_network_io() {
    let _tcp = std::net::TcpStream::connect("127.0.0.1:1");
    let _udp = std::net::UdpSocket::bind("127.0.0.1:0");
    let _async_tcp = tokio::net::TcpStream::connect("127.0.0.1:1");
    let _http = reqwest::blocking::get("http://127.0.0.1:1/");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — network I/O was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"net::TcpStream::connect"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — TcpStream::connect hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"net::UdpSocket::bind"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — UdpSocket::bind hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"tokio::net"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — tokio::net hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"reqwest::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — reqwest hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects network I/O OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::fs::{File, OpenOptions};

pub fn real_filesystem_mutation() {
    let _write = std::fs::write("trusted-output", b"must not mutate");
    let _remove = std::fs::remove_file("trusted-output");
    let _rename = std::fs::rename("trusted-output", "trusted-output-next");
    let _file = File::create("trusted-output");
    let _options = OpenOptions::new().write(true).open("trusted-output");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — filesystem mutation was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::write"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::write hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::remove_file"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::remove_file hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::rename"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::rename hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"File::create"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — File::create hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"OpenOptions::new"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — OpenOptions::new hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects filesystem mutation OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::fs::File;
use std::path::Path;

pub fn real_filesystem_probe_traversal(path: &Path) {
    let _metadata = std::fs::metadata(path);
    let _symlink_metadata = std::fs::symlink_metadata(path);
    let _canonical = std::fs::canonicalize(path);
    let _dir = std::fs::read_dir(path);
    let _link = std::fs::read_link(path);
    let _opened = File::open(path);
    let _path_metadata = path.metadata();
    let _path_canonical = path.canonicalize();
    let _path_link = path.read_link();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — filesystem probe/traversal APIs were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::metadata"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::metadata hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::symlink_metadata"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::symlink_metadata hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::canonicalize"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::canonicalize hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::read_dir"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::read_dir hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"fs::read_link"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — fs::read_link hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"File::open"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — File::open hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *".metadata("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Path::metadata hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *".canonicalize("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Path::canonicalize hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *".read_link("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Path::read_link hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects filesystem probe/traversal OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::thread;

pub async fn real_concurrency_spawning() {
    let _thread = std::thread::spawn(|| 1);
    let _imported = thread::spawn(|| 2);
    let _tokio = tokio::spawn(async { 3 });
    let _blocking = tokio::task::spawn_blocking(|| 4);
    let _local = tokio::task::spawn_local(async { 5 });
    let _join_set = tokio::task::JoinSet::<u8>::new();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — concurrency spawning was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"thread::spawn"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — thread::spawn hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"tokio::spawn"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — tokio::spawn hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"spawn_blocking"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — spawn_blocking hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"spawn_local"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — spawn_local hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"JoinSet"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — JoinSet hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects concurrency spawning OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use rand::rngs::{OsRng, StdRng};

pub fn real_entropy_use() {
    let mut bytes = Vec::new();
    let _bytes = getrandom::getrandom(bytes.as_mut_slice());
    let _thread = rand::thread_rng();
    let _random: u64 = rand::random();
    let _os = OsRng;
    let _std = StdRng::from_entropy();
    let _ring = ring::rand::SystemRandom::new();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — entropy use was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"getrandom::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — getrandom hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"rand::thread_rng"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — rand::thread_rng hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"rand::random"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — rand::random hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"OsRng"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — OsRng hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"from_entropy"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — from_entropy hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"SystemRandom::new"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — SystemRandom::new hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects entropy use OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{LazyLock, Mutex, OnceLock, RwLock};

static mut TRUSTED_COUNTER: usize = 0;
static TRUSTED_CACHE: OnceLock<u8> = OnceLock::new();
static TRUSTED_LAZY: LazyLock<Mutex<u8>> = LazyLock::new(|| Mutex::new(0));
static TRUSTED_RWLOCK: RwLock<u8> = RwLock::new(0);
static TRUSTED_ATOMIC: AtomicUsize = AtomicUsize::new(0);
static TRUSTED_FLAG: AtomicBool = AtomicBool::new(false);

thread_local! {
    static TRUSTED_THREAD_LOCAL: std::cell::RefCell<u8> = std::cell::RefCell::new(0);
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — global mutable state was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"static mut"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — static mut hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"OnceLock"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — OnceLock hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"LazyLock"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — LazyLock hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Mutex"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Mutex hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"RwLock"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — RwLock hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"AtomicUsize"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — AtomicUsize hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"thread_local"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — thread_local hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"RefCell"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — RefCell hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects global mutable state OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::BuildHasher;

pub fn real_randomized_hash_collections() {
    let _map: HashMap<String, String> = HashMap::new();
    let _set: HashSet<String> = HashSet::new();
    let _state = RandomState::new();
    let _hasher = DefaultHasher::new();
    let _trait_ref: Option<&dyn BuildHasher> = None;
    let _external: hashbrown::HashMap<String, String> = hashbrown::HashMap::new();
    let _index_map: indexmap::IndexMap<String, String> = indexmap::IndexMap::new();
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — randomized hash collections were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"HashMap"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — HashMap hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"HashSet"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — HashSet hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"RandomState"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — RandomState hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"DefaultHasher"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — DefaultHasher hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"BuildHasher"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — BuildHasher hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"hashbrown::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — hashbrown hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"indexmap::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — indexmap hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects randomized hash collections OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::path::{Path, PathBuf};

pub fn real_path_exists_probe(path: &Path) -> bool {
    let generated = PathBuf::from("meta/object_keys.json");
    path.exists() || generated.exists() || Path::new("roots/HEAD").exists() || Path::exists(path)
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — Path::exists probes were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *".exists("* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Path::exists hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Path::exists"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Path::exists UFCS hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects path exists probes OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
use std::mem::{self, ManuallyDrop, MaybeUninit};
use std::ptr::{self, NonNull};

pub fn real_manual_memory_primitives(value: Vec<u8>) {
    let _manual = ManuallyDrop::new(value);
    let _maybe = MaybeUninit::<u8>::uninit();
    let boxed = Box::new(7_u8);
    let _leaked = Box::leak(boxed);
    let _dangling = NonNull::<u8>::dangling();
    let _addr = ptr::addr_of!(_maybe);
    let _raw = Vec::<u8>::into_raw_parts(Vec::new());
    mem::forget(_manual);
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — manual memory primitives were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"ManuallyDrop"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — ManuallyDrop hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"MaybeUninit"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — MaybeUninit hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"Box::leak"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — Box::leak hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"NonNull"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — NonNull hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"ptr::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — ptr:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"into_raw"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — into_raw hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"mem::forget"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — mem::forget hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects manual memory primitives OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_compile_time_ambient_inputs() {
    let _build_profile = env!("PROFILE");
    let _optional_config = option_env!("MNEME_TCB_CONFIG");
    let _fixture_text = include_str!("hidden_fixture.txt");
    let _fixture_bytes = include_bytes!("hidden_fixture.bin");
    include!("generated_verifier_fragment.rs");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — compile-time ambient inputs were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"env!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — env! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"option_env!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — option_env! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"include_str!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — include_str! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"include_bytes!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — include_bytes! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"include!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — include! hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects compile-time ambient inputs OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
extern "C" {
    fn verifier_hook();
}

pub fn real_diagnostics_and_native_hooks(value: u8) {
    println!("verifier trace {value}");
    eprintln!("verifier error {value}");
    let _ = dbg!(value);
    log::warn!("verifier warning {value}");
    tracing::debug!("verifier debug {value}");
    let _ = libc::getpid();
    let _ = nix::unistd::getpid();
    let _ = std::arch::is_x86_feature_detected!("avx2");
    core::arch::asm!("nop");
    global_asm!("");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — diagnostics and native hooks were accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"println!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — println! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"eprintln!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — eprintln! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"dbg!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — dbg! hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"log::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — log:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"tracing::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — tracing:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"extern \""* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — extern block hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"libc::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — libc:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"nix::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — nix:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"std::arch::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — std::arch:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"core::arch::"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — core::arch:: hit was not reported"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"global_asm!"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — global_asm! hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner rejects diagnostics and native hooks OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_cast(value: u64) -> usize {
    value as usize
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — real numeric cast was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"numeric as-casts"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — real numeric cast hit was not reported"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn real_index(slice: &[u8]) -> u8 {
    slice[0]
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — real slice index was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"slice-index panic vectors"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — real slice index hit was not reported"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn spaced_index(slice: &[u8]) -> u8 {
    slice [0]
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — spaced slice index was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"slice-index panic vectors"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — spaced slice index hit was not reported"
    echo "$out"
    return 1
  fi

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn call_result_index() -> u8 {
    fn bytes() -> [u8; 1] {
        [0]
    }
    bytes()[0]
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — call-result slice index was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"slice-index panic vectors"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — call-result slice index hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner catches spaced and expression-result indexes OK"

  reset_tcb_self_test_fixture "$tmp" nested
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_tcb_src "$tmp")/nested/mod.rs" <<'RS'
pub fn try_result_index() -> Result<u8, ()> {
    fn fallible_bytes() -> Result<[u8; 1], ()> {
        Ok([0])
    }
    Ok(fallible_bytes()?[0])
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — try-result slice index was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"slice-index panic vectors"* || "$out" != *"nested/mod.rs"* ]]; then
    echo "TCB guard self-test FAILED — try-result slice index hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: scanner catches try-result indexes OK"

  reset_tcb_self_test_fixture "$tmp"
  write_root_tcb_self_test_fixture "$tmp"
  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
mod tests {
    #[test]
    fn fixture_tests_may_use_normal_assertions() {
        let value = Some(7).expect("fixture has a value");
        assert_eq!(value, 7);
        panic!("fixture-only panic must stay outside production scanning");
    }
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser #[cfg(test)] fixtures should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {
    panic!("trusted parser production code must fail closed");
}

#[cfg(test)]
mod tests {}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production panic! was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production panic! hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) boundary OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture(slice: &[u8]) -> u8 {
    slice[0]
}

#[cfg(test)]
mod tests {}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production index was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"slice-index panic vectors"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production index hit was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture(value: u64) -> usize {
    value as usize
}

#[cfg(test)]
mod tests {}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production cast was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"numeric as-casts"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production cast hit was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser index and cast guards OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
mod tests {
    #[test]
    fn fixture_tests_may_use_normal_assertions() {
        panic!("fixture-only panic must stay outside production scanning");
    }
}

pub fn production_after_tests_must_still_be_scanned() {
    panic!("trusted parser production code after tests must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) item was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) item was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser resumes scanning after cfg(test) items OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)] fn inline_fixture_tests_may_panic() { panic!("fixture-only panic must stay outside production scanning"); } pub fn production_after_inline_cfg_item() { panic!("trusted parser production after inline cfg item must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) item was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) item was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser inline cfg(test) items resume scanning OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)] #[allow(dead_code)] fn inline_attribute_stack_fixture_may_panic() { panic!("fixture-only panic must stay outside production scanning"); } pub fn production_after_inline_attribute_stack() { panic!("trusted parser production after inline attribute stack must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) attribute stack was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) attribute stack was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
#[allow(dead_code)]
fn split_attribute_stack_fixture_may_panic() {
    panic!("fixture-only panic must stay outside production scanning");
}

pub fn production_after_split_attribute_stack() {
    panic!("trusted parser production after split attribute stack must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after split cfg(test) attribute stack was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after split cfg(test) attribute stack was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) attribute stacks resume scanning OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[allow(dead_code)] #[cfg(test)] fn pre_attr_inline_fixture_may_panic() {
    panic!("fixture-only panic must stay outside production scanning");
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser inline cfg(test) after another attribute should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[allow(dead_code)]
#[cfg(test)]
fn pre_attr_split_fixture_may_panic() {
    panic!("fixture-only panic must stay outside production scanning");
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser split cfg(test) after another attribute should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[allow(dead_code)] #[cfg(any(test, feature = "production-feature"))]
fn pre_attr_non_test_cfg_stays_scanned() {
    panic!("trusted parser cfg(any(test, feature)) after another attribute must stay scanned");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(any(test, feature)) after another attribute was mistaken for test-only cfg"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser cfg(any(test, feature)) after another attribute was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) after other attributes OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[allow(
    dead_code
)] #[cfg(test)] fn multiline_pre_attr_fixture_may_panic() {
    panic!("fixture-only panic must stay outside production scanning");
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(test) after closing multiline attribute should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[allow(
    dead_code
)] #[cfg(any(test, feature = "production-feature"))] fn multiline_pre_attr_non_test_cfg_stays_scanned() {
    panic!("trusted parser cfg(any(test, feature)) after closing multiline attribute must stay scanned");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(any(test, feature)) after closing multiline attribute was mistaken for test-only cfg"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser cfg(any(test, feature)) after closing multiline attribute was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser multiline attributes before cfg(test) OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[ cfg ( test ) ]
mod spaced_tests {
    #[test]
    fn fixture_tests_may_panic() {
        panic!("fixture-only panic must stay outside production scanning");
    }
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser spaced cfg(test) fixtures should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(testing)]
mod not_the_test_cfg {
    pub fn cfg_testing_code_stays_scanned() {
        panic!("trusted parser cfg(testing) must not be treated as cfg(test)");
    }
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(testing) was mistaken for cfg(test)"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser cfg(testing) production code was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser spaced cfg(test) attributes OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(all(test, feature = "fixture-helpers"))]
mod compound_test_cfg {
    #[test]
    fn fixture_tests_may_panic() {
        panic!("fixture-only panic must stay outside production scanning");
    }
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(all(test, ...)) fixtures should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(any(test, feature = "production-feature"))]
mod maybe_production_cfg {
    pub fn any_test_or_feature_stays_scanned() {
        panic!("trusted parser cfg(any(test, feature)) must not be treated as test-only");
    }
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(any(test, feature)) was mistaken for test-only cfg"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser cfg(any(test, feature)) production code was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser compound cfg(test) attributes OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(not(not(test)))]
mod double_negative_test_cfg {
    #[test]
    fn fixture_tests_may_panic() {
        panic!("fixture-only panic must stay outside production scanning");
    }
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(not(not(test))) fixtures should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(not(test))]
mod non_test_cfg {
    pub fn not_test_code_stays_scanned() {
        panic!("trusted parser cfg(not(test)) must not be treated as test-only");
    }
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(not(test)) was mistaken for test-only cfg"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser cfg(not(test)) production code was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser logical cfg(test) attributes OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(all(
    test,
    feature = "fixture-helpers"
))]
mod multiline_compound_test_cfg {
    #[test]
    fn fixture_tests_may_panic() {
        panic!("fixture-only panic must stay outside production scanning");
    }
}
RS
  if ! out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser multiline cfg(all(test, ...)) fixtures should not trip the guard"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(any(
    test,
    feature = "production-feature"
))]
mod multiline_maybe_production_cfg {
    pub fn any_test_or_feature_stays_scanned() {
        panic!("trusted parser multiline cfg(any(test, feature)) must not be treated as test-only");
    }
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser multiline cfg(any(test, feature)) was mistaken for test-only cfg"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser multiline cfg(any(test, feature)) production code was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser multiline cfg(test) attributes OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)] use core::fmt::Debug; pub fn production_after_inline_cfg_use_item() { panic!("trusted parser production after inline cfg use item must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) semicolon item was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) semicolon item was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
type FixtureOnlyAlias = usize;

pub fn production_after_split_cfg_type_alias() {
    panic!("trusted parser production after split cfg type alias must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after split cfg(test) semicolon item was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after split cfg(test) semicolon item was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)] macro_rules! fixture_only_macro { () => {{ panic!("fixture-only panic must stay outside production scanning"); }}; } pub fn production_after_cfg_macro_item() { panic!("trusted parser production after cfg macro item must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) macro item was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) macro item was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) semicolon and macro items resume scanning OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
fn multiline_signature_fixture<T>(
    value: T,
) where
    T: Copy,
{
    let _ = value;
    panic!("fixture-only panic must stay outside production scanning");
}

pub fn production_after_multiline_signature() {
    panic!("trusted parser production after multiline cfg signature must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) multiline signature was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) multiline signature was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
fn multiline_signature_inline_resume_fixture<T>(
    value: T,
) where
    T: Copy,
{
    let _ = value;
    panic!("fixture-only panic must stay outside production scanning");
} pub fn production_after_inline_multiline_signature_body() { panic!("trusted parser production after inline multiline body close must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) multiline body close was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) multiline body close was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) multiline signatures resume scanning OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
struct FixtureOnly;

#[cfg(test)]
impl FixtureOnly {
    fn method_fixture_may_panic(&self) {
        panic!("fixture-only panic must stay outside production scanning");
    }
}

pub fn production_after_cfg_impl_block() {
    panic!("trusted parser production after cfg impl block must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) impl block was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) impl block was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
struct InlineFixtureOnly;

#[cfg(test)]
impl InlineFixtureOnly {
    fn nested_method_fixture_may_panic(&self) {
        if true {
            panic!("fixture-only panic must stay outside production scanning");
        }
    }
} pub fn production_after_inline_cfg_impl_close() { panic!("trusted parser production after inline cfg impl close must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) impl close was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) impl close was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) impl blocks resume scanning OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
trait FixtureTrait {
    fn default_fixture_method_may_panic(&self) {
        panic!("fixture-only panic must stay outside production scanning");
    }
}

pub fn production_after_cfg_trait_block() {
    panic!("trusted parser production after cfg trait block must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) trait block was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) trait block was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)]
enum FixtureEnum {
    Variant = {
        panic!("fixture-only panic must stay outside production scanning");
        1
    },
}

pub fn production_after_cfg_enum_block() {
    panic!("trusted parser production after cfg enum block must fail closed");
}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) enum block was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after cfg(test) enum block was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {}

#[cfg(test)] extern "C" { fn fixture_only_symbol(); } pub fn production_after_inline_cfg_extern_block() { panic!("trusted parser production after inline cfg extern block must fail closed"); }
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) extern block was accepted"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production after inline cfg(test) extern block was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) trait/enum/extern blocks resume scanning OK"

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
pub fn trusted_parser_fixture() {
    let _cfg_test_text = r#"
#[cfg(test)]
"#;
    panic!("trusted parser production code after cfg text must still be scanned");
}

#[cfg(test)]
mod tests {}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(test) text in a string hid production panic!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production panic! after cfg text was not reported"
    echo "$out"
    return 1
  fi

  cat >"$(self_test_trusted_parser "$tmp")" <<'RS'
/*
#[cfg(test)]
*/
pub fn trusted_parser_fixture() {
    panic!("trusted parser production code after cfg comment must still be scanned");
}

#[cfg(test)]
mod tests {}
RS
  if out="$(run_self_test_guard "$tmp")"; then
    echo "TCB guard self-test FAILED — trusted parser cfg(test) text in a comment hid production panic!"
    echo "$out"
    return 1
  fi
  if [[ "$out" != *"trusted parser key_index_load.rs"* || "$out" != *"panic!"* ]]; then
    echo "TCB guard self-test FAILED — trusted parser production panic! after cfg comment was not reported"
    echo "$out"
    return 1
  fi
  echo "TCB guard self-test: trusted parser cfg(test) cutoff ignores comments/strings OK"

  echo "TCB guard self-test: OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_self_test
  exit $?
fi

run_guard "$ROOT"
