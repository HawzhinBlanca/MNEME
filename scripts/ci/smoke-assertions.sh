#!/usr/bin/env bash
# Shared assertions for cheap CI smoke scripts. Source from the repository root.

require_exact_line() {
  local label="$1"
  local output="$2"
  local expected="$3"

  if ! grep -Fqx -- "$expected" <<<"$output"; then
    echo "$label: missing expected line:" >&2
    echo "  $expected" >&2
    echo "$label: actual output:" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_exact_output() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  if [[ "$actual" != "$expected" ]]; then
    echo "$label: output mismatch" >&2
    echo "$label: expected output:" >&2
    printf '%s\n' "$expected" >&2
    echo "$label: actual output:" >&2
    printf '%s\n' "$actual" >&2
    exit 1
  fi
}

require_absent_substring() {
  local label="$1"
  local output="$2"
  local forbidden="$3"

  if grep -Fq -- "$forbidden" <<<"$output"; then
    echo "$label: forbidden output found: $forbidden" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_line_count() {
  local label="$1"
  local output="$2"
  local expected_count="$3"
  local actual_count

  actual_count="$(wc -l <<<"$output" | tr -d ' ')"
  if [[ "$actual_count" != "$expected_count" ]]; then
    echo "$label: expected exactly $expected_count output lines, got $actual_count" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_exit_status() {
  local label="$1"
  local actual_status="$2"
  local expected_status="$3"
  local output="$4"

  if [[ "$actual_status" != "$expected_status" ]]; then
    echo "$label: expected exit status $expected_status, got $actual_status" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}
