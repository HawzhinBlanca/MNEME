#!/usr/bin/env bash
# Fast executable contract check for validation-lane full-preflight.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

source scripts/ci/smoke-assertions.sh

label="full-preflight-smoke"
output="$(bash scripts/ci/validation-lane.sh full-preflight)"

require_exact_line "$label" "$output" "validation-lane (full-preflight): planned sublanes: quick crypto tamper merge determinism"
require_exact_line "$label" "$output" "validation-lane (full-preflight): heavy checks are NOT executed by this lane."
require_exact_line "$label" "$output" "validation-lane (full-preflight): Section 17.7 cross-host two-machine determinism is NOT proven by this lane (single host)."
require_exact_line "$label" "$output" "validation-lane (full-preflight): to prove it, set MNEME_SECOND_HOST and run scripts/ci/determinism-two-machine.sh on a distinct physical host."
require_exact_line "$label" "$output" "validation-lane (full-preflight): OK"

require_line_count "$label" "$output" "5"

require_absent_substring "$label" "$output" "Finished"
require_absent_substring "$label" "$output" "Running"
require_absent_substring "$label" "$output" "cargo "
require_absent_substring "$label" "$output" "fuzz"
require_absent_substring "$label" "$output" "bench"
require_absent_substring "$label" "$output" "ssh "
require_absent_substring "$label" "$output" "docker"

echo "full-preflight-smoke: OK"
