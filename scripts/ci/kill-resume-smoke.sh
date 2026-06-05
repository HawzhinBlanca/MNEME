#!/usr/bin/env bash
# Quick-lane kill/resume smoke (blueprint §18 quick, §17.3).
# Two cargo invocations (incomplete + kill_resume prefix) reduce lock churn vs five runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-kill-resume}"

if ! cargo check -p mneme-store --features internal_test_support --quiet 2>/dev/null; then
  echo "kill-resume-smoke: mneme-store does not build — failing closed until store kernel is green (§17.3)." >&2
  exit 1
fi

cargo test -p mneme-store --features internal_test_support --test e2e \
  e2e_incomplete_transaction_fails_closed_on_open \
  -- --nocapture
echo "kill-resume-smoke: e2e_incomplete_transaction_fails_closed_on_open OK"

cargo test -p mneme-store --features internal_test_support --test e2e e2e_kill_resume -- --nocapture
echo "kill-resume-smoke: e2e_kill_resume_* OK"

echo "kill-resume-smoke: all §17.3 kill/resume boundaries OK"
exit 0
