#!/usr/bin/env bash
# Crypto lane: proof-verification fault injection (blueprint §18 crypto).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-crypto-fault}"

if cargo test -p mneme-crypto -p mneme-smt fault_injection -- --nocapture 2>/dev/null; then
  echo "crypto-fault-injection: dedicated tests OK"
  exit 0
fi

# Scaffold: no fault-injection module yet — fail closed until wired.
echo "crypto-fault-injection: no fault_injection tests in mneme-crypto/mneme-smt (§18 crypto) — failing closed." >&2
exit 1
