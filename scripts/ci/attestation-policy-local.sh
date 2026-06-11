#!/usr/bin/env bash
# P3 local scaffold: fail-closed attestation evidence parsing + policy placeholders.
#
# HONESTY: mneme-attest validates PEM/DER shape only — NOT vendor quote binding,
# Nitro/SGX/SEV measurement allowlists, or enclave execution proof. Live TEE
# attestation requires operator hardware and MNEME_TEE_ATTESTATION_EVIDENCE.
#
# Usage: scripts/ci/attestation-policy-local.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-attestation-policy-local}"

echo "attestation-policy-local: mode=LOCAL-PARSER (NOT live TEE/vendor quote proof)"

cargo test -p mneme-attest -- --nocapture

POLICY_DOC="$ROOT/docs/P3_LOCAL_SCAFFOLDS.md"
if [[ ! -f "$POLICY_DOC" ]]; then
  echo "attestation-policy-local: missing $POLICY_DOC" >&2
  exit 1
fi

if ! grep -q "AcceptedReportPolicy" "$POLICY_DOC"; then
  echo "attestation-policy-local: P3_LOCAL_SCAFFOLDS must document AcceptedReportPolicy placeholder" >&2
  exit 1
fi

if [[ -n "${MNEME_TEE_ATTESTATION_EVIDENCE:-}" ]]; then
  evidence_path="$MNEME_TEE_ATTESTATION_EVIDENCE"
  if [[ ! -s "$evidence_path" ]]; then
    echo "attestation-policy-local: MNEME_TEE_ATTESTATION_EVIDENCE must point at non-empty evidence: $evidence_path" >&2
    exit 1
  fi
  echo "attestation-policy-local: operator evidence file present ($evidence_path)"
  echo "  Vendor quote binding / AcceptedReportPolicy enforcement is NOT implemented in this scaffold."
else
  echo "attestation-policy-local: SKIP live TEE — MNEME_TEE_ATTESTATION_EVIDENCE unset."
  echo "  Parser/unit tests passed; vendor quote verification remains operator-gated."
fi

echo "attestation-policy-local: OK"
