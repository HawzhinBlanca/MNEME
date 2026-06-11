#!/usr/bin/env bash
# P3 local scaffold: EnvelopeKeyVault adapter contract round-trip (no cloud KMS).
#
# HONESTY: this is NOT live AWS/GCP/PKCS#11 continuous proof. Live endpoint
# verification requires AWS_KMS_KEY_ID (or operator HSM credentials) and is
# human-gated.
#
# Usage: scripts/kms/conformance-local.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
mneme_ci_init "$ROOT" "${MNEME_CI_LANE:-kms-conformance-local}"

echo "kms/conformance-local: mode=LOCAL-VAULT (EnvelopeKeyVault contract — NOT live KMS/HSM proof)"

cargo test -p mneme-crypto -- \
  envelope_vault_roundtrip_and_shred \
  envelope_and_memory_vaults_have_identical_behaviour \
  --nocapture

if [[ -n "${AWS_KMS_KEY_ID:-}" ]] && command -v aws >/dev/null 2>&1; then
  echo "kms/conformance-local: AWS_KMS_KEY_ID set — running dek-from-aws bridge smoke"
  eval "$(bash "$ROOT/scripts/kms/dek-from-aws.sh" --emit-env)"
  if [[ ${#MNEME_KMS_MASTER_KEY_HEX} -ne 64 ]]; then
    echo "kms/conformance-local: dek-from-aws did not yield 32-byte hex DEK" >&2
    exit 1
  fi
  echo "kms/conformance-local: live AWS GenerateDataKey bridge OK (operator-gated endpoint proof)"
else
  echo "kms/conformance-local: SKIP live KMS — AWS_KMS_KEY_ID unset or aws CLI missing."
  echo "  Local EnvelopeKeyVault round-trip passed; cloud continuous proof remains human-gated."
fi

echo "kms/conformance-local: OK"
