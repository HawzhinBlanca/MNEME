#!/usr/bin/env bash
# B6 AWS KMS bridge (rust-toolchain 1.86.0): fetch a 32-byte DEK via AWS CLI and
# export MNEME_KMS_MASTER_KEY_HEX for EnvelopeKeyVault::from_env.
#
# Requires: aws CLI, jq, and IAM permission kms:GenerateDataKey on the CMK.
#
# Usage:
#   export AWS_KMS_KEY_ID=arn:aws:kms:...
#   eval "$(scripts/kms/dek-from-aws.sh)"
#   mneme remember ...   # store uses EnvelopeKeyVault when wired via from_env
set -euo pipefail

KEY_ID="${AWS_KMS_KEY_ID:?set AWS_KMS_KEY_ID}"
OUT="$(aws kms generate-data-key \
  --key-id "$KEY_ID" \
  --key-spec AES_256 \
  --output json)"
PLAINTEXT="$(echo "$OUT" | jq -r '.Plaintext')"
if [[ -z "$PLAINTEXT" || "$PLAINTEXT" == "null" ]]; then
  echo "dek-from-aws: missing Plaintext in KMS response" >&2
  exit 1
fi
HEX="$(echo "$PLAINTEXT" | base64 -d | xxd -p -c 256 | tr -d '\n')"
if [[ ${#HEX} -ne 64 ]]; then
  echo "dek-from-aws: expected 32-byte DEK, got ${#HEX} hex chars" >&2
  exit 1
fi
echo "export MNEME_KMS_MASTER_KEY_HEX=$HEX"
BLOB="$(echo "$OUT" | jq -r '.CiphertextBlob')"
echo "# CiphertextBlob (store in meta/kms-dek.wrap for reopen): $BLOB" >&2
