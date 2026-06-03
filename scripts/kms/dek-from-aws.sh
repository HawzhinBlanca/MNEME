#!/usr/bin/env bash
# B6 AWS KMS bridge (rust-toolchain 1.86.0): fetch a 32-byte DEK via AWS CLI and
# export MNEME_KMS_MASTER_KEY_HEX for EnvelopeKeyVault::from_env.
#
# Requires: aws CLI, jq, and IAM permission kms:GenerateDataKey on the CMK.
#
# Usage:
#   export AWS_KMS_KEY_ID=arn:aws:kms:...
#   scripts/kms/dek-from-aws.sh --store /path/to/store
#   eval "$(scripts/kms/dek-from-aws.sh --store /path/to/store --emit-env)"
#   MNEME_KEY_VAULT=envelope mneme remember ...
set -euo pipefail

STORE=""
EMIT_ENV=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --store)
      STORE="${2:?--store requires a path}"
      shift 2
      ;;
    --emit-env)
      EMIT_ENV=1
      shift
      ;;
    *)
      echo "Usage: $0 [--store PATH] [--emit-env]" >&2
      exit 2
      ;;
  esac
done

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
BLOB="$(echo "$OUT" | jq -r '.CiphertextBlob')"
if [[ -n "$STORE" ]]; then
  mkdir -p "$STORE/meta"
  umask 077
  printf '%s\n' "$BLOB" >"$STORE/meta/kms-dek.wrap"
  chmod 600 "$STORE/meta/kms-dek.wrap"
  echo "dek-from-aws: wrote ciphertext blob to $STORE/meta/kms-dek.wrap" >&2
fi
if [[ "$EMIT_ENV" == "1" ]]; then
  echo "export MNEME_KMS_MASTER_KEY_HEX=$HEX"
else
  echo "dek-from-aws: plaintext DEK withheld from stdout; pass --emit-env only in a trusted shell" >&2
fi
