use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mneme_core::MnemeError;

use crate::types::ED25519_SIG_LEN;

pub fn sign_message(signing_key: &SigningKey, msg: &[u8]) -> [u8; ED25519_SIG_LEN] {
    signing_key.sign(msg).to_bytes()
}

pub fn verify_signature(
    pk: &VerifyingKey,
    msg: &[u8],
    sig: &[u8; ED25519_SIG_LEN],
) -> Result<(), MnemeError> {
    let signature = Signature::from_bytes(sig);
    pk.verify(msg, &signature)
        .map_err(|_| MnemeError::RootSigInvalid)
}

/// Verify a signature from a byte slice; rejects non-64-byte inputs fail-closed.
pub fn verify_signature_bytes(pk: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), MnemeError> {
    let sig_bytes: [u8; ED25519_SIG_LEN] =
        sig.try_into().map_err(|_| MnemeError::RootSigInvalid)?;
    verify_signature(pk, msg, &sig_bytes)
}

/// Parse an Ed25519 verifying key; invalid points fail closed.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, MnemeError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| MnemeError::RootSigInvalid)
}
