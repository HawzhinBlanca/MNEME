use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mneme_core::MnemeError;

use crate::types::{Nonce24, ObjectKey, XCHACHA_NONCE_LEN};

/// Seal `plaintext` with XChaCha20-Poly1305. Returns ciphertext || tag.
pub fn seal(
    key: &ObjectKey,
    nonce: &Nonce24,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, MnemeError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| MnemeError::SchemaDrift)?;
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| MnemeError::ObjectTampered)
}

/// Open XChaCha20-Poly1305 ciphertext. Fail-closed on auth failure.
pub fn open(
    key: &ObjectKey,
    nonce: &Nonce24,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, MnemeError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| MnemeError::SchemaDrift)?;
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| MnemeError::ObjectTampered)
}

/// Generate a fresh random nonce suitable for XChaCha20-Poly1305.
pub fn random_nonce() -> Nonce24 {
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    crate::deterministic::fill_random("aead-nonce", &mut nonce);
    nonce
}
