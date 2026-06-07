use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use mneme_core::MnemeError;

use crate::types::{Nonce24, ObjectKey, XCHACHA_NONCE_LEN};

fn xchacha_cipher(key: &ObjectKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key))
}

/// Seal `plaintext` with XChaCha20-Poly1305. Returns ciphertext || tag.
pub fn seal(
    key: &ObjectKey,
    nonce: &Nonce24,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, MnemeError> {
    let cipher = xchacha_cipher(key);
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
    let cipher = xchacha_cipher(key);
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

#[cfg(test)]
mod tests {
    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn aead_construction_uses_typed_key_not_schema_drift_collapse() {
        let source = include_str!("aead.rs");
        let section = source_between_markers(
            source,
            "use chacha20poly1305",
            "#[cfg(test)]",
            "AEAD production section",
        );

        for forbidden in [
            "new_from_slice(key).map_err(|_| MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "AEAD construction should avoid `{forbidden}` by using typed ObjectKey construction"
            );
        }

        for required in [
            "fn xchacha_cipher(",
            "XChaCha20Poly1305::new(Key::from_slice(key))",
        ] {
            assert!(
                section.contains(required),
                "AEAD construction should include `{required}`"
            );
        }
    }
}
