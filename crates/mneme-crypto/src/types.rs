//! Crypto-local byte newtypes aligned with blueprint §5.5.2.
//! TODO(INTERFACE): promote to mneme-core when interface.rs lands.

pub const PAYLOAD_ALG_PLAINTEXT: u8 = 0;
pub const PAYLOAD_ALG_XCHACHA20_POLY1305: u8 = 1;
pub const PAYLOAD_ALG_EMBARGO: u8 = 2;

pub const KEY_ID_LEN: usize = 16;
pub const OBJECT_KEY_LEN: usize = 32;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const ED25519_SIG_LEN: usize = 64;

/// Per-object vault reference (PayloadEnc.key_id).
pub type KeyId = [u8; KEY_ID_LEN];

/// XChaCha20-Poly1305 key material.
pub type ObjectKey = [u8; OBJECT_KEY_LEN];

/// XChaCha20-Poly1305 nonce (PayloadEnc.nonce).
pub type Nonce24 = [u8; XCHACHA_NONCE_LEN];

pub fn key_id_from_slice(bytes: &[u8]) -> Result<KeyId, mneme_core::MnemeError> {
    bytes
        .try_into()
        .map_err(|_| mneme_core::MnemeError::SchemaDrift)
}

pub fn nonce_from_slice(bytes: &[u8]) -> Result<Nonce24, mneme_core::MnemeError> {
    bytes
        .try_into()
        .map_err(|_| mneme_core::MnemeError::SchemaDrift)
}
