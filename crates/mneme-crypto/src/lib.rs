#![deny(warnings)]

pub mod aead;
#[cfg(feature = "experimental_redaction")]
#[path = "../../../experimental/redaction/mneme-crypto-chameleon.rs"]
pub mod chameleon;
pub mod deterministic;
pub mod envelope_vault;
pub mod keys;
pub mod payload;
pub mod sign;
pub mod types;
pub mod vault;

pub use aead::{open, random_nonce, seal};
#[cfg(feature = "experimental_redaction")]
pub use chameleon::{TrapdoorKey, chameleon_leaf_hash};
pub use deterministic::{disable_fixture_crypto, enable_fixture_crypto};
pub use envelope_vault::EnvelopeKeyVault;
pub use keys::{KeyPair, PublicKeyBytes, TrustConfig, public_key_from_bytes};
pub use payload::{open_payload, seal_payload, shred_payload_key};
pub use sign::{sign_message, verify_signature, verify_signature_bytes, verifying_key_from_bytes};
pub use types::{
    ED25519_SIG_LEN, KEY_ID_LEN, KeyId, Nonce24, OBJECT_KEY_LEN, ObjectKey, PAYLOAD_ALG_PLAINTEXT,
    PAYLOAD_ALG_XCHACHA20_POLY1305, XCHACHA_NONCE_LEN, key_id_from_slice, nonce_from_slice,
};
pub use vault::{FileKeyVault, KeyVault, MemoryKeyVault};
