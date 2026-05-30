//! Ed25519-trapdoor chameleon leaf hash (blueprint §13.3; Ateniese et al. EuroS&P 2017).
//!
//! **Honest weak point:** collision finding requires trapdoor-key custody; see
//! `mneme-forget/TRAPDOOR_CUSTODY.md`.

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mneme_core::MnemeError;

const CH_DOMAIN: &[u8] = b"MNEME-chameleon-v1\x00";

/// Trapdoor holder keys for accountable redaction (operator custody).
#[derive(Clone)]
pub struct TrapdoorKey {
    signing_key: SigningKey,
    pub public: [u8; 32],
}

impl TrapdoorKey {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public,
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Precompute tombstone randomness so the SMT leaf hash stays stable after redact.
    pub fn find_tombstone_randomness(
        &self,
        key: &[u8; 32],
        live_value: &[u8; 32],
        live_randomness: &[u8; 32],
        tombstone_value: &[u8; 32],
    ) -> Result<[u8; 32], MnemeError> {
        let target = chameleon_leaf_hash(key, live_value, live_randomness, &self.public);
        for counter in 0u64..=2_000_000 {
            let mut candidate = [0u8; 32];
            candidate[..8].copy_from_slice(&counter.to_le_bytes());
            let sig = self
                .signing_key
                .sign(&collision_preimage(key, tombstone_value, &candidate));
            candidate[8..].copy_from_slice(&sig.to_bytes()[..24]);
            let h = chameleon_leaf_hash(key, tombstone_value, &candidate, &self.public);
            if h == target {
                return Ok(candidate);
            }
        }
        Err(MnemeError::SchemaDrift)
    }
}

/// Chameleon SMT leaf: `BLAKE3(CH || pk || key || value || r || sig_tail)`.
pub fn chameleon_leaf_hash(
    key: &[u8; 32],
    value: &[u8; 32],
    randomness: &[u8; 32],
    trapdoor_pk: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(CH_DOMAIN);
    h.update(trapdoor_pk);
    h.update(key);
    h.update(value);
    h.update(randomness);
    *h.finalize().as_bytes()
}

fn collision_preimage(key: &[u8; 32], value: &[u8; 32], randomness: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    out.extend_from_slice(randomness);
    out
}
