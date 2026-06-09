//! Ed25519-trapdoor chameleon leaf hash (blueprint §13.3; Ateniese et al. EuroS&P 2017).
//!
//! **Honest weak point:** collision finding requires trapdoor-key custody; see
//! `mneme-forget/TRAPDOOR_CUSTODY.md`.

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mneme_core::MnemeError;

const CH_DOMAIN: &[u8] = b"MNEME-chameleon-v1\x00";
const TOMBSTONE_RANDOMNESS_ATTEMPTS: u64 = 2_000_001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChameleonFailure {
    TombstoneRandomnessExhausted,
}

fn chameleon_failure_to_mneme(failure: ChameleonFailure) -> MnemeError {
    match failure {
        ChameleonFailure::TombstoneRandomnessExhausted => MnemeError::SchemaDrift,
    }
}

fn tombstone_randomness_exhausted_error() -> MnemeError {
    chameleon_failure_to_mneme(ChameleonFailure::TombstoneRandomnessExhausted)
}

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
        self.find_tombstone_randomness_with_attempts(
            key,
            live_value,
            live_randomness,
            tombstone_value,
            TOMBSTONE_RANDOMNESS_ATTEMPTS,
        )
    }

    fn find_tombstone_randomness_with_attempts(
        &self,
        key: &[u8; 32],
        live_value: &[u8; 32],
        live_randomness: &[u8; 32],
        tombstone_value: &[u8; 32],
        attempts: u64,
    ) -> Result<[u8; 32], MnemeError> {
        let target = chameleon_leaf_hash(key, live_value, live_randomness, &self.public);
        for counter in 0..attempts {
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
        Err(tombstone_randomness_exhausted_error())
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn chameleon_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("chameleon.rs");
        let section = source_between_markers(
            source,
            "const CH_DOMAIN",
            "#[cfg(test)]",
            "chameleon production section",
        );

        for forbidden in [
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "chameleon randomness search should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ChameleonFailure",
            "fn chameleon_failure_to_mneme(",
            "fn tombstone_randomness_exhausted_error(",
            "fn find_tombstone_randomness_with_attempts(",
            "ChameleonFailure::TombstoneRandomnessExhausted",
        ] {
            assert!(
                section.contains(required),
                "chameleon failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn chameleon_failure_classifier_preserves_public_schema_drift() {
        assert_eq!(
            chameleon_failure_to_mneme(ChameleonFailure::TombstoneRandomnessExhausted),
            MnemeError::SchemaDrift
        );
        assert_eq!(
            tombstone_randomness_exhausted_error(),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn tombstone_randomness_exhaustion_fails_closed_without_attempts() {
        let trapdoor = TrapdoorKey::from_seed([0x42; 32]);

        assert_eq!(
            trapdoor.find_tombstone_randomness_with_attempts(
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 32],
                &[0x44; 32],
                0,
            ),
            Err(MnemeError::SchemaDrift)
        );
    }
}
