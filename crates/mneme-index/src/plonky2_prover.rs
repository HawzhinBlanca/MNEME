//! Plonky2/V3DB-style ZK retrieval backend — **12-month milestone only (B3)**.
//!
//! **Not in v0 / 90-day scope.** Enabling `plonky2_prover` does not link Plonky2 or any
//! SNARK prover. Every entrypoint fails closed with [`MnemeError::ZkProofInvalid`] so
//! callers cannot accidentally treat an empty stub as a valid proof.
//!
//! v0 ships [`super::commitment_binding`] (feature `commitment_binding`, alias `zk`): a
//! tagged BLAKE3 binding envelope that rejects forgeries but is not zero-knowledge.

use mneme_core::MnemeError;

/// Audit tag for deferral B3 closure (documentation / honesty exports).
pub const B3_DEFERRAL_STATUS: &str = "CLOSED (deferral): Plonky2/V3DB ZK retrieval is a 12-month milestone; not in v0/90-day scope. \
     v0 uses commitment_binding (tagged BLAKE3 envelope only). Enable plonky2_prover only to \
     exercise fail-closed stubs until a real prover lands.";

/// Honesty boundary when `plonky2_prover` is enabled without a linked backend.
pub const PLONKY2_PROVER_HONESTY: &str = "Plonky2 prover not shipped; plonky2_prover feature fails closed. Not zero-knowledge, not SNARK, not truth.";

/// Opaque proof container for the future 12-month backend (no valid instances today).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plonky2RetrievalProof {
    pub proof_bytes: Vec<u8>,
}

/// Prove a private retrieval statement — **always fails closed** until 12-month prover ships.
pub fn prove_plonky2_retrieval(_public_inputs: &[u8]) -> Result<Plonky2RetrievalProof, MnemeError> {
    Err(MnemeError::ZkProofInvalid)
}

/// Verify a Plonky2 retrieval proof — **always fails closed** (no verifier linked).
pub fn verify_plonky2_retrieval(
    _proof: &Plonky2RetrievalProof,
    _public_inputs: &[u8],
) -> Result<(), MnemeError> {
    Err(MnemeError::ZkProofInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b3_deferral_status_documents_12_month_scope() {
        assert!(B3_DEFERRAL_STATUS.contains("12-month"));
        assert!(B3_DEFERRAL_STATUS.contains("CLOSED"));
        assert!(!B3_DEFERRAL_STATUS.to_uppercase().contains("SHIPPED"));
        assert!(PLONKY2_PROVER_HONESTY.contains("fails closed"));
    }

    #[test]
    fn prove_fails_closed_without_prover() {
        assert_eq!(
            prove_plonky2_retrieval(b"inputs"),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn verify_fails_closed_on_any_bytes() {
        let proof = Plonky2RetrievalProof {
            proof_bytes: vec![0u8; 64],
        };
        assert_eq!(
            verify_plonky2_retrieval(&proof, b"inputs"),
            Err(MnemeError::ZkProofInvalid)
        );
    }
}
