//! Commitment-binding receipt envelope (§9.2 privacy path).
//!
//! **Not zero-knowledge.** This module binds `(object_id, embedding_commit)` to a
//! public semantic-leaf commitment using a tagged BLAKE3 digest envelope. It does
//! not hide query or index data and is not a SNARK. Full Plonky2 integration is
//! deferred until CI adopts a nightly toolchain.

use crate::commit::hash_sem_leaf;
use mneme_core::MnemeError;

/// Domain tag for the binding envelope (must never claim Plonky2 / SNARK).
pub const BINDING_ENVELOPE_TAG: &[u8] = b"MNEME-BINDING-ENVELOPE-v1";

/// BLAKE3 digest length for `proof_bytes`.
pub const BINDING_PROOF_LEN: usize = 32;

/// Honesty boundary for commitment-binding receipts (§3, §9.2).
pub const BINDING_HONESTY: &str = "Commitment binding proves leaf commitment only; not zero-knowledge, not truth, not exact-NN, not semantic correctness.";

/// Receipt that binds a semantic leaf commitment without claiming ZK privacy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBindingReceipt {
    pub public_commit: [u8; 32],
    pub proof_bytes: Vec<u8>,
}

/// Prove binding of `(object_id, embedding_commit)` to `public_commit`.
pub fn prove_binding_receipt(
    object_id: &[u8; 32],
    embedding_commit: &[u8; 32],
    public_commit: [u8; 32],
) -> CommitmentBindingReceipt {
    let derived = hash_sem_leaf(object_id, embedding_commit);
    let proof_bytes = binding_proof_digest(&derived, &public_commit);
    CommitmentBindingReceipt {
        public_commit,
        proof_bytes,
    }
}

/// Verify commitment-binding receipt; fails closed on mismatch or forgery.
pub fn verify_binding_receipt(
    receipt: &CommitmentBindingReceipt,
    object_id: &[u8; 32],
    embedding_commit: &[u8; 32],
) -> Result<(), MnemeError> {
    let derived = hash_sem_leaf(object_id, embedding_commit);
    if derived != receipt.public_commit {
        return Err(MnemeError::ZkProofInvalid);
    }
    if receipt.proof_bytes.len() != BINDING_PROOF_LEN {
        return Err(MnemeError::ZkProofInvalid);
    }
    if binding_proof_digest(&derived, &receipt.public_commit) != receipt.proof_bytes {
        return Err(MnemeError::ZkProofInvalid);
    }
    Ok(())
}

fn binding_proof_digest(leaf: &[u8; 32], public: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(BINDING_ENVELOPE_TAG.len() + 64);
    payload.extend_from_slice(BINDING_ENVELOPE_TAG);
    payload.extend_from_slice(leaf);
    payload.extend_from_slice(public);
    blake3::hash(&payload).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../proof/vectors/receipts/zk/privacy_fixture.json")
    }

    #[test]
    fn binding_honesty_strings_non_empty() {
        assert!(BINDING_HONESTY.contains("not zero-knowledge"));
        assert!(BINDING_HONESTY.contains("not truth"));
    }

    #[test]
    fn envelope_tag_is_not_plonky2() {
        let tag = std::str::from_utf8(BINDING_ENVELOPE_TAG).expect("utf8 tag");
        assert_eq!(tag, "MNEME-BINDING-ENVELOPE-v1");
        assert!(!tag.contains("PLONKY2"));
        assert!(!tag.contains("SNARK"));
        assert!(!tag.contains("ZK"));
        assert!(BINDING_HONESTY.contains("not zero-knowledge"));
        assert!(!BINDING_HONESTY.to_uppercase().contains("PLONKY2"));
        assert!(!BINDING_HONESTY.to_uppercase().contains("SNARK"));
    }

    #[test]
    fn privacy_fixture_roundtrip() {
        let raw = fs::read_to_string(fixture_path()).expect("fixture");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let fixture_tag = v["envelope_tag"].as_str().expect("envelope_tag");
        let tag = std::str::from_utf8(BINDING_ENVELOPE_TAG).expect("utf8 tag");
        assert_eq!(fixture_tag, tag);
        assert!(!fixture_tag.contains("PLONKY2"));
        assert!(!fixture_tag.contains("SNARK"));
        let id_hex = v["object_id"].as_str().expect("object_id");
        let emb_hex = v["embedding_commit"].as_str().expect("embedding_commit");
        let mut object_id = [0u8; 32];
        let mut embedding_commit = [0u8; 32];
        hex::decode_to_slice(id_hex, &mut object_id).expect("decode id");
        hex::decode_to_slice(emb_hex, &mut embedding_commit).expect("decode emb");
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        verify_binding_receipt(&receipt, &object_id, &embedding_commit).expect("verify");
        assert_eq!(receipt.proof_bytes.len(), BINDING_PROOF_LEN);
    }

    #[test]
    fn rejects_wrong_public_commit() {
        let object_id = [0x01; 32];
        let embedding_commit = [0x02; 32];
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        let wrong_commit = [0xff; 32];
        let forged = CommitmentBindingReceipt {
            public_commit: wrong_commit,
            proof_bytes: receipt.proof_bytes,
        };
        assert_eq!(
            verify_binding_receipt(&forged, &object_id, &embedding_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn rejects_forged_proof_bytes() {
        let object_id = [0x01; 32];
        let embedding_commit = [0x02; 32];
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let mut receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        receipt.proof_bytes[0] ^= 0x01;
        assert_eq!(
            verify_binding_receipt(&receipt, &object_id, &embedding_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn rejects_wrong_embedding_commit() {
        let object_id = [0x01; 32];
        let embedding_commit = [0x02; 32];
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        let wrong_emb = [0x03; 32];
        assert_eq!(
            verify_binding_receipt(&receipt, &object_id, &wrong_emb),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn rejects_truncated_proof_bytes() {
        let object_id = [0x01; 32];
        let embedding_commit = [0x02; 32];
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        let truncated = CommitmentBindingReceipt {
            public_commit: receipt.public_commit,
            proof_bytes: receipt.proof_bytes[..16].to_vec(),
        };
        assert_eq!(
            verify_binding_receipt(&truncated, &object_id, &embedding_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }
}
