//! Commitment-binding receipt envelope (§9.2 privacy path, v0 scope).
//!
//! **Not zero-knowledge.** This module binds `(object_id, embedding_commit)` to a
//! public semantic-leaf commitment using a tagged BLAKE3 digest envelope. It does
//! not hide query or index data and is not a SNARK. Plonky2/V3DB-style ZK retrieval
//! is a **12-month milestone only** — see `pedersen_schnorr_zk` (real ZK, B3 closed).

use crate::commit::hash_sem_leaf;
use mneme_core::MnemeError;

/// Domain tag for the binding envelope (must never claim Plonky2 / SNARK).
pub const BINDING_ENVELOPE_TAG: &[u8] = b"MNEME-BINDING-ENVELOPE-v1";

/// BLAKE3 digest length for `proof_bytes`.
pub const BINDING_PROOF_LEN: usize = 32;

/// Honesty boundary for commitment-binding receipts (§3, §9.2).
pub const BINDING_HONESTY: &str = concat!(
    "Commitment binding proves leaf commitment only; not zero-knowledge, not truth, ",
    "not exact-NN / not exact nearest-neighbor, not semantic correctness. ",
    "It does not upgrade Phase I ExactDominance: current v1 remains top-k over ",
    "prover-asserted distances, not top-k by true query-to-embedding distance until ",
    "verifiers recompute candidate distances."
);

/// v0 binding path status for audit B3 (Plonky2 is out of scope until 12-month).
pub const B3_V0_BINDING_STATUS: &str =
    "v0/90-day: commitment_binding (BLAKE3 envelope) PASS; Plonky2 ZK retrieval 12-month only.";

/// Receipt that binds a semantic leaf commitment without claiming ZK privacy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBindingReceipt {
    pub public_commit: [u8; 32],
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitmentBindingFailure {
    PublicCommitMismatch,
    ProofLengthInvalid,
    ProofDigestMismatch,
}

fn commitment_binding_failure_to_mneme(failure: CommitmentBindingFailure) -> MnemeError {
    match failure {
        CommitmentBindingFailure::PublicCommitMismatch
        | CommitmentBindingFailure::ProofLengthInvalid
        | CommitmentBindingFailure::ProofDigestMismatch => MnemeError::ZkProofInvalid,
    }
}

fn commitment_binding_error(failure: CommitmentBindingFailure) -> MnemeError {
    commitment_binding_failure_to_mneme(failure)
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
        return Err(commitment_binding_error(
            CommitmentBindingFailure::PublicCommitMismatch,
        ));
    }
    if receipt.proof_bytes.len() != BINDING_PROOF_LEN {
        return Err(commitment_binding_error(
            CommitmentBindingFailure::ProofLengthInvalid,
        ));
    }
    if binding_proof_digest(&derived, &receipt.public_commit) != receipt.proof_bytes {
        return Err(commitment_binding_error(
            CommitmentBindingFailure::ProofDigestMismatch,
        ));
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
    fn binding_honesty_preserves_exact_dominance_distance_caveat() {
        assert_distance_caveat("BINDING_HONESTY", BINDING_HONESTY);
        assert_distance_caveat("mneme-index contract", include_str!("../docs/CONTRACT.md"));
    }

    fn assert_distance_caveat(surface: &str, text: &str) {
        for phrase in [
            "not exact",
            "top-k over prover-asserted distances",
            "not top-k by true query-to-embedding distance",
        ] {
            assert!(
                text.contains(phrase),
                "{surface} missing required honesty phrase `{phrase}`: {text}"
            );
        }
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
    fn binding_verifier_failures_are_classified_not_zkproof_collapsed() {
        let source = include_str!("commitment_binding.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("commitment_binding tests should follow production code");

        assert!(
            !source.contains("return Err(MnemeError::ZkProofInvalid"),
            "commitment binding verifier should route ZkProofInvalid through named classifiers"
        );

        for required in [
            "enum CommitmentBindingFailure",
            "PublicCommitMismatch",
            "ProofLengthInvalid",
            "ProofDigestMismatch",
            "fn commitment_binding_failure_to_mneme(",
            "fn commitment_binding_error(",
        ] {
            assert!(
                source.contains(required),
                "commitment binding verifier should include `{required}`"
            );
        }
    }

    #[test]
    fn binding_failure_classifier_preserves_public_zkproof_invalid() {
        for failure in [
            CommitmentBindingFailure::PublicCommitMismatch,
            CommitmentBindingFailure::ProofLengthInvalid,
            CommitmentBindingFailure::ProofDigestMismatch,
        ] {
            assert_eq!(
                commitment_binding_failure_to_mneme(failure),
                MnemeError::ZkProofInvalid
            );
            assert_eq!(
                commitment_binding_error(failure),
                MnemeError::ZkProofInvalid
            );
        }
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
        assert_eq!(
            v["v0_scope"].as_str().expect("v0_scope"),
            "commitment_binding_blake3_only"
        );
        assert_eq!(
            v["plonky2_milestone"].as_str().expect("plonky2_milestone"),
            "12-month_not_in_v0"
        );
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
        let expected_hex = v["proof_bytes_hex"].as_str().expect("proof_bytes_hex");
        assert_eq!(hex::encode(&receipt.proof_bytes), expected_hex);
        let public_hex = v["public_commit_hex"].as_str().expect("public_commit_hex");
        assert_eq!(hex::encode(public_commit), public_hex);
    }

    #[test]
    fn forgery_vectors_reject_typed() {
        let raw = fs::read_to_string(forgery_vectors_path()).expect("forgery fixture");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let cases = v["cases"].as_array().expect("cases");
        for case in cases {
            let name = case["name"].as_str().expect("name");
            let expected = case["expected_error"].as_str().expect("expected_error");
            assert_eq!(expected, "ZkProofInvalid", "{name}: wrong expected_error");
            let mut object_id = [0u8; 32];
            let mut embedding_commit = [0u8; 32];
            hex::decode_to_slice(
                case["object_id"].as_str().expect("object_id"),
                &mut object_id,
            )
            .expect("decode id");
            hex::decode_to_slice(
                case["embedding_commit"].as_str().expect("embedding_commit"),
                &mut embedding_commit,
            )
            .expect("decode emb");
            let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
            let mut receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
            match name {
                "wrong_public_commit" => receipt.public_commit = [0xff; 32],
                "forged_proof_bytes" => receipt.proof_bytes[0] ^= 0x01,
                "wrong_embedding_commit" => {
                    let wrong_emb = [0x03; 32];
                    assert_eq!(
                        verify_binding_receipt(&receipt, &object_id, &wrong_emb),
                        Err(MnemeError::ZkProofInvalid)
                    );
                    continue;
                }
                "truncated_proof_bytes" => {
                    receipt.proof_bytes = receipt.proof_bytes[..16].to_vec();
                }
                other => panic!("unknown forgery case: {other}"),
            }
            assert_eq!(
                verify_binding_receipt(&receipt, &object_id, &embedding_commit),
                Err(MnemeError::ZkProofInvalid),
                "{name}"
            );
        }
    }

    fn forgery_vectors_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../proof/vectors/receipts/zk/forgery_expectations.json")
    }

    #[test]
    #[ignore = "run with --ignored --nocapture to refresh proof/vectors/receipts/zk/privacy_fixture.json digests"]
    fn dump_privacy_fixture_digests() {
        let object_id = [0x01; 32];
        let embedding_commit = [0x02; 32];
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        eprintln!("public_commit_hex={}", hex::encode(public_commit));
        eprintln!("proof_bytes_hex={}", hex::encode(&receipt.proof_bytes));
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
