//! Authenticated indexes: key-index recall (v0) + committed semantic ANN (90-day).
//!
//! Semantic retrieval uses wrapped `hnsw_rs` with Merkle-committed nodes and
//! deterministic procedure P (integer distance, ObjectId tie-break). Receipts
//! prove procedure-faithfulness, **not** exact nearest neighbors (blueprint §3).

#![forbid(unsafe_code)]
#![deny(warnings)]

mod commit;
mod distance;
mod error;
mod hnsw_backend;
mod key_index;
mod key_index_load;
mod procedure;
mod receipt;
mod semantic;
mod verify;
mod wire;

#[cfg(feature = "commitment_binding")]
mod commitment_binding;

#[cfg(feature = "plonky2_prover")]
mod plonky2_prover;

pub use commit::{SemanticMerkleTree, empty_semantic_root, hash_sem_internal, hash_sem_leaf};
pub use error::IndexError;
pub use key_index::KeyIndex;
pub use key_index_load::{load_key_index_tree, load_object_keys};
pub use procedure::{
    IndexedEntry, PROC_DOMAIN, default_key_procedure, default_semantic_procedure,
    execute_procedure_p, is_key_index_procedure, procedure_id, replay_from_candidates,
};
pub use receipt::SemanticRecallReceipt;
pub use semantic::SemanticIndex;
pub use verify::{HONESTY_NOT_EXACT_NN, verify_ads_vo};
pub use wire::{fuzz_index_path_wire, fuzz_receipt_wire};

#[cfg(feature = "commitment_binding")]
pub use commitment_binding::{
    B3_V0_BINDING_STATUS, BINDING_ENVELOPE_TAG, BINDING_HONESTY, BINDING_PROOF_LEN,
    CommitmentBindingReceipt, prove_binding_receipt, verify_binding_receipt,
};

#[cfg(feature = "plonky2_prover")]
pub use plonky2_prover::{
    B3_DEFERRAL_STATUS, PLONKY2_PROVER_HONESTY, PUBLIC_COMMIT_LEN, Plonky2RetrievalProof,
    RetrievalWitness, ZK_BACKEND, prove_plonky2_retrieval, verify_plonky2_retrieval,
};

/// ADS backend enabled when the `ads` feature is on.
/// Privacy path (`commitment_binding` / `zk` alias) is a tagged BLAKE3 binding envelope only — not SNARK, not Plonky2.
#[cfg(feature = "ads")]
pub const SEMANTIC_BACKEND_ENABLED: bool = true;

#[cfg(not(feature = "ads"))]
pub const SEMANTIC_BACKEND_ENABLED: bool = false;

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{
        DistanceMetric, FixedPointEmbedding, LogicalKey, ObjectId, Procedure, ProcedureAlgo,
    };
    use mneme_smt::SparseMerkleTree;

    fn sample_id(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    #[test]
    fn key_index_roundtrip_namespace_name_to_object_id() {
        let key = LogicalKey {
            namespace: "agent".into(),
            name: "theme".into(),
        };
        let id = sample_id(0xab);
        let mut index = KeyIndex::new();
        index.upsert(&key, id);

        assert_eq!(index.resolve(&key).unwrap(), id);

        let proof = index.prove_membership(&key).unwrap();
        SparseMerkleTree::verify_membership(&proof).unwrap();

        let root_bound = [0x11; 32];
        let receipt = index
            .recall_receipt(&key, root_bound, index.root())
            .unwrap();
        assert_eq!(receipt.root_bound, root_bound);
        assert_eq!(receipt.logical_key, key.hash());
        assert_eq!(receipt.object_id, *id.as_bytes());
        assert_eq!(receipt.key_index_root, index.root());

        let verify_proof = mneme_smt::MembershipProof {
            key: receipt.logical_key,
            value: receipt.object_id,
            path: receipt.membership_proof,
            root: receipt.key_index_root,
            leaf_index: receipt.leaf_index,
        };
        SparseMerkleTree::verify_membership(&verify_proof).unwrap();
    }

    #[test]
    fn key_index_non_membership_roundtrip() {
        let key = LogicalKey {
            namespace: "ns".into(),
            name: "never-written".into(),
        };
        let index = KeyIndex::new();
        let proof = index.prove_non_membership(&key).unwrap();
        mneme_smt::SparseMerkleTree::verify_non_membership(&proof).unwrap();
    }

    #[test]
    fn semantic_backend_enabled_with_ads_feature() {
        if !SEMANTIC_BACKEND_ENABLED {
            panic!("SEMANTIC_BACKEND_ENABLED must be true");
        }
    }

    #[cfg(feature = "plonky2_prover")]
    #[test]
    fn plonky2_prover_real_proof_verifies_and_forgeries_reject() {
        use super::plonky2_prover::{
            B3_DEFERRAL_STATUS, PLONKY2_PROVER_HONESTY, RetrievalWitness, ZK_BACKEND,
            prove_plonky2_retrieval, verify_plonky2_retrieval,
        };
        use mneme_core::MnemeError;
        assert!(B3_DEFERRAL_STATUS.contains("IMPLEMENTED"));
        assert!(PLONKY2_PROVER_HONESTY.contains("zero-knowledge"));
        assert!(PLONKY2_PROVER_HONESTY.contains("NOT Plonky2"));
        assert!(ZK_BACKEND.contains("no trusted setup"));

        let entry = [9u8; 32];
        let proof = prove_plonky2_retrieval(&RetrievalWitness::matching(entry)).expect("prove");
        assert!(!proof.proof_bytes.is_empty());
        verify_plonky2_retrieval(&proof, &proof.public_commit).expect("verify");

        // Forgery: tampering the public commitment must reject.
        let mut wrong = proof.public_commit;
        wrong[0] ^= 0x01;
        assert_eq!(
            verify_plonky2_retrieval(&proof, &wrong),
            Err(MnemeError::ZkProofInvalid)
        );

        // Unsatisfiable witness (query != entry) cannot produce a proof.
        let mut q = entry;
        q[0] ^= 0x01;
        let bad = RetrievalWitness { entry, query: q };
        assert_eq!(
            prove_plonky2_retrieval(&bad),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[cfg(feature = "commitment_binding")]
    #[test]
    fn commitment_binding_receipt_is_not_zk() {
        use super::commitment_binding::{
            BINDING_ENVELOPE_TAG, BINDING_HONESTY, prove_binding_receipt, verify_binding_receipt,
        };
        let object_id = [0x01; 32];
        let embedding_commit = [0x02; 32];
        let public_commit = hash_sem_leaf(&object_id, &embedding_commit);
        let receipt = prove_binding_receipt(&object_id, &embedding_commit, public_commit);
        verify_binding_receipt(&receipt, &object_id, &embedding_commit).unwrap();
        assert!(BINDING_HONESTY.contains("not zero-knowledge"));
        assert!(BINDING_HONESTY.contains("not truth"));
        let tag = std::str::from_utf8(BINDING_ENVELOPE_TAG).expect("utf8 tag");
        assert!(!tag.contains("PLONKY2"));
        assert!(!tag.contains("SNARK"));
        assert!(!tag.contains("ZK"));
    }

    #[test]
    fn semantic_recall_returns_receipt_bound_results() {
        let mut index = SemanticIndex::new();
        let emb = FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap();
        index.insert(sample_id(0x01), emb).unwrap();
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 1,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let receipt = index.recall_receipt(&proc, &query, [0x22; 32]).unwrap();
        assert_eq!(receipt.root_bound, [0x22; 32]);
        assert_eq!(receipt.semantic_commit, index.semantic_commit());
        verify_ads_vo(
            &receipt.verification_object,
            &index.semantic_commit(),
            &proc,
        )
        .unwrap();
    }
}
