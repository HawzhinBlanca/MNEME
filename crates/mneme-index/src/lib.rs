//! Authenticated indexes: key-index recall (v0) plus experimental semantic ANN.
//!
//! The default lean build exports only exact key-index lookup and sidecar replay.
//! Semantic retrieval is compiled only with `experimental_semantic`; receipts
//! prove procedure-faithfulness, **not** exact nearest neighbors (blueprint §3).

#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(feature = "cognition_cert")]
#[path = "../../../experimental/cognition-cert/mneme-index-cognition-cert.rs"]
mod cognition_cert;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-commit.rs"]
mod commit;
#[cfg(feature = "context_gate")]
#[path = "../../../experimental/context-gate/mneme-index-context-gate.rs"]
mod context_gate;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-distance.rs"]
mod distance;
mod error;
#[cfg(feature = "federation")]
#[path = "../../../experimental/federation/mneme-index-federation-cert.rs"]
mod federation_cert;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-hnsw-backend.rs"]
mod hnsw_backend;
mod key_index;
mod key_index_load;
mod procedure;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-provenance.rs"]
mod provenance;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-receipt.rs"]
mod receipt;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-semantic.rs"]
mod semantic;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-verify.rs"]
mod verify;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-wire.rs"]
mod wire;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-index-zkann.rs"]
mod zkann;

#[cfg(feature = "commitment_binding")]
#[path = "../../../experimental/zk-privacy/mneme-index-commitment-binding.rs"]
mod commitment_binding;

#[cfg(feature = "pedersen_schnorr_zk")]
#[path = "../../../experimental/zk-privacy/mneme-index-pedersen-schnorr-zk.rs"]
mod pedersen_schnorr_zk;

#[cfg(feature = "pedersen_schnorr_zk")]
#[path = "../../../experimental/zk-privacy/mneme-index-semantic-zk.rs"]
mod semantic_zk;

#[cfg(feature = "piop_research")]
#[path = "../../../experimental/research/mneme-index-piop-research.rs"]
mod piop_research;

#[cfg(feature = "experimental_semantic")]
pub use commit::{SemanticMerkleTree, empty_semantic_root, hash_sem_internal, hash_sem_leaf};
pub use error::IndexError;
pub use key_index::KeyIndex;
pub use key_index_load::{load_key_index_tree, load_object_keys};
#[cfg(feature = "experimental_semantic")]
pub use procedure::{
    CandidateRow, IndexedEntry, default_semantic_procedure, execute_procedure_p,
    replay_from_candidates,
};
pub use procedure::{PROC_DOMAIN, default_key_procedure, is_key_index_procedure, procedure_id};
#[cfg(feature = "experimental_semantic")]
pub use provenance::{
    align_scoped_receipt_results, build_provenance_attestation, verify_provenance_attestation,
};
#[cfg(feature = "experimental_semantic")]
pub use receipt::SemanticRecallReceipt;
#[cfg(feature = "experimental_semantic")]
pub use receipt::ZkRetrievalAttachment;
#[cfg(feature = "experimental_semantic")]
pub use receipt::{ProvenanceAttestation, ZkannAttachment};
#[cfg(feature = "experimental_semantic")]
pub use semantic::SemanticIndex;
#[cfg(feature = "experimental_semantic")]
pub use verify::{
    HONESTY_NOT_EXACT_NN, verify_ads_vo, verify_ads_vo_membership, verify_semantic_receipt_full,
    verify_semantic_receipt_tcb_gate, verify_semantic_receipt_vo, verify_semantic_receipt_vo_zkann,
};
#[cfg(feature = "experimental_semantic")]
pub use wire::{fuzz_index_path_wire, fuzz_receipt_wire};
#[cfg(feature = "experimental_semantic")]
pub use zkann::{verify_exact_dominance, verify_hnsw_audit_on_demand, verify_zkann_attachment};

#[cfg(feature = "context_gate")]
pub use cognition_cert::{
    CONTEXT_GATE_DRAFT_STATUS, ContextAttestationDraft, assemble_cognition_certificate_v2_draft,
    verify_cognition_certificate_v2_draft, verify_cognition_certificate_v2_draft_strict,
};
#[cfg(feature = "cognition_cert")]
pub use cognition_cert::{
    assemble_cognition_certificate_v1, fuzz_cognition_cert_wire, verify_cognition_certificate_v1,
};
#[cfg(feature = "context_gate")]
pub use context_gate::{CONTEXT_GATE_STRICT_STATUS, apply_context_gate_strict};
#[cfg(feature = "federation")]
pub use federation_cert::{
    FEDERATION_CERT_DRAFT_STATUS, FEDERATION_COGNITION_CERT_VERSION, FederationCognitionCertWire,
    PHASE_IV_FEDERATION_GATE_OPEN, decode_federation_cognition_cert_wire,
    fuzz_federation_cert_verify, fuzz_federation_cert_wire, verify_federation_cognition_cert_wire,
};
#[cfg(feature = "context_gate")]
pub use mneme_gate::{
    verify_consumption_attestation, verify_consumption_attestation_strict,
    verify_output_binding_strict,
};

#[cfg(feature = "commitment_binding")]
pub use commitment_binding::{
    B3_V0_BINDING_STATUS, BINDING_ENVELOPE_TAG, BINDING_HONESTY, BINDING_PROOF_LEN,
    CommitmentBindingReceipt, prove_binding_receipt, verify_binding_receipt,
};

#[cfg(feature = "pedersen_schnorr_zk")]
pub use pedersen_schnorr_zk::{
    PEDERSEN_SCHNORR_HONESTY, PUBLIC_COMMIT_LEN, PedersenSchnorrRetrievalProof, RetrievalWitness,
    ZK_BACKEND, prove_pedersen_schnorr, verify_pedersen_schnorr,
};

// `B3_DEFERRAL_STATUS` re-exported separately because it documents the
// *deferral* (Plonky2/FRI SNARK target not shipped), not the actual backend.
#[cfg(feature = "pedersen_schnorr_zk")]
pub use pedersen_schnorr_zk::B3_DEFERRAL_STATUS;

#[cfg(feature = "piop_research")]
pub use piop_research::{
    PIOP_RESEARCH_HONESTY, PIOP_RESEARCH_STATUS, PIOP_RESEARCH_VERSION, prove_exact_nn_piop,
};

/// Semantic backend enabled when the `experimental_semantic` feature is on.
/// Privacy path is `commitment_binding` only — a tagged BLAKE3 binding envelope,
/// not SNARK, not Plonky2. (The legacy `zk` Cargo feature alias was dropped
/// because it implied zero-knowledge, which the BLAKE3 envelope is not. The
/// deprecated `plonky2_prover` alias maps to `pedersen_schnorr_zk`, not this path.)
#[cfg(feature = "experimental_semantic")]
pub const SEMANTIC_BACKEND_ENABLED: bool = true;

#[cfg(not(feature = "experimental_semantic"))]
pub const SEMANTIC_BACKEND_ENABLED: bool = false;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "experimental_semantic")]
    use mneme_core::{DistanceMetric, FixedPointEmbedding, Procedure, ProcedureAlgo};
    use mneme_core::{LogicalKey, ObjectId};
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
    #[cfg(feature = "experimental_semantic")]
    fn semantic_backend_enabled_with_ads_feature() {
        if !SEMANTIC_BACKEND_ENABLED {
            panic!("SEMANTIC_BACKEND_ENABLED must be true");
        }
    }

    #[cfg(feature = "pedersen_schnorr_zk")]
    #[test]
    fn pedersen_schnorr_zk_real_proof_verifies_and_forgeries_reject() {
        use super::pedersen_schnorr_zk::{
            B3_DEFERRAL_STATUS, PEDERSEN_SCHNORR_HONESTY, RetrievalWitness, ZK_BACKEND,
            prove_pedersen_schnorr, verify_pedersen_schnorr,
        };
        use mneme_core::MnemeError;
        assert!(B3_DEFERRAL_STATUS.contains("IMPLEMENTED"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("zero-knowledge"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("NOT Plonky2"));
        assert!(ZK_BACKEND.contains("no trusted setup"));

        let entry = [9u8; 32];
        let proof = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("prove");
        assert!(!proof.proof_bytes.is_empty());
        verify_pedersen_schnorr(&proof, &proof.public_commit).expect("verify");

        // Forgery: tampering the public commitment must reject.
        let mut wrong = proof.public_commit;
        wrong[0] ^= 0x01;
        assert_eq!(
            verify_pedersen_schnorr(&proof, &wrong),
            Err(MnemeError::ZkProofInvalid)
        );

        // Unsatisfiable witness (query != entry) cannot produce a proof.
        let mut q = entry;
        q[0] ^= 0x01;
        let bad = RetrievalWitness { entry, query: q };
        assert_eq!(
            prove_pedersen_schnorr(&bad),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[cfg(feature = "piop_research")]
    #[test]
    fn piop_research_seam_is_honest() {
        use super::piop_research::{
            PIOP_RESEARCH_HONESTY, PIOP_RESEARCH_STATUS, prove_exact_nn_piop,
        };
        // Research seam must never claim to prove anything.
        assert!(PIOP_RESEARCH_HONESTY.contains("not implemented"));
        assert!(PIOP_RESEARCH_HONESTY.contains("does not prove"));
        assert!(PIOP_RESEARCH_HONESTY.contains("NOT a SNARK"));
        assert!(PIOP_RESEARCH_STATUS.contains("not implemented"));
        // Fail-closed Err — must not panic on the research entry point.
        assert_eq!(
            prove_exact_nn_piop(&[0u8; 32], &[0u8; 32], &[0u8; 32], 1),
            Err(MnemeError::UnsupportedVersion { got: 0 })
        );
    }

    #[test]
    fn piop_research_feature_is_not_default() {
        assert!(
            !cfg!(feature = "piop_research"),
            "piop_research must remain off-by-default and research-only; remove it from default features."
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
    #[cfg(feature = "experimental_semantic")]
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
