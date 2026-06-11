//! CR-6: Cognition Certificate v1 round-trip for `RetrievalProofLevel::CompleteTopK`.

use mneme_core::{
    AsOf, DistanceMetric, ObjectId, Procedure, ProcedureAlgo, RetrievalProofLevel,
    VerificationObject,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_index::{
    AuthenticatedBallTree, CompleteKnnAttachment, CompleteKnnCertAttachment, SemanticRecallReceipt,
    ZkannAttachment, assemble_cognition_certificate_v1, encode_complete_knn_attachment,
    prove_complete_knn, verify_cognition_certificate_v1,
};
use mneme_root::StoredRoot;

fn fixture_points() -> Vec<Vec<f64>> {
    vec![
        vec![0.0, 0.0],
        vec![1.0, 0.0],
        vec![3.0, 1.0],
        vec![7.0, 2.0],
        vec![2.0, 9.0],
        vec![11.0, 4.0],
        vec![5.0, 5.0],
    ]
}

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 3,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

fn build_complete_topk_cert() -> (Vec<u8>, TrustConfig) {
    let operator = KeyPair::from_seed([0x71; 32]);
    let tree = AuthenticatedBallTree::from_points(fixture_points());
    let q = vec![0.0, 0.0];
    let k = 3usize;
    let proof = prove_complete_knn(&tree, &q, k).expect("prove");
    let returned_len = proof.returned.len();
    let att = CompleteKnnCertAttachment {
        commitment: tree.commitment(),
        query: q.clone(),
        k: k as u32,
        proof,
        beacon: None,
    };
    let proof_bytes = encode_complete_knn_attachment(&att).expect("encode attachment");
    let mut receipt = SemanticRecallReceipt::new(
        [0xab; 32],
        [0xcd; 32],
        VerificationObject {
            nodes: Vec::new(),
            candidates: Vec::new(),
            leaf_indices: Vec::new(),
            procedure_id: [0xee; 32],
            query_commit: [0x11; 32],
            result_ids: (0..returned_len).map(|_| ObjectId([0x22; 32])).collect(),
        },
    );
    receipt.zkann = Some(ZkannAttachment {
        level: RetrievalProofLevel::CompleteTopK,
        visited_order: Vec::new(),
    });
    receipt.complete_knn = Some(CompleteKnnAttachment {
        commitment: tree.commitment(),
        query: q,
        k: k as u32,
        proof_bytes,
    });
    let stored = StoredRoot::assemble(
        [0x01; 32], [0x02; 32], [0xcd; 32], [0x03; 14], [0x00; 32], 1, &operator,
    )
    .expect("stored root");
    let mut receipt = receipt;
    receipt.root_bound = stored.preimage_hash;
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, Some(AsOf::RootSeq(1)))
        .expect("assemble");
    (bytes, TrustConfig::new(operator.public_key_bytes()))
}

#[test]
fn complete_topk_cert_round_trip() {
    let (bytes, trust) = build_complete_topk_cert();
    verify_cognition_certificate_v1(&bytes, &trust, &proc()).expect("verify-cert");
}

#[test]
fn complete_topk_cert_is_byte_identical_across_two_assemblies() {
    let (a, _) = build_complete_topk_cert();
    let (b, _) = build_complete_topk_cert();
    assert_eq!(a, b, "deterministic cert bytes");
}
