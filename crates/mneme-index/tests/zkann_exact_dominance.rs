//! zkANN-1 exact dominance + forgery rejection (Phase I P1-1).

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
    RetrievalProofLevel,
};
use mneme_index::{
    SemanticIndex, verify_exact_dominance, verify_semantic_receipt_vo_zkann,
    verify_zkann_attachment,
};

fn oid(b: u8) -> ObjectId {
    ObjectId([b; 32])
}

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

#[test]
fn zkann_exact_dominance_roundtrip() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    index
        .insert(oid(2), FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap())
        .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xab; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    verify_zkann_attachment(&receipt, &proc(), 2).unwrap();
    verify_semantic_receipt_vo_zkann(&receipt, &proc(), 2).unwrap();
}

#[test]
fn zkann_reordered_result_fails_dominance() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    index
        .insert(oid(2), FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap())
        .unwrap();
    let mut receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xab; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    receipt.verification_object.result_ids = vec![oid(2)];
    assert_eq!(
        verify_exact_dominance(&receipt.verification_object, &proc(), 2),
        Err(MnemeError::RetrievalDominanceFailed)
    );
}
