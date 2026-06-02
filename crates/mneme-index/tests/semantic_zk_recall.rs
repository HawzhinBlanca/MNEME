//! Semantic recall + ZK attachment on the agent hot path (`plonky2_prover` feature).

#![cfg(feature = "plonky2_prover")]

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
};
use mneme_index::{SemanticIndex, verify_semantic_receipt_vo};

#[test]
fn semantic_receipt_attaches_zk_when_query_matches_top_embedding_commit() {
    let mut index = SemanticIndex::new();
    let emb = FixedPointEmbedding::new(2, 0, vec![7, 0]).unwrap();
    index.insert(ObjectId([0x01; 32]), emb.clone()).unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let receipt = index.recall_receipt(&proc, &emb, [0xab; 32]).unwrap();
    assert!(
        receipt.zk_retrieval.is_some(),
        "exact query embedding should yield a ZK attachment"
    );
    verify_semantic_receipt_vo(&receipt, &proc).unwrap();
}

#[test]
fn semantic_receipt_zk_rejects_spliced_proof_bytes() {
    let mut index = SemanticIndex::new();
    let emb = FixedPointEmbedding::new(2, 0, vec![7, 0]).unwrap();
    index.insert(ObjectId([0x01; 32]), emb.clone()).unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let mut receipt = index.recall_receipt(&proc, &emb, [0xab; 32]).unwrap();
    let mut zk = receipt.zk_retrieval.take().expect("zk");
    zk.proof_bytes[0] ^= 0xff;
    receipt.zk_retrieval = Some(zk);
    assert_eq!(
        verify_semantic_receipt_vo(&receipt, &proc),
        Err(MnemeError::ZkProofInvalid)
    );
}
