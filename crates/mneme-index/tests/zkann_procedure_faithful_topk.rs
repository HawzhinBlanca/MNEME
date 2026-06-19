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
fn zkann_procedure_faithful_topk_roundtrip() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    index
        .insert(oid(2), FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap())
        .unwrap();
    let receipt = index
        .recall_receipt_zkann(
            &proc(),
            &q,
            [0xab; 32],
            RetrievalProofLevel::ProcedureFaithfulTopK,
        )
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
        .recall_receipt_zkann(
            &proc(),
            &q,
            [0xab; 32],
            RetrievalProofLevel::ProcedureFaithfulTopK,
        )
        .unwrap();
    receipt.verification_object.result_ids = vec![oid(2)];
    assert_eq!(
        verify_exact_dominance(&receipt.verification_object, &proc(), 2),
        Err(MnemeError::RetrievalDominanceFailed)
    );
}

/// ADVERSARIAL (red-team): the forgery the integration suite OMITTED. Drop the true
/// nearest neighbor (a suffix leaf whose siblings' Merkle paths still validate), then set
/// `committed_leaf_count` to the remaining candidate count — exactly what
/// `verify_cognition_certificate_v1` passes. Before the root-binding fix the verifier
/// returned `Ok(())` (hiding the real top match). It MUST fail closed.
#[test]
fn zkann_dropped_true_nearest_neighbor_must_be_rejected() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index // dist 25
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap())
        .unwrap();
    index // dist 64
        .insert(oid(2), FixedPointEmbedding::new(2, 0, vec![8, 0]).unwrap())
        .unwrap();
    index // TRUE nearest (dist 1), highest ObjectId → last (suffix) leaf
        .insert(oid(9), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let mut receipt = index
        .recall_receipt_zkann(
            &proc(),
            &q,
            [0xab; 32],
            RetrievalProofLevel::ProcedureFaithfulTopK,
        )
        .unwrap();

    let vo = &mut receipt.verification_object;
    let drop_commit: Vec<[u8; 32]> = vo
        .candidates
        .iter()
        .filter(|(id, _, _)| *id == oid(9))
        .map(|(id, emb, _)| mneme_index::hash_sem_leaf(id.as_bytes(), emb))
        .collect();
    vo.candidates.retain(|(id, _, _)| *id != oid(9));
    let mut kept_nodes = Vec::new();
    let mut kept_leaf_indices = Vec::new();
    for ((commit, path), leaf_index) in vo
        .nodes
        .clone()
        .into_iter()
        .zip(vo.leaf_indices.clone().into_iter())
    {
        if drop_commit.contains(&commit) {
            continue;
        }
        kept_nodes.push((commit, path));
        kept_leaf_indices.push(leaf_index);
    }
    vo.nodes = kept_nodes;
    vo.leaf_indices = kept_leaf_indices;
    vo.result_ids = vec![oid(1)];
    let forged_count = vo.candidates.len();

    let got = verify_zkann_attachment(&receipt, &proc(), forged_count);
    assert_eq!(
        got,
        Err(MnemeError::RetrievalDominanceFailed),
        "SOUNDNESS: dropping the true nearest neighbor with a self-supplied leaf count \
         must fail closed, not accept (got {got:?})"
    );
}

#[test]
fn zkann_hnsw_audit_roundtrip_uses_true_leaf_indices() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![2, 2]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![10, 0]).unwrap())
        .unwrap();
    index
        .insert(oid(3), FixedPointEmbedding::new(2, 0, vec![0, 3]).unwrap())
        .unwrap();
    index
        .insert(oid(5), FixedPointEmbedding::new(2, 0, vec![1, 1]).unwrap())
        .unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 2,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 42,
    };
    let receipt = index
        .recall_receipt_zkann(
            &proc,
            &q,
            [0xcd; 32],
            RetrievalProofLevel::HnswAuditOnDemand,
        )
        .unwrap();
    assert!(
        !receipt.verification_object.leaf_indices.is_empty(),
        "audit-on-demand receipt must carry true leaf indices"
    );
    verify_semantic_receipt_vo_zkann(
        &receipt,
        &proc,
        receipt.verification_object.candidates.len(),
    )
    .unwrap();
}

#[test]
fn zkann_hnsw_audit_rejects_wrong_leaf_indices() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![2, 2]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![10, 0]).unwrap())
        .unwrap();
    index
        .insert(oid(3), FixedPointEmbedding::new(2, 0, vec![0, 3]).unwrap())
        .unwrap();
    index
        .insert(oid(5), FixedPointEmbedding::new(2, 0, vec![1, 1]).unwrap())
        .unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 8,
        k: 2,
        distance: DistanceMetric::SquaredL2I64,
        seed: 7,
    };
    let mut receipt = index
        .recall_receipt_zkann(
            &proc,
            &q,
            [0xee; 32],
            RetrievalProofLevel::HnswAuditOnDemand,
        )
        .unwrap();
    assert!(
        receipt.verification_object.leaf_indices.len() >= 2,
        "test requires multiple visited nodes to meaningfully check leaf indices"
    );
    receipt.verification_object.leaf_indices.reverse();
    assert_eq!(
        verify_semantic_receipt_vo_zkann(
            &receipt,
            &proc,
            receipt.verification_object.candidates.len()
        ),
        Err(MnemeError::IndexPathInvalid),
        "forged leaf indices must fail-closed (membership paths bound to true indices)"
    );
}
