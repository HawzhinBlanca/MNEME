//! Live semantic-index issuance for `RetrievalProofLevel::CompleteTopK` (CR-6 store wiring).

use crate::complete_knn::{AuthenticatedBallTree, prove_complete_knn};
use crate::complete_knn_cert::{CompleteKnnCertAttachment, encode_complete_knn_attachment};
use crate::error::IndexError;
use crate::procedure::procedure_id;
use crate::receipt::{CompleteKnnAttachment, SemanticRecallReceipt, ZkannAttachment};
use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, RetrievalProofLevel,
    VerificationObject,
};

/// Dequantize fixed-point components to `R^d` for complete-kNN geometry (same scale as ingest).
pub fn fixed_point_to_f64(emb: &FixedPointEmbedding) -> Result<Vec<f64>, MnemeError> {
    emb.validate_shape()?;
    let scale = f64::powi(2.0, i32::from(emb.scale));
    Ok(emb
        .components
        .iter()
        .map(|&c| f64::from(c) * scale)
        .collect())
}

/// Build a complete-kNN semantic receipt from committed embeddings (fail-closed).
pub fn build_complete_topk_receipt(
    object_ids: &[ObjectId],
    embeddings: &[FixedPointEmbedding],
    semantic_commit: [u8; 32],
    root_bound: [u8; 32],
    proc: &Procedure,
    query: &FixedPointEmbedding,
) -> Result<SemanticRecallReceipt, IndexError> {
    if proc.distance != DistanceMetric::SquaredL2I64 {
        return Err(IndexError::SemanticNotImplemented);
    }
    if object_ids.is_empty() || object_ids.len() != embeddings.len() {
        return Err(IndexError::ObjectNotIndexed);
    }
    query
        .validate_shape()
        .map_err(|_| IndexError::EmbeddingShape)?;
    let query_f64 = fixed_point_to_f64(query).map_err(IndexError::from)?;

    let mut points = Vec::with_capacity(embeddings.len());
    for emb in embeddings {
        if emb.dim != query.dim || emb.scale != query.scale {
            return Err(IndexError::EmbeddingShape);
        }
        emb.validate_shape()
            .map_err(|_| IndexError::EmbeddingShape)?;
        points.push(fixed_point_to_f64(emb).map_err(IndexError::from)?);
    }

    let tree = AuthenticatedBallTree::from_points(points);
    let k = usize::try_from(proc.k).map_err(|_| IndexError::ObjectNotIndexed)?;
    if k == 0 {
        return Err(IndexError::ObjectNotIndexed);
    }
    let proof = prove_complete_knn(&tree, &query_f64, k).map_err(IndexError::from)?;

    let result_ids: Vec<ObjectId> = proof
        .returned
        .iter()
        .map(|rp| object_ids[rp.index])
        .collect();

    let att = CompleteKnnCertAttachment {
        commitment: tree.commitment(),
        query: query_f64.clone(),
        k: proc.k,
        proof,
        beacon: None,
    };
    let proof_bytes = encode_complete_knn_attachment(&att).map_err(IndexError::from)?;

    let vo = VerificationObject {
        nodes: Vec::new(),
        candidates: Vec::new(),
        leaf_indices: Vec::new(),
        procedure_id: procedure_id(proc),
        query_commit: query.commit(),
        result_ids,
    };

    let mut receipt = SemanticRecallReceipt::new(root_bound, semantic_commit, vo);
    receipt.zkann = Some(ZkannAttachment {
        level: RetrievalProofLevel::CompleteTopK,
        visited_order: receipt.verification_object.result_ids.clone(),
    });
    receipt.complete_knn = Some(CompleteKnnAttachment {
        commitment: tree.commitment(),
        query: query_f64,
        k: proc.k,
        proof_bytes,
    });
    Ok(receipt)
}
