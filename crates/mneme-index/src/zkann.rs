//! zkANN-1 retrieval proofs: exact dominance + HNSW audit-on-demand (Phase I P1-1).

use crate::procedure::replay_from_candidates;
use crate::receipt::SemanticRecallReceipt;
use crate::verify::verify_ads_vo;
use mneme_core::{MnemeError, ObjectId, Procedure, RetrievalProofLevel, VerificationObject};
use std::collections::HashSet;

/// Verify zkANN-1 attachment on a semantic receipt (ADS + level-specific dominance).
pub fn verify_zkann_attachment(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
    committed_leaf_count: usize,
) -> Result<(), MnemeError> {
    let zkann = receipt
        .zkann
        .as_ref()
        .ok_or(MnemeError::CertificateInvalid)?;
    verify_ads_vo(&receipt.verification_object, &receipt.semantic_commit, proc)?;
    match zkann.level {
        RetrievalProofLevel::ExactDominance => {
            verify_exact_dominance(&receipt.verification_object, proc, committed_leaf_count)
        }
        RetrievalProofLevel::HnswAuditOnDemand => {
            verify_hnsw_audit_on_demand(&receipt.verification_object, proc, &zkann.visited_order)
        }
    }
}

/// Full committed set in VO + top-k dominance (flat index path).
pub fn verify_exact_dominance(
    vo: &VerificationObject,
    proc: &Procedure,
    committed_leaf_count: usize,
) -> Result<(), MnemeError> {
    if vo.candidates.len() != committed_leaf_count {
        return Err(MnemeError::RetrievalDominanceFailed);
    }
    dominance_over_candidates(vo, proc)
}

/// Dominance over the declared visited neighborhood (HNSW audit-on-demand path).
pub fn verify_hnsw_audit_on_demand(
    vo: &VerificationObject,
    proc: &Procedure,
    visited_order: &[ObjectId],
) -> Result<(), MnemeError> {
    if visited_order.is_empty() {
        return Err(MnemeError::RetrievalDominanceFailed);
    }
    let visited: HashSet<ObjectId> = visited_order.iter().copied().collect();
    for id in &vo.result_ids {
        if !visited.contains(id) {
            return Err(MnemeError::RetrievalDominanceFailed);
        }
    }
    for (id, _, _) in &vo.candidates {
        if !visited.contains(id) {
            return Err(MnemeError::RetrievalDominanceFailed);
        }
    }
    dominance_over_candidates(vo, proc)
}

fn dominance_over_candidates(vo: &VerificationObject, proc: &Procedure) -> Result<(), MnemeError> {
    let replayed = replay_from_candidates(proc, &vo.candidates);
    if replayed != vo.result_ids {
        return Err(MnemeError::RetrievalDominanceFailed);
    }
    if replayed.is_empty() {
        return Ok(());
    }
    let mut result_dists: Vec<i64> = replayed
        .iter()
        .filter_map(|id| {
            vo.candidates
                .iter()
                .find(|(cid, _, _)| cid == id)
                .map(|(_, _, d)| *d)
        })
        .collect();
    if result_dists.len() != replayed.len() {
        return Err(MnemeError::RetrievalDominanceFailed);
    }
    result_dists.sort();
    let cutoff = *result_dists
        .last()
        .ok_or(MnemeError::RetrievalDominanceFailed)?;
    let returned: HashSet<ObjectId> = replayed.into_iter().collect();
    for (id, _, dist) in &vo.candidates {
        if !returned.contains(id) && *dist < cutoff {
            return Err(MnemeError::RetrievalDominanceFailed);
        }
    }
    Ok(())
}
