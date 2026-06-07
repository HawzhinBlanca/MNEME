//! zkANN-1 retrieval proofs: authenticated dominance + HNSW audit-on-demand (Phase I P1-1).

use crate::commit::SemanticMerkleTree;
use crate::procedure::replay_from_candidates;
use crate::receipt::SemanticRecallReceipt;
use crate::verify::verify_ads_vo;
use mneme_core::{MnemeError, ObjectId, Procedure, RetrievalProofLevel, VerificationObject};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZkannFailure {
    AttachmentMissing,
    CandidateSetDuplicateObject,
    CandidateSetRootMismatch,
    ExactCandidateCountMismatch,
    VisitedOrderEmpty,
    VisitedOrderDuplicateObject,
    VisitedOrderCandidateMismatch,
    ResultOutsideVisitedSet,
    CandidateOutsideVisitedSet,
    ReplayResultMismatch,
    ReturnedDistanceMissing,
    CutoffDistanceMissing,
    DominatingUnreturnedCandidate,
}

fn zkann_failure_to_mneme(failure: ZkannFailure) -> MnemeError {
    match failure {
        ZkannFailure::AttachmentMissing => MnemeError::CertificateInvalid,
        ZkannFailure::CandidateSetDuplicateObject
        | ZkannFailure::CandidateSetRootMismatch
        | ZkannFailure::ExactCandidateCountMismatch
        | ZkannFailure::VisitedOrderEmpty
        | ZkannFailure::VisitedOrderDuplicateObject
        | ZkannFailure::VisitedOrderCandidateMismatch
        | ZkannFailure::ResultOutsideVisitedSet
        | ZkannFailure::CandidateOutsideVisitedSet
        | ZkannFailure::ReplayResultMismatch
        | ZkannFailure::ReturnedDistanceMissing
        | ZkannFailure::CutoffDistanceMissing
        | ZkannFailure::DominatingUnreturnedCandidate => MnemeError::RetrievalDominanceFailed,
    }
}

fn zkann_error(failure: ZkannFailure) -> MnemeError {
    zkann_failure_to_mneme(failure)
}

/// Verify zkANN-1 attachment on a semantic receipt (ADS + level-specific dominance).
pub fn verify_zkann_attachment(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
    committed_leaf_count: usize,
) -> Result<(), MnemeError> {
    let zkann = receipt
        .zkann
        .as_ref()
        .ok_or_else(|| zkann_error(ZkannFailure::AttachmentMissing))?;
    verify_ads_vo(&receipt.verification_object, &receipt.semantic_commit, proc)?;
    match zkann.level {
        RetrievalProofLevel::ExactDominance => {
            // SOUNDNESS (red-team finding, docs/redteam/PHASE_I_ZKANN_SOUNDNESS.md):
            // completeness MUST be bound to the SIGNED root, never to a prover-supplied
            // count. Authenticate that the candidate set IS the entire committed set by
            // rebuilding the semantic Merkle tree from exactly these leaves and requiring
            // root == semantic_commit. Without this a forge drops the true nearest
            // neighbor (a suffix leaf) and the verifier accepts.
            verify_candidate_set_binds_root(
                &receipt.verification_object,
                &receipt.semantic_commit,
            )?;
            verify_exact_dominance(&receipt.verification_object, proc, committed_leaf_count)
        }
        RetrievalProofLevel::HnswAuditOnDemand => {
            verify_hnsw_audit_on_demand(&receipt.verification_object, proc, &zkann.visited_order)
        }
    }
}

/// Authenticate the COMPLETE candidate set against the signed `semantic_commit`: rebuild
/// the semantic Merkle tree from exactly the presented `(id, embedding_commit)` leaves and
/// require `root == semantic_commit`, rejecting duplicate ObjectIds. Any dropped, added,
/// substituted, or duplicated leaf changes the root → fail closed. This is the authoritative
/// completeness proof for the exact path; it replaces the unsound prover-supplied
/// `committed_leaf_count` (which a red-team forge exploited to hide the true nearest neighbor).
fn verify_candidate_set_binds_root(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
) -> Result<(), MnemeError> {
    let mut ids: Vec<ObjectId> = vo.candidates.iter().map(|(id, _, _)| *id).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    if ids.len() != n {
        return Err(zkann_error(ZkannFailure::CandidateSetDuplicateObject));
    }
    let entries: Vec<(ObjectId, [u8; 32])> = vo
        .candidates
        .iter()
        .map(|(id, emb_commit, _)| (*id, *emb_commit))
        .collect();
    if &SemanticMerkleTree::from_entries(&entries).root() != semantic_commit {
        return Err(zkann_error(ZkannFailure::CandidateSetRootMismatch));
    }
    Ok(())
}

/// Complete authenticated member set in VO + top-k over prover-asserted distances (flat path).
/// This does not prove true query-to-embedding distance ordering until the VO carries embeddings
/// and verifiers recompute candidate distances. Callers via
/// [`verify_zkann_attachment`] MUST first bind the candidate set to the signed root with
/// [`verify_candidate_set_binds_root`]; the `committed_leaf_count` argument is only a
/// secondary cross-check (the root binding is the authoritative completeness proof).
pub fn verify_exact_dominance(
    vo: &VerificationObject,
    proc: &Procedure,
    committed_leaf_count: usize,
) -> Result<(), MnemeError> {
    if vo.candidates.len() != committed_leaf_count {
        return Err(zkann_error(ZkannFailure::ExactCandidateCountMismatch));
    }
    dominance_over_candidates(vo, proc)
}

/// Dominance over prover-chosen authenticated members listed in `visited_order` (not graph replay).
pub fn verify_hnsw_audit_on_demand(
    vo: &VerificationObject,
    proc: &Procedure,
    visited_order: &[ObjectId],
) -> Result<(), MnemeError> {
    if visited_order.is_empty() {
        return Err(zkann_error(ZkannFailure::VisitedOrderEmpty));
    }
    let mut visited = HashSet::with_capacity(visited_order.len());
    for id in visited_order {
        if !visited.insert(*id) {
            return Err(zkann_error(ZkannFailure::VisitedOrderDuplicateObject));
        }
    }
    for id in &vo.result_ids {
        if !visited.contains(id) {
            return Err(zkann_error(ZkannFailure::ResultOutsideVisitedSet));
        }
    }
    let mut candidate_ids = HashSet::with_capacity(vo.candidates.len());
    for (id, _, _) in &vo.candidates {
        if !candidate_ids.insert(*id) {
            return Err(zkann_error(ZkannFailure::CandidateSetDuplicateObject));
        }
        if !visited.contains(id) {
            return Err(zkann_error(ZkannFailure::CandidateOutsideVisitedSet));
        }
    }
    if candidate_ids != visited {
        return Err(zkann_error(ZkannFailure::VisitedOrderCandidateMismatch));
    }
    dominance_over_candidates(vo, proc)
}

fn dominance_over_candidates(vo: &VerificationObject, proc: &Procedure) -> Result<(), MnemeError> {
    let replayed = replay_from_candidates(proc, &vo.candidates);
    if replayed != vo.result_ids {
        return Err(zkann_error(ZkannFailure::ReplayResultMismatch));
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
        return Err(zkann_error(ZkannFailure::ReturnedDistanceMissing));
    }
    result_dists.sort();
    let cutoff = *result_dists
        .last()
        .ok_or_else(|| zkann_error(ZkannFailure::CutoffDistanceMissing))?;
    let returned: HashSet<ObjectId> = replayed.into_iter().collect();
    for (id, _, dist) in &vo.candidates {
        if !returned.contains(id) && *dist < cutoff {
            return Err(zkann_error(ZkannFailure::DominatingUnreturnedCandidate));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{DistanceMetric, ProcedureAlgo};

    fn oid(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    fn hnsw_proc() -> Procedure {
        Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 4,
            k: 1,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        }
    }

    fn hnsw_vo() -> VerificationObject {
        VerificationObject {
            nodes: Vec::new(),
            candidates: vec![(oid(1), [0x11; 32], 1), (oid(2), [0x22; 32], 2)],
            leaf_indices: Vec::new(),
            procedure_id: [0x33; 32],
            query_commit: [0x44; 32],
            result_ids: vec![oid(1)],
        }
    }

    #[test]
    fn zkann_failures_are_classified_not_dominance_collapsed() {
        let source = include_str!("zkann.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("zkann tests should follow production code");

        for forbidden in [
            "return Err(MnemeError::RetrievalDominanceFailed",
            ".ok_or(MnemeError::RetrievalDominanceFailed",
        ] {
            assert!(
                !source.contains(forbidden),
                "zkANN verifier should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ZkannFailure",
            "AttachmentMissing",
            "CandidateSetDuplicateObject",
            "CandidateSetRootMismatch",
            "ExactCandidateCountMismatch",
            "VisitedOrderEmpty",
            "VisitedOrderDuplicateObject",
            "VisitedOrderCandidateMismatch",
            "ResultOutsideVisitedSet",
            "CandidateOutsideVisitedSet",
            "ReplayResultMismatch",
            "ReturnedDistanceMissing",
            "CutoffDistanceMissing",
            "DominatingUnreturnedCandidate",
            "fn zkann_failure_to_mneme(",
            "fn zkann_error(",
        ] {
            assert!(
                source.contains(required),
                "zkANN verifier should include `{required}`"
            );
        }
    }

    #[test]
    fn zkann_failure_classifier_preserves_public_errors() {
        for (failure, expected) in [
            (
                ZkannFailure::AttachmentMissing,
                MnemeError::CertificateInvalid,
            ),
            (
                ZkannFailure::CandidateSetDuplicateObject,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::CandidateSetRootMismatch,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::ExactCandidateCountMismatch,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::VisitedOrderEmpty,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::VisitedOrderDuplicateObject,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::VisitedOrderCandidateMismatch,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::ResultOutsideVisitedSet,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::CandidateOutsideVisitedSet,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::ReplayResultMismatch,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::ReturnedDistanceMissing,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::CutoffDistanceMissing,
                MnemeError::RetrievalDominanceFailed,
            ),
            (
                ZkannFailure::DominatingUnreturnedCandidate,
                MnemeError::RetrievalDominanceFailed,
            ),
        ] {
            assert_eq!(zkann_failure_to_mneme(failure), expected);
            assert_eq!(zkann_error(failure), expected);
        }
    }

    #[test]
    fn hnsw_audit_rejects_duplicate_visited_order_member() {
        let vo = hnsw_vo();

        assert_eq!(
            verify_hnsw_audit_on_demand(&vo, &hnsw_proc(), &[oid(1), oid(1), oid(2)]),
            Err(MnemeError::RetrievalDominanceFailed)
        );
    }

    #[test]
    fn hnsw_audit_rejects_unauthenticated_extra_visited_member() {
        let vo = hnsw_vo();

        assert_eq!(
            verify_hnsw_audit_on_demand(&vo, &hnsw_proc(), &[oid(1), oid(2), oid(9)]),
            Err(MnemeError::RetrievalDominanceFailed)
        );
    }
}
