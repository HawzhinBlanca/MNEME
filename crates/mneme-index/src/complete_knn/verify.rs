//! Fail-closed verifier for complete k-NN proofs (CR-3).

use super::auth_tree::AuthenticatedBallTree;
use super::geometry::squared_euclidean;
use super::prove::{CompleteKnnProof, FrontierNode};
use mneme_core::MnemeError;

/// Honesty string for complete-kNN verification surface.
pub const COMPLETE_KNN_HONESTY: &str = "complete-kNN proves completeness of retrieval (no closer neighbor hidden), not semantic truth; authenticated ≠ true";

/// Verify a complete-kNN proof; fail-closed on any tamper.
pub fn verify_complete_knn(
    commitment: &[u8; 32],
    query: &[f64],
    k: usize,
    proof: &CompleteKnnProof,
) -> Result<(), MnemeError> {
    if proof.returned.len() != k {
        return Err(verify_failure(VerifyFailure::ReturnedCountMismatch));
    }

    let mut recomputed = Vec::with_capacity(k);
    for rp in &proof.returned {
        AuthenticatedBallTree::verify_leaf_proof(commitment, rp.index, &rp.point, &rp.auth)?;
        let d = squared_euclidean(query, &rp.point);
        if (d - rp.distance_sq).abs() > 1e-9 {
            return Err(verify_failure(VerifyFailure::DistanceMismatch));
        }
        recomputed.push((rp.index, d));
    }

    let tau_sq = recomputed.iter().map(|(_, d)| *d).fold(0.0_f64, f64::max);

    for node in &proof.frontier {
        verify_frontier_node(commitment, query, tau_sq, node)?;
    }

    for ex in &proof.excluded {
        AuthenticatedBallTree::verify_leaf_proof(commitment, ex.index, &ex.point, &ex.auth)?;
        let d = squared_euclidean(query, &ex.point);
        if d < tau_sq {
            return Err(verify_failure(VerifyFailure::PruningBoundFailed));
        }
    }

    verify_antichain_cover(proof)?;

    Ok(())
}

/// Returns `(distance_evals, merkle_checks)` for cost accounting.
pub fn verify_complete_knn_cost_bounded(
    commitment: &[u8; 32],
    query: &[f64],
    k: usize,
    proof: &CompleteKnnProof,
) -> Result<(usize, usize), MnemeError> {
    verify_complete_knn(commitment, query, k, proof)?;
    let distance_evals = k + proof.frontier.len();
    let merkle_checks = proof.returned.len() + proof.frontier.len();
    Ok((distance_evals, merkle_checks))
}

fn verify_frontier_node(
    commitment: &[u8; 32],
    query: &[f64],
    tau_sq: f64,
    node: &FrontierNode,
) -> Result<(), MnemeError> {
    AuthenticatedBallTree::verify_internal_proof(
        commitment,
        &node.pivot,
        node.radius_sq,
        &node.left_hash,
        &node.right_hash,
        &node.auth,
    )?;
    let d_qp = squared_euclidean(query, &node.pivot).sqrt();
    let radius = node.radius_sq.sqrt();
    let lower = (d_qp - radius).max(0.0);
    if lower * lower <= tau_sq {
        return Err(verify_failure(VerifyFailure::PruningBoundFailed));
    }
    Ok(())
}

/// Cover check: returned + frontier subtrees + excluded leaves partition all indices.
fn verify_antichain_cover(proof: &CompleteKnnProof) -> Result<(), MnemeError> {
    let mut covered = std::collections::BTreeSet::new();
    for rp in &proof.returned {
        if !covered.insert(rp.index) {
            return Err(verify_failure(VerifyFailure::DuplicateReturned));
        }
    }
    for f in &proof.frontier {
        for &idx in &f.subtree_leaf_indices {
            if covered.contains(&idx) {
                return Err(verify_failure(VerifyFailure::DuplicateFrontier));
            }
            covered.insert(idx);
        }
    }
    for ex in &proof.excluded {
        if covered.contains(&ex.index) {
            return Err(verify_failure(VerifyFailure::DuplicateFrontier));
        }
        covered.insert(ex.index);
    }
    if covered.len() != proof.total_points {
        return Err(verify_failure(VerifyFailure::CoverIncomplete));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyFailure {
    ReturnedCountMismatch,
    DistanceMismatch,
    PruningBoundFailed,
    DuplicateReturned,
    DuplicateFrontier,
    CoverIncomplete,
}

fn verify_failure(f: VerifyFailure) -> MnemeError {
    match f {
        VerifyFailure::ReturnedCountMismatch
        | VerifyFailure::DistanceMismatch
        | VerifyFailure::DuplicateReturned
        | VerifyFailure::DuplicateFrontier
        | VerifyFailure::CoverIncomplete => MnemeError::RetrievalDominanceFailed,
        VerifyFailure::PruningBoundFailed => MnemeError::IndexPathInvalid,
    }
}
