//! Semantic ADS verification: Merkle paths + procedure replay + zkANN dominance.
//!
//! Independent reimplementation mirroring mneme-index `commit.rs`, `verify.rs`,
//! and `zkann.rs`. No `mneme-*` deps.

use crate::domain::{empty_semantic_root, hash_sem_internal, hash_sem_leaf};
use crate::error::CrossrefError;
use crate::procedure::{CandidateRow, Procedure, procedure_id, replay_from_candidates};
use std::collections::{HashMap, HashSet};

/// zkANN-1 retrieval proof level (tags match `RetrievalProofLevel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrievalProofLevel {
    ExactDominance,
    HnswAuditOnDemand,
}

/// ADS verification object (§9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationObject {
    /// `(leaf_commit, merkle_path)` pairs.
    pub nodes: Vec<([u8; 32], Vec<[u8; 32]>)>,
    /// Examined candidates: `(object_id, embedding_commit, integer_distance)`.
    pub candidates: Vec<CandidateRow>,
    /// True leaf indices in the full semantic tree (parallel to `nodes` / `candidates`).
    pub leaf_indices: Vec<usize>,
    pub procedure_id: [u8; 32],
    pub query_commit: [u8; 32],
    pub result_ids: Vec<[u8; 32]>,
}

/// zkANN-1 attachment: proof level + declared visit order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkannAttachment {
    pub level: RetrievalProofLevel,
    pub visited_order: Vec<[u8; 32]>,
}

/// Verify a leaf commitment resolves to `root` when `index` is known.
pub fn verify_path_with_index(
    index: usize,
    leaf_commit: &[u8; 32],
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> Result<(), CrossrefError> {
    let mut current = *leaf_commit;
    let mut idx = index;
    for sibling in path {
        current = if idx % 2 == 0 {
            hash_sem_internal(&current, sibling)
        } else {
            hash_sem_internal(sibling, &current)
        };
        idx /= 2;
    }
    if current != *root {
        return Err(CrossrefError::PathInvalid);
    }
    Ok(())
}

/// Verify ADS backend VO: Merkle paths + deterministic procedure replay.
pub fn verify_ads_vo(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
    proc: &Procedure,
) -> Result<(), CrossrefError> {
    if vo.procedure_id != procedure_id(proc) {
        return Err(CrossrefError::ProcedureMismatch);
    }
    if vo.nodes.len() != vo.leaf_indices.len() || vo.candidates.len() != vo.leaf_indices.len() {
        return Err(CrossrefError::PathInvalid);
    }

    let mut seen_indices = HashSet::with_capacity(vo.leaf_indices.len());
    let mut commit_to_path: HashMap<[u8; 32], (usize, &Vec<[u8; 32]>)> =
        HashMap::with_capacity(vo.nodes.len());
    for ((commit, path), leaf_index) in vo.nodes.iter().zip(vo.leaf_indices.iter()) {
        if !seen_indices.insert(*leaf_index) {
            return Err(CrossrefError::PathInvalid);
        }
        if commit_to_path
            .insert(*commit, (*leaf_index, path))
            .is_some()
        {
            return Err(CrossrefError::PathInvalid);
        }
    }

    for (id, emb, _) in &vo.candidates {
        let commit = hash_sem_leaf(id, emb);
        let Some((leaf_index, path)) = commit_to_path.get(&commit) else {
            return Err(CrossrefError::PathInvalid);
        };
        verify_path_with_index(*leaf_index, &commit, path, semantic_commit)?;
    }

    if replay_from_candidates(proc, &vo.candidates) != vo.result_ids {
        return Err(CrossrefError::ProcedureMismatch);
    }
    Ok(())
}

/// Verify VO plus optional zkANN-1 attachment (mirrors `verify_semantic_receipt_vo_zkann`).
pub fn verify_semantic_vo_zkann(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
    proc: &Procedure,
    zkann: Option<&ZkannAttachment>,
    committed_leaf_count: usize,
) -> Result<(), CrossrefError> {
    match zkann {
        Some(z) => {
            verify_ads_vo(vo, semantic_commit, proc)?;
            match z.level {
                RetrievalProofLevel::ExactDominance => {
                    // SOUNDNESS PARITY with the main verifier (mneme-index
                    // verify_candidate_set_binds_root): completeness MUST bind to the signed
                    // root, never a prover-supplied count. Without this, crossref accepts the
                    // dropped-true-nearest-neighbor forge the main verifier rejects — a
                    // soundness gap AND a divergence between the two verifiers.
                    verify_candidate_set_binds_root(vo, semantic_commit)?;
                    verify_exact_dominance(vo, proc, committed_leaf_count)
                }
                RetrievalProofLevel::HnswAuditOnDemand => {
                    verify_hnsw_audit_on_demand(vo, proc, &z.visited_order)
                }
            }
        }
        None => verify_ads_vo(vo, semantic_commit, proc),
    }
}

/// Full committed set in VO + top-k dominance (flat index path).
pub fn verify_exact_dominance(
    vo: &VerificationObject,
    proc: &Procedure,
    committed_leaf_count: usize,
) -> Result<(), CrossrefError> {
    if vo.candidates.len() != committed_leaf_count {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    dominance_over_candidates(vo, proc)
}

/// Authenticate the COMPLETE candidate set against the signed `semantic_commit` (parity with
/// `mneme-index::zkann::verify_candidate_set_binds_root`): rebuild the semantic Merkle tree from
/// exactly the presented `(object_id, embedding_commit)` leaves and require
/// `root == semantic_commit`, rejecting duplicate object_ids. Any dropped/added/substituted/
/// duplicated leaf changes the root → fail closed. Replaces the unsound prover-supplied count.
fn verify_candidate_set_binds_root(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
) -> Result<(), CrossrefError> {
    let mut ids: Vec<[u8; 32]> = vo.candidates.iter().map(|(id, _, _)| *id).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    if ids.len() != n {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    if rebuild_semantic_root(&vo.candidates) != *semantic_commit {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    Ok(())
}

/// Mirror of `SemanticMerkleTree::from_entries().root()`: sort leaves by object_id, hash each
/// leaf, then pairwise-hash up the tree with odd-node self-promotion.
fn rebuild_semantic_root(candidates: &[CandidateRow]) -> [u8; 32] {
    let mut pairs: Vec<([u8; 32], [u8; 32])> =
        candidates.iter().map(|(id, ec, _)| (*id, *ec)).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut level: Vec<[u8; 32]> = pairs.iter().map(|(id, ec)| hash_sem_leaf(id, ec)).collect();
    if level.is_empty() {
        return empty_semantic_root();
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let l = level[i];
            let r = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            next.push(hash_sem_internal(&l, &r));
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Dominance over the declared visited neighborhood (HNSW audit-on-demand path).
pub fn verify_hnsw_audit_on_demand(
    vo: &VerificationObject,
    proc: &Procedure,
    visited_order: &[[u8; 32]],
) -> Result<(), CrossrefError> {
    if visited_order.is_empty() {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    let visited: HashSet<[u8; 32]> = visited_order.iter().copied().collect();
    for id in &vo.result_ids {
        if !visited.contains(id) {
            return Err(CrossrefError::RetrievalDominanceFailed);
        }
    }
    for (id, _, _) in &vo.candidates {
        if !visited.contains(id) {
            return Err(CrossrefError::RetrievalDominanceFailed);
        }
    }
    dominance_over_candidates(vo, proc)
}

fn dominance_over_candidates(
    vo: &VerificationObject,
    proc: &Procedure,
) -> Result<(), CrossrefError> {
    let replayed = replay_from_candidates(proc, &vo.candidates);
    if replayed != vo.result_ids {
        return Err(CrossrefError::RetrievalDominanceFailed);
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
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    result_dists.sort();
    let cutoff = *result_dists
        .last()
        .ok_or(CrossrefError::RetrievalDominanceFailed)?;
    let returned: HashSet<[u8; 32]> = replayed.into_iter().collect();
    for (id, _, dist) in &vo.candidates {
        if !returned.contains(id) && *dist < cutoff {
            return Err(CrossrefError::RetrievalDominanceFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod soundness_tests {
    use super::*;

    fn cand(id: u8, ec: u8, d: i64) -> CandidateRow {
        ([id; 32], [ec; 32], d)
    }

    fn vo(candidates: Vec<CandidateRow>) -> VerificationObject {
        VerificationObject {
            nodes: vec![],
            candidates,
            leaf_indices: vec![],
            procedure_id: [0u8; 32],
            query_commit: [0u8; 32],
            result_ids: vec![],
        }
    }

    /// Parity with the main verifier's `zkann_dropped_true_nearest_neighbor_must_be_rejected`:
    /// dropping the true nearest neighbor (id 9) yields a different rebuilt root than the signed
    /// `semantic_commit`, so completeness binding fails closed — crossref no longer diverges.
    #[test]
    fn binds_root_rejects_dropped_true_nearest_neighbor() {
        let full = vec![cand(1, 0x11, 5), cand(2, 0x22, 9), cand(9, 0x99, 1)];
        let commit = rebuild_semantic_root(&full);
        assert!(verify_candidate_set_binds_root(&vo(full), &commit).is_ok());

        let dropped = vec![cand(1, 0x11, 5), cand(2, 0x22, 9)]; // true NN (id 9) hidden
        assert_eq!(
            verify_candidate_set_binds_root(&vo(dropped), &commit),
            Err(CrossrefError::RetrievalDominanceFailed),
            "dropping the true nearest neighbor must fail closed (root mismatch)"
        );
    }

    /// Duplicate-padding (repeat a member to hit a count) is rejected before the root check.
    #[test]
    fn binds_root_rejects_duplicate_padding() {
        let full = vec![cand(1, 0x11, 5), cand(2, 0x22, 9)];
        let commit = rebuild_semantic_root(&full);
        let dup = vec![cand(1, 0x11, 5), cand(1, 0x11, 5)];
        assert_eq!(
            verify_candidate_set_binds_root(&vo(dup), &commit),
            Err(CrossrefError::RetrievalDominanceFailed)
        );
    }

    /// A substituted leaf (wrong embedding_commit) changes the root → rejected.
    #[test]
    fn binds_root_rejects_substituted_leaf() {
        let full = vec![cand(1, 0x11, 5), cand(2, 0x22, 9)];
        let commit = rebuild_semantic_root(&full);
        let swapped = vec![cand(1, 0x11, 5), cand(2, 0xAB, 9)]; // 0x22 -> 0xAB
        assert_eq!(
            verify_candidate_set_binds_root(&vo(swapped), &commit),
            Err(CrossrefError::RetrievalDominanceFailed)
        );
    }
}
