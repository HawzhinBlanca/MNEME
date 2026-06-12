//! ADS verification-object checks (§9.2 prover-side helpers; verifier TCB in `mneme-verify`).

use crate::commit::{SemanticMerkleTree, hash_sem_leaf};
use crate::procedure::replay_from_candidates;
use crate::receipt::SemanticRecallReceipt;
use mneme_core::{MnemeError, Procedure, VerificationObject};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(not(feature = "pedersen_schnorr_zk"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisabledZkAttachmentFailure {
    TcbGateBackendUnavailable,
    ZkannGateBackendUnavailable,
}

#[cfg(not(feature = "pedersen_schnorr_zk"))]
fn disabled_zk_attachment_failure_to_mneme(failure: DisabledZkAttachmentFailure) -> MnemeError {
    match failure {
        DisabledZkAttachmentFailure::TcbGateBackendUnavailable
        | DisabledZkAttachmentFailure::ZkannGateBackendUnavailable => MnemeError::ZkProofInvalid,
    }
}

#[cfg(not(feature = "pedersen_schnorr_zk"))]
fn disabled_zk_attachment_error(failure: DisabledZkAttachmentFailure) -> MnemeError {
    disabled_zk_attachment_failure_to_mneme(failure)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdsVerificationFailure {
    ProcedureIdMismatch,
    VerificationObjectShapeInvalid,
    DuplicateLeafIndex,
    DuplicateCandidateObject,
    DuplicateCandidateCommit,
    CandidatePathMissing,
    ReplayResultMismatch,
    ProvenanceObjectsUnavailable,
}

fn ads_verification_failure_to_mneme(failure: AdsVerificationFailure) -> MnemeError {
    match failure {
        AdsVerificationFailure::ProcedureIdMismatch
        | AdsVerificationFailure::ReplayResultMismatch => MnemeError::ProcedureMismatch,
        AdsVerificationFailure::VerificationObjectShapeInvalid
        | AdsVerificationFailure::DuplicateLeafIndex
        | AdsVerificationFailure::DuplicateCandidateObject
        | AdsVerificationFailure::DuplicateCandidateCommit
        | AdsVerificationFailure::CandidatePathMissing => MnemeError::IndexPathInvalid,
        AdsVerificationFailure::ProvenanceObjectsUnavailable => {
            MnemeError::ProvenanceFilterViolation
        }
    }
}

fn ads_verification_error(failure: AdsVerificationFailure) -> MnemeError {
    ads_verification_failure_to_mneme(failure)
}

/// Merkle membership for every VO candidate against `semantic_commit` (always required).
pub fn verify_ads_vo_membership(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
    proc: &Procedure,
) -> Result<(), MnemeError> {
    if vo.procedure_id != crate::procedure::procedure_id(proc) {
        return Err(ads_verification_error(
            AdsVerificationFailure::ProcedureIdMismatch,
        ));
    }
    if vo.nodes.len() != vo.leaf_indices.len() || vo.candidates.len() != vo.leaf_indices.len() {
        return Err(ads_verification_error(
            AdsVerificationFailure::VerificationObjectShapeInvalid,
        ));
    }

    let mut seen_indices = BTreeSet::new();
    let mut commit_to_path: BTreeMap<[u8; 32], (usize, &Vec<[u8; 32]>)> = BTreeMap::new();
    for ((commit, path), leaf_index) in vo.nodes.iter().zip(vo.leaf_indices.iter()) {
        if !seen_indices.insert(*leaf_index) {
            return Err(ads_verification_error(
                AdsVerificationFailure::DuplicateLeafIndex,
            ));
        }
        if commit_to_path
            .insert(*commit, (*leaf_index, path))
            .is_some()
        {
            return Err(ads_verification_error(
                AdsVerificationFailure::DuplicateCandidateCommit,
            ));
        }
    }

    let mut seen_candidate_objects = BTreeSet::new();
    let mut seen_candidate_commits = BTreeSet::new();
    for (id, emb, _) in &vo.candidates {
        if !seen_candidate_objects.insert(*id) {
            return Err(ads_verification_error(
                AdsVerificationFailure::DuplicateCandidateObject,
            ));
        }
        let commit = hash_sem_leaf(id.as_bytes(), emb);
        if !seen_candidate_commits.insert(commit) {
            return Err(ads_verification_error(
                AdsVerificationFailure::DuplicateCandidateCommit,
            ));
        }
        let Some((leaf_index, path)) = commit_to_path.get(&commit) else {
            return Err(ads_verification_error(
                AdsVerificationFailure::CandidatePathMissing,
            ));
        };
        SemanticMerkleTree::verify_path_with_index(*leaf_index, &commit, path, semantic_commit)?;
    }
    Ok(())
}

/// Verify ADS backend VO: Merkle paths + deterministic procedure replay.
pub fn verify_ads_vo(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
    proc: &Procedure,
) -> Result<(), MnemeError> {
    verify_ads_vo_membership(vo, semantic_commit, proc)?;
    let replayed = replay_from_candidates(proc, &vo.candidates)?;
    if replayed != vo.result_ids {
        return Err(ads_verification_error(
            AdsVerificationFailure::ReplayResultMismatch,
        ));
    }
    Ok(())
}

/// Semantic receipt VO gate for the verifier TCB: membership always; dominance via
/// unfiltered replay or provenance attestation; optional ZK attachment.
pub fn verify_semantic_receipt_tcb_gate(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
    object_bytes: Option<&std::collections::BTreeMap<[u8; 32], Vec<u8>>>,
) -> Result<(), MnemeError> {
    verify_ads_vo_membership(&receipt.verification_object, &receipt.semantic_commit, proc)?;
    if receipt.provenance.is_none() {
        let replayed = replay_from_candidates(proc, &receipt.verification_object.candidates)?;
        if replayed != receipt.verification_object.result_ids {
            return Err(ads_verification_error(
                AdsVerificationFailure::ReplayResultMismatch,
            ));
        }
    } else {
        let objs = object_bytes.ok_or_else(|| {
            ads_verification_error(AdsVerificationFailure::ProvenanceObjectsUnavailable)
        })?;
        crate::provenance::verify_provenance_attestation(receipt, proc, objs)?;
    }
    if let Some(zk) = &receipt.zk_retrieval {
        #[cfg(feature = "pedersen_schnorr_zk")]
        {
            crate::semantic_zk::verify_zk_retrieval_attachment(zk, &receipt.verification_object)?;
        }
        #[cfg(not(feature = "pedersen_schnorr_zk"))]
        {
            let _ = zk;
            return Err(disabled_zk_attachment_error(
                DisabledZkAttachmentFailure::TcbGateBackendUnavailable,
            ));
        }
    }
    Ok(())
}

/// Verify ADS VO plus optional ZK retrieval attachment on a semantic recall receipt.
pub fn verify_semantic_receipt_vo(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
) -> Result<(), MnemeError> {
    verify_semantic_receipt_tcb_gate(receipt, proc, None)
}

/// Verify ADS VO plus zkANN-1 attachment (Phase I P1-1).
pub fn verify_semantic_receipt_vo_zkann(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
    committed_leaf_count: usize,
) -> Result<(), MnemeError> {
    verify_ads_vo(&receipt.verification_object, &receipt.semantic_commit, proc)?;
    if let Some(zk) = &receipt.zk_retrieval {
        #[cfg(feature = "pedersen_schnorr_zk")]
        {
            crate::semantic_zk::verify_zk_retrieval_attachment(zk, &receipt.verification_object)?;
        }
        #[cfg(not(feature = "pedersen_schnorr_zk"))]
        {
            let _ = zk;
            return Err(disabled_zk_attachment_error(
                DisabledZkAttachmentFailure::ZkannGateBackendUnavailable,
            ));
        }
    }
    if receipt.zkann.is_some() {
        crate::zkann::verify_zkann_attachment(receipt, proc, committed_leaf_count)?;
    }
    Ok(())
}

/// Full semantic receipt verify: ADS + zkANN + optional provenance attestation (Phase I).
pub fn verify_semantic_receipt_full(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
    committed_leaf_count: usize,
    object_bytes: &std::collections::BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<(), MnemeError> {
    verify_semantic_receipt_vo_zkann(receipt, proc, committed_leaf_count)?;
    if receipt.provenance.is_some() {
        crate::provenance::verify_provenance_attestation(receipt, proc, object_bytes)?;
    }
    Ok(())
}

/// Honesty guard: VO proves procedure-faithfulness, not exact-NN optimality (§3).
pub const HONESTY_NOT_EXACT_NN: &str = concat!(
    "MNEME semantic receipts prove procedure-faithfulness over authenticated data, ",
    "not semantic truth, not exact nearest-neighbor optimality, and not exact top-k under the committed quantized metric (quantized top-k may differ from real-valued top-k). ",
    "ExactDominance v1 proves membership/completeness plus top-k over prover-asserted distances; ",
    "true top-k ranking is not proven and it is not top-k by true query-to-embedding distance ",
    "until verifiers recompute candidate distances."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::SemanticMerkleTree;
    use crate::procedure::{execute_procedure_p, procedure_id};
    use mneme_core::{
        DistanceMetric, FixedPointEmbedding, ObjectId, Procedure, ProcedureAlgo, ProvenanceFilter,
        TrustTier, VerificationObject,
    };

    fn sample_vo() -> (VerificationObject, [u8; 32], Procedure) {
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 2,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let e1 = FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap();
        let e2 = FixedPointEmbedding::new(2, 0, vec![2, 0]).unwrap();
        let id1 = ObjectId([0x01; 32]);
        let id2 = ObjectId([0x02; 32]);
        let c1 = e1.commit();
        let c2 = e2.commit();
        let tree = SemanticMerkleTree::from_entries(&[(id1, c1), (id2, c2)]);
        let root = tree.root();
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let entries = vec![
            crate::procedure::IndexedEntry {
                object_id: id1,
                embedding_commit: c1,
                embedding: e1,
            },
            crate::procedure::IndexedEntry {
                object_id: id2,
                embedding_commit: c2,
                embedding: e2,
            },
        ];
        let (result_ids, candidates) = execute_procedure_p(&proc, &query, &entries).unwrap();
        let nodes = (0..tree.leaf_count())
            .map(|i| {
                let commit = tree.leaf_hash(i).unwrap();
                let path = tree.merkle_path(i).unwrap();
                (commit, path)
            })
            .collect();
        let leaf_indices = (0..tree.leaf_count()).collect();
        let vo = VerificationObject {
            nodes,
            candidates,
            leaf_indices,
            procedure_id: procedure_id(&proc),
            query_commit: query.commit(),
            result_ids,
        };
        (vo, root, proc)
    }

    #[test]
    fn ads_vo_verifies_against_semantic_commit() {
        let (vo, root, proc) = sample_vo();
        verify_ads_vo(&vo, &root, &proc).unwrap();
    }

    #[test]
    fn ads_vo_rejects_wrong_semantic_commit() {
        let (vo, _, proc) = sample_vo();
        let err = verify_ads_vo(&vo, &[0xee; 32], &proc).unwrap_err();
        assert_eq!(err, MnemeError::IndexPathInvalid);
    }

    #[test]
    fn ads_vo_rejects_tampered_candidate_distance() {
        let (mut vo, root, proc) = sample_vo();
        if let Some((_, _, dist)) = vo.candidates.first_mut() {
            *dist = i64::MAX;
        }
        let err = verify_ads_vo(&vo, &root, &proc).unwrap_err();
        assert_eq!(err, MnemeError::ProcedureMismatch);
    }

    #[test]
    fn ads_vo_rejects_duplicate_candidate_reusing_one_authenticated_path() {
        let (mut vo, root, proc) = sample_vo();
        vo.candidates[1] = vo.candidates[0];
        vo.result_ids = crate::procedure::replay_from_candidates(&proc, &vo.candidates)
            .expect("sample procedure bounds should convert to usize");

        assert_eq!(
            verify_ads_vo(&vo, &root, &proc),
            Err(MnemeError::IndexPathInvalid)
        );
    }

    #[test]
    fn ads_verification_failures_are_classified_not_error_collapsed() {
        let source = include_str!("verify.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("verify tests should follow production code");

        for forbidden in [
            "return Err(MnemeError::ProcedureMismatch",
            "return Err(MnemeError::IndexPathInvalid",
            "ok_or(MnemeError::ProvenanceFilterViolation",
        ] {
            assert!(
                !source.contains(forbidden),
                "ADS verification should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum AdsVerificationFailure",
            "ProcedureIdMismatch",
            "VerificationObjectShapeInvalid",
            "DuplicateLeafIndex",
            "DuplicateCandidateObject",
            "DuplicateCandidateCommit",
            "CandidatePathMissing",
            "ReplayResultMismatch",
            "ProvenanceObjectsUnavailable",
            "fn ads_verification_failure_to_mneme(",
            "fn ads_verification_error(",
        ] {
            assert!(
                source.contains(required),
                "ADS verification should include `{required}`"
            );
        }
    }

    #[test]
    fn ads_verification_failure_classifier_preserves_public_errors() {
        for (failure, expected) in [
            (
                AdsVerificationFailure::ProcedureIdMismatch,
                MnemeError::ProcedureMismatch,
            ),
            (
                AdsVerificationFailure::VerificationObjectShapeInvalid,
                MnemeError::IndexPathInvalid,
            ),
            (
                AdsVerificationFailure::DuplicateLeafIndex,
                MnemeError::IndexPathInvalid,
            ),
            (
                AdsVerificationFailure::DuplicateCandidateObject,
                MnemeError::IndexPathInvalid,
            ),
            (
                AdsVerificationFailure::DuplicateCandidateCommit,
                MnemeError::IndexPathInvalid,
            ),
            (
                AdsVerificationFailure::CandidatePathMissing,
                MnemeError::IndexPathInvalid,
            ),
            (
                AdsVerificationFailure::ReplayResultMismatch,
                MnemeError::ProcedureMismatch,
            ),
            (
                AdsVerificationFailure::ProvenanceObjectsUnavailable,
                MnemeError::ProvenanceFilterViolation,
            ),
        ] {
            assert_eq!(ads_verification_failure_to_mneme(failure), expected);
            assert_eq!(ads_verification_error(failure), expected);
        }
    }

    #[test]
    fn ads_verification_malformed_vo_rejections_preserve_public_errors() {
        let (vo, root, proc) = sample_vo();

        let mut wrong_procedure = vo.clone();
        wrong_procedure.procedure_id[0] ^= 0x01;
        assert_eq!(
            verify_ads_vo_membership(&wrong_procedure, &root, &proc),
            Err(MnemeError::ProcedureMismatch)
        );

        let mut wrong_shape = vo.clone();
        wrong_shape.leaf_indices.pop();
        assert_eq!(
            verify_ads_vo_membership(&wrong_shape, &root, &proc),
            Err(MnemeError::IndexPathInvalid)
        );

        let mut duplicate_leaf = vo.clone();
        duplicate_leaf.leaf_indices[1] = duplicate_leaf.leaf_indices[0];
        assert_eq!(
            verify_ads_vo_membership(&duplicate_leaf, &root, &proc),
            Err(MnemeError::IndexPathInvalid)
        );

        let mut duplicate_commit = vo.clone();
        duplicate_commit.nodes[1].0 = duplicate_commit.nodes[0].0;
        assert_eq!(
            verify_ads_vo_membership(&duplicate_commit, &root, &proc),
            Err(MnemeError::IndexPathInvalid)
        );

        let mut missing_path = vo.clone();
        missing_path.nodes.pop();
        missing_path.leaf_indices.pop();
        assert_eq!(
            verify_ads_vo_membership(&missing_path, &root, &proc),
            Err(MnemeError::IndexPathInvalid)
        );
    }

    #[test]
    fn ads_verification_replay_and_provenance_rejections_preserve_public_errors() {
        let (mut vo, root, proc) = sample_vo();
        vo.result_ids.reverse();
        assert_eq!(
            verify_ads_vo(&vo, &root, &proc),
            Err(MnemeError::ProcedureMismatch)
        );

        let (vo, root, proc) = sample_vo();
        let mut receipt = SemanticRecallReceipt::new([0x33; 32], root, vo);
        receipt.provenance = Some(crate::receipt::ProvenanceAttestation {
            filter: ProvenanceFilter {
                written_by: None,
                since: None,
                min_tier: TrustTier::Working,
            },
            candidates: Vec::new(),
        });
        assert_eq!(
            verify_semantic_receipt_tcb_gate(&receipt, &proc, None),
            Err(MnemeError::ProvenanceFilterViolation)
        );
    }

    #[test]
    fn honesty_message_preserves_distance_caveat() {
        assert!(HONESTY_NOT_EXACT_NN.contains("exact top-k under the committed quantized"));
        assert!(HONESTY_NOT_EXACT_NN.contains("quantized top-k may differ from real-valued"));
        assert!(
            HONESTY_NOT_EXACT_NN.contains("procedure-faithfulness"),
            "exported semantic honesty string must preserve the §3 procedure-faithfulness boundary"
        );
        assert!(
            HONESTY_NOT_EXACT_NN.contains("semantic truth"),
            "exported semantic honesty string must not imply authenticated content is true"
        );
        assert!(
            HONESTY_NOT_EXACT_NN.contains("prover-asserted distances"),
            "ExactDominance v1 must stay scoped to prover-asserted distances"
        );
        assert!(
            HONESTY_NOT_EXACT_NN.contains("membership/completeness"),
            "ExactDominance v1 must state that membership/completeness is the proven part"
        );
        assert!(
            HONESTY_NOT_EXACT_NN.contains("top-k ranking is not proven"),
            "ExactDominance v1 must state that top-k ranking is not proven"
        );
        assert!(
            HONESTY_NOT_EXACT_NN.contains("not top-k by true query-to-embedding distance"),
            "ExactDominance v1 must preserve the distance-recompute caveat"
        );
    }

    #[test]
    fn disabled_zk_attachment_gates_are_classified_not_zkproof_collapsed() {
        let source = include_str!("verify.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("verify tests should follow production code");

        assert!(
            !source.contains("return Err(MnemeError::ZkProofInvalid"),
            "disabled ZK attachment gates should route ZkProofInvalid through named classifiers"
        );

        for required in [
            "enum DisabledZkAttachmentFailure",
            "TcbGateBackendUnavailable",
            "ZkannGateBackendUnavailable",
            "fn disabled_zk_attachment_failure_to_mneme(",
            "fn disabled_zk_attachment_error(",
        ] {
            assert!(
                source.contains(required),
                "disabled ZK attachment gates should include `{required}`"
            );
        }
    }

    #[cfg(not(feature = "pedersen_schnorr_zk"))]
    #[test]
    fn disabled_zk_attachment_classifier_preserves_public_zkproof_invalid() {
        for failure in [
            DisabledZkAttachmentFailure::TcbGateBackendUnavailable,
            DisabledZkAttachmentFailure::ZkannGateBackendUnavailable,
        ] {
            assert_eq!(
                disabled_zk_attachment_failure_to_mneme(failure),
                MnemeError::ZkProofInvalid
            );
            assert_eq!(
                disabled_zk_attachment_error(failure),
                MnemeError::ZkProofInvalid
            );
        }
    }

    #[cfg(not(feature = "pedersen_schnorr_zk"))]
    #[test]
    fn disabled_zk_attachment_rejects_valid_ads_receipt_fail_closed() {
        let (vo, root, proc) = sample_vo();
        let mut receipt = SemanticRecallReceipt::new([0x44; 32], root, vo);
        receipt.zk_retrieval = Some(crate::receipt::ZkRetrievalAttachment::default());

        assert_eq!(
            verify_semantic_receipt_vo(&receipt, &proc),
            Err(MnemeError::ZkProofInvalid)
        );
        assert_eq!(
            verify_semantic_receipt_vo_zkann(&receipt, &proc, 2),
            Err(MnemeError::ZkProofInvalid)
        );
    }
}
