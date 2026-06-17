//! ZK retrieval attachment for semantic recall receipts (`pedersen_schnorr_zk` feature).

use crate::pedersen_schnorr_zk::{
    PedersenSchnorrRetrievalProof, RetrievalWitness, prove_pedersen_schnorr,
    verify_pedersen_schnorr,
};
use crate::receipt::{SemanticRecallReceipt, ZkRetrievalAttachment};
use mneme_core::{FixedPointEmbedding, MnemeError, VerificationObject};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticZkAttachmentFailure {
    MissingTopResult,
    MissingTopCandidate,
    QueryCommitMismatch,
}

fn semantic_zk_attachment_failure_to_mneme(failure: SemanticZkAttachmentFailure) -> MnemeError {
    match failure {
        SemanticZkAttachmentFailure::MissingTopResult
        | SemanticZkAttachmentFailure::MissingTopCandidate
        | SemanticZkAttachmentFailure::QueryCommitMismatch => MnemeError::ZkProofInvalid,
    }
}

fn semantic_zk_attachment_error(failure: SemanticZkAttachmentFailure) -> MnemeError {
    semantic_zk_attachment_failure_to_mneme(failure)
}

/// Try to attach a zero-knowledge retrieval-match proof for the top-1 ADS result.
///
/// Succeeds only when `query.commit()` equals the top result's `embedding_commit` (the
/// witness is satisfiable). Otherwise returns `None` — the receipt remains ADS-only.
pub fn try_attach_zk_retrieval(receipt: &mut SemanticRecallReceipt, query: &FixedPointEmbedding) {
    let Some(top_id) = receipt.verification_object.result_ids.first() else {
        return;
    };
    let Some((_, emb_commit, _)) = receipt
        .verification_object
        .candidates
        .iter()
        .find(|(id, _, _)| id == top_id)
    else {
        return;
    };
    let query_commit = query.commit();
    if query_commit != *emb_commit {
        return;
    }
    let witness = RetrievalWitness::matching(query_commit);
    let Ok(proof) = prove_pedersen_schnorr(&witness) else {
        return;
    };
    receipt.zk_retrieval = Some(ZkRetrievalAttachment {
        public_commit: proof.public_commit,
        proof_bytes: proof.proof_bytes,
    });
}

/// Verify optional ZK attachment against the ADS verification object.
pub fn verify_zk_retrieval_attachment(
    zk: &ZkRetrievalAttachment,
    vo: &VerificationObject,
) -> Result<(), MnemeError> {
    let proof = PedersenSchnorrRetrievalProof {
        public_commit: zk.public_commit,
        proof_bytes: zk.proof_bytes.clone(),
    };
    verify_pedersen_schnorr(&proof, &zk.public_commit)?;
    let top = vo.result_ids.first().ok_or_else(|| {
        semantic_zk_attachment_error(SemanticZkAttachmentFailure::MissingTopResult)
    })?;
    let emb = vo
        .candidates
        .iter()
        .find(|(id, _, _)| id == top)
        .map(|(_, e, _)| *e)
        .ok_or_else(|| {
            semantic_zk_attachment_error(SemanticZkAttachmentFailure::MissingTopCandidate)
        })?;
    if vo.query_commit != emb {
        return Err(semantic_zk_attachment_error(
            SemanticZkAttachmentFailure::QueryCommitMismatch,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::ObjectId;

    fn valid_zk_attachment_and_vo() -> (ZkRetrievalAttachment, VerificationObject) {
        let query_commit = [0x07; 32];
        let proof =
            prove_pedersen_schnorr(&RetrievalWitness::matching(query_commit)).expect("zk proof");
        let top_id = ObjectId([0x01; 32]);
        let vo = VerificationObject {
            nodes: Vec::new(),
            candidates: vec![(top_id, query_commit, 0)],
            leaf_indices: vec![0],
            procedure_id: [0x02; 32],
            query_commit,
            result_ids: vec![top_id],
            candidates_embeddings: None,
        };
        let zk = ZkRetrievalAttachment {
            public_commit: proof.public_commit,
            proof_bytes: proof.proof_bytes,
        };
        (zk, vo)
    }

    #[test]
    fn attachment_validation_failures_preserve_public_zk_proof_invalid() {
        let (zk, mut missing_top) = valid_zk_attachment_and_vo();
        missing_top.result_ids.clear();
        assert_eq!(
            verify_zk_retrieval_attachment(&zk, &missing_top),
            Err(MnemeError::ZkProofInvalid)
        );

        let (zk, mut missing_candidate) = valid_zk_attachment_and_vo();
        missing_candidate.candidates.clear();
        assert_eq!(
            verify_zk_retrieval_attachment(&zk, &missing_candidate),
            Err(MnemeError::ZkProofInvalid)
        );

        let (zk, mut query_mismatch) = valid_zk_attachment_and_vo();
        query_mismatch.query_commit[0] ^= 0x01;
        assert_eq!(
            verify_zk_retrieval_attachment(&zk, &query_mismatch),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn attachment_failures_are_classified_not_zkproof_collapsed() {
        let source = include_str!("semantic_zk.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("semantic_zk tests should follow production code");

        for forbidden in [
            "ok_or(MnemeError::ZkProofInvalid",
            "return Err(MnemeError::ZkProofInvalid",
        ] {
            assert!(
                !source.contains(forbidden),
                "ZK attachment validation should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum SemanticZkAttachmentFailure",
            "MissingTopResult",
            "MissingTopCandidate",
            "QueryCommitMismatch",
            "fn semantic_zk_attachment_failure_to_mneme(",
            "fn semantic_zk_attachment_error(",
        ] {
            assert!(
                source.contains(required),
                "ZK attachment validation should include `{required}`"
            );
        }
    }
}
