//! ZK retrieval attachment for semantic recall receipts (`pedersen_schnorr_zk` feature).

use crate::pedersen_schnorr_zk::{
    PedersenSchnorrRetrievalProof, RetrievalWitness, prove_pedersen_schnorr,
    verify_pedersen_schnorr,
};
use crate::receipt::{SemanticRecallReceipt, ZkRetrievalAttachment};
use mneme_core::{FixedPointEmbedding, MnemeError, VerificationObject};

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
    let top = vo.result_ids.first().ok_or(MnemeError::ZkProofInvalid)?;
    let emb = vo
        .candidates
        .iter()
        .find(|(id, _, _)| id == top)
        .map(|(_, e, _)| *e)
        .ok_or(MnemeError::ZkProofInvalid)?;
    if vo.query_commit != emb {
        return Err(MnemeError::ZkProofInvalid);
    }
    Ok(())
}
