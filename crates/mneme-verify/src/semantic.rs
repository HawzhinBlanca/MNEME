//! Semantic ADS receipt gate (§9.3 step 3).

use crate::recall::{RecallContext, verify_provenance, verify_writer_and_tier};
use crate::root::verify_root;
use mneme_core::{
    Entry, MnemeError, ObjectRecord, Procedure, Query, Root, from_bytes_strict, hash_obj,
    object::OBJECT_VERSION,
};
use mneme_crypto::TrustConfig;
use mneme_index::{HONESTY_NOT_EXACT_NN, SemanticRecallReceipt, verify_ads_vo};

/// Honesty boundary for procedure-faithful semantic receipts (§3).
pub const HONESTY_PROCEDURE: &str = HONESTY_NOT_EXACT_NN;

pub struct SemanticRecallInput {
    pub receipt: SemanticRecallReceipt,
    pub root: Root,
}

/// Verify `SemanticRecallReceipt` + ADS VO against signed root (§9.3).
pub fn verify_semantic_receipt(
    receipt: &SemanticRecallReceipt,
    root: &Root,
    proc: &Procedure,
    trust: &TrustConfig,
    previous: Option<&Root>,
) -> Result<(), MnemeError> {
    verify_root(root, trust, previous)?;
    if receipt.root_bound != root.preimage_hash
        || !receipt.binds_to_semantic_commit(&root.semantic_commit)
    {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    verify_ads_vo(&receipt.verification_object, &root.semantic_commit, proc)
}

/// Full trust gate for store `recall_verified` (objects + tier + provenance).
pub fn verify_semantic_recall(
    input: &SemanticRecallInput,
    proc: &Procedure,
    query: &Query,
    trust: &TrustConfig,
    ctx: &RecallContext<'_>,
) -> Result<Vec<Entry>, MnemeError> {
    verify_semantic_receipt(&input.receipt, &input.root, proc, trust, ctx.previous_root)?;
    if let Some(emb) = &query.embedding {
        if emb.commit() != input.receipt.verification_object.query_commit {
            return Err(MnemeError::ProcedureMismatch);
        }
    }

    let mut entries = Vec::new();
    for id in &input.receipt.verification_object.result_ids {
        let bytes = ctx
            .objects
            .get(id.as_bytes())
            .ok_or(MnemeError::ObjectTampered)?;
        if hash_obj(bytes) != *id.as_bytes() {
            return Err(MnemeError::ObjectTampered);
        }
        let record: ObjectRecord = from_bytes_strict(bytes)?;
        if record.version != OBJECT_VERSION {
            return Err(MnemeError::UnsupportedVersion {
                got: record.version,
            });
        }
        let emb_commit = record
            .embedding_commit
            .ok_or(MnemeError::IndexPathInvalid)?;
        let candidate = input
            .receipt
            .verification_object
            .candidates
            .iter()
            .find(|(cid, _, _)| cid == id)
            .ok_or(MnemeError::IndexPathInvalid)?;
        if candidate.1 != emb_commit {
            return Err(MnemeError::ObjectTampered);
        }
        verify_provenance(&record, ctx)?;
        verify_writer_and_tier(&record, trust, query)?;
        entries.push(Entry {
            id: *id,
            record: record.clone(),
            plaintext: record.payload_enc.body.clone(),
        });
    }
    Ok(entries)
}
