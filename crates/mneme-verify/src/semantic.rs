use crate::recall::unsupported_object_version_error;
use crate::recall::{RecallContext, verify_provenance, verify_writer_and_tier};
use crate::root::verify_root;
use mneme_core::{
    Entry, MnemeError, ObjectRecord, Procedure, Query, Root, from_bytes_strict, hash_obj,
    object::OBJECT_VERSION,
};
use mneme_crypto::TrustConfig;
use mneme_index::{HONESTY_NOT_EXACT_NN, SemanticRecallReceipt, verify_semantic_receipt_tcb_gate};

pub const HONESTY_PROCEDURE: &str = HONESTY_NOT_EXACT_NN;

pub struct SemanticRecallInput {
    pub receipt: SemanticRecallReceipt,
    pub root: Root,
}

pub fn verify_semantic_receipt(
    receipt: &SemanticRecallReceipt,
    root: &Root,
    proc: &Procedure,
    trust: &TrustConfig,
    previous: Option<&Root>,
    object_bytes: Option<&std::collections::BTreeMap<[u8; 32], Vec<u8>>>,
) -> Result<(), MnemeError> {
    verify_root(root, trust, previous)?;
    if receipt.root_bound != root.preimage_hash
        || !receipt.binds_to_semantic_commit(&root.semantic_commit)
    {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    verify_semantic_receipt_tcb_gate(receipt, proc, object_bytes)
}

pub fn verify_semantic_recall(
    input: &SemanticRecallInput,
    proc: &Procedure,
    query: &Query,
    trust: &TrustConfig,
    ctx: &RecallContext<'_>,
) -> Result<Vec<Entry>, MnemeError> {
    #[rustfmt::skip]
    verify_semantic_receipt(&input.receipt, &input.root, proc, trust, ctx.previous_root, Some(ctx.objects))?;
    let emb = query
        .embedding
        .as_ref()
        .ok_or(MnemeError::ProcedureMismatch)?;
    emb.validate_shape()?;
    if emb.commit() != input.receipt.verification_object.query_commit {
        return Err(MnemeError::ProcedureMismatch);
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
            return Err(unsupported_object_version_error(record.version));
        }
        let emb_commit = record
            .embedding_commit
            .ok_or(MnemeError::IndexPathInvalid)?;
        let mut candidate_commit = None;
        for (candidate_id, candidate_embedding_commit, _) in
            &input.receipt.verification_object.candidates
        {
            if candidate_id == id {
                candidate_commit = Some(*candidate_embedding_commit);
                break;
            }
        }
        if candidate_commit.ok_or(MnemeError::IndexPathInvalid)? != emb_commit {
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
