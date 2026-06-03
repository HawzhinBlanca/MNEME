//! Provenance-scoped recall attestation (Phase I P1-3).

use crate::procedure::replay_from_candidates;
use crate::receipt::{ProvenanceAttestation, SemanticRecallReceipt};
use mneme_core::{
    CandidateProvenance, MnemeError, ObjectId, Procedure, ProvenanceFilter, TrustTier, hash_obj,
    valid_time_from_ext,
};
pub fn build_provenance_attestation(
    receipt: &SemanticRecallReceipt,
    filter: &ProvenanceFilter,
    object_bytes: &std::collections::BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<ProvenanceAttestation, MnemeError> {
    let mut rows = Vec::new();
    for (id, _, _) in &receipt.verification_object.candidates {
        let bytes = object_bytes
            .get(id.as_bytes())
            .ok_or(MnemeError::ObjectTampered)?;
        let record = mneme_core::from_bytes_strict::<mneme_core::ObjectRecord>(bytes)
            .map_err(|_| MnemeError::ObjectTampered)?;
        if hash_obj(bytes) != *id.as_bytes() {
            return Err(MnemeError::ObjectTampered);
        }
        rows.push(CandidateProvenance {
            object_id: *id,
            writer: record.writer,
            trust_tier: record.trust_tier,
            hlc: hlc_wire_bytes(&record.hlc),
            valid_time_ms: valid_time_from_ext(&record.ext),
        });
    }
    Ok(ProvenanceAttestation {
        filter: filter.clone(),
        candidates: rows,
    })
}

pub fn verify_provenance_attestation(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
    object_bytes: &std::collections::BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<(), MnemeError> {
    let att = receipt
        .provenance
        .as_ref()
        .ok_or(MnemeError::ProvenanceFilterViolation)?;
    if att.candidates.len() != receipt.verification_object.candidates.len() {
        return Err(MnemeError::ProvenanceFilterViolation);
    }
    for row in &att.candidates {
        let bytes = object_bytes
            .get(row.object_id.as_bytes())
            .ok_or(MnemeError::ObjectTampered)?;
        let record = mneme_core::from_bytes_strict::<mneme_core::ObjectRecord>(bytes)
            .map_err(|_| MnemeError::ObjectTampered)?;
        if hash_obj(bytes) != *row.object_id.as_bytes()
            || record.writer != row.writer
            || record.trust_tier != row.trust_tier
            || hlc_wire_bytes(&record.hlc) != row.hlc
            || valid_time_from_ext(&record.ext) != row.valid_time_ms
        {
            return Err(MnemeError::ProvenanceFilterViolation);
        }
    }
    let filtered = filter_candidates(
        &receipt.verification_object.candidates,
        &att.filter,
        &att.candidates,
    )?;
    let replayed = replay_from_candidates(proc, &filtered);
    if replayed != receipt.verification_object.result_ids {
        return Err(MnemeError::ProvenanceFilterViolation);
    }
    for id in &receipt.verification_object.result_ids {
        if !predicate(
            att.candidates
                .iter()
                .find(|c| c.object_id == *id)
                .ok_or(MnemeError::ProvenanceFilterViolation)?,
            &att.filter,
        ) {
            return Err(MnemeError::ProvenanceFilterViolation);
        }
    }
    Ok(())
}

/// Align top-k results with a provenance filter before scoped verification (P1-3).
pub fn align_scoped_receipt_results(
    receipt: &mut SemanticRecallReceipt,
    proc: &Procedure,
) -> Result<(), MnemeError> {
    let att = receipt
        .provenance
        .as_ref()
        .ok_or(MnemeError::ProvenanceFilterViolation)?;
    let filtered = filter_candidates(
        &receipt.verification_object.candidates,
        &att.filter,
        &att.candidates,
    )?;
    receipt.verification_object.result_ids = replay_from_candidates(proc, &filtered);
    Ok(())
}

fn filter_candidates(
    candidates: &[(ObjectId, [u8; 32], i64)],
    filter: &ProvenanceFilter,
    att_rows: &[CandidateProvenance],
) -> Result<Vec<(ObjectId, [u8; 32], i64)>, MnemeError> {
    let by_id: std::collections::BTreeMap<ObjectId, &CandidateProvenance> =
        att_rows.iter().map(|r| (r.object_id, r)).collect();
    let mut out = Vec::new();
    for (id, emb, dist) in candidates {
        let row = by_id.get(id).ok_or(MnemeError::ProvenanceFilterViolation)?;
        if predicate(row, filter) {
            out.push((*id, *emb, *dist));
        }
    }
    Ok(out)
}

fn predicate(row: &CandidateProvenance, filter: &ProvenanceFilter) -> bool {
    if let Some(w) = filter.written_by {
        if row.writer != w {
            return false;
        }
    }
    if let Some(since) = filter.since {
        if row.hlc < since {
            return false;
        }
    }
    let Ok(tier) = TrustTier::from_u8(row.trust_tier) else {
        return false;
    };
    tier >= filter.min_tier
}

fn hlc_wire_bytes(h: &mneme_core::HlcWire) -> [u8; 14] {
    mneme_core::Hlc {
        wall_ms: h.wall_ms,
        counter: h.counter,
        node_id: mneme_core::NodeId::from_bytes(h.node_id),
    }
    .to_bytes()
}
