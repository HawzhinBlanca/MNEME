//! Provenance-scoped recall attestation (Phase I P1-3).

use crate::procedure::replay_from_candidates;
use crate::receipt::{ProvenanceAttestation, SemanticRecallReceipt};
use mneme_core::{
    CandidateProvenance, MnemeError, ObjectId, Procedure, ProvenanceFilter, TrustTier, hash_obj,
    valid_time_from_ext,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvenanceFailure {
    BuildCandidateObjectMissing,
    BuildCandidateObjectDecode,
    BuildCandidateObjectHashMismatch,
    AttestationMissing,
    CandidateCountMismatch,
    VerifyCandidateObjectMissing,
    VerifyCandidateObjectDecode,
    CandidateProvenanceMismatch,
    ReplayMismatch,
    ResultProvenanceMissing,
    ResultPredicateFailed,
    AlignAttestationMissing,
    FilterCandidateProvenanceMissing,
}

fn provenance_failure_to_mneme(failure: ProvenanceFailure) -> MnemeError {
    match failure {
        ProvenanceFailure::BuildCandidateObjectMissing
        | ProvenanceFailure::BuildCandidateObjectDecode
        | ProvenanceFailure::BuildCandidateObjectHashMismatch
        | ProvenanceFailure::VerifyCandidateObjectMissing
        | ProvenanceFailure::VerifyCandidateObjectDecode => MnemeError::ObjectTampered,
        ProvenanceFailure::AttestationMissing
        | ProvenanceFailure::CandidateCountMismatch
        | ProvenanceFailure::CandidateProvenanceMismatch
        | ProvenanceFailure::ReplayMismatch
        | ProvenanceFailure::ResultProvenanceMissing
        | ProvenanceFailure::ResultPredicateFailed
        | ProvenanceFailure::AlignAttestationMissing
        | ProvenanceFailure::FilterCandidateProvenanceMissing => {
            MnemeError::ProvenanceFilterViolation
        }
    }
}

fn provenance_error(failure: ProvenanceFailure) -> MnemeError {
    provenance_failure_to_mneme(failure)
}

pub fn build_provenance_attestation(
    receipt: &SemanticRecallReceipt,
    filter: &ProvenanceFilter,
    object_bytes: &std::collections::BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<ProvenanceAttestation, MnemeError> {
    let mut rows = Vec::new();
    for (id, _, _) in &receipt.verification_object.candidates {
        let bytes = object_bytes
            .get(id.as_bytes())
            .ok_or_else(|| provenance_error(ProvenanceFailure::BuildCandidateObjectMissing))?;
        let record = mneme_core::from_bytes_strict::<mneme_core::ObjectRecord>(bytes)
            .map_err(|_| provenance_error(ProvenanceFailure::BuildCandidateObjectDecode))?;
        if hash_obj(bytes) != *id.as_bytes() {
            return Err(provenance_error(
                ProvenanceFailure::BuildCandidateObjectHashMismatch,
            ));
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
        .ok_or_else(|| provenance_error(ProvenanceFailure::AttestationMissing))?;
    if att.candidates.len() != receipt.verification_object.candidates.len() {
        return Err(provenance_error(ProvenanceFailure::CandidateCountMismatch));
    }
    for row in &att.candidates {
        let bytes = object_bytes
            .get(row.object_id.as_bytes())
            .ok_or_else(|| provenance_error(ProvenanceFailure::VerifyCandidateObjectMissing))?;
        let record = mneme_core::from_bytes_strict::<mneme_core::ObjectRecord>(bytes)
            .map_err(|_| provenance_error(ProvenanceFailure::VerifyCandidateObjectDecode))?;
        if hash_obj(bytes) != *row.object_id.as_bytes()
            || record.writer != row.writer
            || record.trust_tier != row.trust_tier
            || hlc_wire_bytes(&record.hlc) != row.hlc
            || valid_time_from_ext(&record.ext) != row.valid_time_ms
        {
            return Err(provenance_error(
                ProvenanceFailure::CandidateProvenanceMismatch,
            ));
        }
    }
    let filtered = filter_candidates(
        &receipt.verification_object.candidates,
        &att.filter,
        &att.candidates,
    )?;
    let replayed = replay_from_candidates(proc, &filtered);
    if replayed != receipt.verification_object.result_ids {
        return Err(provenance_error(ProvenanceFailure::ReplayMismatch));
    }
    for id in &receipt.verification_object.result_ids {
        if !predicate(
            att.candidates
                .iter()
                .find(|c| c.object_id == *id)
                .ok_or_else(|| provenance_error(ProvenanceFailure::ResultProvenanceMissing))?,
            &att.filter,
        ) {
            return Err(provenance_error(ProvenanceFailure::ResultPredicateFailed));
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
        .ok_or_else(|| provenance_error(ProvenanceFailure::AlignAttestationMissing))?;
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
        let row = by_id
            .get(id)
            .ok_or_else(|| provenance_error(ProvenanceFailure::FilterCandidateProvenanceMissing))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_failures_are_classified_not_error_collapsed() {
        let production = include_str!("provenance.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("provenance.rs should keep tests after production code");

        for forbidden in [
            ".ok_or(MnemeError::ObjectTampered",
            ".map_err(|_| MnemeError::ObjectTampered",
            "return Err(MnemeError::ObjectTampered",
            ".ok_or(MnemeError::ProvenanceFilterViolation",
            "return Err(MnemeError::ProvenanceFilterViolation",
        ] {
            assert!(
                !production.contains(forbidden),
                "provenance production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum ProvenanceFailure",
            "BuildCandidateObjectMissing",
            "BuildCandidateObjectDecode",
            "BuildCandidateObjectHashMismatch",
            "AttestationMissing",
            "CandidateCountMismatch",
            "VerifyCandidateObjectMissing",
            "VerifyCandidateObjectDecode",
            "CandidateProvenanceMismatch",
            "ReplayMismatch",
            "ResultProvenanceMissing",
            "ResultPredicateFailed",
            "AlignAttestationMissing",
            "FilterCandidateProvenanceMissing",
            "fn provenance_failure_to_mneme(",
            "fn provenance_error(",
        ] {
            assert!(
                production.contains(required),
                "provenance production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn provenance_failure_classifier_preserves_public_errors() {
        for failure in [
            ProvenanceFailure::BuildCandidateObjectMissing,
            ProvenanceFailure::BuildCandidateObjectDecode,
            ProvenanceFailure::BuildCandidateObjectHashMismatch,
            ProvenanceFailure::VerifyCandidateObjectMissing,
            ProvenanceFailure::VerifyCandidateObjectDecode,
        ] {
            assert_eq!(
                provenance_failure_to_mneme(failure),
                MnemeError::ObjectTampered
            );
            assert_eq!(provenance_error(failure), MnemeError::ObjectTampered);
        }

        for failure in [
            ProvenanceFailure::AttestationMissing,
            ProvenanceFailure::CandidateCountMismatch,
            ProvenanceFailure::CandidateProvenanceMismatch,
            ProvenanceFailure::ReplayMismatch,
            ProvenanceFailure::ResultProvenanceMissing,
            ProvenanceFailure::ResultPredicateFailed,
            ProvenanceFailure::AlignAttestationMissing,
            ProvenanceFailure::FilterCandidateProvenanceMissing,
        ] {
            assert_eq!(
                provenance_failure_to_mneme(failure),
                MnemeError::ProvenanceFilterViolation
            );
            assert_eq!(
                provenance_error(failure),
                MnemeError::ProvenanceFilterViolation
            );
        }
    }
}
