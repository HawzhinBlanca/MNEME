//! Trick #3 — Proof of non-use after forgetting (forget-absence prototype).

use crate::cognition_cert::{parse_cognition_certificate, verify_cognition_certificate_v1};
use crate::receipt::SemanticRecallReceipt;
use mneme_core::{MnemeError, ObjectId, Procedure};
use mneme_crypto::TrustConfig;
use std::collections::HashSet;

pub const COGNITION_CERT_COMMIT_TAG: &[u8] = b"MNEME-COGNITION-CERT-COMMIT/v1";

pub const FORGET_ABSENCE_STATUS: &str = concat!(
    "PROTOTYPE: forget-absence binds crypto-shred to post-forget certified cognition only. ",
    "Linear Ω(N) scan — not constant-size Jewel C accumulator (C2). Fail-closed."
);

pub const FORGET_ABSENCE_HONESTY: &str = concat!(
    "Forget-absence proves the forgotten target commit does not appear in the authenticated ",
    "used set of operator-supplied cognition certificates strictly after the forget root sequence. ",
    "Used set = result_ids ∪ candidate ObjectIds ∪ zkANN visited_order ∪ provenance candidates. ",
    "Certified cognition only — uncertified read channels are out of scope. ",
    "Relative to the presented certificate chain (operator can withhold certificates — T10). ",
    "Does not prove no out-of-band copy ever existed. Authenticated ≠ true. ",
    "ObjectId forget targets match directly; LogicalKey shred uses key-hash commits and requires ",
    "ObjectId-target forget or a future sidecar mapping for full logical-key non-use. ",
    "Ω(N) scan in the non-aggregating epoch model; constant-size non-use (C2) is not this path."
);

#[derive(Clone, Debug)]
pub struct PostForgetCert<'a> {
    pub cert_bytes: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct PreForgetAnchorCert<'a> {
    pub cert_bytes: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct ForgetAbsenceRequest<'a> {
    pub forget_sequence: u64,
    pub target_commit: [u8; 32],
    pub cognition_cert_commit: Option<[u8; 32]>,
    pub post_forget_certs: &'a [PostForgetCert<'a>],
    pub pre_forget_anchor: Option<PreForgetAnchorCert<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForgetAbsenceFailure {
    PostCertEmpty,
    PostCertSequenceNotStrictlyAfter,
    TargetUsedAfterForget,
    AnchorCommitMismatch,
    AnchorAfterForget,
    AnchorUsedTarget,
}

fn forget_absence_failure_to_mneme(failure: ForgetAbsenceFailure) -> MnemeError {
    match failure {
        ForgetAbsenceFailure::PostCertEmpty
        | ForgetAbsenceFailure::PostCertSequenceNotStrictlyAfter
        | ForgetAbsenceFailure::TargetUsedAfterForget
        | ForgetAbsenceFailure::AnchorCommitMismatch
        | ForgetAbsenceFailure::AnchorAfterForget
        | ForgetAbsenceFailure::AnchorUsedTarget => MnemeError::CertificateInvalid,
    }
}

pub fn cognition_certificate_commit(cert_bytes: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(COGNITION_CERT_COMMIT_TAG.len() + cert_bytes.len());
    payload.extend_from_slice(COGNITION_CERT_COMMIT_TAG);
    payload.extend_from_slice(cert_bytes);
    *blake3::hash(&payload).as_bytes()
}

pub fn certified_used_commits(receipt: &SemanticRecallReceipt) -> HashSet<[u8; 32]> {
    let mut set = HashSet::new();
    let vo = &receipt.verification_object;
    for id in &vo.result_ids {
        set.insert(*id.as_bytes());
    }
    for (id, _, _) in &vo.candidates {
        set.insert(*id.as_bytes());
    }
    if let Some(z) = &receipt.zkann {
        for id in &z.visited_order {
            set.insert(*id.as_bytes());
        }
    }
    if let Some(p) = &receipt.provenance {
        for c in &p.candidates {
            set.insert(*c.object_id.as_bytes());
        }
    }
    set
}

fn verify_post_cert(
    entry: &PostForgetCert<'_>,
    trust: &TrustConfig,
    proc: &Procedure,
    forget_sequence: u64,
    target_commit: [u8; 32],
) -> Result<u64, MnemeError> {
    let root = verify_cognition_certificate_v1(entry.cert_bytes, trust, proc)?;
    if root.sequence <= forget_sequence {
        return Err(forget_absence_failure_to_mneme(
            ForgetAbsenceFailure::PostCertSequenceNotStrictlyAfter,
        ));
    }
    let parsed = parse_cognition_certificate(entry.cert_bytes)?;
    if certified_used_commits(&parsed.receipt).contains(&target_commit) {
        return Err(forget_absence_failure_to_mneme(
            ForgetAbsenceFailure::TargetUsedAfterForget,
        ));
    }
    Ok(root.sequence)
}

fn verify_pre_forget_anchor(
    anchor: &PreForgetAnchorCert<'_>,
    trust: &TrustConfig,
    proc: &Procedure,
    forget_sequence: u64,
    expected_commit: [u8; 32],
    target_commit: [u8; 32],
) -> Result<(), MnemeError> {
    if cognition_certificate_commit(anchor.cert_bytes) != expected_commit {
        return Err(forget_absence_failure_to_mneme(
            ForgetAbsenceFailure::AnchorCommitMismatch,
        ));
    }
    let root = verify_cognition_certificate_v1(anchor.cert_bytes, trust, proc)?;
    if root.sequence > forget_sequence {
        return Err(forget_absence_failure_to_mneme(
            ForgetAbsenceFailure::AnchorAfterForget,
        ));
    }
    let parsed = parse_cognition_certificate(anchor.cert_bytes)?;
    if certified_used_commits(&parsed.receipt).contains(&target_commit) {
        return Err(forget_absence_failure_to_mneme(
            ForgetAbsenceFailure::AnchorUsedTarget,
        ));
    }
    Ok(())
}

pub fn verify_forget_absence(
    request: &ForgetAbsenceRequest<'_>,
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<(), MnemeError> {
    if request.post_forget_certs.is_empty() {
        return Err(forget_absence_failure_to_mneme(
            ForgetAbsenceFailure::PostCertEmpty,
        ));
    }
    if let Some(expected) = request.cognition_cert_commit {
        let anchor = request.pre_forget_anchor.as_ref().ok_or_else(|| {
            forget_absence_failure_to_mneme(ForgetAbsenceFailure::AnchorCommitMismatch)
        })?;
        verify_pre_forget_anchor(
            anchor,
            trust,
            proc,
            request.forget_sequence,
            expected,
            request.target_commit,
        )?;
    }
    for entry in request.post_forget_certs {
        let _ = verify_post_cert(
            entry,
            trust,
            proc,
            request.forget_sequence,
            request.target_commit,
        )?;
    }
    Ok(())
}

pub fn object_id_target_commit(id: &ObjectId) -> [u8; 32] {
    id.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cognition_cert::assemble_cognition_certificate_v1;
    use crate::semantic::SemanticIndex;
    use mneme_core::{DistanceMetric, FixedPointEmbedding, ProcedureAlgo, RetrievalProofLevel};
    use mneme_crypto::KeyPair;
    use mneme_root::StoredRoot;

    fn oid(b: u8) -> ObjectId { ObjectId([b; 32]) }

    fn proc() -> Procedure {
        Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 1,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        }
    }

    fn cert_with_result(result_byte: u8, seq: u64) -> (Vec<u8>, TrustConfig) {
        let operator = KeyPair::from_seed([0x81; 32]);
        let mut index = SemanticIndex::new();
        let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        index.insert(oid(result_byte), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap()).unwrap();
        index.insert(oid(0x03), FixedPointEmbedding::new(2, 0, vec![0, 1]).unwrap()).unwrap();
        let stored = StoredRoot::assemble([0x82; 32], [0x83; 32], index.semantic_commit(), [0x84; 14], [0x00; 32], seq, &operator).unwrap();
        let receipt = index.recall_receipt_zkann(&proc(), &q, stored.preimage_hash, RetrievalProofLevel::ExactDominance).unwrap();
        let bytes = assemble_cognition_certificate_v1(&stored, &receipt, None).unwrap();
        (bytes, TrustConfig::new(operator.public_key_bytes()))
    }

    #[test]
    fn forget_absence_honesty_covers_certified_only_and_omega_n() {
        assert!(FORGET_ABSENCE_HONESTY.contains("Certified cognition only"));
        assert!(FORGET_ABSENCE_HONESTY.contains("Ω(N)"));
    }

    #[test]
    fn forget_absence_passes_when_target_not_in_post_certs() {
        let (post, trust) = cert_with_result(0x02, 5);
        let request = ForgetAbsenceRequest {
            forget_sequence: 3,
            target_commit: oid(0x99).0,
            cognition_cert_commit: None,
            post_forget_certs: &[PostForgetCert { cert_bytes: &post }],
            pre_forget_anchor: None,
        };
        verify_forget_absence(&request, &trust, &proc()).unwrap();
    }

    #[test]
    fn forget_absence_rejects_target_in_post_cert_results() {
        let (post, trust) = cert_with_result(0x01, 5);
        let request = ForgetAbsenceRequest {
            forget_sequence: 3,
            target_commit: oid(0x01).0,
            cognition_cert_commit: None,
            post_forget_certs: &[PostForgetCert { cert_bytes: &post }],
            pre_forget_anchor: None,
        };
        assert_eq!(verify_forget_absence(&request, &trust, &proc()), Err(MnemeError::CertificateInvalid));
    }
}
