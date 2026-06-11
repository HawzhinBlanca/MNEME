use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
    RetrievalProofLevel,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_index::{
    FORGET_ABSENCE_HONESTY, ForgetAbsenceRequest, PostForgetCert, SemanticIndex,
    assemble_cognition_certificate_v1, certified_used_commits, verify_forget_absence,
};
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

fn signed_cert(result_byte: u8, seq: u64) -> (Vec<u8>, TrustConfig) {
    let operator = KeyPair::from_seed([0x91; 32]);
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index.insert(oid(result_byte), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap()).unwrap();
    index.insert(oid(0x03), FixedPointEmbedding::new(2, 0, vec![0, 1]).unwrap()).unwrap();
    let stored = StoredRoot::assemble([0x92; 32], [0x93; 32], index.semantic_commit(), [0x94; 14], [0x00; 32], seq, &operator).unwrap();
    let receipt = index.recall_receipt_zkann(&proc(), &q, stored.preimage_hash, RetrievalProofLevel::ExactDominance).unwrap();
    assert!(certified_used_commits(&receipt).contains(&oid(result_byte).0));
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, None).unwrap();
    (bytes, TrustConfig::new(operator.public_key_bytes()))
}

#[test]
fn forget_absence_honesty_string_is_exported() {
    assert!(FORGET_ABSENCE_HONESTY.contains("withhold"));
    assert!(FORGET_ABSENCE_HONESTY.contains("Authenticated ≠ true"));
}

#[test]
fn forget_absence_end_to_end_pass_and_fail() {
    let (clean, trust) = signed_cert(0x02, 8);
    verify_forget_absence(
        &ForgetAbsenceRequest {
            forget_sequence: 4,
            target_commit: oid(0x77).0,
            cognition_cert_commit: None,
            post_forget_certs: &[PostForgetCert { cert_bytes: &clean }],
            pre_forget_anchor: None,
        },
        &trust,
        &proc(),
    )
    .unwrap();

    let (dirty, trust2) = signed_cert(0x05, 8);
    assert_eq!(
        verify_forget_absence(
            &ForgetAbsenceRequest {
                forget_sequence: 4,
                target_commit: oid(0x05).0,
                cognition_cert_commit: None,
                post_forget_certs: &[PostForgetCert { cert_bytes: &dirty }],
                pre_forget_anchor: None,
            },
            &trust2,
            &proc(),
        ),
        Err(MnemeError::CertificateInvalid)
    );
}
