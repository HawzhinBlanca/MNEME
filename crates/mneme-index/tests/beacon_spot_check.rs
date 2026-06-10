//! Trick #1 beacon spot-check integration tests.

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
    RetrievalProofLevel,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_index::{
    SpotCheckContext, assemble_cognition_certificate_v1_with_beacon,
    audit_beacon_binding_digest, audit_lottery_selected, parse_cognition_certificate,
    prove_audit_beacon, verify_audit_beacon_offline, verify_beacon_spot_check,
    verify_cognition_certificate_v1_with_spot_check, verify_spot_check_exact_nn,
    BEACON_SPOT_CHECK_HONESTY, DEFAULT_AUDIT_RATE_PPM, SemanticIndex,
};
use mneme_root::StoredRoot;

fn oid(b: u8) -> ObjectId {
    ObjectId([b; 32])
}

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

fn signed_fixture() -> (StoredRoot, mneme_index::SemanticRecallReceipt, TrustConfig) {
    let operator = KeyPair::from_seed([0x71; 32]);
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let stored = StoredRoot::assemble(
        [0x72; 32],
        [0x73; 32],
        index.semantic_commit(),
        [0x74; 14],
        [0x00; 32],
        1,
        &operator,
    )
    .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, stored.preimage_hash, RetrievalProofLevel::ExactDominance)
        .unwrap();
    (stored, receipt, TrustConfig::new(operator.public_key_bytes()))
}

#[test]
fn beacon_honesty_mentions_lottery_exact_nn_on_audited_calls_only() {
    assert!(BEACON_SPOT_CHECK_HONESTY.contains("lottery-enforced exact-NN"));
    assert!(BEACON_SPOT_CHECK_HONESTY.contains("audited calls only"));
    assert!(BEACON_SPOT_CHECK_HONESTY.contains("not a SNARK"));
    assert!(BEACON_SPOT_CHECK_HONESTY.contains("procedure-faithful"));
}

#[test]
fn audit_beacon_binding_is_receipt_sensitive() {
    let (_stored, receipt, _trust) = signed_fixture();
    let beacon_a = prove_audit_beacon(100, vec![0xab; 32], &receipt).unwrap();
    let mut other = receipt.clone();
    other.root_bound[0] ^= 0x01;
    let beacon_b = prove_audit_beacon(100, vec![0xab; 32], &other).unwrap();
    assert_ne!(beacon_a.binding_digest, beacon_b.binding_digest);
    assert_eq!(
        audit_beacon_binding_digest(100, &[0xab; 32], &receipt.digest()),
        beacon_a.binding_digest
    );
}

#[test]
fn cognition_cert_v1_without_beacon_unchanged() {
    let (stored, receipt, trust) = signed_fixture();
    let bytes =
        mneme_index::assemble_cognition_certificate_v1(&stored, &receipt, None).unwrap();
    let parsed = parse_cognition_certificate(&bytes).unwrap();
    assert!(parsed.audit_beacon.is_none());
    verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), None).unwrap();
}

#[test]
fn cognition_cert_v1_with_beacon_roundtrip_and_verify() {
    let (stored, receipt, trust) = signed_fixture();
    let beacon = prove_audit_beacon(12_345, vec![0xcd; 32], &receipt).unwrap();
    let bytes = assemble_cognition_certificate_v1_with_beacon(
        &stored,
        &receipt,
        None,
        Some(beacon.clone()),
    )
    .unwrap();
    let parsed = parse_cognition_certificate(&bytes).unwrap();
    assert_eq!(parsed.audit_beacon.as_ref(), Some(&beacon));
    verify_audit_beacon_offline(parsed.audit_beacon.as_ref().unwrap(), &receipt).unwrap();
    if audit_lottery_selected(
        &beacon.beacon_randomness,
        &beacon.binding_digest,
        DEFAULT_AUDIT_RATE_PPM,
    ) {
        let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let emb = FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap();
        let ctx = SpotCheckContext {
            query: &q,
            entries: &[(oid(1), emb)],
        };
        verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), Some(&ctx))
            .unwrap();
    } else {
        verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), None).unwrap();
    }
}

#[test]
fn cognition_cert_v1_rejects_forged_beacon_binding() {
    let (stored, receipt, trust) = signed_fixture();
    let mut beacon = prove_audit_beacon(99, vec![0xef; 32], &receipt).unwrap();
    beacon.binding_digest[0] ^= 0xff;
    let bytes = assemble_cognition_certificate_v1_with_beacon(
        &stored,
        &receipt,
        None,
        Some(beacon),
    )
    .unwrap();
    assert_eq!(
        verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), None),
        Err(MnemeError::CertificateInvalid)
    );
}

#[test]
fn spot_check_exact_nn_accepts_true_distances() {
    let (stored, receipt, _trust) = signed_fixture();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    let emb = FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap();
    let ctx = SpotCheckContext {
        query: &q,
        entries: &[(oid(1), emb)],
    };
    verify_spot_check_exact_nn(
        &receipt.verification_object,
        &proc(),
        &ctx,
    )
    .unwrap();
    let beacon = prove_audit_beacon(1, vec![0x12; 32], &receipt).unwrap();
    if audit_lottery_selected(
        &beacon.beacon_randomness,
        &beacon.binding_digest,
        1_000_000,
    ) {
        verify_beacon_spot_check(
            &beacon,
            &receipt,
            RetrievalProofLevel::ExactDominance,
            &proc(),
            1_000_000,
            Some(&ctx),
        )
        .unwrap();
    }
    let _ = stored;
}

fn appendix_b_audit_beacon_fixture() -> (Vec<u8>, TrustConfig, FixedPointEmbedding) {
    let operator = KeyPair::from_seed([0x42; 32]);
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(0xab), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let stored = StoredRoot::assemble(
        [0x10; 32],
        [0x11; 32],
        index.semantic_commit(),
        [0x12; 14],
        [0x00; 32],
        1,
        &operator,
    )
    .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, stored.preimage_hash, RetrievalProofLevel::ExactDominance)
        .unwrap();
    let beacon = prove_audit_beacon(1_000_000, vec![0xcd; 32], &receipt).unwrap();
    let bytes = assemble_cognition_certificate_v1_with_beacon(
        &stored,
        &receipt,
        None,
        Some(beacon),
    )
    .unwrap();
    (bytes, TrustConfig::new(operator.public_key_bytes()), q)
}

#[test]
fn proof_vector_cognition_cert_v1_audit_beacon_verifies() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../proof/vectors/certs/cognition_cert_v1_audit_beacon.cbor");
    let bytes = std::fs::read(&path).expect("audit beacon fixture must exist");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../proof/vectors/certs/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let entry = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"].as_str() == Some("cognition_cert_v1_audit_beacon"))
        .expect("manifest entry");
    let pk_hex = entry["operator_pubkey_hex"].as_str().unwrap();
    let pk_bytes: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    let trust = TrustConfig::new(pk_bytes);
    let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    let emb = FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap();
    let ctx = SpotCheckContext {
        query: &query,
        entries: &[(oid(0xab), emb)],
    };
    let parsed = parse_cognition_certificate(&bytes).unwrap();
    let beacon = parsed.audit_beacon.as_ref().unwrap();
    if audit_lottery_selected(
        &beacon.beacon_randomness,
        &beacon.binding_digest,
        DEFAULT_AUDIT_RATE_PPM,
    ) {
        verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), Some(&ctx))
            .unwrap();
    } else {
        verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), None).unwrap();
    }
}

#[test]
#[ignore]
fn dump_cognition_cert_v1_audit_beacon_fixture() {
    let (bytes, trust, _) = appendix_b_audit_beacon_fixture();
    let out_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proof/vectors/certs");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        out_dir.join("cognition_cert_v1_audit_beacon.cbor"),
        &bytes,
    )
    .unwrap();
    eprintln!(
        "cognition_cert_v1_audit_beacon_operator_pubkey_hex={}",
        hex::encode(trust.operator_keys[0])
    );
    eprintln!(
        "cognition_cert_v1_audit_beacon_wire_hex={}",
        hex::encode(&bytes)
    );
}
