//! Chameleon redaction invariants (§13.3).

use mneme_core::{
    LogicalKey, MemoryKind, ObjectRecord, PayloadEnc, TrustTier, hash_obj, to_bytes_canonical,
};
use mneme_crypto::KeyPair;
use mneme_forget::{
    RedactForgetInput, forget_redact, verify_object_identity, verify_redacted_object_identity,
    verify_redaction_record,
};
use mneme_smt::SparseMerkleTree;

fn fixture_record() -> ObjectRecord {
    ObjectRecord {
        version: mneme_core::object::OBJECT_VERSION,
        kind: MemoryKind::Episodic as u8,
        parent_ids: vec![],
        writer: [0x11; 32],
        session: [0x22; 16],
        hlc: mneme_core::object::HlcWire {
            wall_ms: 1,
            counter: 0,
            node_id: [0x33; 16],
        },
        trust_tier: TrustTier::Working.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: b"secret-payload-for-redact-test".to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    }
}

#[test]
fn redact_preserves_object_id_and_root_verifies() {
    let operator = KeyPair::from_seed([0x55; 32]);
    let record = fixture_record();
    let bytes = to_bytes_canonical(&record).expect("canonical");
    let object_id = hash_obj(&bytes);
    let key = LogicalKey {
        namespace: "redact".into(),
        name: "key".into(),
    };
    let mut smt = SparseMerkleTree::new();
    smt.upsert(key.hash(), object_id);

    let outcome = forget_redact(RedactForgetInput {
        logical_key: &key,
        key_index: &smt,
        object_bytes: &bytes,
        operator: &operator,
        reason: "compliance",
    })
    .expect("redact");
    assert_eq!(outcome.object_id, object_id);
    verify_redacted_object_identity(
        &outcome.redacted_bytes,
        &object_id,
        &key.hash(),
        &operator.public_key_bytes(),
    )
    .expect("identity");
    verify_object_identity(&outcome.redacted_bytes, &object_id).expect("structural");
    verify_redaction_record(&outcome.record).expect("signed record");
}

#[test]
fn tampered_redaction_record_rejected() {
    let operator = KeyPair::from_seed([0x66; 32]);
    let record = fixture_record();
    let bytes = to_bytes_canonical(&record).expect("canonical");
    let object_id = hash_obj(&bytes);
    let key = LogicalKey {
        namespace: "redact".into(),
        name: "tamper".into(),
    };
    let mut smt = SparseMerkleTree::new();
    smt.upsert(key.hash(), object_id);
    let mut outcome = forget_redact(RedactForgetInput {
        logical_key: &key,
        key_index: &smt,
        object_bytes: &bytes,
        operator: &operator,
        reason: "audit",
    })
    .expect("redact");
    outcome.record.signature[0] ^= 0x01;
    assert!(verify_redaction_record(&outcome.record).is_err());
}
