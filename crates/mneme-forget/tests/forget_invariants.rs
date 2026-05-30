//! §13.2 / §9.5 / §17.1 red→green forget invariants.

use mneme_core::{
    LogicalKey, MemoryKind, MnemeError, ObjectRecord, from_bytes_strict, hash_obj,
    to_bytes_canonical,
};
use mneme_crypto::KeyPair;
use mneme_crypto::{MemoryKeyVault, PAYLOAD_ALG_XCHACHA20_POLY1305, open_payload, seal_payload};
use mneme_forget::{
    ShredForgetInput, forget_shred, payload_aad, payload_unreadable, prove_absent,
    structure_intact, verify_absence, verify_signed_root,
};
use mneme_root::StoredRoot;
use mneme_smt::{SparseMerkleTree, TOMBSTONE};

#[test]
fn object_fixture_roundtrips_before_seal() {
    let record = ObjectRecord::fixture(MemoryKind::Semantic);
    let bytes = to_bytes_canonical(&record).expect("encode");
    from_bytes_strict::<ObjectRecord>(&bytes).expect("decode fixture");
}

#[test]
fn sealed_payload_enc_roundtrips_alone() {
    let mut vault = MemoryKeyVault::new();
    let pe = seal_payload(&mut vault, b"x", b"aad").expect("seal");
    let bytes = to_bytes_canonical(&pe).expect("encode pe");
    from_bytes_strict::<mneme_core::PayloadEnc>(&bytes).expect("decode pe");
}

#[test]
fn sealed_payload_roundtrips_inside_object_record() {
    let mut vault = MemoryKeyVault::new();
    let mut record = ObjectRecord::fixture(MemoryKind::Semantic);
    record.payload_enc = seal_payload(&mut vault, b"x", b"aad").expect("seal");
    let bytes = to_bytes_canonical(&record).expect("encode sealed");
    from_bytes_strict::<ObjectRecord>(&bytes).expect("decode sealed");
}

fn encrypted_record(body_plain: &[u8], vault: &mut MemoryKeyVault) -> (Vec<u8>, LogicalKey) {
    let key = LogicalKey {
        namespace: "gdpr".into(),
        name: "email".into(),
    };
    let aad = payload_aad(&key);
    let mut record = ObjectRecord::fixture(MemoryKind::Semantic);
    record.payload_enc = seal_payload(vault, body_plain, &aad).expect("seal");
    let bytes = to_bytes_canonical(&record).expect("canonical");
    from_bytes_strict::<ObjectRecord>(&bytes).expect("roundtrip");
    (bytes, key)
}

#[test]
fn red_green_shred_alone_still_allows_membership_until_tombstone() {
    let mut vault = MemoryKeyVault::new();
    let (bytes, key) = encrypted_record(b"user@example.com", &mut vault);
    let id = hash_obj(&bytes);
    let key_hash = key.hash();

    let mut smt = SparseMerkleTree::new();
    smt.upsert(key_hash, id);

    // Shred vault key only — SMT still maps live object id (the gap).
    let record: ObjectRecord = from_bytes_strict(&bytes).unwrap();
    mneme_crypto::shred_payload_key(&mut vault, &record.payload_enc).expect("shred");
    assert!(smt.prove_membership(key_hash).is_ok());

    // Tombstone closes the gap: recall path must fail closed.
    smt.tombstone(key_hash);
    assert_eq!(
        smt.prove_membership(key_hash).unwrap_err(),
        MnemeError::Forgotten
    );
}

#[test]
fn gdpr_erase_prove_absent_and_forgotten_on_read() {
    let mut vault = MemoryKeyVault::new();
    let (bytes, key) = encrypted_record(b"user@example.com", &mut vault);
    let id = hash_obj(&bytes);
    let key_hash = key.hash();
    let mut smt = SparseMerkleTree::new();
    smt.upsert(key_hash, id);

    forget_shred(ShredForgetInput {
        logical_key: &key,
        key_index: &mut smt,
        vault: &mut vault,
        object_bytes: Some(&bytes),
    })
    .expect("forget");

    let proof = prove_absent(&smt, &key).expect("prove_absent");
    verify_absence(&proof).expect("verify absence");
    assert_eq!(
        smt.prove_membership(key_hash).unwrap_err(),
        MnemeError::Forgotten
    );
    structure_intact(&bytes, &id).expect("hash intact");
    payload_unreadable(&vault, &bytes, &key).expect("ciphertext unreadable");
}

#[test]
fn signed_root_still_verifies_after_shred_forget() {
    let operator = KeyPair::generate();
    let trust = mneme_crypto::TrustConfig::new(operator.public_key_bytes());

    let mut vault = MemoryKeyVault::new();
    let (bytes, key) = encrypted_record(b"secret", &mut vault);
    let id = hash_obj(&bytes);
    let mut smt = SparseMerkleTree::new();
    smt.upsert(key.hash(), id);

    let prev = [0u8; 32];
    let stored = StoredRoot::assemble(
        [0xaa; 32],
        smt.root(),
        [0u8; 32],
        [0u8; 14],
        prev,
        1,
        &operator,
    )
    .expect("assemble");

    forget_shred(ShredForgetInput {
        logical_key: &key,
        key_index: &mut smt,
        vault: &mut vault,
        object_bytes: Some(&bytes),
    })
    .expect("forget");

    let stored2 = StoredRoot::assemble(
        [0xaa; 32],
        smt.root(),
        [0u8; 32],
        [0u8; 14],
        stored.preimage_hash,
        2,
        &operator,
    )
    .expect("assemble2");
    let root = stored2.to_root();
    let prev_root = stored.to_root();
    verify_signed_root(&root, &trust, Some(&prev_root)).expect("root verifies");
}

#[test]
fn prove_absent_rejects_live_key() {
    let mut smt = SparseMerkleTree::new();
    let key = LogicalKey {
        namespace: "ns".into(),
        name: "live".into(),
    };
    let kh = key.hash();
    smt.upsert(kh, [0x42; 32]);
    assert_eq!(
        prove_absent(&smt, &key).unwrap_err(),
        MnemeError::TombstoneConflict
    );
}

#[test]
fn tombstone_non_membership_proof_conflicts_with_ff_sentinel() {
    let mut smt = SparseMerkleTree::new();
    let key = LogicalKey {
        namespace: "t".into(),
        name: "gone".into(),
    };
    smt.tombstone(key.hash());
    let proof = prove_absent(&smt, &key).expect("prove");
    assert_eq!(proof.conflicting_leaf, Some((key.hash(), TOMBSTONE)));
    verify_absence(&proof).expect("verify");
}

#[test]
fn encrypted_payload_open_fails_after_shred_before_tombstone() {
    let mut vault = MemoryKeyVault::new();
    let (bytes, key) = encrypted_record(b"x", &mut vault);
    let record: ObjectRecord = from_bytes_strict(&bytes).unwrap();
    assert_eq!(record.payload_enc.alg, PAYLOAD_ALG_XCHACHA20_POLY1305);
    mneme_crypto::shred_payload_key(&mut vault, &record.payload_enc).expect("shred");
    assert_eq!(
        open_payload(&vault, &record.payload_enc, &payload_aad(&key)).unwrap_err(),
        MnemeError::Forgotten
    );
}
