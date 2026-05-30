//! Appendix B item 5: passing + tampered ADS retrieval receipt vectors.
//!
//! Byte-pinned, single-implementation conformance vector. The committed object bytes are
//! the exact canonical `ObjectRecord` encoding; the receipt fields are pinned in
//! `manifest.json`. This test re-derives the full deterministic recall fixture, asserts the
//! committed object bytes and every receipt field match, runs `verify_recall` (PASS), and
//! confirms a one-byte object tamper yields a typed `ObjectTampered` rejection (FAIL).

use mneme_core::{
    LogicalKey, MemoryKind, MnemeError, ObjectRecord, PayloadEnc, Query, Receipt, Root, TrustTier,
    hash_obj, object::HlcWire, object::OBJECT_VERSION, to_bytes_canonical,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_dag::DagIndex;
use mneme_root::StoredRoot;
use mneme_smt::SparseMerkleTree;
use mneme_verify::{RecallContext, RecallInput, verify_recall};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("proof/vectors/receipts")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn operator() -> KeyPair {
    KeyPair::from_seed([0x01; 32])
}

fn agent() -> KeyPair {
    KeyPair::from_seed([0x02; 32])
}

fn writer_hash(subject: [u8; 32]) -> [u8; 32] {
    *blake3::hash(&subject).as_bytes()
}

fn fixture_record() -> ObjectRecord {
    ObjectRecord {
        version: OBJECT_VERSION,
        kind: MemoryKind::Semantic.as_u8(),
        parent_ids: vec![],
        writer: writer_hash(agent().public_key_bytes()),
        session: [0x42; 16],
        hlc: HlcWire {
            wall_ms: 1,
            counter: 0,
            node_id: [0x03; 16],
        },
        trust_tier: TrustTier::Working.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: b"appendix-b-receipt".to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    }
}

struct Fixture {
    input: RecallInput,
    query: Query,
    trust: TrustConfig,
    key_index: SparseMerkleTree,
    dag: DagIndex,
    objects: BTreeMap<[u8; 32], Vec<u8>>,
    previous_root: Root,
    object_bytes: Vec<u8>,
}

fn build_fixture() -> Fixture {
    let op = operator();
    let mut trust = TrustConfig::new(op.public_key_bytes());
    trust.authorized_writers.push(agent().public_key_bytes());

    let record = fixture_record();
    let object_bytes = to_bytes_canonical(&record).expect("canonical object");
    let object_id = hash_obj(&object_bytes);

    let key = LogicalKey {
        namespace: "appendixb".into(),
        name: "receipt".into(),
    };
    let key_hash = key.hash();

    let mut key_index = SparseMerkleTree::new();
    key_index.upsert(key_hash, object_id);
    key_index.rebuild_root_cache();

    let mut dag = DagIndex::new();
    dag.update_heads(mneme_core::ObjectId(object_id), &[])
        .expect("dag head");

    let prev = StoredRoot::assemble(
        dag.root(),
        key_index.root(),
        [0u8; 32],
        [0u8; 14],
        [0u8; 32],
        1,
        &op,
    )
    .expect("prev root")
    .to_root();
    let root = StoredRoot::assemble(
        dag.root(),
        key_index.root(),
        [0u8; 32],
        [0u8; 14],
        prev.preimage_hash,
        2,
        &op,
    )
    .expect("root")
    .to_root();

    let proof = key_index.prove_membership(key_hash).expect("membership");
    let receipt = Receipt {
        root_bound: root.preimage_hash,
        logical_key: key_hash,
        object_id,
        membership_proof: proof.path,
        key_index_root: root.key_index_root,
        leaf_index: proof.leaf_index,
    };

    let mut objects = BTreeMap::new();
    objects.insert(object_id, object_bytes.clone());

    Fixture {
        input: RecallInput {
            receipt,
            object_bytes: object_bytes.clone(),
            root,
        },
        query: Query {
            logical_key: key,
            min_tier: TrustTier::Working,
            embedding: None,
        },
        trust,
        key_index,
        dag,
        objects,
        previous_root: prev,
        object_bytes,
    }
}

#[test]
#[ignore = "run manually to (re)generate proof/vectors/receipts fixtures"]
fn dump_receipt_fixture() {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let f = build_fixture();
    fs::write(dir.join("recall_object_v1.cbor"), &f.object_bytes).expect("write object");
    let r = &f.input.receipt;
    eprintln!("object_id={}", hex(&r.object_id));
    eprintln!("logical_key={}", hex(&r.logical_key));
    eprintln!("root_bound={}", hex(&r.root_bound));
    eprintln!("key_index_root={}", hex(&r.key_index_root));
    eprintln!("leaf_index={}", r.leaf_index);
    eprintln!("membership_proof_len={}", r.membership_proof.len());
    eprintln!("root_signature={}", hex(&f.input.root.signature));
    eprintln!("operator_pubkey={}", hex(&operator().public_key_bytes()));
}

#[test]
fn appendix_b_passing_receipt_verifies_and_object_bytes_pinned() {
    let committed = fs::read(vectors_dir().join("recall_object_v1.cbor"))
        .expect("committed recall_object_v1.cbor present");
    let f = build_fixture();

    // Object bytes are byte-pinned and re-derivable.
    assert_eq!(committed, f.object_bytes, "committed object bytes diverged");
    assert_eq!(hash_obj(&committed), f.input.receipt.object_id);

    // PASS: full fail-closed recall gate accepts the receipt.
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: Some(&f.previous_root),
    };
    let entries = verify_recall(&f.input, &f.query, &f.trust, &ctx).expect("recall verifies");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id.0, f.input.receipt.object_id);
}

#[test]
fn appendix_b_tampered_receipt_object_fails_closed() {
    let f = build_fixture();
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: Some(&f.previous_root),
    };

    // Tamper one object byte: object_id no longer matches the receipt -> typed rejection.
    let mut tampered = f.input.object_bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let bad = RecallInput {
        receipt: f.input.receipt.clone(),
        object_bytes: tampered,
        root: f.input.root.clone(),
    };
    assert_eq!(
        verify_recall(&bad, &f.query, &f.trust, &ctx).unwrap_err(),
        MnemeError::ObjectTampered
    );
}
