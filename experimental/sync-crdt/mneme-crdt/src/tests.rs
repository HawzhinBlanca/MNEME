//! Red→green invariant tests + merge_convergence property (§17.5, §18 merge).

use crate::{
    PeerSnapshot, apply_peer_snapshot, decode_sync_message, encode_sync_message,
    merge_object_versions, mst_diff, verify_object_bytes,
};
use mneme_core::object::{HlcWire, MemoryKind, OBJECT_VERSION, ObjectRecord};
use mneme_core::{
    LogicalKey, MnemeError, NodeId, PayloadEnc, SyncMessage, TrustTier, encode_canonical, hash_obj,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_dag::DagIndex;
use mneme_smt::SparseMerkleTree;
use proptest::prelude::*;
use std::collections::HashMap;

fn sample_record(writer: [u8; 32], kind: MemoryKind, wall_ms: u64) -> ObjectRecord {
    ObjectRecord {
        version: OBJECT_VERSION,
        kind: kind.as_u8(),
        parent_ids: Vec::new(),
        writer,
        session: [0u8; 16],
        hlc: HlcWire {
            wall_ms,
            counter: 0,
            node_id: [0x02; 16],
        },
        trust_tier: TrustTier::Trusted.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: b"payload".to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    }
}

fn record_bytes(rec: &ObjectRecord) -> Vec<u8> {
    encode_canonical(rec).expect("encode")
}

fn writer_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(pubkey).as_bytes()
}

#[test]
fn inv3_verify_object_bytes_rejects_tamper() {
    let rec = sample_record(writer_hash(&[0x11; 32]), MemoryKind::Episodic, 1);
    let bytes = record_bytes(&rec);
    let id = hash_obj(&bytes);
    verify_object_bytes(&id, &bytes).expect("ok");
    let mut bad = bytes.clone();
    bad[0] ^= 0xff;
    assert!(matches!(
        verify_object_bytes(&id, &bad),
        Err(MnemeError::ObjectTampered)
    ));
}

#[test]
fn sync_wire_roundtrip_hello() {
    let msg = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0xab; 16]),
        head_root: [0xcd; 32],
        head_sig: vec![1, 2, 3],
    };
    let wire = encode_sync_message(&msg).expect("encode");
    let back = decode_sync_message(&wire).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn sync_wire_roundtrip_have_objects() {
    let msg = SyncMessage::HaveObjects {
        objects: vec![vec![9, 8, 7]],
    };
    let wire = encode_sync_message(&msg).expect("encode");
    let back = decode_sync_message(&wire).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn mst_diff_detects_peer_only_key() {
    let local = SparseMerkleTree::new();
    let mut peer = SparseMerkleTree::new();
    let key = [0x01; 32];
    peer.upsert(key, [0xaa; 32]);
    let diff = mst_diff(&local, &peer);
    assert_eq!(diff.peer_only_keys, vec![key]);
    assert!(diff.conflicting_keys.is_empty());
    let _ = local;
}

#[test]
fn crdt_lww_identity_picks_newer_hlc() {
    let w = writer_hash(&[0x22; 32]);
    let local = sample_record(w, MemoryKind::Identity, 1);
    let peer = sample_record(w, MemoryKind::Identity, 2);
    let lb = record_bytes(&local);
    let pb = record_bytes(&peer);
    let lid = hash_obj(&lb);
    let pid = hash_obj(&pb);
    let winner = merge_object_versions(lid, &lb, pid, &pb).expect("merge");
    assert_eq!(winner.object_id, pid);
}

#[test]
fn merge_convergence() {
    merge_convergence_two_agents_same_root();
}

#[test]
fn merge_convergence_two_agents_same_root() {
    let op = KeyPair::from_seed([0x01; 32]);
    let agent_b = KeyPair::from_seed([0x02; 32]);
    let mut trust = TrustConfig::new(op.public_key_bytes());
    trust.authorize_capability_subject(agent_b.public_key_bytes());

    let key = LogicalKey {
        namespace: "user".into(),
        name: "k1".into(),
    };
    let key_hash = key.hash();

    let rec_a = sample_record(
        writer_hash(&op.public_key_bytes()),
        MemoryKind::Episodic,
        10,
    );
    let bytes_a = record_bytes(&rec_a);
    let id_a = hash_obj(&bytes_a);

    let rec_b = sample_record(
        writer_hash(&agent_b.public_key_bytes()),
        MemoryKind::Episodic,
        20,
    );
    let bytes_b = record_bytes(&rec_b);
    let id_b = hash_obj(&bytes_b);

    let mut smt_a = SparseMerkleTree::new();
    smt_a.upsert(key_hash, id_a);
    let mut objects_a = HashMap::from([(id_a, bytes_a.clone())]);
    let mut k2o_a = HashMap::from([(key_hash, id_a)]);
    let mut ok_a = HashMap::from([(id_a, key.clone())]);

    let peer = PeerSnapshot {
        key_index: {
            let mut ki = SparseMerkleTree::new();
            ki.upsert(key_hash, id_b);
            ki
        },
        key_to_object: HashMap::from([(key_hash, id_b)]),
        object_keys: HashMap::from([(id_b, key.clone())]),
        objects: HashMap::from([(id_b, bytes_b.clone())]),
        dag: DagIndex::new(),
    };

    apply_peer_snapshot(
        &mut smt_a,
        &mut k2o_a,
        &mut ok_a,
        &mut objects_a,
        &mut DagIndex::new(),
        &peer,
        &trust,
    )
    .expect("apply");

    let root_a = smt_a.root();

    let mut smt_b = SparseMerkleTree::new();
    smt_b.upsert(key_hash, id_b);
    let mut objects_b = HashMap::from([(id_b, bytes_b.clone())]);
    let mut k2o_b = HashMap::from([(key_hash, id_b)]);
    let mut ok_b = HashMap::from([(id_b, key.clone())]);

    let peer_a = PeerSnapshot {
        key_index: {
            let mut ki = SparseMerkleTree::new();
            ki.upsert(key_hash, id_a);
            ki
        },
        key_to_object: HashMap::from([(key_hash, id_a)]),
        object_keys: HashMap::from([(id_a, key.clone())]),
        objects: HashMap::from([(id_a, bytes_a)]),
        dag: DagIndex::new(),
    };

    apply_peer_snapshot(
        &mut smt_b,
        &mut k2o_b,
        &mut ok_b,
        &mut objects_b,
        &mut DagIndex::new(),
        &peer_a,
        &trust,
    )
    .expect("apply");

    let root_b = smt_b.root();
    assert_eq!(
        root_a, root_b,
        "CRDT merge convergence: same key-index root"
    );
}

#[test]
fn peer_tombstone_removes_local_live_leaf() {
    let op = KeyPair::from_seed([0x01; 32]);
    let mut trust = TrustConfig::new(op.public_key_bytes());
    trust.authorize_capability_subject(op.public_key_bytes());

    let key = LogicalKey {
        namespace: "user".into(),
        name: "deleted".into(),
    };
    let key_hash = key.hash();
    let bytes = record_bytes(&sample_record(
        writer_hash(&op.public_key_bytes()),
        MemoryKind::Episodic,
        10,
    ));
    let object_id = hash_obj(&bytes);

    let mut local_index = SparseMerkleTree::new();
    local_index.upsert(key_hash, object_id);
    let mut local_key_to_object = HashMap::from([(key_hash, object_id)]);
    let mut local_object_keys = HashMap::from([(object_id, key.clone())]);
    let mut local_objects = HashMap::from([(object_id, bytes)]);

    let mut peer_index = SparseMerkleTree::new();
    peer_index.tombstone(key_hash);
    let peer = PeerSnapshot {
        key_index: peer_index,
        key_to_object: HashMap::new(),
        object_keys: HashMap::new(),
        objects: HashMap::new(),
        dag: DagIndex::new(),
    };

    let outcome = apply_peer_snapshot(
        &mut local_index,
        &mut local_key_to_object,
        &mut local_object_keys,
        &mut local_objects,
        &mut DagIndex::new(),
        &peer,
        &trust,
    )
    .expect("apply tombstone");

    assert_eq!(outcome.keys_updated, 1);
    assert!(local_index.is_tombstoned(&key_hash));
    assert!(!local_key_to_object.contains_key(&key_hash));
    assert!(!local_object_keys.contains_key(&object_id));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn merge_convergence_property_n_agents_conflicting_keys(
        agents in prop::collection::vec((0u8..4, 0u16..512, any::<u8>()), 2..=6),
    ) {
        let op = KeyPair::from_seed([0x55; 32]);
        let mut trust = TrustConfig::new(op.public_key_bytes());

        let snapshots = agents
            .iter()
            .enumerate()
            .map(|(idx, (key_slot, wall_delta, _order_key))| {
                let seed = 0x70u8 + idx as u8;
                let keypair = KeyPair::from_seed([seed; 32]);
                trust.authorize_capability_subject(keypair.public_key_bytes());

                // Force the first two agents onto the same key, then let the
                // remaining agents choose random allowed conflict buckets.
                let slot = if idx < 2 { 0 } else { *key_slot };
                merge_property_snapshot(
                    &keypair,
                    slot,
                    1_000 + u64::from(*wall_delta),
                )
            })
            .collect::<Vec<_>>();

        let mut random_order = (0..snapshots.len()).collect::<Vec<_>>();
        random_order.sort_by_key(|idx| (agents[*idx].2, *idx));
        let mut reverse_order = random_order.clone();
        reverse_order.reverse();
        let canonical_order = (0..snapshots.len()).collect::<Vec<_>>();

        let random_root = root_for_snapshot_order(&snapshots, &random_order, &trust).unwrap();
        let reverse_root = root_for_snapshot_order(&snapshots, &reverse_order, &trust).unwrap();
        let canonical_root = root_for_snapshot_order(&snapshots, &canonical_order, &trust).unwrap();

        prop_assert_eq!(random_root, reverse_root);
        prop_assert_eq!(random_root, canonical_root);
    }
}

fn merge_property_snapshot(keypair: &KeyPair, key_slot: u8, wall_ms: u64) -> PeerSnapshot {
    let key = LogicalKey {
        namespace: "merge-prop".into(),
        name: format!("key-{}", key_slot % 4),
    };
    let key_hash = key.hash();
    let bytes = record_bytes(&sample_record(
        writer_hash(&keypair.public_key_bytes()),
        merge_property_kind(key_slot),
        wall_ms,
    ));
    let id = hash_obj(&bytes);
    let mut key_index = SparseMerkleTree::new();
    key_index.upsert(key_hash, id);
    PeerSnapshot {
        key_index,
        key_to_object: HashMap::from([(key_hash, id)]),
        object_keys: HashMap::from([(id, key)]),
        objects: HashMap::from([(id, bytes)]),
        dag: DagIndex::new(),
    }
}

fn merge_property_kind(key_slot: u8) -> MemoryKind {
    match key_slot % 4 {
        0 => MemoryKind::Episodic,
        1 => MemoryKind::Semantic,
        2 => MemoryKind::Identity,
        _ => MemoryKind::Procedural,
    }
}

fn root_for_snapshot_order(
    snapshots: &[PeerSnapshot],
    order: &[usize],
    trust: &TrustConfig,
) -> Result<[u8; 32], MnemeError> {
    let mut smt = SparseMerkleTree::new();
    let mut objs = HashMap::new();
    let mut k2o = HashMap::new();
    let mut okeys = HashMap::new();
    let mut dag = DagIndex::new();

    for idx in order {
        apply_peer_snapshot(
            &mut smt,
            &mut k2o,
            &mut okeys,
            &mut objs,
            &mut dag,
            &snapshots[*idx],
            trust,
        )?;
    }

    Ok(smt.root())
}

#[test]
fn appendix_b_mst_convergence_vector_matches_fixture() {
    let raw = include_str!("../../../../proof/vectors/mst/convergence_triple.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).expect("json fixture");
    let expected = fixture["expected_key_index_root"]
        .as_str()
        .expect("expected root");

    let mut trust = TrustConfig::new(KeyPair::from_seed([0x01; 32]).public_key_bytes());
    for seed in [0x0a, 0x0b, 0x0c] {
        trust.authorize_capability_subject(KeyPair::from_seed([seed; 32]).public_key_bytes());
    }

    let orders = fixture["message_orders"].as_array().expect("orders");
    assert_eq!(orders.len(), 3);
    let first_order = orders[0]
        .as_array()
        .expect("order")
        .iter()
        .map(|v| v.as_str().expect("agent label"))
        .collect::<Vec<_>>();
    let computed = mst_root_for_order(&first_order, &trust);
    assert!(
        expected.len() == 64 && expected.chars().all(|c| c.is_ascii_hexdigit()),
        "MST vector must pin a 32-byte hex root, got {expected}; computed {computed}"
    );
    for order in orders {
        let labels: Vec<&str> = order
            .as_array()
            .expect("order")
            .iter()
            .map(|v| v.as_str().expect("agent label"))
            .collect();
        assert_eq!(mst_root_for_order(&labels, &trust), expected);
    }
}

fn mst_root_for_order(order: &[&str], trust: &TrustConfig) -> String {
    let mut smt = SparseMerkleTree::new();
    let mut objs = HashMap::new();
    let mut k2o = HashMap::new();
    let mut okeys = HashMap::new();
    let mut dag = DagIndex::new();

    for label in order {
        let snap = mst_vector_snapshot(label);
        apply_peer_snapshot(
            &mut smt, &mut k2o, &mut okeys, &mut objs, &mut dag, &snap, trust,
        )
        .expect("apply fixture snapshot");
    }

    to_hex(&smt.root())
}

fn mst_vector_snapshot(label: &str) -> PeerSnapshot {
    let seed = match label {
        "A" => 0x0a,
        "B" => 0x0b,
        "C" => 0x0c,
        other => panic!("unknown MST fixture agent {other}"),
    };
    let keypair = KeyPair::from_seed([seed; 32]);
    let key = LogicalKey {
        namespace: "mst".into(),
        name: label.to_ascii_lowercase(),
    };
    let key_hash = key.hash();
    let bytes = record_bytes(&sample_record(
        writer_hash(&keypair.public_key_bytes()),
        MemoryKind::Episodic,
        u64::from(seed),
    ));
    let id = hash_obj(&bytes);
    let mut key_index = SparseMerkleTree::new();
    key_index.upsert(key_hash, id);
    PeerSnapshot {
        key_index,
        key_to_object: HashMap::from([(key_hash, id)]),
        object_keys: HashMap::from([(id, key)]),
        objects: HashMap::from([(id, bytes)]),
        dag: DagIndex::new(),
    }
}

fn to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
