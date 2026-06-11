//! Integration tests for VCP D1 convergence certificate sidecar.

use crate::{
    ConvergenceCert, ConvergenceVerify, PeerSnapshot, apply_peer_snapshot, encode_convergence_cert,
    verify_convergence,
};
use mneme_core::object::{HlcWire, MemoryKind, OBJECT_VERSION, ObjectRecord};
use mneme_core::{
    LogicalKey, ObjectId, PayloadEnc, TrustTier, encode_canonical, from_bytes_strict, hash_obj,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_dag::DagIndex;
use mneme_smt::SparseMerkleTree;
use proptest::prelude::*;
use std::collections::{BTreeSet, HashMap};

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

fn canonical_dag_root(ids: &[[u8; 32]], objects: &HashMap<[u8; 32], Vec<u8>>) -> [u8; 32] {
    let mut dag = DagIndex::new();
    for id in ids {
        let bytes = objects.get(id).expect("object bytes");
        let record: ObjectRecord = from_bytes_strict(bytes).expect("parse");
        dag.update_heads(ObjectId(*id), &record.parent_ids)
            .expect("dag");
    }
    dag.root()
}

fn convergence_cert_for_live_heads(
    key_index_root: [u8; 32],
    key_to_object: &HashMap<[u8; 32], [u8; 32]>,
    objects: &HashMap<[u8; 32], Vec<u8>>,
) -> ConvergenceCert {
    let ids: Vec<[u8; 32]> = key_to_object.values().copied().collect();
    ConvergenceCert::build(key_index_root, canonical_dag_root(&ids, objects), ids)
}

#[test]
fn merge_convergence_certs_match_after_bidirectional_sync() {
    let op = KeyPair::from_seed([0x01; 32]);
    let agent_b = KeyPair::from_seed([0x02; 32]);
    let mut trust = TrustConfig::new(op.public_key_bytes());
    trust.authorize_capability_subject(agent_b.public_key_bytes());
    let key = LogicalKey {
        namespace: "user".into(),
        name: "k1".into(),
    };
    let key_hash = key.hash();
    let bytes_a = record_bytes(&sample_record(
        writer_hash(&op.public_key_bytes()),
        MemoryKind::Working,
        10,
    ));
    let id_a = hash_obj(&bytes_a);
    let bytes_b = record_bytes(&sample_record(
        writer_hash(&agent_b.public_key_bytes()),
        MemoryKind::Working,
        20,
    ));
    let id_b = hash_obj(&bytes_b);
    let mut smt_a = SparseMerkleTree::new();
    smt_a.upsert(key_hash, id_a);
    let mut objects_a = HashMap::from([(id_a, bytes_a.clone())]);
    let mut k2o_a = HashMap::from([(key_hash, id_a)]);
    let mut ok_a = HashMap::from([(id_a, key.clone())]);
    let mut dag_a = DagIndex::new();
    let peer_b = PeerSnapshot {
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
        &mut dag_a,
        &peer_b,
        &trust,
    )
    .expect("apply");
    let mut smt_b = SparseMerkleTree::new();
    smt_b.upsert(key_hash, id_b);
    let mut objects_b = HashMap::from([(id_b, bytes_b.clone())]);
    let mut k2o_b = HashMap::from([(key_hash, id_b)]);
    let mut ok_b = HashMap::from([(id_b, key.clone())]);
    let mut dag_b = DagIndex::new();
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
        &mut dag_b,
        &peer_a,
        &trust,
    )
    .expect("apply");
    assert_eq!(smt_a.root(), smt_b.root());
    assert_eq!(k2o_a, k2o_b);
    let cert_a = convergence_cert_for_live_heads(smt_a.root(), &k2o_a, &objects_a);
    let cert_b = convergence_cert_for_live_heads(smt_b.root(), &k2o_b, &objects_b);
    assert_eq!(
        verify_convergence(&cert_a, &cert_b),
        ConvergenceVerify::Converged
    );
    assert!(!encode_convergence_cert(&cert_a).expect("encode").is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn mset_commitment_order_independent(ids in prop::collection::vec(any::<[u8; 32]>(), 1..=8)) {
        use crate::ObjectMultiset;
        let forward = ObjectMultiset::from_object_ids(ids.iter());
        let mut shuffled = ids.clone(); shuffled.reverse();
        prop_assert_eq!(forward.commitment(), ObjectMultiset::from_object_ids(shuffled.iter()).commitment());
    }
}
