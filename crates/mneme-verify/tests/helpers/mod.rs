#![allow(unused_imports, dead_code)]
//! Shared tamper fixtures.

mod semantic;

use mneme_core::{
    LogicalKey, MemoryKind, ObjectRecord, PayloadEnc, Receipt, Root, TrustTier, hash_obj,
    object::HlcWire, to_bytes_canonical,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_dag::DagIndex;
use mneme_root::StoredRoot;
use mneme_smt::SparseMerkleTree;
use mneme_verify::RecallInput;
use std::collections::BTreeMap;

pub use semantic::{SemanticFixture, build_valid_semantic_recall, sample_procedure};

/// Lightweight signed-root chain for checkpoint/root tamper tests (no SMT/DAG walk).
pub struct RootChainFixture {
    pub root: Root,
    pub trust: TrustConfig,
    pub previous_root: Option<Root>,
}

pub fn build_root_chain_fixture() -> RootChainFixture {
    let operator = KeyPair::from_seed([0x01; 32]);
    let trust = TrustConfig::new(operator.public_key_bytes());
    let prev_stored = StoredRoot::assemble(
        [0x11; 32], [0x22; 32], [0u8; 32], [0u8; 14], [0u8; 32], 1, &operator,
    )
    .expect("prev");
    let previous = prev_stored.to_root();
    let stored = StoredRoot::assemble(
        [0x33; 32],
        [0x44; 32],
        [0u8; 32],
        [0u8; 14],
        previous.preimage_hash,
        2,
        &operator,
    )
    .expect("root");
    RootChainFixture {
        root: stored.to_root(),
        trust,
        previous_root: Some(previous),
    }
}

pub struct RecallFixture {
    pub input: RecallInput,
    pub trust: TrustConfig,
    pub key_index: SparseMerkleTree,
    pub dag: DagIndex,
    pub objects: BTreeMap<[u8; 32], Vec<u8>>,
    pub previous_root: Option<Root>,
}

impl Clone for RecallFixture {
    fn clone(&self) -> Self {
        Self {
            input: RecallInput {
                receipt: self.input.receipt.clone(),
                object_bytes: self.input.object_bytes.clone(),
                root: self.input.root.clone(),
            },
            trust: self.trust.clone(),
            key_index: self.key_index.clone(),
            dag: self.dag.clone(),
            objects: self.objects.clone(),
            previous_root: self.previous_root.clone(),
        }
    }
}

pub fn theme_key(namespace: &str, name: &str) -> LogicalKey {
    LogicalKey {
        namespace: namespace.into(),
        name: name.into(),
    }
}

pub fn build_valid_recall() -> RecallFixture {
    let operator = KeyPair::from_seed([0x01; 32]);
    let agent = KeyPair::from_seed([0x02; 32]);
    let writer = writer_hash(agent.public_key_bytes());
    let mut trust = TrustConfig::new(operator.public_key_bytes());
    trust.authorized_writers.push(agent.public_key_bytes());
    let record = ObjectRecord {
        version: mneme_core::object::OBJECT_VERSION,
        kind: MemoryKind::Semantic.as_u8(),
        parent_ids: vec![],
        writer,
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
            body: b"tamper-fixture".to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    };
    let object_bytes = to_bytes_canonical(&record).expect("canonical");
    let object_id = hash_obj(&object_bytes);

    let key = theme_key("tamper", "key");
    let key_hash = key.hash();

    let mut key_index = SparseMerkleTree::new();
    key_index.upsert(key_hash, object_id);
    key_index.rebuild_root_cache();

    let mut dag = DagIndex::new();
    dag.update_heads(mneme_core::ObjectId(object_id), &[])
        .expect("dag head");

    let prev_stored = StoredRoot::assemble(
        dag.root(),
        key_index.root(),
        [0u8; 32],
        [0u8; 14],
        [0u8; 32],
        1,
        &operator,
    )
    .expect("prev");
    let previous = prev_stored.to_root();
    let stored = StoredRoot::assemble(
        dag.root(),
        key_index.root(),
        [0u8; 32],
        [0u8; 14],
        previous.preimage_hash,
        2,
        &operator,
    )
    .expect("root");
    let root = stored.to_root();

    let proof = key_index.prove_membership(key_hash).expect("proof");
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

    RecallFixture {
        input: RecallInput {
            receipt,
            object_bytes,
            root,
        },
        trust,
        key_index,
        dag,
        objects,
        previous_root: Some(previous),
    }
}

pub fn build_valid_recall_with_parent() -> RecallFixture {
    let operator = KeyPair::from_seed([0x01; 32]);
    let agent = KeyPair::from_seed([0x02; 32]);
    let writer = writer_hash(agent.public_key_bytes());
    let mut trust = TrustConfig::new(operator.public_key_bytes());
    trust.authorized_writers.push(agent.public_key_bytes());

    let parent_record = ObjectRecord {
        version: mneme_core::object::OBJECT_VERSION,
        kind: MemoryKind::Semantic.as_u8(),
        parent_ids: vec![],
        writer,
        session: [0x41; 16],
        hlc: HlcWire {
            wall_ms: 1,
            counter: 0,
            node_id: [0x04; 16],
        },
        trust_tier: TrustTier::Working.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: b"parent-fixture".to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    };
    let parent_bytes = to_bytes_canonical(&parent_record).expect("parent");
    let parent_id = hash_obj(&parent_bytes);

    let record = ObjectRecord {
        version: mneme_core::object::OBJECT_VERSION,
        kind: MemoryKind::Semantic.as_u8(),
        parent_ids: vec![parent_id],
        writer,
        session: [0x42; 16],
        hlc: HlcWire {
            wall_ms: 2,
            counter: 0,
            node_id: [0x03; 16],
        },
        trust_tier: TrustTier::Working.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: b"tamper-fixture".to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    };
    let object_bytes = to_bytes_canonical(&record).expect("canonical");
    let object_id = hash_obj(&object_bytes);
    let key_hash = theme_key("tamper", "key").hash();

    let mut key_index = SparseMerkleTree::new();
    key_index.upsert(key_hash, object_id);
    key_index.rebuild_root_cache();

    let mut dag = DagIndex::new();
    dag.update_heads(mneme_core::ObjectId(parent_id), &[])
        .expect("parent");
    dag.update_heads(mneme_core::ObjectId(object_id), &[parent_id])
        .expect("child");

    let prev_stored = StoredRoot::assemble(
        dag.root(),
        key_index.root(),
        [0u8; 32],
        [0u8; 14],
        [0u8; 32],
        1,
        &operator,
    )
    .expect("prev");
    let previous = prev_stored.to_root();
    let stored = StoredRoot::assemble(
        dag.root(),
        key_index.root(),
        [0u8; 32],
        [0u8; 14],
        previous.preimage_hash,
        2,
        &operator,
    )
    .expect("root");
    let root = stored.to_root();
    let proof = key_index.prove_membership(key_hash).expect("proof");

    let mut objects = BTreeMap::new();
    objects.insert(parent_id, parent_bytes);
    objects.insert(object_id, object_bytes.clone());

    RecallFixture {
        input: RecallInput {
            receipt: Receipt {
                root_bound: root.preimage_hash,
                logical_key: key_hash,
                object_id,
                membership_proof: proof.path,
                key_index_root: root.key_index_root,
                leaf_index: proof.leaf_index,
            },
            object_bytes,
            root,
        },
        trust,
        key_index,
        dag,
        objects,
        previous_root: Some(previous),
    }
}

fn writer_hash(subject: [u8; 32]) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(&subject);
    *h.finalize().as_bytes()
}
