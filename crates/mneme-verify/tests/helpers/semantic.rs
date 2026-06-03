//! Semantic recall fixtures for tamper suite (§17.2).

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MemoryKind, ObjectId, ObjectRecord, PayloadEnc, Procedure,
    ProcedureAlgo, Root, TrustTier, hash_obj, object::HlcWire, to_bytes_canonical,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_dag::DagIndex;
use mneme_index::{SemanticIndex, SemanticRecallReceipt};
use mneme_root::StoredRoot;
use mneme_smt::SparseMerkleTree;
use std::collections::BTreeMap;

pub struct SemanticFixture {
    pub receipt: SemanticRecallReceipt,
    pub procedure: Procedure,
    pub root: Root,
    pub trust: TrustConfig,
    pub previous_root: Option<Root>,
    pub key_index: SparseMerkleTree,
    pub dag: DagIndex,
    pub objects: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Clone for SemanticFixture {
    fn clone(&self) -> Self {
        Self {
            receipt: self.receipt.clone(),
            procedure: self.procedure.clone(),
            root: self.root.clone(),
            trust: self.trust.clone(),
            previous_root: self.previous_root.clone(),
            key_index: self.key_index.clone(),
            dag: self.dag.clone(),
            objects: self.objects.clone(),
        }
    }
}

pub fn sample_procedure() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 2,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

pub fn sample_query_embedding() -> FixedPointEmbedding {
    FixedPointEmbedding::new(2, 0, vec![0, 0]).expect("query")
}

pub fn build_valid_semantic_recall() -> SemanticFixture {
    let operator = KeyPair::from_seed([0x01; 32]);
    let agent = KeyPair::from_seed([0x02; 32]);
    let writer = writer_hash(agent.public_key_bytes());
    let mut trust = TrustConfig::new(operator.public_key_bytes());
    trust.authorized_writers.push(agent.public_key_bytes());

    let proc = sample_procedure();
    let mut semantic = SemanticIndex::new();
    let embeddings = [
        FixedPointEmbedding::new(2, 0, vec![1, 0]).expect("e1"),
        FixedPointEmbedding::new(2, 0, vec![2, 0]).expect("e2"),
        FixedPointEmbedding::new(2, 0, vec![10, 0]).expect("e3"),
    ];
    let mut objects = BTreeMap::new();
    let mut ids = Vec::new();
    for (idx, emb) in embeddings.iter().enumerate() {
        let record = ObjectRecord {
            version: mneme_core::object::OBJECT_VERSION,
            kind: MemoryKind::Semantic.as_u8(),
            parent_ids: vec![],
            writer,
            session: [0x55; 16],
            hlc: HlcWire {
                wall_ms: u64::try_from(idx + 1).unwrap_or(1),
                counter: 0,
                node_id: [0x06; 16],
            },
            trust_tier: TrustTier::Working.as_u8(),
            payload_enc: PayloadEnc {
                alg: 0,
                key_id: None,
                nonce: None,
                body: format!("semantic-fixture-{idx}").into_bytes(),
            },
            embedding_commit: Some(emb.commit()),
            redaction_slot: None,
            ext: None,
        };
        let bytes = to_bytes_canonical(&record).expect("canonical");
        let oid = hash_obj(&bytes);
        ids.push(ObjectId(oid));
        objects.insert(oid, bytes);
        semantic.insert(ObjectId(oid), emb.clone()).expect("insert");
    }

    let mut dag = DagIndex::new();
    for id in &ids {
        dag.update_heads(*id, &[]).expect("dag");
    }

    let semantic_commit = semantic.semantic_commit();
    let prev_stored = StoredRoot::assemble(
        dag.root(),
        SparseMerkleTree::new().root(),
        semantic_commit,
        [0u8; 14],
        [0u8; 32],
        1,
        &operator,
    )
    .expect("prev");
    let previous = prev_stored.to_root();
    let stored = StoredRoot::assemble(
        dag.root(),
        SparseMerkleTree::new().root(),
        semantic_commit,
        [0u8; 14],
        previous.preimage_hash,
        2,
        &operator,
    )
    .expect("root");
    let root = stored.to_root();
    let query = sample_query_embedding();
    let receipt = semantic
        .recall_receipt(&proc, &query, root.preimage_hash)
        .expect("receipt");

    SemanticFixture {
        receipt,
        procedure: proc,
        root,
        trust,
        previous_root: Some(previous),
        key_index: SparseMerkleTree::new(),
        dag,
        objects,
    }
}

fn writer_hash(subject: [u8; 32]) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(&subject);
    *h.finalize().as_bytes()
}
