//! MNEME store kernel: open / remember / recall_verified / forget / promote (blueprint §7).
//!
//! **INV-5:** Agent-facing reads use [`Store::recall_verified`] / [`Store::recall_verified_default`]
//! only. Untrusted recall assembly is `pub(crate)` inside this crate.

mod atomic;
mod forget;
mod layout;
mod merge;
mod pause;
mod recall;

use mneme_cap::Capability;
use mneme_core::object::HlcWire;
use mneme_core::{
    Draft, Entry, FixedPointEmbedding, LogicalKey, MnemeError, NodeId, ObjectId, ObjectRecord,
    PayloadEnc, Procedure, Query, Root, TrustTier, from_bytes_strict, hash_obj, to_bytes_canonical,
};
use mneme_crypto::FileKeyVault;
use mneme_crypto::{KeyPair, TrustConfig, open_payload, seal_payload};
use mneme_dag::DagIndex;
use mneme_forget::{payload_aad, prove_absent as forget_prove_absent};
use mneme_index::SemanticRecallReceipt;
use mneme_index::{KeyIndex, SemanticIndex};
use mneme_root::StoredRoot;
use mneme_smt::NonMembershipProof;
use mneme_verify::{
    RecallContext, RecallInput, SemanticRecallInput, verify_recall, verify_semantic_recall,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub use layout::Tombstone;
pub use pause::{
    AFTER_APPEND_CHECKPOINT, AFTER_BEGIN_INCOMPLETE, AFTER_KEY_INDEX, AFTER_OBJECT_WRITE,
    AFTER_PERSIST_INDEX, AFTER_WRITE_HEAD, BEFORE_COMMIT_INCOMPLETE, test_clear_pause,
    test_set_pause_at,
};

pub struct Store {
    path: PathBuf,
    operator: KeyPair,
    pub trust: TrustConfig,
    key_index: KeyIndex,
    semantic: SemanticIndex,
    dag: DagIndex,
    objects: HashMap<[u8; 32], Vec<u8>>,
    key_to_object: HashMap<[u8; 32], [u8; 32]>,
    object_keys: HashMap<[u8; 32], LogicalKey>,
    embeddings: HashMap<[u8; 32], FixedPointEmbedding>,
    vault: FileKeyVault,
    roots: Vec<Root>,
    hlc: mneme_core::Hlc,
    sequence: u64,
}

pub struct Recall {
    pub entries: Vec<mneme_core::ObjectRef>,
    pub receipt: Option<mneme_core::Receipt>,
    pub semantic_receipt: Option<SemanticRecallReceipt>,
    pub root: Root,
}

impl Store {
    pub fn create(path: &Path, operator: KeyPair) -> Result<Self, MnemeError> {
        layout::init_store(path)?;
        let trust = TrustConfig::new(operator.public_key_bytes());
        let node_id = NodeId::from_bytes([0x01; 16]);
        let mut store = Self {
            path: path.to_path_buf(),
            operator,
            trust,
            key_index: KeyIndex::new(),
            semantic: SemanticIndex::new(),
            dag: DagIndex::new(),
            objects: HashMap::new(),
            key_to_object: HashMap::new(),
            object_keys: HashMap::new(),
            embeddings: HashMap::new(),
            vault: FileKeyVault::new(path)?,
            roots: Vec::new(),
            hlc: mneme_core::Hlc::zero(node_id),
            sequence: 0,
        };
        store.commit_root()?;
        Ok(store)
    }

    pub fn open(path: &Path, operator: KeyPair) -> Result<Self, MnemeError> {
        layout::check_incomplete(path)?;
        let trust = TrustConfig::new(operator.public_key_bytes());
        let state = layout::load_state(path)?;
        let stored = layout::read_head(path)?;
        stored.verify_signature(&operator.verifying_key())?;
        let root = stored.to_root();
        let mut store = Self {
            path: path.to_path_buf(),
            operator,
            trust,
            key_index: state.key_index,
            semantic: SemanticIndex::new(),
            dag: state.dag,
            objects: state.objects,
            key_to_object: state.key_to_object,
            object_keys: state.object_keys,
            embeddings: state.embeddings,
            vault: FileKeyVault::new(path)?,
            roots: vec![root.clone()],
            hlc: state.hlc,
            sequence: stored.sequence,
        };
        store.rebuild_semantic_index()?;
        Ok(store)
    }

    pub fn trust(&self) -> &TrustConfig {
        &self.trust
    }

    pub fn trust_mut(&mut self) -> &mut TrustConfig {
        &mut self.trust
    }

    pub fn operator_keypair(&self) -> &KeyPair {
        &self.operator
    }

    pub fn current_hlc(&self) -> &mneme_core::Hlc {
        &self.hlc
    }

    pub fn remember(
        &mut self,
        draft: Draft,
        cap: &Capability,
    ) -> Result<(ObjectId, Root), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_write(&draft.namespace, draft.kind) {
            return Err(MnemeError::CapDenied);
        }
        let tier = draft.trust_tier.unwrap_or_else(|| cap.default_tier());
        layout::begin_transaction(&self.path)?;
        pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
        let result = (|| -> Result<(ObjectId, Root), MnemeError> {
            let (id, _) = self.apply_remember_draft(&draft, cap, tier, true, true)?;
            let key_hash = LogicalKey {
                namespace: draft.namespace.clone(),
                name: draft.logical_name.clone(),
            }
            .hash();
            layout::persist_key_index_upsert(&self.path, &key_hash, id.as_bytes())?;
            layout::persist_object_keys(&self.path, self)?;
            layout::persist_embeddings(&self.path, self)?;
            pause::checkpoint(pause::AFTER_PERSIST_INDEX)?;
            self.commit_root_inner()?;
            pause::checkpoint(pause::BEFORE_COMMIT_INCOMPLETE)?;
            Ok((id, self.current_root()?))
        })();

        match result {
            Ok(v) => {
                layout::commit_transaction(&self.path)?;
                Ok(v)
            }
            Err(MnemeError::IncompleteTransaction) => Err(MnemeError::IncompleteTransaction),
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    /// Batch seed for the §19 v0 recall perf bench only (not production API).
    /// One transaction and one root commit for `count` key-index entries; avoids per-entry disk/fsync.
    #[doc(hidden)]
    pub fn bench_populate_semantic_entries(
        &mut self,
        namespace: &str,
        count: usize,
        cap: &Capability,
    ) -> Result<(), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_write(namespace, mneme_core::MemoryKind::Semantic) {
            return Err(MnemeError::CapDenied);
        }
        let tier = cap.default_tier();
        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<(), MnemeError> {
            let mut ids = Vec::with_capacity(count);
            for i in 0..count {
                let draft = Draft {
                    namespace: namespace.into(),
                    logical_name: format!("key-{i:05}"),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: b"x".to_vec(),
                    parent_ids: vec![],
                    session: [0x42; 16],
                    trust_tier: None,
                    embedding: None,
                };
                let (id, _) = self.apply_remember_draft(&draft, cap, tier, false, false)?;
                ids.push(id);
            }
            self.dag.seed_independent_heads(&ids)?;
            self.key_index.tree_mut().rebuild_root_cache();
            layout::persist_key_index(&self.path, self)?;
            layout::persist_object_keys(&self.path, self)?;
            layout::persist_embeddings(&self.path, self)?;
            self.commit_root_inner()?;
            Ok(())
        })();
        match result {
            Ok(()) => layout::commit_transaction(&self.path),
            Err(MnemeError::IncompleteTransaction) => Err(MnemeError::IncompleteTransaction),
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    fn apply_remember_draft(
        &mut self,
        draft: &Draft,
        cap: &Capability,
        tier: TrustTier,
        durable_object: bool,
        update_dag: bool,
    ) -> Result<(ObjectId, [u8; 32]), MnemeError> {
        self.hlc.tick_local(self.hlc.wall_ms.saturating_add(1));

        let mut parent_ids: Vec<[u8; 32]> =
            draft.parent_ids.iter().map(|p| *p.as_bytes()).collect();
        parent_ids.sort();

        let key = LogicalKey {
            namespace: draft.namespace.clone(),
            name: draft.logical_name.clone(),
        };
        let payload_enc = seal_payload(&mut self.vault, &draft.body, &payload_aad(&key))?;

        let record = ObjectRecord {
            version: mneme_core::object::OBJECT_VERSION,
            kind: draft.kind as u8,
            parent_ids: parent_ids.clone(),
            writer: cap.writer_hash(),
            session: draft.session,
            hlc: HlcWire::from(&self.hlc),
            trust_tier: tier.as_u8(),
            payload_enc,
            embedding_commit: draft.embedding.as_ref().map(FixedPointEmbedding::commit),
            redaction_slot: None,
            ext: None,
        };

        let canonical = to_bytes_canonical(&record)?;
        let id_bytes = hash_obj(&canonical);
        let id = ObjectId(id_bytes);

        pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
        self.objects.insert(id_bytes, canonical.clone());
        if durable_object {
            layout::write_object(&self.path, &id_bytes, &canonical)?;
            pause::checkpoint(pause::AFTER_OBJECT_WRITE)?;
        }
        self.key_index.upsert(&key, id);
        self.key_to_object.insert(key.hash(), id_bytes);
        self.object_keys.insert(id_bytes, key);
        if let Some(emb) = draft.embedding.clone() {
            self.embeddings.insert(id_bytes, emb.clone());
            self.semantic.insert(id, emb).map_err(index_err)?;
        }
        if update_dag {
            self.dag.update_heads(id, &parent_ids)?;
        }
        pause::checkpoint(pause::AFTER_KEY_INDEX)?;
        Ok((id, id_bytes))
    }

    /// Fail-closed recall: untrusted index fetch plus [`verify_recall`] / semantic gate (INV-5).
    pub fn recall_verified(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
    ) -> Result<Vec<Entry>, MnemeError> {
        let recall = self.recall(query, proc, cap)?;
        let previous_root = self.roots.get(self.roots.len().wrapping_sub(2));
        if let Some(receipt) = recall.receipt {
            let object_bytes = self
                .objects
                .get(&receipt.object_id)
                .cloned()
                .ok_or(MnemeError::ObjectTampered)?;
            let objects = provenance_objects_for_bytes(&self.objects, &object_bytes)?;
            let ctx = RecallContext {
                key_index: self.key_index.tree(),
                dag: &self.dag,
                objects: &objects,
                previous_root,
            };
            let input = RecallInput {
                receipt,
                object_bytes,
                root: recall.root,
            };
            let mut entries = verify_recall(&input, query, &self.trust, &ctx)?;
            self.decrypt_entries(&mut entries)?;
            return Ok(entries);
        }
        if let Some(semantic_receipt) = recall.semantic_receipt {
            let mut seed_ids: Vec<[u8; 32]> = semantic_receipt
                .verification_object
                .result_ids
                .iter()
                .map(|id| *id.as_bytes())
                .collect();
            seed_ids.sort();
            seed_ids.dedup();
            let objects = provenance_objects_for_ids(&self.objects, &seed_ids)?;
            let ctx = RecallContext {
                key_index: self.key_index.tree(),
                dag: &self.dag,
                objects: &objects,
                previous_root,
            };
            let input = SemanticRecallInput {
                receipt: semantic_receipt,
                root: recall.root,
            };
            let mut entries = verify_semantic_recall(&input, proc, query, &self.trust, &ctx)?;
            self.decrypt_entries(&mut entries)?;
            return Ok(entries);
        }
        Err(MnemeError::ReceiptRootMismatch)
    }

    /// Fail-closed recall with default key-index procedure (adoption-layer compat).
    pub fn recall_verified_default(
        &self,
        query: &Query,
        cap: &Capability,
    ) -> Result<Vec<Entry>, MnemeError> {
        let proc = mneme_index::default_key_procedure();
        self.recall_verified(query, &proc, cap)
    }

    /// v0 ergonomic alias: key-index `recall_verified` with default procedure.
    pub fn recall_verified_compat(
        &self,
        query: &Query,
        cap: &Capability,
    ) -> Result<Vec<Entry>, MnemeError> {
        self.recall_verified_default(query, cap)
    }

    pub fn promote(
        &mut self,
        id: &ObjectId,
        to: TrustTier,
        cap: &Capability,
    ) -> Result<Root, MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_promote() {
            return Err(MnemeError::PromoteDenied);
        }
        let id_bytes = *id.as_bytes();
        let bytes = self
            .objects
            .get(&id_bytes)
            .cloned()
            .ok_or(MnemeError::ObjectTampered)?;
        let mut record: ObjectRecord = from_bytes_strict(&bytes)?;
        if TrustTier::from_u8(record.trust_tier)? >= to {
            return self.current_root();
        }
        record.trust_tier = to.as_u8();
        self.hlc.tick_local(self.hlc.wall_ms.saturating_add(1));
        let canonical = to_bytes_canonical(&record)?;
        let new_id_bytes = hash_obj(&canonical);
        let parent_ids = record.parent_ids.clone();

        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<Root, MnemeError> {
            if new_id_bytes != id_bytes {
                for (key_hash, obj_id) in self.key_to_object.iter_mut() {
                    if *obj_id == id_bytes {
                        self.key_index.tree_mut().upsert(*key_hash, new_id_bytes);
                        *obj_id = new_id_bytes;
                    }
                }
                self.dag.rekey_object(id_bytes, new_id_bytes, &parent_ids)?;
                if let Some(emb) = self.embeddings.remove(&id_bytes) {
                    self.embeddings.insert(new_id_bytes, emb);
                }
                if let Some(logical_key) = self.object_keys.remove(&id_bytes) {
                    self.object_keys.insert(new_id_bytes, logical_key);
                }
                self.objects.remove(&id_bytes);
                layout::remove_object(&self.path, &id_bytes)?;
            }
            self.objects.insert(new_id_bytes, canonical.clone());
            layout::write_object(&self.path, &new_id_bytes, &canonical)?;
            layout::persist_key_index(&self.path, self)?;
            layout::persist_object_keys(&self.path, self)?;
            layout::persist_embeddings(&self.path, self)?;
            self.rebuild_semantic_index()?;
            self.commit_root_inner()?;
            self.current_root()
        })();

        match result {
            Ok(v) => {
                layout::commit_transaction(&self.path)?;
                Ok(v)
            }
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    pub fn prove_absent(&self, logical_key: &LogicalKey) -> Result<NonMembershipProof, MnemeError> {
        forget_prove_absent(self.key_index.tree(), logical_key)
    }

    pub fn prove_membership(
        &self,
        logical_key: &LogicalKey,
    ) -> Result<mneme_smt::MembershipProof, MnemeError> {
        self.key_index.prove_membership(logical_key)
    }

    pub fn head(&self) -> Result<(Root, Option<Root>), MnemeError> {
        let current = self.current_root()?;
        let previous = if self.roots.len() > 1 {
            Some(self.roots[self.roots.len() - 2].clone())
        } else {
            None
        };
        Ok((current, previous))
    }

    pub fn current_root(&self) -> Result<Root, MnemeError> {
        self.roots
            .last()
            .cloned()
            .ok_or(MnemeError::RootInconsistent)
    }

    pub fn tamper_object_bytes(&mut self, id: &[u8; 32]) -> Result<(), MnemeError> {
        let bytes = self.objects.get_mut(id).ok_or(MnemeError::ObjectTampered)?;
        if !bytes.is_empty() {
            bytes[0] ^= 0xff;
        }
        layout::write_object(&self.path, id, bytes)?;
        Ok(())
    }

    pub fn inject_tampered_entry(
        &mut self,
        key: &LogicalKey,
        body: &[u8],
    ) -> Result<(), MnemeError> {
        let record = ObjectRecord {
            version: mneme_core::object::OBJECT_VERSION,
            kind: mneme_core::MemoryKind::Semantic as u8,
            parent_ids: vec![],
            writer: [0xee; 32],
            session: [0u8; 16],
            hlc: HlcWire {
                wall_ms: 0,
                counter: 0,
                node_id: [0u8; 16],
            },
            trust_tier: TrustTier::Trusted.as_u8(),
            payload_enc: PayloadEnc {
                alg: 0,
                key_id: None,
                nonce: None,
                body: body.to_vec(),
            },
            embedding_commit: None,
            redaction_slot: None,
            ext: None,
        };
        let bytes = to_bytes_canonical(&record)?;
        let id_bytes = hash_obj(&bytes);
        let key_hash = key.hash();
        self.objects.insert(id_bytes, bytes.clone());
        layout::write_object(&self.path, &id_bytes, &bytes)?;
        self.key_index.upsert(key, ObjectId(id_bytes));
        self.key_to_object.insert(key_hash, id_bytes);
        Ok(())
    }

    pub(crate) fn key_to_object_ref(&self) -> &HashMap<[u8; 32], [u8; 32]> {
        &self.key_to_object
    }

    pub(crate) fn tombstones_ref(&self) -> Vec<[u8; 32]> {
        self.key_index.tree().tombstone_keys()
    }

    pub(crate) fn embeddings_ref(&self) -> &HashMap<[u8; 32], FixedPointEmbedding> {
        &self.embeddings
    }

    pub(crate) fn object_keys_ref(&self) -> &HashMap<[u8; 32], LogicalKey> {
        &self.object_keys
    }

    fn decrypt_entries(&self, entries: &mut [Entry]) -> Result<(), MnemeError> {
        for entry in entries {
            let logical_key = self
                .object_keys
                .get(entry.id.as_bytes())
                .ok_or(MnemeError::SchemaDrift)?;
            entry.plaintext = open_payload(
                &self.vault,
                &entry.record.payload_enc,
                &payload_aad(logical_key),
            )?;
        }
        Ok(())
    }

    pub(crate) fn rebuild_semantic_index(&mut self) -> Result<(), MnemeError> {
        let mut semantic = SemanticIndex::new();
        for (id_bytes, emb) in &self.embeddings {
            if self.objects.contains_key(id_bytes) {
                semantic
                    .insert(ObjectId(*id_bytes), emb.clone())
                    .map_err(index_err)?;
            }
        }
        self.semantic = semantic;
        Ok(())
    }

    pub(crate) fn commit_root_inner(&mut self) -> Result<(), MnemeError> {
        let prev = self
            .roots
            .last()
            .map(|r| r.preimage_hash)
            .unwrap_or([0u8; 32]);
        self.sequence += 1;
        let stored = StoredRoot::assemble(
            self.dag.root(),
            self.key_index.root(),
            self.semantic.semantic_commit(),
            self.hlc.to_bytes(),
            prev,
            self.sequence,
            &self.operator,
        )?;
        let root = stored.to_root();
        self.roots.push(root);
        layout::append_checkpoint(&self.path, &stored)?;
        pause::checkpoint(pause::AFTER_APPEND_CHECKPOINT)?;
        layout::write_head(&self.path, &stored)?;
        pause::checkpoint(pause::AFTER_WRITE_HEAD)?;
        Ok(())
    }

    fn commit_root(&mut self) -> Result<(), MnemeError> {
        self.commit_root_inner()
    }

    fn verify_cap(&self, cap: &Capability) -> Result<(), MnemeError> {
        cap.verify(&self.operator, &self.hlc)
    }
}

fn provenance_objects_for_bytes(
    store_objects: &HashMap<[u8; 32], Vec<u8>>,
    object_bytes: &[u8],
) -> Result<BTreeMap<[u8; 32], Vec<u8>>, MnemeError> {
    let record: ObjectRecord = from_bytes_strict(object_bytes)?;
    provenance_objects_for_ids(store_objects, &record.parent_ids)
}

fn provenance_objects_for_ids(
    store_objects: &HashMap<[u8; 32], Vec<u8>>,
    seed_ids: &[[u8; 32]],
) -> Result<BTreeMap<[u8; 32], Vec<u8>>, MnemeError> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<[u8; 32]> = seed_ids.to_vec();
    while let Some(id) = stack.pop() {
        if out.contains_key(&id) {
            continue;
        }
        let bytes = store_objects
            .get(&id)
            .cloned()
            .ok_or(MnemeError::ObjectTampered)?;
        let record: ObjectRecord = from_bytes_strict(&bytes)?;
        for parent in &record.parent_ids {
            if !out.contains_key(parent) {
                stack.push(*parent);
            }
        }
        out.insert(id, bytes);
    }
    Ok(out)
}

fn index_err(e: mneme_index::IndexError) -> MnemeError {
    match e {
        mneme_index::IndexError::SemanticNotImplemented => MnemeError::ProcedureMismatch,
        mneme_index::IndexError::DuplicateObject | mneme_index::IndexError::ObjectNotIndexed => {
            MnemeError::IndexPathInvalid
        }
    }
}
