//! MNEME store kernel: open / remember / recall_verified / forget / promote (blueprint §7).
//!
//! **INV-5:** Agent-facing reads use [`Store::recall_verified`] / [`Store::recall_verified_default`]
//! only. Untrusted recall assembly is `pub(crate)` inside this crate.

#[cfg(feature = "context_gate")]
pub use context_gate::ContextGateRecallOpts;
mod action;
mod audit;
pub use action::{
    action_commit_forget, action_commit_promote, action_commit_remember, enforce_external_action,
};
pub use audit::AUDIT_TARGET;
mod atomic;
mod certify;
#[cfg(feature = "context_gate")]
mod context_gate;
mod forget;
mod layout;
mod merge;
mod pause;
mod recall;
#[cfg(feature = "bitemporal_recall")]
mod recall_at;
mod repair;
mod scoped_recall;

pub use repair::{RepairReport, repair_store};

use mneme_cap::Capability;
use mneme_core::object::HlcWire;
use mneme_core::{
    ActionReceipt, Draft, Entry, FixedPointEmbedding, LogicalKey, MnemeError, NodeId, ObjectId,
    ObjectRecord, PayloadEnc, Procedure, Query, Root, TrustTier, from_bytes_strict, hash_obj,
    to_bytes_canonical,
};
use mneme_crypto::{FileKeyVault, KeyVault};
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
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};

/// Upper bound on distinct (key, tier) results held by the session recall cache.
/// Bounded so a long sweep of unique queries cannot grow it without limit; once
/// full the slot set is reset rather than evicted one-by-one (deterministic).
const RECALL_CACHE_CAP: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreLocalSchemaFailure {
    MissingObjectKey,
    BenchEmbeddingZeroDimension,
}

/// §22 session verified-recall cache (K3 "cache last verified root + receipt for
/// repeated queries in a session"). Holds results that already passed
/// [`verify_recall`], keyed by `(logical_key_hash, min_tier)` and bound to the
/// signed root they were verified under. It is **fail-closed**: any store mutation
/// commits a new root (new `preimage_hash`), so a stale `root_hash` invalidates the
/// whole cache on the next read — a forgotten or superseded entry can never be
/// served. Only key-index recalls are cached; semantic recalls bypass it.
#[derive(Default)]
struct RecallSessionCache {
    root_hash: [u8; 32],
    entries: HashMap<([u8; 32], u8), Vec<Entry>>,
}

impl RecallSessionCache {
    fn lookup(&self, root_hash: &[u8; 32], key: &([u8; 32], u8)) -> Option<Vec<Entry>> {
        if &self.root_hash != root_hash {
            return None;
        }
        self.entries.get(key).cloned()
    }

    fn store(&mut self, root_hash: [u8; 32], key: ([u8; 32], u8), entries: &[Entry]) {
        if self.root_hash != root_hash || self.entries.len() >= RECALL_CACHE_CAP {
            self.entries.clear();
            self.root_hash = root_hash;
        }
        self.entries.insert(key, entries.to_vec());
    }
}

#[cfg(feature = "phase_iii_prove_forget")]
pub use forget::ForgetProven;

pub use layout::Tombstone;
pub use merge::{SyncManifest, SyncSnapshot};
pub use mneme_core::AsOf;
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
    /// B6: the per-object key vault is abstracted behind the [`KeyVault`] trait so a
    /// future HSM/KMS adapter is a drop-in (`*_with_vault` constructors) with no
    /// kernel change. `+ Send` keeps `Store` usable inside `Arc<Mutex<Store>>` across
    /// `tokio::spawn` (mnemed). The vault is outside the verifier TCB — it gates only
    /// payload-key availability, never whether a recall verifies against the root.
    vault: Box<dyn KeyVault + Send>,
    roots: Vec<Root>,
    hlc: mneme_core::Hlc,
    sequence: u64,
    recall_cache: RefCell<RecallSessionCache>,
    /// Held for the store lifetime; released on drop (single-writer invariant).
    _store_lock: File,
}

pub struct Recall {
    pub entries: Vec<mneme_core::ObjectRef>,
    pub receipt: Option<mneme_core::Receipt>,
    pub semantic_receipt: Option<SemanticRecallReceipt>,
    pub root: Root,
}

impl Store {
    pub fn create(path: &Path, operator: KeyPair) -> Result<Self, MnemeError> {
        let vault = Box::new(FileKeyVault::new(path)?);
        Self::create_with_vault(path, operator, vault)
    }

    /// B6 HSM/KMS seam: create a store backed by a caller-supplied [`KeyVault`].
    /// The default ([`Store::create`]) uses the on-disk [`FileKeyVault`]; a KMS/HSM
    /// adapter is injected here with no kernel change. See `docs/HSM_KMS_ADAPTER.md`.
    pub fn create_with_vault(
        path: &Path,
        operator: KeyPair,
        vault: Box<dyn KeyVault + Send>,
    ) -> Result<Self, MnemeError> {
        layout::init_store(path)?;
        atomic::audit_durability_at_open(path)?;
        let _store_lock = atomic::open_store_lock(path)?;
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
            vault,
            roots: Vec::new(),
            hlc: mneme_core::Hlc::zero(node_id),
            sequence: 0,
            recall_cache: RefCell::new(RecallSessionCache::default()),
            _store_lock,
        };
        store.commit_root()?;
        Ok(store)
    }

    pub fn open(path: &Path, operator: KeyPair) -> Result<Self, MnemeError> {
        Self::open_pinned(path, operator, None)
    }

    /// Cold-open with an optional operator-supplied trusted root pin (§2.4 residual).
    ///
    /// INV-6 / `Store::open` already reject the *disk-detectable* A-REPLAY rollback
    /// (a HEAD below an on-disk signed checkpoint). The remaining variant — an
    /// attacker who **deletes** the newer checkpoint and rolls the entire store back
    /// to a self-consistent older snapshot — is byte-indistinguishable from a
    /// legitimately-older store and cannot be rejected from disk alone. When the
    /// operator carries the expected HEAD `preimage_hash` out-of-band and passes it
    /// here, a mismatch is rejected as `RootReplayed`, closing that residual.
    pub fn open_pinned(
        path: &Path,
        operator: KeyPair,
        pinned_root: Option<[u8; 32]>,
    ) -> Result<Self, MnemeError> {
        let vault = Box::new(FileKeyVault::new(path)?);
        Self::open_pinned_with_vault(path, operator, pinned_root, vault)
    }

    /// B6 HSM/KMS seam: open with a caller-supplied [`KeyVault`]. Same A-REPLAY /
    /// INV-6 cold-open checks as [`Store::open_pinned`]; only the key backend differs.
    pub fn open_with_vault(
        path: &Path,
        operator: KeyPair,
        vault: Box<dyn KeyVault + Send>,
    ) -> Result<Self, MnemeError> {
        Self::open_pinned_with_vault(path, operator, None, vault)
    }

    pub fn open_pinned_with_vault(
        path: &Path,
        operator: KeyPair,
        pinned_root: Option<[u8; 32]>,
        vault: Box<dyn KeyVault + Send>,
    ) -> Result<Self, MnemeError> {
        layout::check_incomplete(path)?;
        atomic::audit_durability_at_open(path)?;
        let _store_lock = atomic::open_store_lock(path)?;
        let mut trust = TrustConfig::new(operator.public_key_bytes());
        let state = layout::load_state(path)?;
        let stored = layout::read_head(path)?;
        stored.verify_signature(&operator.verifying_key())?;
        if let Some(expected) = pinned_root {
            if stored.preimage_hash != expected {
                return Err(MnemeError::RootReplayed);
            }
        }
        // A-REPLAY / INV-6: reject a cold open whose HEAD has been rolled back below
        // an on-disk signed checkpoint, and pin the log's max HLC as the replay floor
        // (mirrors `verify_store`; the `.incomplete` guard above covers the
        // append→write_head crash window so this only fires on genuine rollback).
        let root = stored.to_root();
        if let Some((max_seq, max_hlc)) =
            mneme_root::max_signed_checkpoint(path, &trust.operator_keys)?
        {
            if max_seq > stored.sequence {
                return Err(MnemeError::RootReplayed);
            }
            trust.last_seen_hlc = Some(max_hlc);
        }
        mneme_root::check_replay(&root, trust.last_seen_hlc)?;
        mneme_root::verify_checkpoint_chain(path, &trust.operator_keys, &stored)?;
        if state.key_index.root() != root.key_index_root {
            return Err(MnemeError::RootInconsistent);
        }
        validate_live_key_index_object_keys(&state)?;
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
            vault,
            roots: vec![root.clone()],
            hlc: state.hlc,
            sequence: stored.sequence,
            recall_cache: RefCell::new(RecallSessionCache::default()),
            _store_lock,
        };
        store.rebuild_semantic_index()?;
        if store.semantic.semantic_commit() != root.semantic_commit {
            return Err(MnemeError::RootInconsistent);
        }
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
        self.remember_with_action(draft, cap, None)
    }

    /// Remember with optional Phase III `ActionReceipt` (see `phase_iii_require_action`).
    pub fn remember_with_action(
        &mut self,
        draft: Draft,
        cap: &Capability,
        action_receipt: Option<&ActionReceipt>,
    ) -> Result<(ObjectId, Root), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_write(&draft.namespace, draft.kind) {
            return Err(MnemeError::CapDenied);
        }
        let pre_root = self.current_root()?;
        action::enforce_external_action(
            action_receipt,
            action::action_commit_remember(&draft),
            cap,
            &pre_root,
        )?;
        let tier = draft.trust_tier.unwrap_or_else(|| cap.default_tier());
        layout::begin_transaction(&self.path)?;
        pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
        let result = (|| -> Result<(ObjectId, Root), MnemeError> {
            let (id, _) = self.apply_remember_draft(&draft, cap, tier, true, true)?;
            let logical_key = LogicalKey {
                namespace: draft.namespace.clone(),
                name: draft.logical_name.clone(),
            };
            let key_hash = logical_key.hash();
            // Incremental sidecar persistence: append-only journal entries instead
            // of an O(n) `object_keys.json`/`embeddings.json` rewrite per write
            // (§22 K5). Replay on open reconstructs the maps (`load_state`).
            layout::persist_key_index_upsert(&self.path, &key_hash, id.as_bytes())?;
            layout::persist_object_keys_upsert(&self.path, id.as_bytes(), &logical_key)?;
            if let Some(emb) = draft.embedding.as_ref() {
                layout::persist_embeddings_upsert(&self.path, id.as_bytes(), emb)?;
            }
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
            // §22 durable group-commit: batch the per-object vault keys into one
            // journal fsync instead of one fsync per key (~98% of ingest cost). Done
            // inside the closure so a vault that fails to open a batch window aborts
            // the transaction via the error arm below (no leaked `.incomplete`).
            self.vault.begin_batch()?;
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
                    valid_time_ms: None,
                };
                let (id, _) = self.apply_remember_draft(&draft, cap, tier, false, false)?;
                ids.push(id);
            }
            self.vault.flush_batch()?;
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
            Err(MnemeError::IncompleteTransaction) => {
                self.vault.cancel_batch();
                Err(MnemeError::IncompleteTransaction)
            }
            Err(e) => {
                self.vault.cancel_batch();
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    /// Durable batch ingest (§22 group-commit): apply many drafts in ONE atomic
    /// `.incomplete`-guarded transaction with a single vault-key journal fsync and a
    /// single root commit, instead of one full transaction (≈5 fsyncs) per entry.
    /// Crash-safe: a crash before commit leaves `.incomplete` → cold open rejects and
    /// the whole batch rolls back. Objects are durably written (per-object content
    /// fsync) so committed entries survive; the win is amortizing the per-key,
    /// checkpoint, HEAD, and sidecar fsyncs across the batch. Returns the new root.
    pub fn remember_batch(
        &mut self,
        drafts: Vec<Draft>,
        cap: &Capability,
    ) -> Result<Root, MnemeError> {
        self.verify_cap(cap)?;
        for d in &drafts {
            if !cap.permits_write(&d.namespace, d.kind) {
                return Err(MnemeError::CapDenied);
            }
        }
        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<Root, MnemeError> {
            self.vault.begin_batch()?;
            pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
            for draft in &drafts {
                let tier = draft.trust_tier.unwrap_or_else(|| cap.default_tier());
                self.apply_remember_draft(draft, cap, tier, true, true)?;
            }
            self.vault.flush_batch()?;
            // One full sidecar persist for the whole batch (not per entry).
            self.key_index.tree_mut().rebuild_root_cache();
            layout::persist_key_index(&self.path, self)?;
            layout::persist_object_keys(&self.path, self)?;
            layout::persist_embeddings(&self.path, self)?;
            pause::checkpoint(pause::AFTER_PERSIST_INDEX)?;
            self.commit_root_inner()?;
            pause::checkpoint(pause::BEFORE_COMMIT_INCOMPLETE)?;
            self.current_root()
        })();
        match result {
            Ok(root) => {
                layout::commit_transaction(&self.path)?;
                Ok(root)
            }
            Err(MnemeError::IncompleteTransaction) => {
                self.vault.cancel_batch();
                Err(MnemeError::IncompleteTransaction)
            }
            Err(e) => {
                self.vault.cancel_batch();
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    /// Batch seed for the §22 / F-7 semantic-recall bench only (not production API).
    /// Like [`Store::bench_populate_semantic_entries`] but attaches a distinct
    /// [`bench_embedding`] to every entry so they land in the HNSW semantic index
    /// and the semantic (ANN) `recall_verified` path is exercisable under load.
    /// One transaction / one root commit; no per-entry fsync.
    #[doc(hidden)]
    pub fn bench_populate_embedded_entries(
        &mut self,
        namespace: &str,
        count: usize,
        dim: u32,
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
                    embedding: Some(bench_embedding(i, dim)?),
                    valid_time_ms: None,
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
        let payload_enc = seal_payload(&mut *self.vault, &draft.body, &payload_aad(&key))?;

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
            ext: draft.valid_time_ms.map(mneme_core::ext_map_with_valid_time),
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
        // Authorize once here (cap signature + read scope); the internal `recall`
        // assembly no longer re-verifies, so neither cache hits nor misses pay a
        // double cap check on the hot path.
        self.authorize_read(query, cap)?;
        // §22 K3 session cache: serve a repeated key-index query from the last
        // verified result while the signed root is unchanged. Fail-closed — any
        // store mutation rotates the signed root and invalidates the cache.
        let cache_key = if mneme_index::is_key_index_procedure(proc) {
            let root_hash = self.current_root()?.preimage_hash;
            let key = (query.logical_key.hash(), query.min_tier.as_u8());
            if let Some(entries) = self.recall_cache.borrow().lookup(&root_hash, &key) {
                return Ok(entries);
            }
            Some((root_hash, key))
        } else {
            None
        };

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
            let mut entries = verify_recall(&input, query, &self.trust, &ctx).inspect_err(|e| {
                audit::emit_verify_recall_rejection(e, "key_index");
            })?;
            self.decrypt_entries(&mut entries)?;
            if let Some((root_hash, key)) = cache_key {
                self.recall_cache
                    .borrow_mut()
                    .store(root_hash, key, &entries);
            }
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
            let mut entries = verify_semantic_recall(&input, proc, query, &self.trust, &ctx)
                .inspect_err(|e| {
                    audit::emit_verify_recall_rejection(e, "semantic");
                })?;
            self.decrypt_entries(&mut entries)?;
            return Ok(entries);
        }
        Err(MnemeError::ReceiptRootMismatch)
    }

    /// Benchmark-only: run the untrusted recall assembly (index fetch + membership
    /// proof build) WITHOUT the `verify_recall` gate, so a caller can isolate the
    /// §22 hot-path verification overhead (`recall_verified` minus `recall`). Not a
    /// production API: this path is fail-open and must never be exposed to agents.
    #[doc(hidden)]
    pub fn bench_recall_raw(&self, query: &Query, cap: &Capability) -> Result<(), MnemeError> {
        self.authorize_read(query, cap)?;
        let proc = mneme_index::default_key_procedure();
        let recall = self.recall(query, &proc, cap)?;
        std::hint::black_box(&recall);
        Ok(())
    }

    /// Read authorization shared by all verified-recall entry points: cap
    /// signature validity plus read scope for the query's namespace/tier (§7).
    fn authorize_read(&self, query: &Query, cap: &Capability) -> Result<(), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_read(&query.logical_key.namespace, query.min_tier) {
            return Err(MnemeError::CapDenied);
        }
        Ok(())
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

    /// Fail-closed semantic recall with the default semantic procedure (HNSW).
    ///
    /// Same TCB gate as `recall_verified`; the query MUST carry an embedding. Per the
    /// §3 honesty boundary this proves procedure-faithfulness over the committed
    /// candidate set under the quantized metric — NOT true nearest neighbors.
    pub fn recall_verified_semantic_default(
        &self,
        query: &Query,
        cap: &Capability,
    ) -> Result<Vec<Entry>, MnemeError> {
        let proc = mneme_index::default_semantic_procedure();
        self.recall_verified(query, &proc, cap)
    }

    pub fn promote(
        &mut self,
        id: &ObjectId,
        to: TrustTier,
        cap: &Capability,
    ) -> Result<Root, MnemeError> {
        self.promote_with_action(id, to, cap, None)
    }

    pub fn promote_with_action(
        &mut self,
        id: &ObjectId,
        to: TrustTier,
        cap: &Capability,
        action_receipt: Option<&ActionReceipt>,
    ) -> Result<Root, MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_promote() {
            return Err(MnemeError::PromoteDenied);
        }
        let pre_root = self.current_root()?;
        action::enforce_external_action(
            action_receipt,
            action::action_commit_promote(id, to),
            cap,
            &pre_root,
        )?;
        let id_bytes = *id.as_bytes();
        let bytes = self
            .objects
            .get(&id_bytes)
            .cloned()
            .ok_or(MnemeError::ObjectTampered)?;
        let mut record: ObjectRecord = from_bytes_strict(&bytes)?;
        let from_tier = record.trust_tier;
        if TrustTier::from_u8(from_tier)? >= to {
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
            let root = self.current_root()?;
            layout::append_promotion_event(
                &self.path,
                &layout::PromotionEvent {
                    from_id: hex::encode(id_bytes),
                    to_id: hex::encode(new_id_bytes),
                    from_tier,
                    to_tier: to.as_u8(),
                    writer: hex::encode(cap.writer_hash()),
                    hlc: hex::encode(self.hlc.to_bytes()),
                    sequence: root.sequence,
                },
            )?;
            Ok(root)
        })();

        match result {
            Ok(v) => {
                layout::commit_transaction(&self.path)?;
                audit::emit_promote(v.sequence, &id_bytes, to.as_u8());
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
                .ok_or_else(missing_object_key_error)?;
            entry.plaintext = open_payload(
                &*self.vault,
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

    /// §22 incremental semantic rebuild on merge: O(added) inserts when no tombstones removed.
    pub(crate) fn apply_semantic_merge_delta(
        &mut self,
        pre_objects: &std::collections::HashSet<[u8; 32]>,
    ) -> Result<(), MnemeError> {
        let mut removed = Vec::new();
        for id in pre_objects {
            if !self.objects.contains_key(id) {
                removed.push(*id);
            }
        }
        let mut added = Vec::new();
        for (id, emb) in &self.embeddings {
            if self.objects.contains_key(id) && !pre_objects.contains(id) {
                added.push((ObjectId(*id), emb.clone()));
            }
        }
        self.semantic
            .apply_merge_delta(&added, &removed)
            .map_err(index_err)
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
        // Bi-temporal point-in-time recall is the sole consumer of per-commit
        // full key-index snapshots (O(N) write, O(N x writes) disk). Gated OFF in
        // the lean default so remember/forget stay O(1) on the write path.
        #[cfg(feature = "bitemporal_recall")]
        layout::snapshot_key_index_at_seq(&self.path, self.sequence, self)?;

        // Optional hash-chained root pace-log. HONESTY: this is a BLAKE3-sequential
        // pace log (mneme-pace) whose segment labels carry "seq:root_preimage" — it is
        // NOT an RFC6962 transparency log: it has no Merkle inclusion/consistency proofs
        // and, being single-operator, does not prevent equivocation. It is a derived,
        // rebuildable artifact (every root is already in the signed checkpoint log). It
        // rewrites the whole CBOR file per commit (O(n)), so it is gated OFF by default
        // to keep the lean write path O(1); enable with the `root_pace_log` feature.
        #[cfg(feature = "root_pace_log")]
        self.append_root_pace_log(&self.roots[self.roots.len() - 1])?;

        Ok(())
    }

    /// Crash-safe append of the just-committed root to the optional pace-log
    /// (`meta/root-pace.log`). Written via a `.incomplete` temp + atomic rename so a
    /// crash mid-write never leaves a torn log. Mirrors the post-`write_head` pattern
    /// used by the bitemporal snapshot: the root is already durable, so this runs last.
    #[cfg(feature = "root_pace_log")]
    fn append_root_pace_log(&self, root: &Root) -> Result<(), MnemeError> {
        let log_path = self.path.join("meta/root-pace.log");
        let mut log = if log_path.exists() {
            let bytes = std::fs::read(&log_path).map_err(|_| MnemeError::IndexPathInvalid)?;
            mneme_pace::load_log(&bytes)?
        } else {
            let cal = mneme_pace::PaceCalibration {
                alg: mneme_pace::PACE_ALG_BLAKE3_SEQUENTIAL,
                iterations_per_tick: 10,
                tick_target_ms: 1,
            };
            mneme_pace::create_log(self.operator.public_key_bytes(), cal)
                .map_err(|e| e.to_mneme())?
        };
        let label = Some(format!(
            "{}:{}",
            root.sequence,
            hex::encode(root.preimage_hash)
        ));
        let iters = log.calibration.iterations_per_tick;
        mneme_pace::append_segment(&mut log, iters, label).map_err(|e| e.to_mneme())?;
        let bytes = mneme_pace::save_log(&log)?;
        let tmp_path = self.path.join("meta/root-pace.log.incomplete");
        std::fs::write(&tmp_path, bytes).map_err(|_| MnemeError::IndexPathInvalid)?;
        std::fs::rename(&tmp_path, &log_path).map_err(|_| MnemeError::IndexPathInvalid)?;
        Ok(())
    }

    fn commit_root(&mut self) -> Result<(), MnemeError> {
        self.commit_root_inner()
    }

    pub fn create_robr_receipt(
        &self,
        prompt: &str,
        weight_measurement: [u8; 32],
        sampling: String,
        context: &[([u8; 32], Vec<u8>)],
        output_commit: [u8; 32],
    ) -> Result<Vec<u8>, MnemeError> {
        let root = self.current_root()?;
        mneme_account::robr::mint_robr_receipt(
            &self.operator,
            &root,
            prompt,
            weight_measurement,
            sampling,
            context,
            output_commit,
        )
    }

    fn verify_cap(&self, cap: &Capability) -> Result<(), MnemeError> {
        cap.verify(&self.operator, &self.hlc)
    }
}

/// Deterministic, well-spread embedding for the §22 / F-7 semantic bench: a
/// `dim`-wide fixed-point vector whose components are a reproducible hash spread of
/// `i` across `[-1024, 1024)`. Spreading across all dims (rather than a near-collinear
/// vector) keeps the HNSW index non-degenerate so populate stays ~linear, while
/// determinism means a query reusing entry `m`'s vector resolves to `m` as the exact
/// nearest neighbour. `dim >= 1`.
#[doc(hidden)]
pub fn bench_embedding(i: usize, dim: u32) -> Result<FixedPointEmbedding, MnemeError> {
    if dim == 0 {
        return Err(bench_embedding_dimension_error());
    }
    let mut components = vec![0i16; dim as usize];
    for (d, slot) in components.iter_mut().enumerate() {
        // Knuth-style multiplicative mix per (i, dim) — deterministic, no RNG state.
        let mixed = (i as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add((d as u64).wrapping_mul(0x632B_E593_7F4A_1C97));
        *slot = ((mixed >> 17) % 2048) as i16 - 1024;
    }
    FixedPointEmbedding::new(dim, 0, components)
}

fn validate_live_key_index_object_keys(state: &layout::LoadedState) -> Result<(), MnemeError> {
    for (key_hash, object_id) in &state.key_to_object {
        if !state.objects.contains_key(object_id) {
            return Err(MnemeError::RootInconsistent);
        }
        match state.object_keys.get(object_id) {
            Some(logical_key) if logical_key.hash() == *key_hash => {}
            _ => return Err(MnemeError::RootInconsistent),
        }
    }
    for (object_id, logical_key) in &state.object_keys {
        if !state.objects.contains_key(object_id) {
            return Err(MnemeError::RootInconsistent);
        }
        if state.key_index.tree().get(&logical_key.hash()).is_none() {
            return Err(MnemeError::RootInconsistent);
        }
    }
    Ok(())
}

fn store_local_schema_failure_to_mneme(failure: StoreLocalSchemaFailure) -> MnemeError {
    match failure {
        StoreLocalSchemaFailure::MissingObjectKey
        | StoreLocalSchemaFailure::BenchEmbeddingZeroDimension => MnemeError::SchemaDrift,
    }
}

fn missing_object_key_error() -> MnemeError {
    store_local_schema_failure_to_mneme(StoreLocalSchemaFailure::MissingObjectKey)
}

fn bench_embedding_dimension_error() -> MnemeError {
    store_local_schema_failure_to_mneme(StoreLocalSchemaFailure::BenchEmbeddingZeroDimension)
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
        mneme_index::IndexError::EmbeddingShape => MnemeError::SchemaDrift,
        mneme_index::IndexError::DuplicateObject | mneme_index::IndexError::ObjectNotIndexed => {
            MnemeError::IndexPathInvalid
        }
    }
}
