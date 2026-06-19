//! Store-level merge driver (blueprint §9.4) + §11 over-the-wire anti-entropy.

use crate::Store;
use crate::layout;
use crate::pause;
use mneme_core::{LogicalKey, MnemeError, ObjectRecord, Root, from_bytes_strict, hash_obj};
use mneme_crdt::{PeerSnapshot, apply_peer_snapshot};
use mneme_crypto::{
    FileKeyVault, KEY_ID_LEN, KeyVault, Nonce24, OBJECT_KEY_LEN, XCHACHA_NONCE_LEN, open,
    random_nonce, seal,
};
use mneme_dag::DagIndex;
use mneme_smt::SparseMerkleTree;
use std::path::Path;

/// Domain-separating associated data binding a sealed vault-key bundle to its purpose
/// (B4). Prevents a sealed bundle from being mistaken for any other AEAD ciphertext.
const VAULT_SYNC_AAD: &[u8] = b"mneme-vault-sync-v1";

/// Transport-agnostic, serializable peer snapshot for §11 network anti-entropy.
///
/// Carries the authenticated *structure* — key-index leaves, tombstones, the
/// object-id → logical-key map, and the **ciphertext** object blobs. Every object is
/// re-hashed on ingest so a tampering A-NET adversary is rejected, and the signed
/// root converges over ciphertext regardless of whether keys travel.
///
/// `encrypted_keys` (B4) optionally carries the per-object payload-decryption keys,
/// **AEAD-sealed under the operator-derived channel key** ([`KeyPair::vault_channel_key`]).
/// It is empty for a keyless ([`Store::export_sync_snapshot`]) snapshot. When present
/// and the recipient shares the operator key (same trust domain), the recipient
/// decrypts and imports the keys and can recall the peer's merged entries as
/// **plaintext**. An A-NET adversary or a *different* operator derives a different
/// channel key and cannot open the bundle — so the keyless confidentiality boundary
/// is preserved for everyone outside the trust domain, and a tampered bundle simply
/// fails AEAD and is dropped (recall fails closed; convergence is unaffected).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncSnapshot {
    /// `(key_hash, object_id)` MST leaves.
    pub leaves: Vec<([u8; 32], [u8; 32])>,
    /// Tombstoned key hashes.
    pub tombstones: Vec<[u8; 32]>,
    /// `(object_id, namespace, name)` logical-key bindings.
    pub object_keys: Vec<([u8; 32], String, String)>,
    /// Canonical object record bytes (ciphertext payloads).
    pub objects: Vec<Vec<u8>>,
    /// B4: optional AEAD-sealed vault-key bundle (`nonce24 ‖ ciphertext` of fixed-width
    /// `key_id(16) ‖ object_key(32)` records). Empty = keyless snapshot. Sealed under
    /// the operator channel key; only a same-operator peer can open it.
    #[serde(default)]
    pub encrypted_keys: Vec<u8>,
}

/// Lightweight §11 anti-entropy manifest: the authenticated *structure* (leaves,
/// tombstones, logical-key bindings) plus the peer's object-id set — but **no object
/// bytes**. A peer requests this first, computes which object ids it lacks, and
/// fetches only that delta (the large ciphertext blobs), instead of pulling the
/// whole [`SyncSnapshot`]. Metadata is small (~96 B/object); object bytes dominate
/// size, so transferring only the delta is the real bandwidth win.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncManifest {
    /// `(key_hash, object_id)` MST leaves.
    pub leaves: Vec<([u8; 32], [u8; 32])>,
    /// Tombstoned key hashes.
    pub tombstones: Vec<[u8; 32]>,
    /// `(object_id, namespace, name)` logical-key bindings.
    pub object_keys: Vec<([u8; 32], String, String)>,
    /// All object ids the peer holds (for delta computation; no bytes).
    pub object_ids: Vec<[u8; 32]>,
}

impl SyncSnapshot {
    /// Rebuild the in-memory [`PeerSnapshot`] consumed by `apply_peer_snapshot`.
    /// Objects are keyed by their *recomputed* content hash (INV-1 / A-NET): a blob
    /// mutated in transit lands under a different id than the MST leaf references, so
    /// `apply_peer_snapshot` cannot bind it to a key (and `verify_object_bytes`
    /// rejects it). `peer.dag` is unused by the merge, so a fresh index suffices.
    fn to_peer_snapshot(&self) -> PeerSnapshot {
        let mut key_index = SparseMerkleTree::default();
        let mut key_to_object = std::collections::HashMap::new();
        for (key_hash, object_id) in &self.leaves {
            key_index.upsert(*key_hash, *object_id);
            key_to_object.insert(*key_hash, *object_id);
        }
        for tombstone in &self.tombstones {
            key_index.tombstone(*tombstone);
        }
        key_index.rebuild_root_cache();
        let mut object_keys = std::collections::HashMap::new();
        for (id, namespace, name) in &self.object_keys {
            object_keys.insert(
                *id,
                LogicalKey {
                    namespace: namespace.clone(),
                    name: name.clone(),
                },
            );
        }
        let mut objects = std::collections::HashMap::new();
        for bytes in &self.objects {
            objects.insert(hash_obj(bytes), bytes.clone());
        }
        PeerSnapshot {
            key_index,
            key_to_object,
            object_keys,
            objects,
            dag: DagIndex::new(),
        }
    }
}

impl Store {
    /// Deterministic MST merge from another on-disk store (§9.4, §19 12-month).
    pub fn merge_from_path(&mut self, peer_path: &Path) -> Result<Root, MnemeError> {
        layout::check_incomplete(peer_path)?;
        let peer_state = layout::load_state(peer_path)?;
        let peer_snapshot = PeerSnapshot {
            key_index: peer_state.key_index.tree().clone(),
            key_to_object: peer_state.key_to_object,
            object_keys: peer_state.object_keys,
            objects: peer_state.objects,
            dag: peer_state.dag,
        };
        self.commit_merge(&peer_snapshot, Some(peer_path))
    }

    /// §11 anti-entropy merge from a peer [`SyncSnapshot`] received over the wire.
    /// Same verified merge core as [`Self::merge_from_path`]; no vault-key transfer.
    pub fn merge_from_snapshot(&mut self, snapshot: &SyncSnapshot) -> Result<Root, MnemeError> {
        let peer_snapshot = snapshot.to_peer_snapshot();
        let root = self.commit_merge(&peer_snapshot, None)?;
        // B4: if the peer sealed its vault keys under our shared operator channel key,
        // import them so the merged entries are recall-able as plaintext. Fail-closed:
        // a foreign/tampered bundle fails AEAD and is dropped — convergence (above) is
        // already committed over ciphertext, and recall of those entries simply fails
        // closed (no plaintext leak). Keys are imported AFTER the merge transaction; a
        // crash in between loses only un-imported keys, which the next sync re-supplies.
        if !snapshot.encrypted_keys.is_empty() {
            self.import_sealed_vault_keys(&snapshot.encrypted_keys);
        }
        Ok(root)
    }

    /// Import a §11 sealed vault-key bundle (B4). Best-effort and fail-closed: any
    /// length/AEAD failure imports nothing (the recipient simply cannot decrypt the
    /// affected entries). Only keys we do not already hold are imported.
    fn import_sealed_vault_keys(&mut self, framed: &[u8]) {
        if framed.len() < XCHACHA_NONCE_LEN {
            return;
        }
        let (nonce_bytes, ciphertext) = framed.split_at(XCHACHA_NONCE_LEN);
        let mut nonce: Nonce24 = [0u8; XCHACHA_NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        let channel = self.operator.vault_channel_key();
        let Ok(plain) = open(&channel, &nonce, ciphertext, VAULT_SYNC_AAD) else {
            return; // foreign operator or tampered bundle → no plaintext, fail closed
        };
        let rec = KEY_ID_LEN + OBJECT_KEY_LEN;
        for chunk in plain.chunks_exact(rec) {
            let mut key_id = [0u8; KEY_ID_LEN];
            key_id.copy_from_slice(&chunk[..KEY_ID_LEN]);
            let mut key = [0u8; OBJECT_KEY_LEN];
            key.copy_from_slice(&chunk[KEY_ID_LEN..]);
            if !self.vault.contains(&key_id) {
                let _ = self.vault.import_key(&key_id, &key);
            }
        }
    }

    /// Export this store's authenticated structure for §11 sync (ciphertext only).
    pub fn export_sync_snapshot(&self) -> SyncSnapshot {
        let leaves: Vec<([u8; 32], [u8; 32])> = self.key_index.tree().iter_leaves().collect();
        let tombstones = self.key_index.tree().tombstone_keys();
        let object_keys: Vec<([u8; 32], String, String)> = self
            .object_keys_ref()
            .iter()
            .map(|(id, key)| (*id, key.namespace.clone(), key.name.clone()))
            .collect();
        let objects: Vec<Vec<u8>> = self.objects.values().cloned().collect();
        SyncSnapshot {
            leaves,
            tombstones,
            object_keys,
            objects,
            encrypted_keys: Vec::new(),
        }
    }

    /// Export the §11 snapshot **with** the per-object payload keys AEAD-sealed under
    /// the operator channel key (B4). A same-trust-domain peer (same operator key) can
    /// decrypt and import the keys on merge and recall the entries as plaintext; anyone
    /// else recovers only the ciphertext that [`Self::export_sync_snapshot`] carries.
    pub fn export_sync_snapshot_sealed(&self) -> SyncSnapshot {
        let mut snapshot = self.export_sync_snapshot();
        snapshot.encrypted_keys = self.seal_vault_keys();
        snapshot
    }

    /// Build the sealed vault-key bundle for every payload key this store holds.
    /// Plaintext bundle = concat of fixed-width `key_id(16) ‖ object_key(32)` records;
    /// the returned frame is `nonce24 ‖ XChaCha20-Poly1305(channel_key, bundle)`. Empty
    /// when there are no encrypted payloads or sealing fails (caller ships keyless).
    fn seal_vault_keys(&self) -> Vec<u8> {
        let mut bundle = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for bytes in self.objects.values() {
            let Ok(record) = from_bytes_strict::<ObjectRecord>(bytes) else {
                continue;
            };
            if let Some(key_id) = record.payload_enc.key_id {
                if seen.insert(key_id) {
                    if let Ok(key) = self.vault.get(&key_id) {
                        bundle.extend_from_slice(&key_id);
                        bundle.extend_from_slice(&key);
                    }
                }
            }
        }
        if bundle.is_empty() {
            return Vec::new();
        }
        let channel = self.operator.vault_channel_key();
        let nonce = random_nonce();
        match seal(&channel, &nonce, &bundle, VAULT_SYNC_AAD) {
            Ok(ciphertext) => {
                let mut framed = Vec::with_capacity(nonce.len() + ciphertext.len());
                framed.extend_from_slice(&nonce);
                framed.extend_from_slice(&ciphertext);
                framed
            }
            Err(_) => Vec::new(),
        }
    }

    /// Export the §11 anti-entropy manifest (structure + object-id set, no bytes).
    pub fn export_sync_manifest(&self) -> SyncManifest {
        let snap = self.export_sync_snapshot();
        SyncManifest {
            leaves: snap.leaves,
            tombstones: snap.tombstones,
            object_keys: snap.object_keys,
            object_ids: self.objects.keys().copied().collect(),
        }
    }

    /// Object ids in `manifest` that this store does NOT already hold — the delta a
    /// peer must fetch (`WantObjects`). Computed locally; nothing crosses the wire.
    pub fn missing_object_ids(&self, manifest: &SyncManifest) -> Vec<[u8; 32]> {
        manifest
            .object_ids
            .iter()
            .filter(|id| !self.objects.contains_key(*id))
            .copied()
            .collect()
    }

    /// Canonical bytes for the requested object ids this store holds (`HaveObjects`
    /// response). Unknown ids are skipped — the receiver re-hashes on ingest.
    pub fn export_objects(&self, ids: &[[u8; 32]]) -> Vec<Vec<u8>> {
        ids.iter()
            .filter_map(|id| self.objects.get(id).cloned())
            .collect()
    }

    /// §11 incremental anti-entropy merge: apply a peer `manifest` given only the
    /// `fetched_objects` delta (the object ids this store lacked). Objects referenced
    /// by divergent peer leaves are either in the delta or already local; we supply
    /// **both** so the verified merge core always finds them — only the delta crossed
    /// the wire. Convergence/ tamper-rejection are identical to [`Self::merge_from_snapshot`].
    pub fn merge_from_manifest(
        &mut self,
        manifest: &SyncManifest,
        fetched_objects: Vec<Vec<u8>>,
    ) -> Result<Root, MnemeError> {
        let mut objects = fetched_objects;
        objects.extend(self.objects.values().cloned());

        // FAIL CLOSED on an incomplete delta. `apply_peer_snapshot` silently skips a
        // divergent leaf whose object is absent — fine as defense-in-depth, but at
        // THIS layer a peer that advertises a leaf in its manifest yet does not serve
        // the object (truncated/malicious `HaveObjects`) would otherwise merge with no
        // error while silently DIVERGING. Require every live leaf's object to be
        // present (in the delta or already local) before merging; reject otherwise.
        let present: std::collections::HashSet<[u8; 32]> =
            objects.iter().map(|b| hash_obj(b)).collect();
        for (_key_hash, object_id) in &manifest.leaves {
            if *object_id != mneme_smt::TOMBSTONE && !present.contains(object_id) {
                return Err(MnemeError::ProvenanceBroken);
            }
        }

        let snapshot = SyncSnapshot {
            leaves: manifest.leaves.clone(),
            tombstones: manifest.tombstones.clone(),
            object_keys: manifest.object_keys.clone(),
            objects,
            // Incremental (manifest+delta) path converges ciphertext only; sealed
            // key transfer is the full-snapshot path (B4). Keyless here by design.
            encrypted_keys: Vec::new(),
        };
        self.merge_from_snapshot(&snapshot)
    }

    /// Shared transactional merge body for both on-disk and wire merges. When
    /// `peer_vault_path` is `Some`, payload-decryption keys for newly merged objects
    /// are copied from the peer's on-disk vault (on-disk merge only).
    fn commit_merge(
        &mut self,
        peer_snapshot: &PeerSnapshot,
        peer_vault_path: Option<&Path>,
    ) -> Result<Root, MnemeError> {
        // Snapshot pre-merge object set so we durably write only the newly-merged
        // object blobs, not the whole store (§22 K6).
        let pre_objects: std::collections::HashSet<[u8; 32]> =
            self.objects.keys().copied().collect();

        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<Root, MnemeError> {
            pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
            apply_peer_snapshot(
                self.key_index.tree_mut(),
                &mut self.key_to_object,
                &mut self.object_keys,
                &mut self.objects,
                &mut self.dag,
                peer_snapshot,
                &self.trust,
            )?;
            if let Some(peer_path) = peer_vault_path {
                copy_peer_vault_keys(peer_snapshot, peer_path, &self.objects, &mut *self.vault)?;
            }
            // VCP D2 / survivor-D T5: drop tombstone orphans so bilateral manifest-delta
            // merge lands on identical object sets (not just matching key-index roots).
            prune_to_converged_object_set(self)?;
            // Write only newly-merged object blobs with one directory fsync per shard
            // (§22 merge-transaction barrier — avoids O(merged) parent-dir fsyncs).
            let new_objects: Vec<([u8; 32], &[u8])> = self
                .objects
                .iter()
                .filter(|(id, _)| !pre_objects.contains(*id))
                .map(|(id, bytes)| (*id, bytes.as_slice()))
                .collect();
            layout::write_objects_batch(&self.path, &new_objects)?;
            pause::checkpoint(pause::AFTER_OBJECT_WRITE)?;
            self.apply_semantic_merge_delta(&pre_objects)?;
            pause::checkpoint(pause::AFTER_KEY_INDEX)?;
            // §22 B5: one snapshot persist (O(1) fsync) for the key-index and
            // object-keys sidecars, instead of an O(merged) loop of per-key journal
            // appends — each append did `sync_all` + `sync_parent_dir` on the shared
            // `meta/` dir, which serialized hard under concurrent multi-agent merge
            // (the measured 0.03–0.08 merges/s ceiling, sys≫user). The snapshot
            // writes the whole sidecar once and truncates the journal; it is
            // deterministic (BTreeMap) and captures the full merged index + tombstones.
            self.key_index.tree_mut().rebuild_root_cache();
            layout::persist_key_index(&self.path, self)?;
            layout::persist_object_keys(&self.path, self)?;
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
            Err(MnemeError::IncompleteTransaction) => Err(MnemeError::IncompleteTransaction),
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }
}

fn copy_peer_vault_keys(
    peer_snapshot: &PeerSnapshot,
    peer_path: &Path,
    local_objects: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    local_vault: &mut dyn KeyVault,
) -> Result<(), MnemeError> {
    let peer_vault = FileKeyVault::new(peer_path)?;
    for (id, bytes) in &peer_snapshot.objects {
        if !local_objects.contains_key(id) {
            continue;
        }
        let record: ObjectRecord = from_bytes_strict(bytes)?;
        if let Some(key_id) = record.payload_enc.key_id {
            if !local_vault.contains(&key_id) {
                let key = peer_vault.get(&key_id)?;
                local_vault.import_key(&key_id, &key)?;
            }
        }
    }
    Ok(())
}

/// Live object closure: MST winners, OR-set alternates (same logical-key hash), parents.
///
/// Complexity: O(keys + objects) — precomputes a reverse index from logical-key-hash to
/// object-ids so the OR-set alternate lookup is O(1) per winner instead of the previous
/// O(|object_keys|), turning an O(n²) inner scan into an O(n) pass.
fn converged_object_ids(
    key_index: &mneme_smt::SparseMerkleTree,
    key_to_object: &std::collections::HashMap<[u8; 32], [u8; 32]>,
    object_keys: &std::collections::HashMap<[u8; 32], LogicalKey>,
    objects: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> std::collections::HashSet<[u8; 32]> {
    // Precompute reverse map: logical-key-hash → all object-ids that reference it.
    // This replaces the previous O(|object_keys|) linear scan per winner.
    let mut key_hash_to_ids: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
        std::collections::HashMap::new();
    for (object_id, lk) in object_keys {
        key_hash_to_ids
            .entry(lk.hash())
            .or_default()
            .push(*object_id);
    }

    let mut keep = std::collections::HashSet::new();
    for (key_hash, &winner) in key_to_object {
        if key_index.is_tombstoned(key_hash) {
            continue;
        }
        keep.insert(winner);
        // OR-set alternates: all objects mapped to the same logical-key-hash (O(1) lookup).
        if let Some(alts) = key_hash_to_ids.get(key_hash) {
            for alt_id in alts {
                keep.insert(*alt_id);
            }
        }
    }
    let mut stack: Vec<[u8; 32]> = keep.iter().copied().collect();
    while let Some(id) = stack.pop() {
        let Some(bytes) = objects.get(&id) else {
            continue;
        };
        let Ok(record) = from_bytes_strict::<ObjectRecord>(bytes) else {
            continue;
        };
        for parent in &record.parent_ids {
            if keep.insert(*parent) {
                stack.push(*parent);
            }
        }
    }
    keep
}

fn prune_to_converged_object_set(store: &mut Store) -> Result<usize, MnemeError> {
    let keep = converged_object_ids(
        store.key_index.tree(),
        store.key_to_object_ref(),
        store.object_keys_ref(),
        &store.objects,
    );
    let to_remove: Vec<[u8; 32]> = store
        .objects
        .keys()
        .filter(|id| !keep.contains(*id))
        .copied()
        .collect();
    if to_remove.is_empty() {
        return Ok(0);
    }
    for id in &to_remove {
        store.objects.remove(id);
        store.object_keys.remove(id);
        store.embeddings.remove(id);
        layout::remove_object(&store.path, id)?;
    }
    let entries: Vec<(mneme_core::ObjectId, Vec<[u8; 32]>)> = store
        .objects
        .iter()
        .filter_map(|(id, bytes)| {
            from_bytes_strict::<ObjectRecord>(bytes)
                .ok()
                .map(|record| (mneme_core::ObjectId(*id), record.parent_ids))
        })
        .collect();
    store.dag.rebuild_from(&entries)?;
    Ok(to_remove.len())
}

#[cfg(test)]
mod d2_object_set_convergence_tests {
    use super::*;
    use mneme_cap::agent_cap;
    use mneme_core::{Draft, ForgetMode, ForgetTarget, MemoryKind};
    use mneme_crypto::KeyPair;
    use std::collections::HashSet;
    use tempfile::tempdir;
    fn test_cap(o: &KeyPair) -> mneme_cap::Capability {
        agent_cap(o, o.public_key_bytes()).unwrap()
    }
    fn test_draft(ns: &str, name: &str, body: &[u8]) -> Draft {
        Draft {
            namespace: ns.into(),
            logical_name: name.into(),
            kind: MemoryKind::Episodic,
            body: body.to_vec(),
            parent_ids: vec![],
            session: [0x01; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        }
    }
    fn object_id_set(s: &Store) -> HashSet<[u8; 32]> {
        s.export_sync_manifest().object_ids.into_iter().collect()
    }
    fn merge_both_ways(a: &mut Store, b: &mut Store) {
        let mb = b.export_sync_manifest();
        a.merge_from_manifest(&mb, b.export_objects(&a.missing_object_ids(&mb)))
            .unwrap();
        let ma = a.export_sync_manifest();
        b.merge_from_manifest(&ma, a.export_objects(&b.missing_object_ids(&ma)))
            .unwrap();
    }
    #[test]
    fn manifest_delta_disjoint_keys_object_sets_converge() {
        let op = KeyPair::from_seed([0xd2; 32]);
        let cap = test_cap(&op);
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let mut a = Store::create(da.path(), op.clone()).unwrap();
        let mut b = Store::create(db.path(), op).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        b.trust_mut().authorized_writers.push(cap.subject);
        a.remember(test_draft("peer", "only-a", b"alpha"), &cap)
            .unwrap();
        b.remember(test_draft("peer", "only-b", b"beta"), &cap)
            .unwrap();
        merge_both_ways(&mut a, &mut b);
        assert_eq!(object_id_set(&a), object_id_set(&b));
    }
    #[test]
    fn manifest_delta_conflicting_episodic_object_sets_converge_with_alts() {
        let op = KeyPair::from_seed([0xd3; 32]);
        let cap = test_cap(&op);
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let mut a = Store::create(da.path(), op.clone()).unwrap();
        let mut b = Store::create(db.path(), op).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        b.trust_mut().authorized_writers.push(cap.subject);
        a.remember(test_draft("peer", "shared", b"from-A"), &cap)
            .unwrap();
        b.remember(test_draft("peer", "shared", b"from-B"), &cap)
            .unwrap();
        merge_both_ways(&mut a, &mut b);
        assert_eq!(object_id_set(&a), object_id_set(&b));
        assert_eq!(object_id_set(&a).len(), 2);
    }
    #[test]
    fn manifest_delta_prunes_tombstone_orphans_and_converges() {
        let op = KeyPair::from_seed([0xd4; 32]);
        let cap = test_cap(&op);
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let mut a = Store::create(da.path(), op.clone()).unwrap();
        let mut b = Store::create(db.path(), op).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        b.trust_mut().authorized_writers.push(cap.subject);
        a.remember(test_draft("peer", "forgotten", b"orphan-me"), &cap)
            .unwrap();
        a.forget(
            ForgetTarget::LogicalKey(LogicalKey {
                namespace: "peer".into(),
                name: "forgotten".into(),
            }),
            &cap,
            ForgetMode::Shred,
        )
        .unwrap();
        assert_eq!(object_id_set(&a).len(), 1);
        b.remember(test_draft("peer", "live", b"beta"), &cap)
            .unwrap();
        merge_both_ways(&mut a, &mut b);
        assert_eq!(object_id_set(&a), object_id_set(&b));
        assert_eq!(object_id_set(&a).len(), 1);
    }

    /// Root short-circuit invariant: merging two already-converged stores must leave
    /// both stores byte-identical (same object-id sets and same root sequence).
    ///
    /// This validates that the `apply_peer_snapshot` root-identity fast-path does
    /// not corrupt state when called on fully-synced stores.
    #[test]
    fn manifest_delta_idempotent_on_already_converged_stores() {
        let op = KeyPair::from_seed([0xd5; 32]);
        let cap = test_cap(&op);
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let mut a = Store::create(da.path(), op.clone()).unwrap();
        let mut b = Store::create(db.path(), op).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        b.trust_mut().authorized_writers.push(cap.subject);
        a.remember(test_draft("sync", "shared-key", b"shared-body"), &cap)
            .unwrap();
        b.remember(test_draft("sync", "shared-key", b"shared-body"), &cap)
            .unwrap();
        // First merge: both learn about each other's identical object.
        merge_both_ways(&mut a, &mut b);
        let ids_after_first = object_id_set(&a);

        // Second merge: stores are now converged — fast-path must apply and produce no changes.
        merge_both_ways(&mut a, &mut b);
        assert_eq!(
            object_id_set(&a),
            ids_after_first,
            "converged merge must not change object-id sets"
        );
        assert_eq!(
            object_id_set(&a),
            object_id_set(&b),
            "both stores must remain identical after idempotent merge"
        );
    }

    /// Tombstone propagation: if peer has forgotten a key that local still holds live,
    /// the tombstone must win and the key must be absent from both stores after merge.
    #[test]
    fn manifest_delta_tombstone_propagation_peer_wins_over_local_live() {
        let op = KeyPair::from_seed([0xd6; 32]);
        let cap = test_cap(&op);
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let mut a = Store::create(da.path(), op.clone()).unwrap();
        let mut b = Store::create(db.path(), op).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        b.trust_mut().authorized_writers.push(cap.subject);
        // Both write the same key.
        a.remember(test_draft("sync", "will-forget", b"to-be-forgotten"), &cap)
            .unwrap();
        b.remember(test_draft("sync", "will-forget", b"to-be-forgotten"), &cap)
            .unwrap();
        // B forgets its copy.
        b.forget(
            ForgetTarget::LogicalKey(LogicalKey {
                namespace: "sync".into(),
                name: "will-forget".into(),
            }),
            &cap,
            ForgetMode::Shred,
        )
        .unwrap();
        // After merge, A must adopt B's tombstone.
        merge_both_ways(&mut a, &mut b);
        // The tombstone key must not appear as a live object in either store's manifest.
        // (The manifest only exports live object IDs, not tombstones.)
        let ids_a = object_id_set(&a);
        let ids_b = object_id_set(&b);
        assert_eq!(ids_a, ids_b, "stores must converge");
        // Both must have exactly the tombstone (zero live keys) since the only key was forgotten.
        assert!(
            ids_a.is_empty(),
            "tombstone must win: no live objects expected"
        );
    }
}
