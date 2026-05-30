//! Store-level merge driver (blueprint §9.4) + §11 over-the-wire anti-entropy.

use crate::Store;
use crate::layout;
use crate::pause;
use mneme_core::{LogicalKey, MnemeError, ObjectRecord, Root, from_bytes_strict, hash_obj};
use mneme_crdt::{PeerSnapshot, apply_peer_snapshot};
use mneme_crypto::{FileKeyVault, KeyVault};
use mneme_dag::DagIndex;
use mneme_smt::SparseMerkleTree;
use std::path::Path;

/// Transport-agnostic, serializable peer snapshot for §11 network anti-entropy.
///
/// Carries the authenticated *structure* only — key-index leaves, tombstones, the
/// object-id → logical-key map, and the **ciphertext** object blobs. It deliberately
/// does NOT carry vault (payload-decryption) keys: every object is re-hashed on
/// ingest so a tampering A-NET adversary is rejected, and the signed root converges
/// over ciphertext, but payload confidentiality is preserved across an untrusted
/// sync channel. Decrypting a peer's merged entries requires out-of-band key custody
/// (the operator-key-custody assumption of §2.3), exactly as for on-disk merge.
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
        self.commit_merge(&peer_snapshot, None)
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
        }
    }

    /// Shared transactional merge body for both on-disk and wire merges. When
    /// `peer_vault_path` is `Some`, payload-decryption keys for newly merged objects
    /// are copied from the peer's on-disk vault (on-disk merge only).
    fn commit_merge(
        &mut self,
        peer_snapshot: &PeerSnapshot,
        peer_vault_path: Option<&Path>,
    ) -> Result<Root, MnemeError> {
        // Snapshot pre-merge state so the durable write/persist below touches only
        // the newly-merged delta instead of the whole store (§22 K6).
        let pre_objects: std::collections::HashSet<[u8; 32]> =
            self.objects.keys().copied().collect();
        let pre_key_to_object = self.key_to_object.clone();
        let pre_tombstones: std::collections::HashSet<[u8; 32]> =
            self.tombstones_ref().into_iter().collect();

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
                copy_peer_vault_keys(peer_snapshot, peer_path, &self.objects, &mut self.vault)?;
            }
            // Write only newly-merged object blobs — a merge now costs O(merged)
            // fsynced writes instead of re-fsyncing every object in the store.
            for (id, bytes) in &self.objects {
                if !pre_objects.contains(id) {
                    layout::write_object(&self.path, id, bytes)?;
                }
            }
            pause::checkpoint(pause::AFTER_OBJECT_WRITE)?;
            self.rebuild_semantic_index()?;
            pause::checkpoint(pause::AFTER_KEY_INDEX)?;
            // Persist only changed key-index / object-key mappings and newly merged
            // tombstones through the append-only journals (no O(n) full rewrite or
            // full journal re-append). Merge brings no embeddings, so the embedding
            // sidecar is left untouched.
            for (key_hash, object_id) in &self.key_to_object {
                if pre_key_to_object.get(key_hash) != Some(object_id) {
                    layout::persist_key_index_upsert(&self.path, key_hash, object_id)?;
                    if let Some(key) = self.object_keys.get(object_id) {
                        layout::persist_object_keys_upsert(&self.path, object_id, key)?;
                    }
                }
            }
            for tombstone in self.tombstones_ref() {
                if !pre_tombstones.contains(&tombstone) {
                    layout::persist_key_index_tombstone(&self.path, &tombstone)?;
                }
            }
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
    local_vault: &mut FileKeyVault,
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
