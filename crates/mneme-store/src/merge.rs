//! Store-level merge driver (blueprint §9.4).

use crate::Store;
use crate::layout;
use crate::pause;
use mneme_core::{MnemeError, ObjectRecord, Root, from_bytes_strict};
use mneme_crdt::{PeerSnapshot, apply_peer_snapshot};
use mneme_crypto::{FileKeyVault, KeyVault};
use std::path::Path;

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

        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<Root, MnemeError> {
            pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
            apply_peer_snapshot(
                self.key_index.tree_mut(),
                &mut self.key_to_object,
                &mut self.object_keys,
                &mut self.objects,
                &mut self.dag,
                &peer_snapshot,
                &self.trust,
            )?;
            copy_peer_vault_keys(&peer_snapshot, peer_path, &self.objects, &mut self.vault)?;
            for (id, bytes) in &self.objects {
                layout::write_object(&self.path, id, bytes)?;
            }
            pause::checkpoint(pause::AFTER_OBJECT_WRITE)?;
            self.rebuild_semantic_index()?;
            pause::checkpoint(pause::AFTER_KEY_INDEX)?;
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
