//! MST key-index diff + merge (blueprint §9.4).

use crate::crdt::{merge_object_versions, verify_object_bytes};
use mneme_core::{LogicalKey, MnemeError, ObjectId};
use mneme_dag::DagIndex;
use mneme_smt::{SparseMerkleTree, TOMBSTONE};
use std::collections::{BTreeSet, HashMap};

/// Trust predicate for peer writers (pubkey bytes → writer hash check).
pub trait WriterTrust: Send + Sync {
    fn trusts_writer_hash(&self, writer_hash: &[u8; 32]) -> bool;
}

impl WriterTrust for mneme_crypto::TrustConfig {
    fn trusts_writer_hash(&self, writer_hash: &[u8; 32]) -> bool {
        self.trusts_writer(writer_hash)
    }
}

/// Snapshot of peer store state for anti-entropy merge.
#[derive(Clone, Debug, Default)]
pub struct PeerSnapshot {
    pub key_index: SparseMerkleTree,
    pub key_to_object: HashMap<[u8; 32], [u8; 32]>,
    pub object_keys: HashMap<[u8; 32], LogicalKey>,
    pub objects: HashMap<[u8; 32], Vec<u8>>,
    pub dag: DagIndex,
}

/// Keys whose key-index leaf differs between local and peer MST roots.
#[derive(Clone, Debug, Default)]
pub struct MstDiff {
    pub peer_only_keys: Vec<[u8; 32]>,
    pub conflicting_keys: Vec<[u8; 32]>,
    pub local_only_keys: Vec<[u8; 32]>,
}

/// Diff key-index SMT leaf sets (order-independent).
pub fn mst_diff(local: &SparseMerkleTree, peer: &SparseMerkleTree) -> MstDiff {
    let local_keys: BTreeSet<_> = local.iter_leaves().map(|(k, _)| k).collect();
    let peer_keys: BTreeSet<_> = peer.iter_leaves().map(|(k, _)| k).collect();
    let mut diff = MstDiff::default();
    for key in peer_keys.difference(&local_keys) {
        diff.peer_only_keys.push(*key);
    }
    for key in local_keys.difference(&peer_keys) {
        diff.local_only_keys.push(*key);
    }
    for key in local_keys.intersection(&peer_keys) {
        let lv = local.get(key).unwrap_or(TOMBSTONE);
        let pv = peer.get(key).unwrap_or(TOMBSTONE);
        if lv != pv {
            diff.conflicting_keys.push(*key);
        }
    }
    diff
}

/// Outcome of applying peer data into local merge buffers.
#[derive(Clone, Debug, Default)]
pub struct MergeApplyResult {
    pub objects_inserted: usize,
    pub keys_updated: usize,
}

/// Apply peer snapshot into local mutable state (re-hash + CRDT semantics).
pub fn apply_peer_snapshot(
    local_key_index: &mut SparseMerkleTree,
    local_key_to_object: &mut HashMap<[u8; 32], [u8; 32]>,
    local_object_keys: &mut HashMap<[u8; 32], LogicalKey>,
    local_objects: &mut HashMap<[u8; 32], Vec<u8>>,
    local_dag: &mut DagIndex,
    peer: &PeerSnapshot,
    trust: &dyn WriterTrust,
) -> Result<MergeApplyResult, MnemeError> {
    let diff = mst_diff(local_key_index, &peer.key_index);
    let mut result = MergeApplyResult::default();

    let mut keys_to_process: BTreeSet<[u8; 32]> = BTreeSet::new();
    for k in diff.peer_only_keys {
        keys_to_process.insert(k);
    }
    for k in diff.conflicting_keys {
        keys_to_process.insert(k);
    }
    for k in peer.key_index.tombstone_keys() {
        keys_to_process.insert(k);
    }

    for key_hash in keys_to_process {
        let peer_val = peer.key_index.get(&key_hash).unwrap_or(TOMBSTONE);
        if peer_val == TOMBSTONE {
            let previous = local_key_index.get(&key_hash);
            let removed = local_key_to_object.remove(&key_hash);
            if let Some(object_id) = removed {
                local_object_keys.remove(&object_id);
            }
            if previous != Some(TOMBSTONE) || removed.is_some() {
                result.keys_updated += 1;
            }
            local_key_index.tombstone(key_hash);
            continue;
        }
        if local_key_index.is_tombstoned(&key_hash) {
            continue;
        }
        let peer_id = peer_val;
        let peer_bytes = match peer.objects.get(&peer_id) {
            Some(b) => b.as_slice(),
            None => continue,
        };
        verify_object_bytes(&peer_id, peer_bytes)?;
        authorize_writer(peer_bytes, trust)?;

        let local_id = local_key_to_object.get(&key_hash).copied();
        match local_id {
            None => {
                ingest_object(
                    local_key_index,
                    local_key_to_object,
                    local_object_keys,
                    local_objects,
                    local_dag,
                    peer,
                    key_hash,
                    peer_id,
                    peer_bytes,
                )?;
                result.objects_inserted += 1;
                result.keys_updated += 1;
            }
            Some(local_id) if local_id == peer_id => {}
            Some(local_id) => {
                let local_bytes = local_objects
                    .get(&local_id)
                    .ok_or(MnemeError::ObjectTampered)?;
                let winner = merge_object_versions(local_id, local_bytes, peer_id, peer_bytes)?;
                let logical = peer
                    .object_keys
                    .get(&peer_id)
                    .or_else(|| local_object_keys.get(&local_id))
                    .or_else(|| local_object_keys.get(&peer_id))
                    .cloned();
                for (alt_id, alt_bytes) in winner.retained_alternatives {
                    verify_object_bytes(&alt_id, &alt_bytes)?;
                    authorize_writer(&alt_bytes, trust)?;
                    ingest_object_bytes(local_objects, local_dag, alt_id, &alt_bytes)?;
                    if let Some(logical) = &logical {
                        local_object_keys.insert(alt_id, logical.clone());
                    }
                    result.objects_inserted += 1;
                }
                ingest_object(
                    local_key_index,
                    local_key_to_object,
                    local_object_keys,
                    local_objects,
                    local_dag,
                    peer,
                    key_hash,
                    winner.object_id,
                    &winner.canonical_bytes,
                )?;
                result.keys_updated += 1;
            }
        }
    }

    Ok(result)
}

fn authorize_writer(bytes: &[u8], trust: &dyn WriterTrust) -> Result<(), MnemeError> {
    let record: mneme_core::object::ObjectRecord = mneme_core::from_bytes_strict(bytes)?;
    if !trust.trusts_writer_hash(&record.writer) {
        return Err(MnemeError::UnauthorizedWriter);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ingest_object(
    key_index: &mut SparseMerkleTree,
    key_to_object: &mut HashMap<[u8; 32], [u8; 32]>,
    object_keys: &mut HashMap<[u8; 32], LogicalKey>,
    objects: &mut HashMap<[u8; 32], Vec<u8>>,
    dag: &mut DagIndex,
    peer: &PeerSnapshot,
    key_hash: [u8; 32],
    object_id: [u8; 32],
    bytes: &[u8],
) -> Result<(), MnemeError> {
    ingest_object_bytes(objects, dag, object_id, bytes)?;
    key_index.upsert(key_hash, object_id);
    key_to_object.insert(key_hash, object_id);
    if let Some(logical) = peer.object_keys.get(&object_id) {
        object_keys.insert(object_id, logical.clone());
    }
    Ok(())
}

fn ingest_object_bytes(
    objects: &mut HashMap<[u8; 32], Vec<u8>>,
    dag: &mut DagIndex,
    object_id: [u8; 32],
    bytes: &[u8],
) -> Result<(), MnemeError> {
    if objects.contains_key(&object_id) {
        return Ok(());
    }
    let record: mneme_core::object::ObjectRecord = mneme_core::from_bytes_strict(bytes)?;
    let parents: Vec<[u8; 32]> = record.parent_ids.clone();
    objects.insert(object_id, bytes.to_vec());
    dag.update_heads(ObjectId(object_id), &parents)?;
    Ok(())
}

/// Object ids present on peer but not local (for WantObjects).
pub fn peer_object_ids_to_fetch(
    local: &HashMap<[u8; 32], Vec<u8>>,
    peer: &PeerSnapshot,
) -> Vec<[u8; 32]> {
    peer.objects
        .keys()
        .filter(|id| !local.contains_key(*id))
        .copied()
        .collect()
}
