use crate::root::verify_root;
use mneme_core::{MnemeError, ObjectRecord, Root, from_bytes_strict, hash_obj};
use mneme_crypto::TrustConfig;
use mneme_dag::load_content_addressed_objects;
use mneme_index::{load_key_index_tree, load_semantic_commit};
use mneme_root::{CheckpointLog, StoredRoot};
use std::collections::BTreeMap;
use std::path::Path;

/// Stand-alone store verifier report (§7 `verify_store`, boot-time / CI gate).
pub struct RootReport {
    pub root: Root,
    pub object_count: usize,
}

pub struct SignatureOnlyHead {
    pub root: Root,
}

/// Signature-only head check. This is not a tamper gate because it does not
/// scan object blobs or sidecar indexes.
#[doc(hidden)]
pub fn verify_signed_head_only(
    root: &Root,
    trust: &TrustConfig,
) -> Result<SignatureOnlyHead, MnemeError> {
    verify_root(root, trust, None)?;
    Ok(SignatureOnlyHead { root: root.clone() })
}

/// Fail-closed verifier for an on-disk store directory (§7, §10).
pub fn verify_store(path: &Path, trust: &TrustConfig) -> Result<RootReport, MnemeError> {
    let incomplete_marker = path.join(".incomplete");
    if mneme_root::path_entry_exists_no_follow(&incomplete_marker)? {
        return Err(MnemeError::IncompleteTransaction);
    }
    let stored = read_head(path)?;
    if stored.preimage().hash() != stored.preimage_hash {
        return Err(MnemeError::RootSigInvalid);
    }
    let previous = load_previous_root(path, stored.sequence)?;
    let root = stored.to_root();
    // A-REPLAY / INV-6: HEAD below an on-disk signed checkpoint is rollback;
    // the log's max HLC pins `last_seen_hlc` for the replay gate.
    let mut trust = trust.clone();
    if let Some((max_seq, max_hlc)) = mneme_root::max_signed_checkpoint(path, &trust.operator_keys)?
    {
        if max_seq > stored.sequence {
            return Err(MnemeError::RootReplayed);
        }
        if match trust.last_seen_hlc {
            Some(last_seen_hlc) => max_hlc > last_seen_hlc,
            None => true,
        } {
            trust.last_seen_hlc = Some(max_hlc);
        }
    }
    verify_root(&root, &trust, previous.as_ref())?;
    // F-3 / INV-4: re-verify every checkpoint so non-adjacent tamper fails closed.
    mneme_root::verify_checkpoint_chain(path, &trust.operator_keys, &stored)?;
    let objects = load_content_addressed_objects(path)?;
    let key_index = load_key_index_tree(path)?;
    if key_index.root() != root.key_index_root
        || objects.dag.root() != root.dag_head_root
        || load_semantic_commit(path, objects.objects.keys())? != root.semantic_commit
    {
        return Err(MnemeError::RootInconsistent);
    }
    for (id, bytes) in &objects.objects {
        if hash_obj(bytes) != *id {
            return Err(MnemeError::ObjectTampered);
        }
        let record: ObjectRecord = from_bytes_strict(bytes)?;
        for parent in &record.parent_ids {
            let parent_bytes = objects
                .objects
                .get(parent)
                .ok_or(MnemeError::ProvenanceBroken)?;
            if hash_obj(parent_bytes) != *parent {
                return Err(MnemeError::ProvenanceBroken);
            }
        }
    }
    // B-1 / §7 verifier completeness: object_keys carries the object_id to
    // LogicalKey reverse binding that the signed key-index cannot reconstruct.
    let object_keys: BTreeMap<_, _> = mneme_index::load_object_keys(path)?.into_iter().collect();
    for (id, logical_key) in &object_keys {
        let Some(_) = objects.objects.get(id) else {
            return Err(MnemeError::RootInconsistent);
        };
        let Some(_) = key_index.get(&logical_key.hash()) else {
            return Err(MnemeError::RootInconsistent);
        };
    }
    for (key_hash, object_id) in key_index.iter_leaves() {
        if object_id == mneme_smt::TOMBSTONE {
            continue;
        }
        let object_key_matches_leaf = match object_keys.get(&object_id) {
            Some(logical_key) => logical_key.hash() == key_hash,
            None => false,
        };
        if !object_key_matches_leaf {
            return Err(MnemeError::RootInconsistent);
        }
    }
    Ok(RootReport {
        root,
        object_count: verified_object_count(&objects.objects),
    })
}

fn verified_object_count(objects: &BTreeMap<[u8; 32], Vec<u8>>) -> usize {
    objects.len()
}

fn read_head(path: &Path) -> Result<StoredRoot, MnemeError> {
    CheckpointLog::read_head(path)
}

fn load_previous_root(path: &Path, sequence: u64) -> Result<Option<Root>, MnemeError> {
    if sequence <= 1 {
        return Ok(None);
    }
    Ok(CheckpointLog::try_read_checkpoint(path, sequence - 1)?.map(|stored| stored.to_root()))
}
