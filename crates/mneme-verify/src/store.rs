//! Stand-alone store verifier (§7 `verify_store`, boot-time / CI gate).

use crate::root::verify_root;
use mneme_core::{MnemeError, ObjectId, ObjectRecord, Root, from_bytes_strict, hash_obj};
use mneme_crypto::TrustConfig;
use mneme_dag::DagIndex;
use mneme_index::load_key_index_tree;
use mneme_root::StoredRoot;
use mneme_smt::SparseMerkleTree;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub struct RootReport {
    pub root: Root,
    pub object_count: usize,
}

pub struct SignatureOnlyHead {
    pub root: Root,
}

pub fn verify_signed_head_only(
    root: &Root,
    trust: &TrustConfig,
) -> Result<SignatureOnlyHead, MnemeError> {
    verify_root(root, trust, None)?;
    Ok(SignatureOnlyHead { root: root.clone() })
}
/// Fail-closed verifier for an on-disk store directory (§7, §10).
pub fn verify_store(path: &Path, trust: &TrustConfig) -> Result<RootReport, MnemeError> {
    if path.join(".incomplete").exists() {
        return Err(MnemeError::IncompleteTransaction);
    }
    let stored = read_head(path)?;
    if stored.preimage().hash() != stored.preimage_hash {
        return Err(MnemeError::RootSigInvalid);
    }
    let previous = load_previous_root(path, stored.sequence)?;
    let root = stored.to_root();
    // A-REPLAY / INV-6: scan the append-only checkpoint log; a HEAD below an
    // on-disk signed checkpoint is a rollback, and the log's max HLC is the
    // monotonic floor pinned into `last_seen_hlc` for the replay gate.
    let mut trust = trust.clone();
    if let Some((max_seq, max_hlc)) = mneme_root::max_signed_checkpoint(path, &trust.operator_keys)?
    {
        if max_seq > stored.sequence {
            return Err(MnemeError::RootReplayed);
        }
        if trust.last_seen_hlc.map(|h| max_hlc > h).unwrap_or(true) {
            trust.last_seen_hlc = Some(max_hlc);
        }
    }
    verify_root(&root, &trust, previous.as_ref())?;
    let state = load_state(path)?;
    if state.key_index.root() != root.key_index_root || state.dag.root() != root.dag_head_root {
        return Err(MnemeError::RootInconsistent);
    }
    for (id, bytes) in &state.objects {
        if hash_obj(bytes) != *id {
            return Err(MnemeError::ObjectTampered);
        }
        let record: ObjectRecord = from_bytes_strict(bytes)?;
        for parent in &record.parent_ids {
            let parent_bytes = state
                .objects
                .get(parent)
                .ok_or(MnemeError::ProvenanceBroken)?;
            if hash_obj(parent_bytes) != *parent {
                return Err(MnemeError::ProvenanceBroken);
            }
        }
    }
    Ok(RootReport {
        root,
        object_count: state.objects.len(),
    })
}

struct LoadedState {
    key_index: SparseMerkleTree,
    dag: DagIndex,
    objects: BTreeMap<[u8; 32], Vec<u8>>,
}

fn read_head(path: &Path) -> Result<StoredRoot, MnemeError> {
    let head_path = path.join("roots/HEAD");
    let bytes = fs::read(&head_path).map_err(|e| io_err(&head_path, e))?;
    StoredRoot::from_bytes(&bytes)
}

fn load_previous_root(path: &Path, sequence: u64) -> Result<Option<Root>, MnemeError> {
    if sequence <= 1 {
        return Ok(None);
    }
    let prev_path = path.join(format!("roots/{}.root.cbor", sequence - 1));
    if !prev_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&prev_path).map_err(|e| io_err(&prev_path, e))?;
    Ok(Some(StoredRoot::from_bytes(&bytes)?.to_root()))
}

fn load_state(path: &Path) -> Result<LoadedState, MnemeError> {
    let mut objects = BTreeMap::new();
    let objects_dir = path.join("objects");
    if objects_dir.exists() {
        walk_objects(&objects_dir, &mut objects)?;
    }
    let key_index = load_key_index_tree(path)?;
    let mut dag = DagIndex::new();
    let entries = objects
        .iter()
        .map(|(id, bytes)| {
            Ok((
                ObjectId(*id),
                from_bytes_strict::<ObjectRecord>(bytes)?.parent_ids,
            ))
        })
        .collect::<Result<Vec<_>, MnemeError>>()?;
    dag.rebuild_from(&entries)?;
    Ok(LoadedState {
        key_index,
        dag,
        objects,
    })
}

fn walk_objects(dir: &Path, out: &mut BTreeMap<[u8; 32], Vec<u8>>) -> Result<(), MnemeError> {
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        if path.is_dir() {
            walk_objects(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "cbor") {
            let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
            out.insert(hash_obj(&bytes), bytes);
        }
    }
    Ok(())
}

fn io_err(path: &Path, err: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: err.kind().to_string(),
    }
}
