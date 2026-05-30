//! Stand-alone store verifier (§7 `verify_store`, boot-time / CI gate).

use crate::root::verify_root;
use mneme_core::{
    MnemeError, ObjectId, ObjectRecord, Root, decode_hex32, from_bytes_strict, hash_obj,
};
use mneme_crypto::TrustConfig;
use mneme_dag::DagIndex;
use mneme_root::StoredRoot;
use mneme_smt::SparseMerkleTree;
use std::collections::{BTreeMap, HashMap};
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
#[deprecated(
    since = "0.1.0",
    note = "verify_signed_head_only; use verify_store for boot/CI"
)]
#[doc(hidden)]
pub fn verify_store_head(
    root: &Root,
    trust: &TrustConfig,
) -> Result<SignatureOnlyHead, MnemeError> {
    verify_signed_head_only(root, trust)
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
    verify_root(&root, trust, previous.as_ref())?;
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
    let key_index = load_key_index(path)?;
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

#[derive(serde::Deserialize, Default)]
struct KeyIndexSidecar {
    entries: HashMap<String, String>,
    tombstones: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum KeyIndexJournalEntry {
    Upsert { key: String, object: String },
    Tombstone { key: String },
}

fn load_key_index(path: &Path) -> Result<SparseMerkleTree, MnemeError> {
    let sidecar_path = path.join("meta/key_index.json");
    let mut sidecar = if sidecar_path.exists() {
        let data = fs::read_to_string(&sidecar_path).map_err(|e| io_err(&sidecar_path, e))?;
        serde_json::from_str(&data).map_err(|_| MnemeError::SerializationNonCanonical)?
    } else {
        KeyIndexSidecar::default()
    };
    let journal_path = path.join("meta/key_index.journal");
    if journal_path.exists() {
        let data = fs::read_to_string(&journal_path).map_err(|e| io_err(&journal_path, e))?;
        for line in data.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str(line).map_err(|_| MnemeError::SerializationNonCanonical)? {
                KeyIndexJournalEntry::Upsert { key, object } => {
                    decode_hex32(&key)?;
                    decode_hex32(&object)?;
                    sidecar.tombstones.retain(|t| t != &key);
                    sidecar.entries.insert(key, object);
                }
                KeyIndexJournalEntry::Tombstone { key } => {
                    decode_hex32(&key)?;
                    sidecar.entries.remove(&key);
                    if !sidecar.tombstones.contains(&key) {
                        sidecar.tombstones.push(key);
                    }
                }
            }
        }
    }
    let mut tree = SparseMerkleTree::new();
    for (k, v) in sidecar.entries {
        tree.upsert(decode_hex32(&k)?, decode_hex32(&v)?);
    }
    for t in sidecar.tombstones {
        tree.tombstone(decode_hex32(&t)?);
    }
    tree.rebuild_root_cache();
    Ok(tree)
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
