//! Reconstruct the key-index SMT from the on-disk sidecar + append-only journal.
//!
//! This reconstruction is **not** trust-critical: the verifier compares the
//! resulting SMT root against the operator-signed `key_index_root`, so a faulty
//! or tampered reconstruction fails closed (`RootInconsistent`) instead of
//! admitting forged state. It lives here (the key-index owner) to keep the
//! verifier TCB minimal (§17.6) and to avoid duplicating the sidecar/journal
//! format across crates. Error types are preserved verbatim for the tamper suite.

use mneme_core::{LogicalKey, MnemeError, decode_hex32};
use mneme_smt::SparseMerkleTree;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(serde::Deserialize, Default)]
struct KeyIndexSidecar {
    entries: HashMap<String, String>,
    tombstones: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct ObjectKeysSidecar {
    entries: HashMap<String, LogicalKeySidecarEntry>,
}

#[derive(serde::Deserialize)]
struct LogicalKeySidecarEntry {
    namespace: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct ObjectKeysJournalEntry {
    id: String,
    namespace: String,
    name: String,
}

/// Replay the `meta/object_keys.json` snapshot + `meta/object_keys.journal` into
/// the reverse index (`object_id → LogicalKey`), mirroring `Store`'s loader.
///
/// This sidecar carries `object_id → (namespace, name)` plaintext that the store
/// trusts (e.g. as AEAD AAD on decrypt) but which is **not** recoverable from the
/// signed key-index (the SMT is keyed by `LogicalKey.hash()`). The verifier
/// cross-checks the decoded entries against already-verified state (§7, B-1), so
/// this reconstruction is not itself trust-critical: any parse/hex fault fails
/// closed with `SchemaDrift`, mirroring `Store::open`. It lives here (alongside
/// `load_key_index_tree`) to keep the verifier TCB minimal (§17.6). The journal is
/// applied after the snapshot (last write wins per object id), matching the store.
pub fn load_object_keys(store: &Path) -> Result<Vec<([u8; 32], LogicalKey)>, MnemeError> {
    let mut merged: HashMap<[u8; 32], LogicalKey> = HashMap::new();
    let snapshot = store.join("meta/object_keys.json");
    if snapshot.exists() {
        let data = fs::read_to_string(&snapshot).map_err(|e| io_err(&snapshot, e))?;
        let sidecar: ObjectKeysSidecar =
            serde_json::from_str(&data).map_err(|_| MnemeError::SchemaDrift)?;
        for (id_hex, entry) in sidecar.entries {
            merged.insert(
                decode_hex32(&id_hex)?,
                LogicalKey {
                    namespace: entry.namespace,
                    name: entry.name,
                },
            );
        }
    }
    let journal = store.join("meta/object_keys.journal");
    if journal.exists() {
        let data = fs::read_to_string(&journal).map_err(|e| io_err(&journal, e))?;
        for line in data.lines().filter(|l| !l.trim().is_empty()) {
            let entry: ObjectKeysJournalEntry =
                serde_json::from_str(line).map_err(|_| MnemeError::SchemaDrift)?;
            merged.insert(
                decode_hex32(&entry.id)?,
                LogicalKey {
                    namespace: entry.namespace,
                    name: entry.name,
                },
            );
        }
    }
    Ok(merged.into_iter().collect())
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum KeyIndexJournalEntry {
    Upsert { key: String, object: String },
    Tombstone { key: String },
}

/// Replay `meta/key_index.json` + `meta/key_index.journal` under `store` into an SMT.
pub fn load_key_index_tree(store: &Path) -> Result<SparseMerkleTree, MnemeError> {
    let sidecar_path = store.join("meta/key_index.json");
    let mut sidecar = if sidecar_path.exists() {
        let data = fs::read_to_string(&sidecar_path).map_err(|e| io_err(&sidecar_path, e))?;
        serde_json::from_str(&data).map_err(|_| MnemeError::SerializationNonCanonical)?
    } else {
        KeyIndexSidecar::default()
    };
    let journal_path = store.join("meta/key_index.journal");
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

fn io_err(path: &Path, err: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: err.kind().to_string(),
    }
}
