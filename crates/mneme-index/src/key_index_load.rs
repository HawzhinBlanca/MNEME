//! Reconstruct the key-index SMT from the on-disk sidecar + append-only journal.
//!
//! This reconstruction is **not** trust-critical: the verifier compares the
//! resulting SMT root against the operator-signed `key_index_root`, so a faulty
//! or tampered reconstruction fails closed (`RootInconsistent`) instead of
//! admitting forged state. It lives here (the key-index owner) to keep the
//! verifier TCB minimal (§17.6) and to avoid duplicating the sidecar/journal
//! format across crates. Error types are preserved verbatim for the tamper suite.

use mneme_core::{MnemeError, decode_hex32};
use mneme_smt::SparseMerkleTree;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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
