//! Offline repair: clear a self-consistent `.incomplete` marker and sweep orphan blobs.

use crate::atomic::{entry_exists, incomplete_marker};
use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, TrustConfig};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Report from [`repair_store`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    pub cleared_incomplete: bool,
    pub orphans_removed: usize,
}

/// Re-validate on-disk state against HEAD, clear `.incomplete` only when consistent,
/// then remove object blobs not referenced by the live key-index / object-keys maps.
pub fn repair_store(path: &Path, operator: &KeyPair) -> Result<RepairReport, MnemeError> {
    let trust = TrustConfig::new(operator.public_key_bytes());
    let incomplete = incomplete_marker(path);
    let had_incomplete = entry_exists(&incomplete)?;
    if had_incomplete {
        let backup = path.join(".incomplete.repair-check");
        fs::rename(&incomplete, &backup).map_err(|e| io_err(&incomplete, e))?;
        match mneme_verify::verify_store(path, &trust) {
            Ok(_) => {
                fs::remove_file(&backup).map_err(|e| io_err(&backup, e))?;
            }
            Err(err) => {
                let _ = fs::rename(&backup, &incomplete);
                return Err(err);
            }
        }
    } else {
        mneme_verify::verify_store(path, &trust)?;
    }
    let orphans_removed = sweep_orphan_objects(path)?;
    Ok(RepairReport {
        cleared_incomplete: had_incomplete,
        orphans_removed,
    })
}

fn sweep_orphan_objects(path: &Path) -> Result<usize, MnemeError> {
    let referenced = referenced_object_ids(path)?;
    let mut removed = 0usize;
    for blob in list_object_blobs(path)? {
        let id = blob.object_id;
        if referenced.contains(&id) {
            continue;
        }
        fs::remove_file(&blob.path).map_err(|e| io_err(&blob.path, e))?;
        removed += 1;
    }
    Ok(removed)
}

struct ObjectBlob {
    path: PathBuf,
    object_id: [u8; 32],
}

fn referenced_object_ids(path: &Path) -> Result<HashSet<[u8; 32]>, MnemeError> {
    let mut ids = HashSet::new();
    for (id, _) in mneme_index::load_object_keys(path)? {
        ids.insert(id);
    }
    Ok(ids)
}

fn list_object_blobs(path: &Path) -> Result<Vec<ObjectBlob>, MnemeError> {
    let objects_dir = path.join("objects");
    if !objects_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    collect_object_blobs(&objects_dir, &mut out)?;
    Ok(out)
}

fn collect_object_blobs(dir: &Path, out: &mut Vec<ObjectBlob>) -> Result<(), MnemeError> {
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_object_blobs(&path, out)?;
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !file_name.ends_with(".cbor") {
            continue;
        }
        let stem = file_name.trim_end_matches(".cbor");
        if stem.len() != 64 {
            continue;
        }
        let mut id = [0u8; 32];
        hex::decode_to_slice(stem, &mut id).map_err(|_| MnemeError::SchemaDrift)?;
        out.push(ObjectBlob {
            path,
            object_id: id,
        });
    }
    Ok(())
}

fn io_err(path: &Path, e: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use mneme_cap::agent_cap;
    use mneme_core::{Draft, MemoryKind};
    use tempfile::TempDir;

    #[test]
    fn repair_clears_self_consistent_incomplete_marker() {
        let dir = TempDir::new().expect("tempdir");
        let operator = KeyPair::generate();
        let mut store = Store::create(dir.path(), operator.clone()).expect("create");
        let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
        let draft = Draft {
            namespace: "repair".into(),
            logical_name: "entry".into(),
            kind: MemoryKind::Episodic,
            body: b"payload".to_vec(),
            parent_ids: vec![],
            session: [0x01; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        store.remember(draft, &cap).expect("remember");
        drop(store);
        crate::atomic::begin_incomplete(dir.path()).expect("marker");
        let report = repair_store(dir.path(), &operator).expect("repair");
        assert!(report.cleared_incomplete);
        assert!(!incomplete_marker(dir.path()).exists());
        Store::open(dir.path(), operator).expect("reopen");
    }

    #[cfg(unix)]
    #[test]
    fn repair_clears_self_consistent_dangling_symlink_incomplete_marker() {
        let dir = TempDir::new().expect("tempdir");
        let operator = KeyPair::generate();
        let mut store = Store::create(dir.path(), operator.clone()).expect("create");
        let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
        let draft = Draft {
            namespace: "repair".into(),
            logical_name: "dangling-entry".into(),
            kind: MemoryKind::Episodic,
            body: b"payload".to_vec(),
            parent_ids: vec![],
            session: [0x02; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        store.remember(draft, &cap).expect("remember");
        drop(store);

        let missing = dir.path().join("missing-incomplete-marker");
        let marker = incomplete_marker(dir.path());
        std::os::unix::fs::symlink(&missing, &marker).expect("dangling marker symlink");
        assert!(!marker.exists(), "fixture should be a dangling symlink");

        let report = repair_store(dir.path(), &operator).expect("repair");
        assert!(report.cleared_incomplete);
        assert!(
            std::fs::symlink_metadata(&marker).is_err(),
            "repair should remove the marker symlink entry"
        );
        assert!(
            std::fs::symlink_metadata(dir.path().join(".incomplete.repair-check")).is_err(),
            "repair backup entry should be removed after consistency proof"
        );
        assert!(
            !missing.exists(),
            "repair must not materialize a dangling marker target"
        );
        Store::open(dir.path(), operator).expect("reopen");
    }
}
