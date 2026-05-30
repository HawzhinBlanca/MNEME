//! Append-only checkpoint log and atomic HEAD pointer (§5.7, §5.8).

use crate::StoredRoot;
use crate::atomic;
use mneme_core::MnemeError;
use std::fs;
use std::path::{Path, PathBuf};

/// On-disk checkpoint log under `store/roots/`.
pub struct CheckpointLog;

impl CheckpointLog {
    pub fn ensure_dir(store: &Path) -> Result<(), MnemeError> {
        fs::create_dir_all(store.join("roots")).map_err(|e| io_err(&store.join("roots"), e))
    }

    /// Append-only: create-new `roots/<seq>.root.cbor`.
    pub fn append(store: &Path, root: &StoredRoot) -> Result<(), MnemeError> {
        let file = checkpoint_path(store, root.sequence);
        atomic::create_new(&file, &root.to_bytes()?)
    }

    /// Atomic rename write of `roots/HEAD`.
    pub fn write_head(store: &Path, root: &StoredRoot) -> Result<(), MnemeError> {
        atomic::atomic_write(&head_path(store), &root.to_bytes()?)
    }

    pub fn read_head(store: &Path) -> Result<StoredRoot, MnemeError> {
        let path = head_path(store);
        let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
        StoredRoot::from_bytes(&bytes)
    }

    pub fn read_checkpoint(store: &Path, sequence: u64) -> Result<StoredRoot, MnemeError> {
        let path = checkpoint_path(store, sequence);
        let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
        StoredRoot::from_bytes(&bytes)
    }

    /// Persist checkpoint then atomically update HEAD (store commit order).
    pub fn commit(store: &Path, root: &StoredRoot) -> Result<(), MnemeError> {
        Self::append(store, root)?;
        Self::write_head(store, root)
    }
}

fn head_path(store: &Path) -> PathBuf {
    store.join("roots/HEAD")
}

fn checkpoint_path(store: &Path, sequence: u64) -> PathBuf {
    store.join(format!("roots/{sequence}.root.cbor"))
}

fn io_err(path: &Path, e: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    }
}
