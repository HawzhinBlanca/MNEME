//! Append-only checkpoint log and atomic HEAD pointer (§5.7, §5.8).

use crate::StoredRoot;
use crate::atomic;
use mneme_core::MnemeError;
use mneme_crypto::{public_key_from_bytes, verify_signature_bytes};
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

/// Highest validly-signed checkpoint in the append-only log (`roots/<seq>.root.cbor`),
/// returned as `(sequence, hlc_max)`. Cold-open A-REPLAY / INV-6 defense: a HEAD whose
/// sequence is below an on-disk signed checkpoint is a rollback, and the returned
/// `hlc_max` is the monotonic floor a verifier must pin into `last_seen_hlc`.
///
/// Only checkpoints whose preimage hashes and whose Ed25519 signature verify under an
/// `operator_keys` member count as evidence, so an A-DB adversary cannot fabricate a
/// bogus higher checkpoint (no operator key) to deny service; unparseable / unsigned
/// stray files are ignored rather than trusted.
pub fn max_signed_checkpoint(
    store: &Path,
    operator_keys: &[[u8; 32]],
) -> Result<Option<(u64, [u8; 14])>, MnemeError> {
    let dir = store.join("roots");
    let read = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let mut best: Option<(u64, [u8; 14])> = None;
    for entry in read {
        let path = entry.map_err(|e| io_err(&dir, e))?.path();
        let seq = match path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".root.cbor"))
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(s) => s,
            None => continue,
        };
        let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
        let stored = match StoredRoot::from_bytes(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if stored.sequence == seq
            && checkpoint_signature_valid(&stored, operator_keys)
            && best.map(|(b, _)| seq > b).unwrap_or(true)
        {
            best = Some((seq, stored.hlc_max));
        }
    }
    Ok(best)
}

fn checkpoint_signature_valid(stored: &StoredRoot, operator_keys: &[[u8; 32]]) -> bool {
    if stored.preimage().hash() != stored.preimage_hash {
        return false;
    }
    operator_keys.iter().any(|pk| {
        public_key_from_bytes(pk)
            .and_then(|k| verify_signature_bytes(&k, &stored.preimage_hash, &stored.signature))
            .is_ok()
    })
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
