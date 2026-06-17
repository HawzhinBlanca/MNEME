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

/// Field-compare every on-disk checkpoint `roots/<n>.root.cbor` against the
/// verified `head` and against the chain links (INV-4, F-3 completeness).
///
/// `max_signed_checkpoint` only *ignores* an unparseable/unsigned checkpoint
/// (it never trusts one), and `verify_root` only re-checks HEAD's immediate
/// predecessor (`seq-1`). A tampered **non-adjacent** intermediate checkpoint
/// therefore left `verify_store == Ok`. This walk closes that gap: every present
/// checkpoint file must (a) carry a sequence matching its filename, (b) verify
/// under an `operator_keys` member, (c) for the present predecessor link its
/// `prev_root` to checkpoint `n-1`'s preimage hash (or the zero root at `n==1`),
/// (d) never exceed `head.sequence`, and (e) at `head.sequence` be byte-identical
/// (preimage + signature + prev_root) to the verified HEAD. Missing intermediate
/// files are tolerated (sparse fixtures): this re-verifies what exists rather than
/// imposing contiguity, so it never rejects a legitimately-built store.
pub fn verify_checkpoint_chain(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
) -> Result<(), MnemeError> {
    let dir = store.join("roots");
    let read = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let mut by_seq: std::collections::BTreeMap<u64, StoredRoot> = std::collections::BTreeMap::new();
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
        let stored = StoredRoot::from_bytes(&bytes)?;
        if stored.sequence != seq {
            return Err(MnemeError::RootInconsistent);
        }
        if !checkpoint_signature_valid(&stored, operator_keys) {
            return Err(MnemeError::RootSigInvalid);
        }
        if seq > head.sequence {
            return Err(MnemeError::RootReplayed);
        }
        by_seq.insert(seq, stored);
    }
    // F-3: the checkpoint file at HEAD's own sequence MUST be present. Every
    // legitimate commit (`CheckpointLog::commit`) appends `roots/<seq>.root.cbor`
    // *before* it writes HEAD, so a HEAD that points at a sequence with no
    // matching on-disk checkpoint is a truncated / tampered log (the current
    // checkpoint was emptied or deleted) — fail closed rather than trust HEAD
    // alone. When present it is additionally held byte-identical to HEAD below.
    if !by_seq.contains_key(&head.sequence) {
        return Err(MnemeError::RootInconsistent);
    }
    for (&seq, stored) in &by_seq {
        match seq.checked_sub(1) {
            Some(0) | None => {
                if stored.prev_root != [0u8; 32] {
                    return Err(MnemeError::RootInconsistent);
                }
            }
            Some(parent_seq) => {
                if let Some(parent) = by_seq.get(&parent_seq) {
                    if stored.prev_root != parent.preimage_hash {
                        return Err(MnemeError::RootInconsistent);
                    }
                }
            }
        }
        if seq == head.sequence
            && (stored.preimage_hash != head.preimage_hash
                || stored.signature != head.signature
                || stored.prev_root != head.prev_root)
        {
            return Err(MnemeError::RootInconsistent);
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoredRoot;
    use mneme_crypto::KeyPair;
    use std::fs;
    use tempfile::tempdir;

    /// Build a minimal valid checkpoint chain on disk.
    /// Returns the operator KeyPair and the last StoredRoot (HEAD).
    fn build_chain(store: &Path, length: u64) -> (KeyPair, StoredRoot) {
        let op = KeyPair::from_seed([0x42; 32]);
        CheckpointLog::ensure_dir(store).unwrap();
        let dag = [0x01u8; 32];
        let key = [0x02u8; 32];
        let sem = [0x03u8; 32];
        let hlc = [0x01u8; 14];
        let mut prev_hash = [0u8; 32];
        let mut last: Option<StoredRoot> = None;
        for seq in 1..=length {
            let stored = StoredRoot::assemble(dag, key, sem, hlc, prev_hash, seq, &op).unwrap();
            prev_hash = stored.preimage_hash;
            CheckpointLog::commit(store, &stored).unwrap();
            last = Some(stored);
        }
        (op, last.unwrap())
    }

    /// SEC-CKP-1: verify_checkpoint_chain accepts a fully-valid chain.
    #[test]
    fn verify_chain_valid_chain_is_accepted() {
        let dir = tempdir().unwrap();
        let (op, head) = build_chain(dir.path(), 3);
        let keys = vec![op.public_key_bytes()];
        assert!(verify_checkpoint_chain(dir.path(), &keys, &head).is_ok());
    }

    /// SEC-CKP-2: missing HEAD checkpoint file must fail closed —
    /// HEAD must have a corresponding on-disk checkpoint.
    #[test]
    fn verify_chain_missing_head_checkpoint_file_fails_closed() {
        let dir = tempdir().unwrap();
        let (op, head) = build_chain(dir.path(), 2);
        let head_file = dir
            .path()
            .join(format!("roots/{}.root.cbor", head.sequence));
        fs::remove_file(&head_file).unwrap();
        let keys = vec![op.public_key_bytes()];
        let result = verify_checkpoint_chain(dir.path(), &keys, &head);
        assert!(result.is_err(), "missing HEAD checkpoint must fail closed");
        assert_eq!(result.unwrap_err(), MnemeError::RootInconsistent);
    }

    /// SEC-CKP-3: a checkpoint with sequence > HEAD sequence must be rejected (rollback attack).
    #[test]
    fn verify_chain_future_checkpoint_beyond_head_fails_closed() {
        let dir = tempdir().unwrap();
        let (op, head) = build_chain(dir.path(), 2);
        let dag = [0x01u8; 32];
        let key = [0x02u8; 32];
        let sem = [0x03u8; 32];
        let hlc = [0x01u8; 14];
        let future = StoredRoot::assemble(dag, key, sem, hlc, head.preimage_hash, 3, &op).unwrap();
        let future_path = dir.path().join("roots/3.root.cbor");
        fs::write(&future_path, future.to_bytes().unwrap()).unwrap();
        let keys = vec![op.public_key_bytes()];
        let result = verify_checkpoint_chain(dir.path(), &keys, &head);
        assert!(result.is_err(), "checkpoint beyond HEAD must fail closed");
        assert_eq!(result.unwrap_err(), MnemeError::RootReplayed);
    }

    /// SEC-CKP-4: a chain with a tampered prev_root link must fail.
    #[test]
    fn verify_chain_tampered_prev_link_fails_closed() {
        let dir = tempdir().unwrap();
        let (op, _head) = build_chain(dir.path(), 2);
        let dag = [0x0Bu8; 32];
        let key = [0x0Cu8; 32];
        let sem = [0x0Du8; 32];
        let hlc = [0x02u8; 14];
        let bad_prev = [0xBA; 32]; // wrong prev — breaks the chain link
        let bad = StoredRoot::assemble(dag, key, sem, hlc, bad_prev, 2, &op).unwrap();
        let p2 = dir.path().join("roots/2.root.cbor");
        fs::write(&p2, bad.to_bytes().unwrap()).unwrap();
        // Update HEAD to the tampered seq=2 so missing-HEAD doesn't fire first.
        let head_p = dir.path().join("roots/HEAD");
        fs::write(&head_p, bad.to_bytes().unwrap()).unwrap();
        let keys = vec![op.public_key_bytes()];
        let result = verify_checkpoint_chain(dir.path(), &keys, &bad);
        assert!(result.is_err(), "tampered prev_root link must fail closed");
    }

    /// SEC-CKP-5: a chain with one gap (seq=2 missing) is tolerated.
    #[test]
    fn verify_chain_sparse_chain_with_gap_is_tolerated() {
        let dir = tempdir().unwrap();
        let (op, head) = build_chain(dir.path(), 3);
        fs::remove_file(dir.path().join("roots/2.root.cbor")).unwrap();
        let keys = vec![op.public_key_bytes()];
        assert!(
            verify_checkpoint_chain(dir.path(), &keys, &head).is_ok(),
            "sparse chains with gaps should be tolerated"
        );
    }

    /// SEC-CKP-6: signature byte corruption in a checkpoint file must fail closed.
    #[test]
    fn verify_chain_signature_corruption_fails_closed() {
        let dir = tempdir().unwrap();
        let (op, head) = build_chain(dir.path(), 2);
        // Read the sequence-2 checkpoint file and flip a byte in the signature.
        let p2 = dir.path().join("roots/2.root.cbor");
        let mut raw = fs::read(&p2).unwrap();
        // Flip the very last byte — signatures are at the tail of CBOR encoding.
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        fs::write(&p2, &raw).unwrap();
        let keys = vec![op.public_key_bytes()];
        let result = verify_checkpoint_chain(dir.path(), &keys, &head);
        assert!(
            result.is_err(),
            "corrupted checkpoint signature must fail closed"
        );
    }
}
