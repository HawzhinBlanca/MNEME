use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use mneme_core::MnemeError;
use zeroize::Zeroize;

use crate::types::{KEY_ID_LEN, KeyId, OBJECT_KEY_LEN, ObjectKey};

pub(crate) fn durability_fsync_enabled() -> bool {
    !debug_no_fsync_requested()
}

#[cfg(debug_assertions)]
fn debug_no_fsync_requested() -> bool {
    std::env::var_os("MNEME_NO_FSYNC").is_some()
}

#[cfg(not(debug_assertions))]
fn debug_no_fsync_requested() -> bool {
    false
}

/// Per-object key vault (blueprint §5.8 `keys/vault/`).
///
/// This is the HSM/KMS pluggability seam (B6): the store kernel holds a
/// `Box<dyn KeyVault + Send>` and never names a concrete vault, so a future
/// AWS KMS / GCP KMS / PKCS#11 adapter only has to implement this trait — no
/// kernel change. The trait lives **outside the verifier TCB**: a vault decides
/// only whether per-object payload *decryption keys* are available, never whether
/// a recall verifies against the signed root. See `docs/HSM_KMS_ADAPTER.md`.
pub trait KeyVault {
    /// Generate a fresh per-object key and return it with its `KeyId`.
    fn new_key(&mut self) -> Result<(ObjectKey, KeyId), MnemeError>;
    /// Fetch a live key by id. Returns [`MnemeError::Forgotten`] for a shredded id
    /// and [`MnemeError::KeyVaultMissing`] for one that was never stored.
    fn get(&self, key_id: &KeyId) -> Result<ObjectKey, MnemeError>;
    /// Crypto-shred a key (irreversible). Subsequent `get` must return `Forgotten`.
    fn shred(&mut self, key_id: &KeyId) -> Result<(), MnemeError>;
    /// True iff a live (non-shredded) key with this id is held.
    fn contains(&self, key_id: &KeyId) -> bool;

    /// Import externally-supplied key material (anti-entropy merge / B4 sealed
    /// bundle). Idempotent. Must reject re-import of a shredded id with
    /// [`MnemeError::Forgotten`] to stay fail-closed. An adapter whose backend
    /// cannot accept raw key bytes (e.g. an HSM with non-extractable keys) should
    /// return an error rather than silently succeed — a silent success would let a
    /// merge believe a key arrived when it did not.
    fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError>;

    /// Begin a batched-write window: an implementation MAY buffer `new_key` writes
    /// until [`Self::flush_batch`] for group-commit durability. The default is a
    /// no-op for vaults that write eagerly (every `new_key` is already durable).
    /// Must be idempotent.
    fn begin_batch(&mut self) -> Result<(), MnemeError> {
        Ok(())
    }

    /// Flush all buffered writes durably and end the batch window. Default no-op
    /// (an eager vault has nothing buffered).
    fn flush_batch(&mut self) -> Result<(), MnemeError> {
        Ok(())
    }

    /// Abort a batch window, discarding buffered (un-flushed) writes. Called on
    /// transaction rollback so discarded keys belong to objects being thrown away.
    /// Default no-op.
    fn cancel_batch(&mut self) {}
}

/// In-memory vault for tests and ephemeral stores.
#[derive(Clone, Debug, Default)]
pub struct MemoryKeyVault {
    keys: HashMap<KeyId, ObjectKey>,
    shredded: HashMap<KeyId, ()>,
}

impl MemoryKeyVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyVault for MemoryKeyVault {
    fn new_key(&mut self) -> Result<(ObjectKey, KeyId), MnemeError> {
        let (key, key_id) = generate_unique_key_id(&self.keys, &self.shredded)?;
        self.keys.insert(key_id, key);
        Ok((key, key_id))
    }

    fn get(&self, key_id: &KeyId) -> Result<ObjectKey, MnemeError> {
        if self.shredded.contains_key(key_id) {
            return Err(MnemeError::Forgotten);
        }
        self.keys
            .get(key_id)
            .copied()
            .ok_or(MnemeError::KeyVaultMissing)
    }

    fn shred(&mut self, key_id: &KeyId) -> Result<(), MnemeError> {
        if !self.keys.contains_key(key_id) && !self.shredded.contains_key(key_id) {
            return Err(MnemeError::KeyVaultMissing);
        }
        if let Some(mut key) = self.keys.remove(key_id) {
            key.zeroize();
        }
        self.shredded.insert(*key_id, ());
        Ok(())
    }

    fn contains(&self, key_id: &KeyId) -> bool {
        self.keys.contains_key(key_id) && !self.shredded.contains_key(key_id)
    }

    fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError> {
        if self.shredded.contains_key(key_id) {
            return Err(MnemeError::Forgotten);
        }
        self.keys.entry(*key_id).or_insert(*key);
        Ok(())
    }

    // begin_batch / flush_batch / cancel_batch use the trait no-op defaults: an
    // in-memory vault writes eagerly, so there is nothing to buffer or fsync.
}

/// File-backed vault rooted at `store/keys/vault/`.
///
/// A process-lifetime in-memory key cache (`live` + `shredded`) is loaded once on
/// open and kept authoritative by every mutating method. This removes the
/// per-`get` filesystem `stat`+`open`+`read` that dominated the verified-recall
/// p99 tail (§22 K2): the flat `keys/vault/` directory grows with the store, so a
/// per-recall disk lookup developed a heavy tail past ~10k entries. The cache is
/// fail-closed — a shredded key is evicted from `live` and recorded in `shredded`,
/// so `get` returns `Forgotten`/`KeyVaultMissing` without ever serving stale bytes
/// the running session did not author, and durability is unchanged (key files and
/// `.shred` tombstones are still written/fsynced to disk).
pub struct FileKeyVault {
    root: PathBuf,
    live: HashMap<KeyId, ObjectKey>,
    shredded: HashSet<KeyId>,
    /// When `Some`, `new_key` buffers `(id, key)` records here instead of writing +
    /// fsyncing one file each. `flush_batch` appends them all to `vault.journal` with
    /// a SINGLE fsync — the §22 durable group-commit win (per-key fsync was ~98% of
    /// ingest cost). Buffered keys are still inserted into `live` immediately so
    /// `get` works mid-batch; durability arrives at `flush_batch`, which the store
    /// calls inside the same `.incomplete`-guarded transaction (crash before flush →
    /// transaction aborts → the buffered keys were never committed, so losing them
    /// is harmless). Vault layout is invisible to the signed root, so this changes
    /// no determinism digest.
    batch: Option<Vec<(KeyId, ObjectKey)>>,
}

impl FileKeyVault {
    pub fn new(store_root: impl AsRef<Path>) -> Result<Self, MnemeError> {
        let root = store_root.as_ref().join("keys").join("vault");
        fs::create_dir_all(&root).map_err(|e| io_error(root.display().to_string(), e))?;
        let (live, shredded) = load_vault_dir(&root)?;
        Ok(Self {
            root,
            live,
            shredded,
            batch: None,
        })
    }

    fn key_path(&self, key_id: &KeyId) -> PathBuf {
        self.root.join(hex::encode(key_id))
    }

    fn tombstone_path(&self, key_id: &KeyId) -> PathBuf {
        self.root.join(format!("{}.shred", hex::encode(key_id)))
    }
}

impl KeyVault for FileKeyVault {
    fn new_key(&mut self) -> Result<(ObjectKey, KeyId), MnemeError> {
        loop {
            let key = random_object_key();
            let key_id = random_key_id();
            if self.live.contains_key(&key_id) || self.shredded.contains(&key_id) {
                continue;
            }
            let path = self.key_path(&key_id);
            if path.exists() || self.tombstone_path(&key_id).exists() {
                continue;
            }
            if let Some(buf) = self.batch.as_mut() {
                // Batched: buffer for the single journal fsync at flush_batch; insert
                // into `live` now so mid-batch `get`/recall works.
                buf.push((key_id, key));
                self.live.insert(key_id, key);
            } else {
                write_key_file(&path, &key)?;
                self.live.insert(key_id, key);
            }
            return Ok((key, key_id));
        }
    }

    fn get(&self, key_id: &KeyId) -> Result<ObjectKey, MnemeError> {
        if self.shredded.contains(key_id) {
            return Err(MnemeError::Forgotten);
        }
        self.live
            .get(key_id)
            .copied()
            .ok_or(MnemeError::KeyVaultMissing)
    }

    fn shred(&mut self, key_id: &KeyId) -> Result<(), MnemeError> {
        let path = self.key_path(key_id);
        let tombstone = self.tombstone_path(key_id);
        let known = self.live.contains_key(key_id) || self.shredded.contains(key_id);
        if !known && !path.exists() && !tombstone.exists() {
            return Err(MnemeError::KeyVaultMissing);
        }
        if path.exists() {
            secure_delete(&path)?;
        }
        if !tombstone.exists() {
            let file = File::create(&tombstone)
                .map_err(|e| io_error(tombstone.display().to_string(), e))?;
            if durability_fsync_enabled() {
                file.sync_all()
                    .map_err(|e| io_error(tombstone.display().to_string(), e))?;
                sync_parent_dir(&tombstone)?;
            }
        }
        self.live.remove(key_id);
        self.shredded.insert(*key_id);
        Ok(())
    }

    fn contains(&self, key_id: &KeyId) -> bool {
        self.live.contains_key(key_id) && !self.shredded.contains(key_id)
    }

    /// Import peer key material for objects accepted by anti-entropy merge.
    fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError> {
        if self.shredded.contains(key_id) || self.tombstone_path(key_id).exists() {
            return Err(MnemeError::Forgotten);
        }
        let path = self.key_path(key_id);
        if !path.exists() {
            write_key_file(&path, key)?;
        }
        self.live.insert(*key_id, *key);
        Ok(())
    }

    /// Begin a batched-write window: subsequent `new_key`s buffer in memory until
    /// [`Self::flush_batch`]. Idempotent.
    fn begin_batch(&mut self) -> Result<(), MnemeError> {
        if self.batch.is_none() {
            self.batch = Some(Vec::new());
        }
        Ok(())
    }

    /// Persist all buffered keys to the append-only `vault.journal` with a single
    /// fsync, then end the batch window. No-op if not batching.
    fn flush_batch(&mut self) -> Result<(), MnemeError> {
        let Some(buffered) = self.batch.take() else {
            return Ok(());
        };
        if buffered.is_empty() {
            return Ok(());
        }
        let journal = self.root.join("vault.journal");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal)
            .map_err(|e| io_error(journal.display().to_string(), e))?;
        // Each record is fixed-width KEY_ID_LEN ‖ OBJECT_KEY_LEN so replay needs no
        // delimiter parsing; a torn final record (crash mid-write) is ignored on load.
        let mut buf = Vec::with_capacity(buffered.len() * (KEY_ID_LEN + OBJECT_KEY_LEN));
        for (id, key) in &buffered {
            buf.extend_from_slice(id);
            buf.extend_from_slice(key);
        }
        file.write_all(&buf)
            .map_err(|e| io_error(journal.display().to_string(), e))?;
        if durability_fsync_enabled() {
            file.sync_all()
                .map_err(|e| io_error(journal.display().to_string(), e))?;
        }
        Ok(())
    }

    /// Abort a batch window: drop buffered (un-journaled) keys from `live` and end
    /// the batch. Called on transaction rollback — those keys were never durable and
    /// belong to objects the transaction is discarding. No-op if not batching.
    fn cancel_batch(&mut self) {
        if let Some(buffered) = self.batch.take() {
            for (id, _) in buffered {
                self.live.remove(&id);
            }
        }
    }
}

impl Drop for FileKeyVault {
    fn drop(&mut self) {
        for val in self.live.values_mut() {
            val.zeroize();
        }
        if let Some(buf) = self.batch.as_mut() {
            for (_, val) in buf {
                val.zeroize();
            }
        }
    }
}

/// Load the live keys and shred tombstones from `keys/vault/` once on open.
fn load_vault_dir(root: &Path) -> Result<(HashMap<KeyId, ObjectKey>, HashSet<KeyId>), MnemeError> {
    let mut live = HashMap::new();
    let mut shredded = HashSet::new();
    let rd = match fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((live, shredded)),
        Err(e) => return Err(io_error(root.display().to_string(), e)),
    };
    for entry in rd {
        let entry = entry.map_err(|e| io_error(root.display().to_string(), e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == "vault.journal" {
            continue; // replayed below, after per-file keys
        }
        if let Some(stem) = name.strip_suffix(".shred") {
            if let Some(key_id) = hex::decode_key_id(stem) {
                shredded.insert(key_id);
            }
        } else if let Some(key_id) = hex::decode_key_id(name) {
            let key = read_key_file(&entry.path())?;
            live.insert(key_id, key);
        }
    }
    // Replay the batched-key journal (fixed-width KEY_ID_LEN ‖ OBJECT_KEY_LEN records).
    // A torn trailing record from a crash mid-append is silently ignored — those keys
    // belong to an aborted (`.incomplete`) transaction and were never committed.
    let journal = root.join("vault.journal");
    if journal.exists() {
        let data = fs::read(&journal).map_err(|e| io_error(journal.display().to_string(), e))?;
        let rec = KEY_ID_LEN + OBJECT_KEY_LEN;
        for chunk in data.chunks_exact(rec) {
            let mut key_id = [0u8; KEY_ID_LEN];
            key_id.copy_from_slice(&chunk[..KEY_ID_LEN]);
            let mut key = [0u8; OBJECT_KEY_LEN];
            key.copy_from_slice(&chunk[KEY_ID_LEN..]);
            live.insert(key_id, key);
        }
    }
    // A shredded key never coexists with live material; tombstones win fail-closed.
    for id in &shredded {
        live.remove(id);
    }
    Ok((live, shredded))
}

fn generate_unique_key_id(
    live: &HashMap<KeyId, ObjectKey>,
    shredded: &HashMap<KeyId, ()>,
) -> Result<(ObjectKey, KeyId), MnemeError> {
    loop {
        let key = random_object_key();
        let key_id = random_key_id();
        if !live.contains_key(&key_id) && !shredded.contains_key(&key_id) {
            return Ok((key, key_id));
        }
    }
}

pub(crate) fn random_object_key() -> ObjectKey {
    let mut key = [0u8; OBJECT_KEY_LEN];
    crate::deterministic::fill_random("vault-object-key", &mut key);
    key
}

pub(crate) fn random_key_id() -> KeyId {
    let mut id = [0u8; KEY_ID_LEN];
    crate::deterministic::fill_random("vault-key-id", &mut id);
    id
}

fn write_key_file(path: &Path, key: &ObjectKey) -> Result<(), MnemeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io_error(path.display().to_string(), e))?;
    file.write_all(key)
        .map_err(|e| io_error(path.display().to_string(), e))?;
    // Debug/test builds honor the same `MNEME_NO_FSYNC` test knob as the store's
    // atomic writer and journals; release builds always fsync.
    if durability_fsync_enabled() {
        file.sync_all()
            .map_err(|e| io_error(path.display().to_string(), e))?;
        sync_parent_dir(path)?;
    }
    Ok(())
}

fn read_key_file(path: &Path) -> Result<ObjectKey, MnemeError> {
    let mut file = File::open(path).map_err(|e| io_error(path.display().to_string(), e))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| io_error(path.display().to_string(), e))?;
    buf.try_into().map_err(|_| MnemeError::KeyVaultCorrupt)
}

fn secure_delete(path: &Path) -> Result<(), MnemeError> {
    let meta = fs::metadata(path).map_err(|e| io_error(path.display().to_string(), e))?;
    let len = meta.len();
    if len > 0 {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| io_error(path.display().to_string(), e))?;
        let zeros = vec![0u8; len.min(4096) as usize];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..chunk])
                .map_err(|e| io_error(path.display().to_string(), e))?;
            remaining -= chunk as u64;
        }
        file.sync_all()
            .map_err(|e| io_error(path.display().to_string(), e))?;
    }
    fs::remove_file(path).map_err(|e| io_error(path.display().to_string(), e))?;
    if durability_fsync_enabled() {
        sync_parent_dir(path)?;
    }
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<(), MnemeError> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(());
            }
            let dir = File::open(parent).map_err(|e| io_error(parent.display().to_string(), e))?;
            dir.sync_all()
                .map_err(|e| io_error(parent.display().to_string(), e))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub(crate) fn io_error(path: String, err: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path,
        kind: format!("{:?}", err.kind()),
    }
}

pub(crate) mod hex {
    use crate::types::{KEY_ID_LEN, KeyId};

    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Decode a vault filename stem into a `KeyId`, or `None` for unrelated files.
    pub fn decode_key_id(s: &str) -> Option<KeyId> {
        if s.len() != KEY_ID_LEN * 2 {
            return None;
        }
        let mut out = [0u8; KEY_ID_LEN];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    fn production_source(source: &str) -> &str {
        source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _tests)| production)
    }

    #[test]
    fn no_fsync_escape_hatch_is_debug_only_and_centralized() {
        let vault = production_source(include_str!("vault.rs"));
        let envelope = production_source(include_str!("envelope_vault.rs"));
        let combined = [vault, envelope].join("\n");

        assert!(
            vault.contains("fn durability_fsync_enabled("),
            "vault fsync decisions must route through a named helper"
        );
        assert!(
            vault.contains("#[cfg(debug_assertions)]"),
            "MNEME_NO_FSYNC may only be read in debug builds"
        );
        assert!(
            vault.contains("#[cfg(not(debug_assertions))]"),
            "release builds must compile an env-independent fsync path"
        );
        assert_eq!(
            combined
                .matches("std::env::var(\"MNEME_NO_FSYNC\")")
                .count(),
            0,
            "vault write paths must not read MNEME_NO_FSYNC directly"
        );
        assert_eq!(
            combined
                .matches("std::env::var_os(\"MNEME_NO_FSYNC\")")
                .count(),
            1,
            "only the debug-only helper may inspect MNEME_NO_FSYNC"
        );
    }
}
