//! Envelope-encrypted file vault (B6) — per-object keys encrypted at rest under a
//! 32-byte master key from `MNEME_KMS_MASTER_KEY_HEX` (e.g. an AWS KMS data key fetched
//! out-of-process by `scripts/kms/dek-from-aws.sh`).
//!
//! Layout matches [`FileKeyVault`] (`keys/vault/` journal + per-id files) but bytes on
//! disk are `nonce24 ‖ AEAD(master, object_key)` — never plaintext keys.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use mneme_core::MnemeError;

use crate::aead::{open, random_nonce, seal};
use crate::types::{KEY_ID_LEN, KeyId, OBJECT_KEY_LEN, ObjectKey};
use crate::vault::{io_error, random_key_id, random_object_key};

const ENVELOPE_AAD: &[u8] = b"mneme-envelope-key-v1";
const WRAPPED_KEY_LEN: usize = XCHACHA_NONCE_LEN + OBJECT_KEY_LEN + 16;
const JOURNAL_RECORD_LEN: usize = KEY_ID_LEN + WRAPPED_KEY_LEN;

use crate::types::XCHACHA_NONCE_LEN;

/// Master-key envelope vault at `store/keys/vault/`.
pub struct EnvelopeKeyVault {
    root: PathBuf,
    master: [u8; 32],
    live: HashMap<KeyId, ObjectKey>,
    shredded: HashSet<KeyId>,
    batch: Option<Vec<(KeyId, ObjectKey)>>,
}

impl EnvelopeKeyVault {
    /// Connect using `MNEME_KMS_MASTER_KEY_HEX` (64 hex chars).
    pub fn from_env(store_root: impl AsRef<Path>) -> Result<Self, MnemeError> {
        let hex = std::env::var("MNEME_KMS_MASTER_KEY_HEX").map_err(|_| MnemeError::IoFailed {
            path: "MNEME_KMS_MASTER_KEY_HEX".into(),
            kind: "unset".into(),
        })?;
        Self::from_master_hex(store_root, hex.trim())
    }

    pub fn from_master_hex(store_root: impl AsRef<Path>, hex: &str) -> Result<Self, MnemeError> {
        let master = parse_master_hex(hex)?;
        Self::from_master(store_root, master)
    }

    pub fn from_master(store_root: impl AsRef<Path>, master: [u8; 32]) -> Result<Self, MnemeError> {
        let root = store_root.as_ref().join("keys").join("vault");
        fs::create_dir_all(&root).map_err(|e| io_error(root.display().to_string(), e))?;
        let (live, shredded) = load_envelope_dir(&root, &master)?;
        Ok(Self {
            root,
            master,
            live,
            shredded,
            batch: None,
        })
    }

    fn key_path(&self, key_id: &KeyId) -> PathBuf {
        self.root.join(crate::vault::hex::encode(key_id))
    }

    fn tombstone_path(&self, key_id: &KeyId) -> PathBuf {
        self.root
            .join(format!("{}.shred", crate::vault::hex::encode(key_id)))
    }

    fn wrap(&self, key: &ObjectKey) -> Result<Vec<u8>, MnemeError> {
        let nonce = random_nonce();
        let ct = seal(&self.master, &nonce, key, ENVELOPE_AAD)?;
        let mut out = Vec::with_capacity(WRAPPED_KEY_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap(&self, bytes: &[u8]) -> Result<ObjectKey, MnemeError> {
        if bytes.len() != WRAPPED_KEY_LEN {
            return Err(MnemeError::KeyVaultCorrupt);
        }
        let nonce = crate::types::nonce_from_slice(&bytes[..XCHACHA_NONCE_LEN])
            .map_err(|_| MnemeError::KeyVaultCorrupt)?;
        let opened = open(
            &self.master,
            &nonce,
            &bytes[XCHACHA_NONCE_LEN..],
            ENVELOPE_AAD,
        )?;
        if opened.len() != OBJECT_KEY_LEN {
            return Err(MnemeError::KeyVaultCorrupt);
        }
        let mut key = [0u8; OBJECT_KEY_LEN];
        key.copy_from_slice(&opened);
        Ok(key)
    }
}

impl crate::vault::KeyVault for EnvelopeKeyVault {
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
                buf.push((key_id, key));
                self.live.insert(key_id, key);
            } else {
                write_wrapped_key(&path, &self.wrap(&key)?)?;
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
            fs::remove_file(&path).map_err(|e| io_error(path.display().to_string(), e))?;
            if crate::vault::durability_fsync_enabled() {
                sync_parent_dir(&path)?;
            }
        }
        if !tombstone.exists() {
            let file = File::create(&tombstone)
                .map_err(|e| io_error(tombstone.display().to_string(), e))?;
            if crate::vault::durability_fsync_enabled() {
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

    fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError> {
        if self.shredded.contains(key_id) || self.tombstone_path(key_id).exists() {
            return Err(MnemeError::Forgotten);
        }
        let path = self.key_path(key_id);
        if !path.exists() {
            write_wrapped_key(&path, &self.wrap(key)?)?;
        }
        self.live.insert(*key_id, *key);
        Ok(())
    }

    fn begin_batch(&mut self) -> Result<(), MnemeError> {
        if self.batch.is_none() {
            self.batch = Some(Vec::new());
        }
        Ok(())
    }

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
        let mut buf = Vec::with_capacity(buffered.len() * JOURNAL_RECORD_LEN);
        for (id, key) in &buffered {
            let wrapped = self.wrap(key)?;
            buf.extend_from_slice(id);
            buf.extend_from_slice(&wrapped);
        }
        file.write_all(&buf)
            .map_err(|e| io_error(journal.display().to_string(), e))?;
        if crate::vault::durability_fsync_enabled() {
            file.sync_all()
                .map_err(|e| io_error(journal.display().to_string(), e))?;
        }
        Ok(())
    }

    fn cancel_batch(&mut self) {
        if let Some(buffered) = self.batch.take() {
            for (id, _) in buffered {
                self.live.remove(&id);
            }
        }
    }
}

fn parse_master_hex(hex: &str) -> Result<[u8; 32], MnemeError> {
    let bytes = ::hex::decode(hex).map_err(|_| MnemeError::KeyVaultCorrupt)?;
    if bytes.len() != 32 {
        return Err(MnemeError::KeyVaultCorrupt);
    }
    let mut master = [0u8; 32];
    master.copy_from_slice(&bytes);
    Ok(master)
}

fn write_wrapped_key(path: &Path, wrapped: &[u8]) -> Result<(), MnemeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_error(parent.display().to_string(), e))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| io_error(path.display().to_string(), e))?;
        f.write_all(wrapped)
            .map_err(|e| io_error(path.display().to_string(), e))?;
        if crate::vault::durability_fsync_enabled() {
            f.sync_all()
                .map_err(|e| io_error(path.display().to_string(), e))?;
        }
    }
    fs::rename(&tmp, path).map_err(|e| io_error(path.display().to_string(), e))?;
    sync_parent_dir(path)?;
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

fn read_wrapped_key(path: &Path) -> Result<Vec<u8>, MnemeError> {
    let bytes = fs::read(path).map_err(|e| io_error(path.display().to_string(), e))?;
    if bytes.len() != WRAPPED_KEY_LEN {
        return Err(MnemeError::KeyVaultCorrupt);
    }
    Ok(bytes)
}

fn load_envelope_dir(
    root: &Path,
    master: &[u8; 32],
) -> Result<(HashMap<KeyId, ObjectKey>, HashSet<KeyId>), MnemeError> {
    let vault = EnvelopeKeyVault {
        root: root.to_path_buf(),
        master: *master,
        live: HashMap::new(),
        shredded: HashSet::new(),
        batch: None,
    };
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
            continue;
        }
        if let Some(stem) = name.strip_suffix(".shred") {
            if let Some(key_id) = crate::vault::hex::decode_key_id(stem) {
                shredded.insert(key_id);
            }
        } else if let Some(key_id) = crate::vault::hex::decode_key_id(name) {
            let wrapped = read_wrapped_key(&entry.path())?;
            let key = vault.unwrap(&wrapped)?;
            live.insert(key_id, key);
        }
    }
    let journal = root.join("vault.journal");
    if journal.exists() {
        let bytes = fs::read(&journal).map_err(|e| io_error(journal.display().to_string(), e))?;
        let full = bytes.len() / JOURNAL_RECORD_LEN;
        for i in 0..full {
            let off = i * JOURNAL_RECORD_LEN;
            let mut key_id = [0u8; KEY_ID_LEN];
            key_id.copy_from_slice(&bytes[off..off + KEY_ID_LEN]);
            let wrapped = &bytes[off + KEY_ID_LEN..off + JOURNAL_RECORD_LEN];
            let key = vault.unwrap(wrapped)?;
            live.insert(key_id, key);
        }
    }
    Ok((live, shredded))
}

impl Drop for EnvelopeKeyVault {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master.zeroize();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::KeyVault;
    use tempfile::tempdir;

    fn vault(dir: &std::path::Path) -> EnvelopeKeyVault {
        let master = [0x42u8; 32];
        EnvelopeKeyVault::from_master(dir, master).unwrap()
    }

    fn reload(dir: &std::path::Path) -> EnvelopeKeyVault {
        let master = [0x42u8; 32];
        EnvelopeKeyVault::from_master(dir, master).unwrap()
    }

    /// ENV-1: new_key → get returns the same object key (AEAD round-trip).
    #[test]
    fn new_key_get_round_trip() {
        let dir = tempdir().unwrap();
        let mut v = vault(dir.path());
        let (key, id) = v.new_key().unwrap();
        let got = v.get(&id).unwrap();
        assert_eq!(key, got, "new_key + get must return the same object key");
    }

    /// ENV-2: shred must return Forgotten (not KeyVaultMissing) on subsequent get.
    #[test]
    fn shred_returns_forgotten_not_missing() {
        let dir = tempdir().unwrap();
        let mut v = vault(dir.path());
        let (_key, id) = v.new_key().unwrap();
        v.shred(&id).unwrap();
        let result = v.get(&id);
        assert_eq!(
            result,
            Err(MnemeError::Forgotten),
            "shredded key must return Forgotten"
        );
    }

    /// ENV-3: a vault opened with a different master key must fail AEAD.
    #[test]
    fn wrong_master_key_fails_aead() {
        let dir = tempdir().unwrap();
        {
            let master = [0x11u8; 32];
            let mut v = EnvelopeKeyVault::from_master(dir.path(), master).unwrap();
            let _ = v.new_key().unwrap();
        }
        // Re-open with a different master — AEAD open() returns ObjectTampered on auth failure.
        let bad_master = [0xFFu8; 32];
        let result = EnvelopeKeyVault::from_master(dir.path(), bad_master);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("wrong master key must fail AEAD authentication"),
        };
        // open() in aead.rs maps chacha20poly1305 auth failure → ObjectTampered.
        assert!(
            matches!(
                err,
                MnemeError::ObjectTampered | MnemeError::KeyVaultCorrupt
            ),
            "wrong master must produce ObjectTampered or KeyVaultCorrupt",
        );
    }

    /// ENV-4: shredded tombstone survives vault reload — subsequent get still returns Forgotten.
    #[test]
    fn shred_persists_across_reload() {
        let dir = tempdir().unwrap();
        let id = {
            let mut v = vault(dir.path());
            let (_key, id) = v.new_key().unwrap();
            v.shred(&id).unwrap();
            id
        };
        let v2 = reload(dir.path());
        assert_eq!(
            v2.get(&id),
            Err(MnemeError::Forgotten),
            "tombstone must survive reload"
        );
    }

    /// ENV-5: batch flush then reload recovers all keys intact.
    #[test]
    fn batch_flush_then_reload_recovers_keys() {
        let dir = tempdir().unwrap();
        let (key_a, id_a, key_b, id_b) = {
            let mut v = vault(dir.path());
            v.begin_batch().unwrap();
            let (ka, ia) = v.new_key().unwrap();
            let (kb, ib) = v.new_key().unwrap();
            v.flush_batch().unwrap();
            (ka, ia, kb, ib)
        };
        let v2 = reload(dir.path());
        assert_eq!(
            v2.get(&id_a).unwrap(),
            key_a,
            "batch key A must survive reload"
        );
        assert_eq!(
            v2.get(&id_b).unwrap(),
            key_b,
            "batch key B must survive reload"
        );
    }

    /// ENV-6: double-shred is idempotent — the second call must still succeed (or return Forgotten).
    #[test]
    fn double_shred_is_idempotent() {
        let dir = tempdir().unwrap();
        let mut v = vault(dir.path());
        let (_key, id) = v.new_key().unwrap();
        v.shred(&id).unwrap();
        // Second shred must not panic or return KeyVaultMissing — tombstone already exists.
        let result = v.shred(&id);
        assert!(
            result.is_ok() || result == Err(MnemeError::Forgotten),
            "double-shred must be idempotent (got error)",
        );
    }

    /// ENV-7: cancel_batch must revoke in-memory keys — cancelled keys must not be readable.
    #[test]
    fn cancel_batch_revokes_keys() {
        let dir = tempdir().unwrap();
        let mut v = vault(dir.path());
        v.begin_batch().unwrap();
        let (_key, id) = v.new_key().unwrap();
        // Key is accessible before cancel.
        assert!(
            v.get(&id).is_ok(),
            "key must be accessible before cancel_batch"
        );
        v.cancel_batch();
        // Key must NOT be accessible after cancel.
        let result = v.get(&id);
        assert!(
            result.is_err(),
            "cancelled batch key must not be accessible: {:?}",
            result.ok(),
        );
        // Reload must also not see the key (it was never flushed to disk).
        let v2 = reload(dir.path());
        assert!(
            v2.get(&id).is_err(),
            "cancelled batch key must not survive reload",
        );
    }
}
