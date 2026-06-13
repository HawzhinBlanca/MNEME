//! Envelope-encrypted file vault (B6) — per-object keys encrypted at rest under a
//! 32-byte master key from `MNEME_KMS_MASTER_KEY_HEX` (e.g. an AWS KMS data key fetched
//! out-of-process by `scripts/kms/dek-from-aws.sh`).
//!
//! Layout matches [`FileKeyVault`] (`keys/vault/` journal + per-id files) but bytes on
//! disk are `nonce24 ‖ AEAD(master, object_key)` — never plaintext keys.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use mneme_core::MnemeError;

use crate::aead::{open, random_nonce, seal};
use crate::types::{KEY_ID_LEN, KeyId, OBJECT_KEY_LEN, ObjectKey};
use crate::vault::{
    SecretFileMode, VaultLayoutIdentity, capture_vault_layout_identity, ensure_vault_root_dir,
    entry_exists, io_error, open_append_single_link, random_key_id, random_object_key,
    read_single_link_file, sync_parent_dir, validate_single_link_file,
    validate_vault_layout_identity, write_new_secret_file,
};

const ENVELOPE_AAD: &[u8] = b"mneme-envelope-key-v1";
const WRAPPED_KEY_LEN: usize = XCHACHA_NONCE_LEN + OBJECT_KEY_LEN + 16;
const JOURNAL_RECORD_LEN: usize = KEY_ID_LEN + WRAPPED_KEY_LEN;

use crate::types::XCHACHA_NONCE_LEN;

/// Master-key envelope vault at `store/keys/vault/`.
pub struct EnvelopeKeyVault {
    root: PathBuf,
    layout_identity: VaultLayoutIdentity,
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
        let store_root = store_root.as_ref();
        let root = store_root.join("keys").join("vault");
        ensure_vault_root_dir(store_root, &root)?;
        let layout_identity = capture_vault_layout_identity(store_root, &root)?;
        let (live, shredded) = load_envelope_dir(&root, &master)?;
        validate_vault_layout_identity(&layout_identity)?;
        Ok(Self {
            root,
            layout_identity,
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
        unwrap_wrapped_key(&self.master, bytes)
    }

    fn validate_root_dir(&self) -> Result<(), MnemeError> {
        validate_vault_layout_identity(&self.layout_identity)
    }
}

impl crate::vault::KeyVault for EnvelopeKeyVault {
    fn new_key(&mut self) -> Result<(ObjectKey, KeyId), MnemeError> {
        self.validate_root_dir()?;
        loop {
            let key = random_object_key();
            let key_id = random_key_id();
            if self.live.contains_key(&key_id) || self.shredded.contains(&key_id) {
                continue;
            }
            let path = self.key_path(&key_id);
            if entry_exists(&path)? || entry_exists(&self.tombstone_path(&key_id))? {
                continue;
            }
            if let Some(buf) = self.batch.as_mut() {
                buf.push((key_id, key));
                self.live.insert(key_id, key);
            } else {
                self.validate_root_dir()?;
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
        self.validate_root_dir()?;
        let path = self.key_path(key_id);
        let tombstone = self.tombstone_path(key_id);
        let known = self.live.contains_key(key_id) || self.shredded.contains(key_id);
        let path_exists = entry_exists(&path)?;
        let tombstone_exists = entry_exists(&tombstone)?;
        if !known && !path_exists && !tombstone_exists {
            return Err(MnemeError::KeyVaultMissing);
        }
        if path_exists {
            self.validate_root_dir()?;
            validate_single_link_file(&path)?;
            fs::remove_file(&path).map_err(|e| io_error(path.display().to_string(), e))?;
            if crate::vault::durability_fsync_enabled() {
                sync_parent_dir(&path)?;
            }
        }
        if tombstone_exists {
            validate_single_link_file(&tombstone)?;
        } else {
            self.validate_root_dir()?;
            write_new_secret_file(&tombstone, b"", SecretFileMode::Default)?;
        }
        self.live.remove(key_id);
        self.shredded.insert(*key_id);
        Ok(())
    }

    fn contains(&self, key_id: &KeyId) -> bool {
        self.live.contains_key(key_id) && !self.shredded.contains(key_id)
    }

    fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError> {
        self.validate_root_dir()?;
        let tombstone = self.tombstone_path(key_id);
        if self.shredded.contains(key_id) {
            return Err(MnemeError::Forgotten);
        }
        if entry_exists(&tombstone)? {
            validate_single_link_file(&tombstone)?;
            return Err(MnemeError::Forgotten);
        }
        if let Some(existing) = self.live.get(key_id) {
            if existing != key {
                return Err(MnemeError::KeyVaultCorrupt);
            }
        }
        let path = self.key_path(key_id);
        if entry_exists(&path)? {
            let existing = self.unwrap(&read_wrapped_key(&path)?)?;
            if existing != *key {
                return Err(MnemeError::KeyVaultCorrupt);
            }
        } else {
            self.validate_root_dir()?;
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
        let Some(buffered) = self.batch.as_ref() else {
            return Ok(());
        };
        if buffered.is_empty() {
            self.batch = None;
            return Ok(());
        }
        self.validate_root_dir()?;
        let journal = self.root.join("vault.journal");
        let mut file = open_append_single_link(&journal)?;
        let mut buf = Vec::with_capacity(buffered.len() * JOURNAL_RECORD_LEN);
        for (id, key) in buffered {
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
        self.batch = None;
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
    write_new_secret_file(path, wrapped, SecretFileMode::OwnerOnly)
}

fn read_wrapped_key(path: &Path) -> Result<Vec<u8>, MnemeError> {
    let bytes = read_single_link_file(path)?;
    if bytes.len() != WRAPPED_KEY_LEN {
        return Err(MnemeError::KeyVaultCorrupt);
    }
    Ok(bytes)
}

fn unwrap_wrapped_key(master: &[u8; 32], bytes: &[u8]) -> Result<ObjectKey, MnemeError> {
    if bytes.len() != WRAPPED_KEY_LEN {
        return Err(MnemeError::KeyVaultCorrupt);
    }
    let nonce = crate::types::nonce_from_slice(&bytes[..XCHACHA_NONCE_LEN])
        .map_err(|_| MnemeError::KeyVaultCorrupt)?;
    let opened = open(master, &nonce, &bytes[XCHACHA_NONCE_LEN..], ENVELOPE_AAD)?;
    object_key_from_opened_bytes(&opened)
}

fn object_key_from_opened_bytes(bytes: &[u8]) -> Result<ObjectKey, MnemeError> {
    if bytes.len() != OBJECT_KEY_LEN {
        return Err(MnemeError::KeyVaultCorrupt);
    }
    let mut key = [0u8; OBJECT_KEY_LEN];
    key.copy_from_slice(bytes);
    Ok(key)
}

fn load_envelope_dir(
    root: &Path,
    master: &[u8; 32],
) -> Result<(HashMap<KeyId, ObjectKey>, HashSet<KeyId>), MnemeError> {
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
                validate_single_link_file(&entry.path())?;
                shredded.insert(key_id);
            }
        } else if let Some(key_id) = crate::vault::hex::decode_key_id(name) {
            let wrapped = read_wrapped_key(&entry.path())?;
            let key = unwrap_wrapped_key(master, &wrapped)?;
            live.insert(key_id, key);
        }
    }
    let journal = root.join("vault.journal");
    if entry_exists(&journal)? {
        let bytes = read_single_link_file(&journal)?;
        let full = bytes.len() / JOURNAL_RECORD_LEN;
        for i in 0..full {
            let off = i * JOURNAL_RECORD_LEN;
            let mut key_id = [0u8; KEY_ID_LEN];
            key_id.copy_from_slice(&bytes[off..off + KEY_ID_LEN]);
            let wrapped = &bytes[off + KEY_ID_LEN..off + JOURNAL_RECORD_LEN];
            let key = unwrap_wrapped_key(master, wrapped)?;
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
