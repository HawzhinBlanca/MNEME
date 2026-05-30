use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use mneme_core::MnemeError;

use crate::types::{KEY_ID_LEN, KeyId, OBJECT_KEY_LEN, ObjectKey};

/// Per-object key vault (blueprint §5.8 `keys/vault/`).
pub trait KeyVault {
    fn new_key(&mut self) -> Result<(ObjectKey, KeyId), MnemeError>;
    fn get(&self, key_id: &KeyId) -> Result<ObjectKey, MnemeError>;
    fn shred(&mut self, key_id: &KeyId) -> Result<(), MnemeError>;
    fn contains(&self, key_id: &KeyId) -> bool;
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
        self.keys.remove(key_id);
        self.shredded.insert(*key_id, ());
        Ok(())
    }

    fn contains(&self, key_id: &KeyId) -> bool {
        self.keys.contains_key(key_id) && !self.shredded.contains_key(key_id)
    }
}

/// File-backed vault rooted at `store/keys/vault/`.
pub struct FileKeyVault {
    root: PathBuf,
}

impl FileKeyVault {
    pub fn new(store_root: impl AsRef<Path>) -> Result<Self, MnemeError> {
        let root = store_root.as_ref().join("keys").join("vault");
        fs::create_dir_all(&root).map_err(|e| io_error(root.display().to_string(), e))?;
        Ok(Self { root })
    }

    /// Import peer key material for objects accepted by anti-entropy merge.
    pub fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError> {
        if self.tombstone_path(key_id).exists() {
            return Err(MnemeError::Forgotten);
        }
        let path = self.key_path(key_id);
        if path.exists() {
            return Ok(());
        }
        write_key_file(&path, key)
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
            let path = self.key_path(&key_id);
            if path.exists() || self.tombstone_path(&key_id).exists() {
                continue;
            }
            write_key_file(&path, &key)?;
            return Ok((key, key_id));
        }
    }

    fn get(&self, key_id: &KeyId) -> Result<ObjectKey, MnemeError> {
        if self.tombstone_path(key_id).exists() {
            return Err(MnemeError::Forgotten);
        }
        let path = self.key_path(key_id);
        if !path.exists() {
            return Err(MnemeError::KeyVaultMissing);
        }
        read_key_file(&path)
    }

    fn shred(&mut self, key_id: &KeyId) -> Result<(), MnemeError> {
        let path = self.key_path(key_id);
        let tombstone = self.tombstone_path(key_id);
        if !path.exists() && !tombstone.exists() {
            return Err(MnemeError::KeyVaultMissing);
        }
        if path.exists() {
            secure_delete(&path)?;
        }
        if !tombstone.exists() {
            File::create(&tombstone).map_err(|e| io_error(tombstone.display().to_string(), e))?;
        }
        Ok(())
    }

    fn contains(&self, key_id: &KeyId) -> bool {
        self.key_path(key_id).exists() && !self.tombstone_path(key_id).exists()
    }
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

fn random_object_key() -> ObjectKey {
    let mut key = [0u8; OBJECT_KEY_LEN];
    crate::deterministic::fill_random("vault-object-key", &mut key);
    key
}

fn random_key_id() -> KeyId {
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
    file.sync_all()
        .map_err(|e| io_error(path.display().to_string(), e))?;
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
    Ok(())
}

fn io_error(path: String, err: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path,
        kind: format!("{:?}", err.kind()),
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}
