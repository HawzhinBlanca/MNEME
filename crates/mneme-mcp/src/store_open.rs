//! Store path and capability bootstrap for the MCP server process.

use mneme_cap::{agent_cap, tool_channel_cap};
use mneme_crypto::{EnvelopeKeyVault, FileKeyVault, KeyPair, KeyVault, load_or_generate_operator};
use mneme_store::{Store, store_head_entry_exists_no_follow};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const TEST_OPERATOR_SEED_HEX: &str =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

pub struct McpRuntime {
    pub handlers: crate::handlers::MemoryHandlers,
    pub store_path: PathBuf,
}

pub fn default_store_path() -> PathBuf {
    std::env::var("MNEME_STORE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".mneme").join("store"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

pub fn open_runtime(store_path: &Path) -> Result<McpRuntime, mneme_core::MnemeError> {
    let seed = std::env::var("MNEME_OPERATOR_SEED").ok();
    open_runtime_with_operator_seed(store_path, seed.as_deref())
}

fn open_runtime_with_operator_seed(
    store_path: &Path,
    seed_hex: Option<&str>,
) -> Result<McpRuntime, mneme_core::MnemeError> {
    let operator = load_or_generate_operator(store_path, seed_hex)?;
    let tool_writer = derive_tool_writer_keypair(&operator);
    let store = open_or_create_store(store_path, operator.clone())?;
    let mut store = store;
    let write_cap = tool_channel_cap(&operator, tool_writer.public_key_bytes())?;
    let read_cap = agent_cap(&operator, operator.public_key_bytes())?;
    let writer_pk = tool_writer.public_key_bytes();
    if !store.trust().trusts_writer(&write_cap.writer_hash()) {
        store.trust_mut().authorized_writers.push(writer_pk);
    }
    let shared = Arc::new(Mutex::new(store));
    let handlers = crate::handlers::MemoryHandlers::new(shared, write_cap, read_cap);
    Ok(McpRuntime {
        handlers,
        store_path: store_path.to_path_buf(),
    })
}

fn open_or_create_store(
    store_path: &Path,
    operator: KeyPair,
) -> Result<Store, mneme_core::MnemeError> {
    if store_head_entry_exists_no_follow(store_path)? {
        return open_store_with_vault(store_path, operator);
    }
    std::fs::create_dir_all(store_path).map_err(|e| mneme_core::MnemeError::IoFailed {
        path: store_path.display().to_string(),
        kind: e.to_string(),
    })?;
    Store::create_with_vault(store_path, operator, vault_for_path(store_path)?)
}

fn open_store_with_vault(
    store_path: &Path,
    operator: KeyPair,
) -> Result<Store, mneme_core::MnemeError> {
    Store::open_with_vault(store_path, operator, vault_for_path(store_path)?)
}

fn vault_for_path(store_path: &Path) -> Result<Box<dyn KeyVault + Send>, mneme_core::MnemeError> {
    if std::env::var_os("MNEME_KMS_MASTER_KEY_HEX").is_some() {
        Ok(Box::new(EnvelopeKeyVault::from_env(store_path)?))
    } else {
        Ok(Box::new(FileKeyVault::new(store_path)?))
    }
}

fn derive_tool_writer_keypair(operator: &KeyPair) -> KeyPair {
    let seed = operator_seed_bytes(operator);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mneme-mcp-tool-writer-v1\x00");
    hasher.update(&seed);
    KeyPair::from_seed(*hasher.finalize().as_bytes())
}

fn operator_seed_bytes(operator: &KeyPair) -> [u8; 32] {
    operator.signing_key().to_bytes()
}

pub fn test_runtime(dir: &Path) -> McpRuntime {
    open_runtime_with_operator_seed(dir, Some(TEST_OPERATOR_SEED_HEX)).expect("test runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn replace_head_with_dangling_symlink(store_path: &Path) -> PathBuf {
        let head = store_path.join("roots/HEAD");
        let missing = store_path.join("missing-head");
        std::fs::remove_file(store_path.join("roots/1.root.cbor"))
            .expect("remove genesis checkpoint");
        std::fs::remove_file(&head).expect("remove real HEAD");
        std::os::unix::fs::symlink(&missing, &head).expect("dangling HEAD symlink");
        assert!(!head.exists(), "fixture should be a dangling symlink");
        missing
    }

    #[cfg(unix)]
    #[test]
    fn mcp_runtime_rejects_dangling_head_entry_instead_of_recreating_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = open_runtime_with_operator_seed(dir.path(), Some(TEST_OPERATOR_SEED_HEX))
            .expect("initial MCP runtime");
        drop(runtime);

        let missing = replace_head_with_dangling_symlink(dir.path());

        match open_runtime_with_operator_seed(dir.path(), Some(TEST_OPERATOR_SEED_HEX)) {
            Err(mneme_core::MnemeError::IoFailed { path, .. }) => {
                assert!(
                    path.ends_with("roots/HEAD"),
                    "unexpected failure path: {path}"
                );
            }
            Err(mneme_core::MnemeError::RootInconsistent) => {}
            Err(err) => panic!("expected dangling HEAD failure, got {err:?}"),
            Ok(_) => panic!("MCP runtime recreated a tampered store with dangling HEAD"),
        }

        assert!(
            !missing.exists(),
            "MCP boot must not materialize HEAD symlink target"
        );
        assert!(
            std::fs::symlink_metadata(dir.path().join("roots/HEAD"))
                .expect("dangling HEAD entry")
                .file_type()
                .is_symlink(),
            "MCP boot must leave the tampered HEAD entry for explicit repair"
        );
        assert!(
            !dir.path().join("roots/1.root.cbor").exists(),
            "MCP boot must not recreate a deleted checkpoint"
        );
    }
}
