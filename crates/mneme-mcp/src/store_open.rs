//! Store path and capability bootstrap for the MCP server process.

use mneme_cap::{agent_cap, tool_channel_cap};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    let operator = load_or_generate_operator(
        store_path,
        std::env::var("MNEME_OPERATOR_SEED").ok().as_deref(),
    )?;
    let tool_writer = KeyPair::generate();
    let store = if store_path.join("root").join("head").exists() || store_path.join("head").exists()
    {
        Store::open(store_path, operator.clone())?
    } else {
        std::fs::create_dir_all(store_path).map_err(|_| mneme_core::MnemeError::IoFailed {
            path: store_path.display().to_string(),
            kind: "create_dir".into(),
        })?;
        Store::create(store_path, operator.clone())?
    };
    let mut store = store;
    let write_cap = tool_channel_cap(&operator, tool_writer.public_key_bytes())?;
    let read_cap = agent_cap(&operator, operator.public_key_bytes())?;
    if !store.trust().trusts_writer(&write_cap.writer_hash()) {
        store
            .trust_mut()
            .authorized_writers
            .push(tool_writer.public_key_bytes());
    }
    let shared = Arc::new(Mutex::new(store));
    let handlers = crate::handlers::MemoryHandlers::new(shared, write_cap, read_cap);
    Ok(McpRuntime {
        handlers,
        store_path: store_path.to_path_buf(),
    })
}

fn load_or_generate_operator(
    store: &Path,
    seed_hex: Option<&str>,
) -> Result<KeyPair, mneme_core::MnemeError> {
    let seed_path = store.join(".operator_seed");
    if let Some(hex) = seed_hex {
        return Ok(KeyPair::from_seed(parse_seed_hex(hex)?));
    }
    if seed_path.exists() {
        let hex =
            std::fs::read_to_string(&seed_path).map_err(|_| mneme_core::MnemeError::IoFailed {
                path: seed_path.display().to_string(),
                kind: "read".into(),
            })?;
        return Ok(KeyPair::from_seed(parse_seed_hex(hex.trim())?));
    }
    let (operator, seed) = KeyPair::generate_with_seed();
    std::fs::create_dir_all(store).ok();
    std::fs::write(&seed_path, hex::encode(seed)).map_err(|_| {
        mneme_core::MnemeError::IoFailed {
            path: seed_path.display().to_string(),
            kind: "write".into(),
        }
    })?;
    Ok(operator)
}

fn parse_seed_hex(hex_str: &str) -> Result<[u8; 32], mneme_core::MnemeError> {
    let bytes = hex::decode(hex_str).map_err(|_| mneme_core::MnemeError::CapMalformed)?;
    if bytes.len() != 32 {
        return Err(mneme_core::MnemeError::CapMalformed);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

pub fn test_runtime(dir: &Path) -> McpRuntime {
    open_runtime(dir).expect("test runtime")
}
