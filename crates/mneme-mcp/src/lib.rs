//! MCP adoption layer: `memory.remember` / `memory.recall` / `memory.forget`
//! / `memory.forget_proof` (blueprint §14.1).
//!
//! - `memory.recall` uses **only** [`MemoryHandlers::recall`] → `Store::recall_verified` (fail-closed).
//! - `memory.remember` uses the tool-channel capability → quarantine tier (§13.4 A-INJ mitigation).
//! - Tool descriptions embed the §3 honesty boundary.

#![forbid(unsafe_code)]

pub mod handlers;
pub mod honesty;
pub mod protocol;
pub mod server;
pub mod store_open;

pub use handlers::MemoryHandlers;
pub use handlers::normalize_tool_namespace;
pub use honesty::{
    AINJ_MITIGATION, FORGET_DESCRIPTION, FORGET_PROOF_DESCRIPTION, HONESTY_FOOTER,
    RECALL_DESCRIPTION, REMEMBER_DESCRIPTION, tool_error_message,
};
pub use store_open::{McpRuntime, default_store_path, open_runtime};
