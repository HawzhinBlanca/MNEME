//! MCP adoption layer: `record-with-provenance` / `recall-with-signed-chain` /
//! `erase-with-receipt-and-proof-of-absence` / `verify` (blueprint §14.1).
//!
//! - `recall-with-signed-chain` uses **only**
//!   [`MemoryHandlers::recall_with_signed_chain`] → `Store::recall_verified` (fail-closed).
//! - `record-with-provenance` uses the tool-channel capability → quarantine tier (§13.4 A-INJ mitigation).
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
    AINJ_MITIGATION, ERASE_DESCRIPTION, HONESTY_FOOTER, RECALL_DESCRIPTION, RECORD_DESCRIPTION,
    VERIFY_DESCRIPTION, tool_error_message,
};
pub use store_open::{McpRuntime, default_store_path, open_runtime};
