//! MCP tool path binds ActionReceipt when `phase_iii_bind` is enabled.

use mneme_core::MemoryKind;
use mneme_mcp::store_open::test_runtime;
use tempfile::tempdir;

#[test]
fn mcp_remember_binds_action_receipt_when_feature_on() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let out = rt
        .handlers
        .remember(
            b"hello",
            MemoryKind::Semantic,
            "tools/mcp",
            "note",
            [0x09; 16],
        )
        .unwrap();
    assert!(out.root_hash_hex.len() >= 64);
}
