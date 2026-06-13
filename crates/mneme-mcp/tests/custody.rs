//! MCP operator seed custody regressions.

use std::process::{Command, Stdio};

use mneme_mcp::store_open::test_runtime;
use tempfile::tempdir;

#[test]
fn mcp_start_without_seed_or_master_fails_closed_without_plaintext_seed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let output = Command::new(env!("CARGO_BIN_EXE_mneme-mcp"))
        .env("MNEME_STORE_PATH", &store)
        .env_remove("MNEME_OPERATOR_SEED")
        .env_remove("MNEME_KMS_MASTER_KEY_HEX")
        .stdin(Stdio::null())
        .output()
        .expect("run mneme-mcp");

    assert!(
        !output.status.success(),
        "MCP must not start without explicit operator seed custody"
    );
    assert!(
        !store.join(".operator_seed").exists(),
        "MCP must not create legacy plaintext operator seeds"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key vault missing") || stderr.contains("KeyVaultMissing"),
        "expected seed-custody failure on stderr, got: {stderr}"
    );
}

#[test]
fn mcp_test_runtime_seed_override_does_not_persist_plaintext_seed() {
    let dir = tempdir().expect("tempdir");
    let runtime = test_runtime(dir.path());

    assert_eq!(runtime.store_path, dir.path());
    assert!(
        !dir.path().join(".operator_seed").exists(),
        "explicit operator seed overrides are process custody and must not be persisted"
    );
}
