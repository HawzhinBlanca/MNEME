//! MCP operator-seed custody must match the canonical `mneme-crypto` path used by
//! the daemon and CLI: honor `MNEME_KMS_MASTER_KEY_HEX` (seal the seed, never write
//! plaintext) and fail closed when no custody is configured. Regression test for a
//! previously divergent local key-derivation that ignored the KMS master and wrote
//! a plaintext `.operator_seed`, so an MCP-opened store derived a DIFFERENT operator
//! than the daemon under a KMS deployment.

use mneme_mcp::open_runtime;
use std::path::Path;
use std::sync::Mutex;
use tempfile::tempdir;

// These tests mutate process env (`set_var`/`remove_var` are `unsafe` in edition
// 2024), so serialize them and scope the env changes under this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn set_master(master_hex: &str) {
    // SAFETY: serialized by ENV_LOCK; no other thread in this binary reads env
    // concurrently while held.
    unsafe {
        std::env::remove_var("MNEME_OPERATOR_SEED");
        std::env::set_var("MNEME_KMS_MASTER_KEY_HEX", master_hex);
    }
}

fn clear_custody() {
    unsafe {
        std::env::remove_var("MNEME_OPERATOR_SEED");
        std::env::remove_var("MNEME_KMS_MASTER_KEY_HEX");
    }
}

fn sealed_path(store: &Path) -> std::path::PathBuf {
    store.join("keys").join("operator_seed.sealed")
}

fn plaintext_path(store: &Path) -> std::path::PathBuf {
    store.join(".operator_seed")
}

#[test]
fn mcp_honors_kms_master_seals_seed_and_writes_no_plaintext() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let master = "42".repeat(32);
    set_master(&master);

    // The daemon/CLI path establishes the store's sealed operator identity.
    let daemon_op = mneme_crypto::load_or_generate_operator(&store, None)
        .expect("canonical operator under master");
    assert!(
        sealed_path(&store).exists(),
        "master seals the operator seed"
    );
    assert!(
        !plaintext_path(&store).exists(),
        "KMS custody must never write a plaintext .operator_seed"
    );

    // The MCP must open the SAME store under the same master without diverging:
    // it reads the sealed seed instead of generating a fresh plaintext key.
    let rt = open_runtime(&store).expect("MCP opens the KMS-backed store");
    assert_eq!(rt.store_path, store);

    // Re-deriving via the canonical path yields the SAME operator (stable sealed
    // seed) — i.e. the MCP did not overwrite it with a divergent identity.
    let after = mneme_crypto::load_or_generate_operator(&store, None)
        .expect("canonical operator after MCP open");
    assert_eq!(
        daemon_op.public_key_bytes(),
        after.public_key_bytes(),
        "MCP open must not change the operator identity"
    );
    assert!(
        !plaintext_path(&store).exists(),
        "MCP open under a master must not create a plaintext seed"
    );

    clear_custody();
}

#[test]
fn mcp_fails_closed_without_any_operator_custody() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    clear_custody();

    // No seed and no master: the MCP must fail closed, not silently generate a key.
    // (McpRuntime is not Debug, so match rather than expect_err.)
    let result = open_runtime(&store);
    assert!(
        matches!(result, Err(mneme_core::MnemeError::KeyVaultMissing)),
        "no custody must fail closed with KeyVaultMissing"
    );
    assert!(
        !plaintext_path(&store).exists(),
        "fail-closed custody must not write a plaintext .operator_seed"
    );
    assert!(
        !sealed_path(&store).exists(),
        "fail-closed custody must not seal a seed under an implicit key"
    );
}
