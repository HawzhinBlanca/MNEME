//! Store-path `bind_external_action` (P3-1).

use mneme_cap::{Capability, Permissions};
use mneme_core::{MemoryKind, TrustTier};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use tempfile::TempDir;

fn setup() -> (TempDir, Store, KeyPair, Capability) {
    let dir = TempDir::new().unwrap();
    let operator = KeyPair::generate();
    let store = Store::create(dir.path(), operator.clone()).unwrap();
    let cap = Capability::issue(
        &operator,
        operator.public_key_bytes(),
        vec!["default".into()],
        vec![MemoryKind::Episodic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap();
    (dir, store, operator, cap)
}

#[cfg(not(feature = "phase_iii_bind"))]
#[test]
fn bind_external_action_fail_closed_by_default() {
    let (_dir, store, operator, cap) = setup();
    let err = store
        .bind_external_action([0xAB; 32], &cap, &operator, None)
        .unwrap_err();
    assert!(matches!(
        err,
        mneme_core::MnemeError::UnsupportedVersion { .. }
    ));
}

#[cfg(not(feature = "phase_iii_bind"))]
#[test]
fn bind_external_action_stays_closed_when_prove_forget_unifies_account_bind() {
    // Workspace builds enable `phase_iii_prove_forget` on mneme-store (via mneme-cli/mcp/mnemed),
    // which transitively unifies `mneme-account/phase_iii_bind_action`. The store seam must still
    // fail closed until `phase_iii_bind` is explicitly enabled.
    let (_dir, store, operator, cap) = setup();
    assert!(matches!(
        store
            .bind_external_action([0xEF; 32], &cap, &operator, None)
            .unwrap_err(),
        mneme_core::MnemeError::UnsupportedVersion { .. }
    ));
}

#[cfg(feature = "phase_iii_bind")]
#[test]
fn bind_external_action_mints_under_current_root() {
    let (_dir, store, operator, cap) = setup();
    let root = store.current_root().unwrap();
    let receipt = store
        .bind_external_action([0xCD; 32], &cap, &operator, None)
        .unwrap();
    assert_eq!(receipt.root_bound, root.preimage_hash);
    assert!(!receipt.signature.is_empty());
}
