//! Store-path `bind_external_action` (P3-1).

use mneme_account::PHASE_III_BIND_ACTION_OPEN;
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
    assert!(!std::hint::black_box(PHASE_III_BIND_ACTION_OPEN));
    let err = store
        .bind_external_action([0xAB; 32], &cap, &operator, None)
        .unwrap_err();
    assert!(matches!(
        err,
        mneme_core::MnemeError::UnsupportedVersion { .. }
    ));
}

#[cfg(feature = "phase_iii_bind")]
#[test]
fn bind_external_action_mints_under_current_root() {
    assert!(std::hint::black_box(PHASE_III_BIND_ACTION_OPEN));
    let (_dir, store, operator, cap) = setup();
    let root = store.current_root().unwrap();
    let receipt = store
        .bind_external_action([0xCD; 32], &cap, &operator, None)
        .unwrap();
    assert_eq!(receipt.root_bound, root.preimage_hash);
    assert!(!receipt.signature.is_empty());
}
