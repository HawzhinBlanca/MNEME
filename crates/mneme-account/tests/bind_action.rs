//! Store-path `bind_action` minting (feature `phase_iii_bind_action`).

#[cfg(feature = "phase_iii_verify")]
use mneme_account::verify_action_receipt_wire;
use mneme_account::{PHASE_III_BIND_ACTION_OPEN, bind_action};
use mneme_cap::{Capability, Permissions};
#[cfg(feature = "phase_iii_verify")]
use mneme_core::encode_action_receipt;
use mneme_core::{MemoryKind, MnemeError, Root, TrustTier};
use mneme_crypto::KeyPair;

fn issuer() -> KeyPair {
    KeyPair::from_seed([0x01; 32])
}
fn sanctioner() -> KeyPair {
    KeyPair::from_seed([0x02; 32])
}

fn sample_capability() -> Capability {
    Capability::issue(
        &issuer(),
        issuer().public_key_bytes(),
        vec!["default".into()],
        vec![MemoryKind::Episodic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap()
}

fn sample_root() -> Root {
    Root {
        version: 1,
        preimage_hash: [0x10; 32],
        dag_head_root: [0x11; 32],
        key_index_root: [0x12; 32],
        semantic_commit: [0x13; 32],
        hlc_max: [0x14; 14],
        prev_root: [0x15; 32],
        signature: vec![0x00; 64],
        sequence: 7,
    }
}

#[test]
fn bind_action_gate_open_mints_signed_receipt() {
    assert!(std::hint::black_box(PHASE_III_BIND_ACTION_OPEN));
    let cap = sample_capability();
    let root = sample_root();
    let action = [0xAA; 32];
    let receipt = bind_action(action, cap.inner(), &sanctioner(), &root, None).unwrap();
    assert!(!receipt.signature.is_empty());
    assert_eq!(receipt.sanctioner, sanctioner().public_key_bytes());
    assert_eq!(receipt.root_bound, root.preimage_hash);
}

#[test]
fn bind_action_rejects_unsigned_capability() {
    let mut inner = sample_capability().into_core();
    inner.signature.clear();
    let root = sample_root();
    assert_eq!(
        bind_action([0xAA; 32], &inner, &sanctioner(), &root, None).unwrap_err(),
        MnemeError::CapMalformed
    );
}

#[cfg(feature = "phase_iii_verify")]
#[test]
fn bind_action_wire_verifies_with_phase_iii_verify() {
    let cap = sample_capability();
    let root = sample_root();
    let receipt = bind_action([0xBB; 32], cap.inner(), &sanctioner(), &root, None).unwrap();
    let wire = encode_action_receipt(&receipt).unwrap();
    verify_action_receipt_wire(&wire).unwrap();
}
