use mneme_account::{
    PHASE_III_GATE_OPEN, mint_action_receipt, prove_forget, verify_action_receipt,
    verify_action_receipt_bound, verify_action_receipt_wire, verify_forget_proof_wire,
};
use mneme_cap::{Capability, Permissions};
use mneme_core::{
    ForgetMode, ForgetProof, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Root, TrustTier,
    encode_action_receipt, encode_forget_proof,
};
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
fn gate_opens_with_phase_iii_verify_feature() {
    assert!(std::hint::black_box(PHASE_III_GATE_OPEN));
}

#[test]
fn action_receipt_mint_verify_wire_and_optional_cert_v2() {
    let cap = sample_capability();
    let root = sample_root();
    let action = [0xAA; 32];
    let cert = [0xCC; 32];
    let receipt = mint_action_receipt(&sanctioner(), action, &cap, &root, Some(cert)).unwrap();
    verify_action_receipt_bound(&receipt, action, &cap, &root).unwrap();
    verify_action_receipt_wire(&encode_action_receipt(&receipt).unwrap()).unwrap();
    let mut bad = receipt.clone();
    bad.signature[0] ^= 1;
    assert_eq!(verify_action_receipt(&bad), Err(MnemeError::RootSigInvalid));
}

#[test]
fn forget_proof_witness_stub_unsupported_version() {
    let root = sample_root();
    let target = ForgetTarget::LogicalKey(LogicalKey {
        namespace: "default".into(),
        name: "s".into(),
    });
    assert_eq!(
        prove_forget(&target, ForgetMode::Shred, &root, None).unwrap_err(),
        MnemeError::UnsupportedVersion {
            got: mneme_core::FORGET_PROOF_VERSION
        }
    );
    let wire = encode_forget_proof(&ForgetProof {
        version: mneme_core::FORGET_PROOF_VERSION,
        target_commit: [0x31; 32],
        mode: ForgetMode::Shred,
        shred_commit: [0x32; 32],
        absence_path: vec![[0x33; 32]],
        root_bound: [0x34; 32],
        cognition_cert_commit: Some([0xDD; 32]),
    })
    .unwrap();
    assert_eq!(
        verify_forget_proof_wire(&wire).unwrap_err(),
        MnemeError::UnsupportedVersion {
            got: mneme_core::FORGET_PROOF_VERSION
        }
    );
}
