//! Phase III stubs must fail closed until the gate opens.
//!
//! These tests pin the honest behavior: `bind_action` / `prove_forget` reject
//! with `UnsupportedVersion`, never returning a fabricated receipt or proof —
//! and they reject *even when* a cert v2 commit is supplied.

#[cfg(not(feature = "phase_iii_verify"))]
use mneme_account::PHASE_III_GATE_OPEN;
use mneme_account::{
    bind_action, prove_forget, verify_action_receipt_wire, verify_forget_proof_wire,
};
use mneme_core::{
    ACTION_RECEIPT_VERSION, ActionReceipt, Capability, FORGET_PROOF_VERSION, ForgetMode,
    ForgetProof, ForgetTarget, LogicalKey, MnemeError, ObjectId, Root, encode_action_receipt,
    encode_forget_proof,
};

fn sample_capability() -> Capability {
    Capability {
        issuer: [0x01; 32],
        subject: [0x02; 32],
        namespaces: vec!["default".to_string()],
        kinds: vec![0],
        tier_max: 3,
        tier_default: 1,
        permissions: 0xFF,
        caveats: vec![],
        signature: vec![0x00; 64],
    }
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

#[cfg(not(feature = "phase_iii_verify"))]
#[test]
fn gate_is_closed() {
    // `black_box` prevents const-folding so the assertion is a real runtime check.
    let gate = std::hint::black_box(PHASE_III_GATE_OPEN);
    assert!(
        !gate,
        "Phase III gate must stay closed until proving/signing logic lands and forgeries fail closed"
    );
}

#[test]
fn bind_action_fails_closed_without_cert() {
    let cap = sample_capability();
    let root = sample_root();
    let result = bind_action([0xAA; 32], &cap, [0xBB; 32], &root, None);
    assert_eq!(
        result.unwrap_err(),
        MnemeError::UnsupportedVersion {
            got: ACTION_RECEIPT_VERSION
        }
    );
}

#[test]
fn bind_action_fails_closed_even_with_cert_commit() {
    let cap = sample_capability();
    let root = sample_root();
    // Supplying a cert v2 commit must not unlock a fabricated receipt.
    let result = bind_action([0xAA; 32], &cap, [0xBB; 32], &root, Some([0xCC; 32]));
    assert!(matches!(
        result,
        Err(MnemeError::UnsupportedVersion {
            got: ACTION_RECEIPT_VERSION
        })
    ));
}

#[test]
fn prove_forget_fails_closed_for_key_and_object_targets() {
    let root = sample_root();
    let key_target = ForgetTarget::LogicalKey(LogicalKey {
        namespace: "default".to_string(),
        name: "secret".to_string(),
    });
    let obj_target = ForgetTarget::ObjectId(ObjectId([0x42; 32]));

    for target in [key_target, obj_target] {
        let result = prove_forget(&target, ForgetMode::Shred, &root, None);
        assert_eq!(
            result.unwrap_err(),
            MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION
            }
        );
    }
}

#[test]
fn prove_forget_fails_closed_for_redact_and_with_cert() {
    let root = sample_root();
    let target = ForgetTarget::ObjectId(ObjectId([0x42; 32]));
    let result = prove_forget(&target, ForgetMode::Redact, &root, Some([0xDD; 32]));
    assert!(matches!(
        result,
        Err(MnemeError::UnsupportedVersion {
            got: FORGET_PROOF_VERSION
        })
    ));
}

fn sample_action_receipt_wire(cert: Option<[u8; 32]>) -> Vec<u8> {
    let receipt = ActionReceipt {
        version: ACTION_RECEIPT_VERSION,
        action_commit: [0x21; 32],
        capability_commit: [0x22; 32],
        sanctioner: [0x23; 32],
        root_bound: [0x24; 32],
        hlc: [0x25; 14],
        cognition_cert_commit: cert,
        signature: vec![0xAA; 8],
    };
    encode_action_receipt(&receipt).expect("receipt wire")
}

fn sample_forget_proof_wire(cert: Option<[u8; 32]>) -> Vec<u8> {
    let proof = ForgetProof {
        version: FORGET_PROOF_VERSION,
        target_commit: [0x31; 32],
        mode: ForgetMode::Shred,
        shred_commit: [0x32; 32],
        absence_path: vec![[0x33; 32]],
        root_bound: [0x34; 32],
        cognition_cert_commit: cert,
    };
    encode_forget_proof(&proof).expect("forget proof wire")
}

#[cfg(not(feature = "phase_iii_verify"))]
#[test]
fn verify_action_receipt_wire_fails_closed_but_parses() {
    let wire = sample_action_receipt_wire(Some([0xCC; 32]));
    let err = verify_action_receipt_wire(&wire).unwrap_err();
    assert_eq!(
        err,
        MnemeError::UnsupportedVersion {
            got: ACTION_RECEIPT_VERSION
        }
    );
}

#[test]
fn verify_action_receipt_wire_rejects_malformed_wire() {
    let mut wire = sample_action_receipt_wire(None);
    wire.truncate(wire.len().saturating_sub(5));
    let err = verify_action_receipt_wire(&wire).unwrap_err();
    assert_eq!(err, MnemeError::SchemaDrift);
}

#[cfg(not(feature = "phase_iii_verify"))]
#[test]
fn verify_forget_proof_wire_fails_closed_but_parses() {
    let wire = sample_forget_proof_wire(None);
    let err = verify_forget_proof_wire(&wire).unwrap_err();
    assert_eq!(
        err,
        MnemeError::UnsupportedVersion {
            got: FORGET_PROOF_VERSION
        }
    );
}

#[test]
fn verify_forget_proof_wire_rejects_malformed_wire() {
    let mut wire = sample_forget_proof_wire(Some([0xDD; 32]));
    wire.truncate(wire.len().saturating_sub(17));
    let err = verify_forget_proof_wire(&wire).unwrap_err();
    assert_eq!(err, MnemeError::SchemaDrift);
}
