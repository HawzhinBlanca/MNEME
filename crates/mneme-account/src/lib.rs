//! Phase III accountability kernel (ROADMAP Phase III).

#![forbid(unsafe_code)]
#![deny(warnings)]

use mneme_core::{
    ACTION_RECEIPT_VERSION, ActionReceipt, Capability, FORGET_PROOF_VERSION, ForgetMode,
    ForgetProof, ForgetTarget, MnemeError, Root, decode_action_receipt, decode_forget_proof,
};

#[cfg(feature = "phase_iii_verify")]
mod verify;

#[cfg(feature = "phase_iii_verify")]
pub use verify::{
    mint_action_receipt, verify_action_receipt, verify_action_receipt_bound, verify_forget_proof,
};

#[cfg(feature = "phase_iii_verify")]
pub const PHASE_III_GATE_OPEN: bool = true;

#[cfg(not(feature = "phase_iii_verify"))]
pub const PHASE_III_GATE_OPEN: bool = false;

pub fn bind_action(
    _action_commit: [u8; 32],
    _capability: &Capability,
    _sanctioner: [u8; 32],
    _root: &Root,
    _cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ActionReceipt, MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: ACTION_RECEIPT_VERSION,
    })
}

pub fn prove_forget(
    _target: &ForgetTarget,
    _mode: ForgetMode,
    _root: &Root,
    _cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ForgetProof, MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: FORGET_PROOF_VERSION,
    })
}

#[cfg(feature = "phase_iii_verify")]
pub fn verify_action_receipt_wire(bytes: &[u8]) -> Result<(), MnemeError> {
    verify::verify_action_receipt(&decode_action_receipt(bytes)?)
}

#[cfg(not(feature = "phase_iii_verify"))]
pub fn verify_action_receipt_wire(bytes: &[u8]) -> Result<(), MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: decode_action_receipt(bytes)?.version,
    })
}

#[cfg(feature = "phase_iii_verify")]
pub fn verify_forget_proof_wire(bytes: &[u8]) -> Result<(), MnemeError> {
    verify::verify_forget_proof(&decode_forget_proof(bytes)?)
}

#[cfg(not(feature = "phase_iii_verify"))]
pub fn verify_forget_proof_wire(bytes: &[u8]) -> Result<(), MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: decode_forget_proof(bytes)?.version,
    })
}
