//! Phase III accountability kernel (ROADMAP Phase III).

#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(not(feature = "phase_iii_bind_action"))]
use mneme_core::ACTION_RECEIPT_VERSION;
#[cfg(not(feature = "phase_iii_prove_forget"))]
use mneme_core::FORGET_PROOF_VERSION;
use mneme_core::{
    ActionReceipt, Capability, ForgetMode, ForgetProof, ForgetTarget, MnemeError, Root,
    decode_action_receipt, decode_forget_proof,
};

#[cfg(feature = "phase_iii_bind_action")]
mod sign;

#[cfg(feature = "phase_iii_prove_forget")]
mod forget;

#[cfg(feature = "phase_iii_verify")]
mod verify;

#[cfg(feature = "phase_iii_bind_action")]
pub use sign::{bind_action_impl, mint_action_receipt};

#[cfg(feature = "phase_iii_prove_forget")]
pub use forget::{ForgetProofWitness, mint_forget_proof, prove_forget_impl, target_commit};

#[cfg(feature = "phase_iii_verify")]
pub use verify::{
    verify_action_receipt, verify_action_receipt_bound, verify_forget_proof,
    verify_forget_proof_bound,
};

/// Explicit gate for store-path `bind_action` minting (default **closed**).
/// Opens with `phase_iii_bind_action` or `phase_iii_verify` Cargo features.
#[cfg(feature = "phase_iii_bind_action")]
pub const PHASE_III_BIND_ACTION_OPEN: bool = true;

#[cfg(not(feature = "phase_iii_bind_action"))]
pub const PHASE_III_BIND_ACTION_OPEN: bool = false;

/// Gate for offline ActionReceipt / ForgetProof wire verify (default **closed**).
#[cfg(feature = "phase_iii_verify")]
pub const PHASE_III_GATE_OPEN: bool = true;

#[cfg(not(feature = "phase_iii_verify"))]
pub const PHASE_III_GATE_OPEN: bool = false;

/// Gate for `prove_forget` / `mint_forget_proof` (default **closed**).
#[cfg(feature = "phase_iii_prove_forget")]
pub const PHASE_III_PROVE_FORGET_OPEN: bool = true;

#[cfg(not(feature = "phase_iii_prove_forget"))]
pub const PHASE_III_PROVE_FORGET_OPEN: bool = false;

pub fn bind_action(
    action_commit: [u8; 32],
    capability: &Capability,
    sanctioner_signer: &mneme_crypto::KeyPair,
    root: &Root,
    cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ActionReceipt, MnemeError> {
    #[cfg(feature = "phase_iii_bind_action")]
    {
        let _ = std::hint::black_box(PHASE_III_BIND_ACTION_OPEN);
        return sign::bind_action_impl(
            action_commit,
            capability,
            sanctioner_signer,
            root,
            cognition_cert_commit,
        );
    }
    #[cfg(not(feature = "phase_iii_bind_action"))]
    {
        let _ = (
            action_commit,
            capability,
            sanctioner_signer,
            root,
            cognition_cert_commit,
        );
        Err(MnemeError::UnsupportedVersion {
            got: ACTION_RECEIPT_VERSION,
        })
    }
}

#[cfg(not(feature = "phase_iii_prove_forget"))]
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

#[cfg(feature = "phase_iii_prove_forget")]
pub fn prove_forget(
    target: &ForgetTarget,
    mode: ForgetMode,
    root: &Root,
    cognition_cert_commit: Option<[u8; 32]>,
    witness: &ForgetProofWitness<'_>,
) -> Result<ForgetProof, MnemeError> {
    let _ = std::hint::black_box(PHASE_III_PROVE_FORGET_OPEN);
    forget::prove_forget_impl(target, mode, root, cognition_cert_commit, witness)
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
pub fn verify_forget_proof_wire(bytes: &[u8], root: &Root) -> Result<(), MnemeError> {
    verify::verify_forget_proof(&decode_forget_proof(bytes)?, root)
}

#[cfg(not(feature = "phase_iii_verify"))]
pub fn verify_forget_proof_wire(bytes: &[u8], _root: &Root) -> Result<(), MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: decode_forget_proof(bytes)?.version,
    })
}
