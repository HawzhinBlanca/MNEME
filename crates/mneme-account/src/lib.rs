//! Phase III accountability kernel (ROADMAP Phase III).

#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(any(not(feature = "phase_iii_bind_action"), test))]
use mneme_core::ACTION_RECEIPT_VERSION;
#[cfg(any(not(feature = "phase_iii_prove_forget"), test))]
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

#[cfg(any(
    not(feature = "phase_iii_bind_action"),
    not(feature = "phase_iii_prove_forget"),
    not(feature = "phase_iii_verify"),
    test
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountGateFailure {
    BindAction,
    ProveForget,
    VerifyActionReceipt(u16),
    VerifyForgetProof(u16),
}

#[cfg(any(
    not(feature = "phase_iii_bind_action"),
    not(feature = "phase_iii_prove_forget"),
    not(feature = "phase_iii_verify"),
    test
))]
fn account_gate_failure_to_mneme(failure: AccountGateFailure) -> MnemeError {
    match failure {
        AccountGateFailure::BindAction => MnemeError::UnsupportedVersion {
            got: ACTION_RECEIPT_VERSION,
        },
        AccountGateFailure::ProveForget => MnemeError::UnsupportedVersion {
            got: FORGET_PROOF_VERSION,
        },
        AccountGateFailure::VerifyActionReceipt(got)
        | AccountGateFailure::VerifyForgetProof(got) => MnemeError::UnsupportedVersion { got },
    }
}

#[cfg(any(not(feature = "phase_iii_bind_action"), test))]
fn bind_action_gate_closed_error() -> MnemeError {
    account_gate_failure_to_mneme(AccountGateFailure::BindAction)
}

#[cfg(any(not(feature = "phase_iii_prove_forget"), test))]
fn prove_forget_gate_closed_error() -> MnemeError {
    account_gate_failure_to_mneme(AccountGateFailure::ProveForget)
}

#[cfg(any(not(feature = "phase_iii_verify"), test))]
fn verify_action_receipt_gate_closed_error(got: u16) -> MnemeError {
    account_gate_failure_to_mneme(AccountGateFailure::VerifyActionReceipt(got))
}

#[cfg(any(not(feature = "phase_iii_verify"), test))]
fn verify_forget_proof_gate_closed_error(got: u16) -> MnemeError {
    account_gate_failure_to_mneme(AccountGateFailure::VerifyForgetProof(got))
}

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
        sign::bind_action_impl(
            action_commit,
            capability,
            sanctioner_signer,
            root,
            cognition_cert_commit,
        )
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
        Err(bind_action_gate_closed_error())
    }
}

#[cfg(not(feature = "phase_iii_prove_forget"))]
pub fn prove_forget(
    _target: &ForgetTarget,
    _mode: ForgetMode,
    _root: &Root,
    _cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ForgetProof, MnemeError> {
    Err(prove_forget_gate_closed_error())
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
    Err(verify_action_receipt_gate_closed_error(
        decode_action_receipt(bytes)?.version,
    ))
}

#[cfg(feature = "phase_iii_verify")]
pub fn verify_forget_proof_wire(bytes: &[u8], root: &Root) -> Result<(), MnemeError> {
    verify::verify_forget_proof(&decode_forget_proof(bytes)?, root)
}

#[cfg(not(feature = "phase_iii_verify"))]
pub fn verify_forget_proof_wire(bytes: &[u8], _root: &Root) -> Result<(), MnemeError> {
    Err(verify_forget_proof_gate_closed_error(
        decode_forget_proof(bytes)?.version,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_source() -> &'static str {
        include_str!("lib.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("mneme-account tests should follow production code")
    }

    #[test]
    fn default_closed_phase_iii_gates_are_classified_not_unsupported_version_collapsed() {
        let production = production_source();

        for forbidden in [
            "Err(MnemeError::UnsupportedVersion",
            "return Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !production.contains(forbidden),
                "default-closed Phase III gate should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum AccountGateFailure",
            "BindAction",
            "ProveForget",
            "VerifyActionReceipt",
            "VerifyForgetProof",
            "fn account_gate_failure_to_mneme(",
            "fn bind_action_gate_closed_error(",
            "fn prove_forget_gate_closed_error(",
            "fn verify_action_receipt_gate_closed_error(",
            "fn verify_forget_proof_gate_closed_error(",
        ] {
            assert!(
                production.contains(required),
                "default-closed Phase III gate classification should include `{required}`"
            );
        }
    }

    #[test]
    fn account_gate_classifier_preserves_public_unsupported_version() {
        for (failure, expected) in [
            (AccountGateFailure::BindAction, ACTION_RECEIPT_VERSION),
            (AccountGateFailure::ProveForget, FORGET_PROOF_VERSION),
            (AccountGateFailure::VerifyActionReceipt(7), 7),
            (AccountGateFailure::VerifyForgetProof(11), 11),
        ] {
            assert_eq!(
                account_gate_failure_to_mneme(failure),
                MnemeError::UnsupportedVersion { got: expected }
            );
        }

        assert_eq!(
            bind_action_gate_closed_error(),
            MnemeError::UnsupportedVersion {
                got: ACTION_RECEIPT_VERSION
            }
        );
        assert_eq!(
            prove_forget_gate_closed_error(),
            MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION
            }
        );
        assert_eq!(
            verify_action_receipt_gate_closed_error(13),
            MnemeError::UnsupportedVersion { got: 13 }
        );
        assert_eq!(
            verify_forget_proof_gate_closed_error(17),
            MnemeError::UnsupportedVersion { got: 17 }
        );
    }
}
