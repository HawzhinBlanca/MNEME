//! Phase III accountability kernel — **stubs only** (ROADMAP Phase III).
//!
//! Exposes the two Phase III seams:
//! - [`bind_action`] — non-repudiation (P3-1): bind an external action to its
//!   authorizing capability and the sanctioning human identity.
//! - [`prove_forget`] — verifiable forgetting (P3-2): crypto-shred witness plus
//!   proof-of-absence under a signed root.
//!
//! **The Phase III gate is closed.** Neither function has proving / signing /
//! verification logic yet, so both **fail closed** with
//! [`MnemeError::UnsupportedVersion`]. A stub that returned `Ok(..)` with an
//! empty receipt or proof would be a fabricated success — forbidden by the
//! zero-fabrication rule and by MNEME's fail-closed default. Rejecting is the
//! honest behavior until the gate opens.
//!
//! **Cert v2 dependency:** these seams will fold into the Phase II cognition
//! certificate ("cert v2"), whose layout is not finalized. The receipt/proof
//! types carry an **optional** `cognition_cert_commit` for that link; callers
//! pass `Some(commit)` only when a real cert v2 commit exists, `None` otherwise.
//! Even with a commit supplied, the gated API still fails closed today.

#![forbid(unsafe_code)]
#![deny(warnings)]

use mneme_core::{
    ACTION_RECEIPT_VERSION, ActionReceipt, Capability, FORGET_PROOF_VERSION, ForgetMode,
    ForgetProof, ForgetTarget, MnemeError, Root,
};

/// Phase III gate. Flipped to `true` only when `bind_action` / `prove_forget`
/// implement real proving, signing, and verification *and* the adversarial
/// red-team's forgeries fail closed. While `false`, the public API rejects.
pub const PHASE_III_GATE_OPEN: bool = false;

/// Bind an external action to the capability that authorized it and the human
/// identity that sanctioned it (NIST non-repudiation, Phase III P3-1).
///
/// On success (Phase III, not yet) this returns a signed [`ActionReceipt`]
/// bound to `root` and — when present — the cognition certificate ("cert v2")
/// commit the action consumed. **Today the gate is closed**, so it always
/// returns `Err(MnemeError::UnsupportedVersion { got: ACTION_RECEIPT_VERSION })`.
///
/// The parameters are accepted now to freeze the call shape; they are not yet
/// inspected (no partial validation that could imply a guarantee we cannot make).
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

/// Prove that `target` was forgotten: crypto-shred witness plus proof-of-absence
/// under the signed `root` (Phase III P3-2, verifiable forgetting).
///
/// On success (Phase III, not yet) this returns a [`ForgetProof`] establishing
/// both deletion and not-served-after, optionally bound to a cert v2 commit.
/// **Today the gate is closed**, so it always returns
/// `Err(MnemeError::UnsupportedVersion { got: FORGET_PROOF_VERSION })`.
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
