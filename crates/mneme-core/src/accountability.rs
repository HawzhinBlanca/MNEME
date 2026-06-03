//! Phase III accountability wire skeletons (ROADMAP Phase III, P3-1 / P3-2).
//!
//! **STATUS: wire skeleton only — not a frozen interface seam, not implemented.**
//! These types declare the *shape* of the Phase III certificate extensions
//! (authorized action + honored forgetting). No proving, signing, hashing-to-a
//! -domain-tag, or verification logic exists yet: the Phase III gate is closed
//! and the `mneme-account` crate fails closed (`MnemeError::UnsupportedVersion`).
//! Unlike [`crate::interface`], this module is **not** under the §20.3 interface
//! freeze; layouts here are provisional until the Phase III seam is reviewed and
//! frozen (at which point `*_VERSION` and any domain tags are pinned).
//!
//! **Honesty boundary (CLAUDE.md §honesty, carried into Phase III):**
//! - An [`ActionReceipt`] binds an external action to the capability that
//!   authorized it and the human identity that sanctioned it. It proves
//!   *authorization + non-repudiation* — never that the action was wise, nor
//!   that its premises were true.
//! - A [`ForgetProof`] proves *crypto-shred witness + proof-of-absence under a
//!   signed root* (deleted, and not served from trusted memory afterward). It
//!   does **not** prove that no out-of-band copy ever existed elsewhere.
//! - The link to the Phase II cognition certificate ("cert v2") is an
//!   **optional** field: cert v2's layout is not yet finalized, so we bind only
//!   an opaque 32-byte commit when one is available and `None` otherwise. We
//!   never fabricate a commit to imply a cognition proof that was not produced.

use crate::interface::ForgetMode;

/// Phase III action-receipt wire version. Distinct from `OBJECT_VERSION` and the
/// root version; the value `3` marks the Phase III seam and is provisional until
/// the seam is frozen. Used by `mneme-account::bind_action` as the
/// `UnsupportedVersion { got }` payload while the gate is closed.
pub const ACTION_RECEIPT_VERSION: u16 = 3;

/// Phase III forget-proof wire version (see [`ACTION_RECEIPT_VERSION`]).
pub const FORGET_PROOF_VERSION: u16 = 3;

/// Non-repudiation receipt binding an external action to its authorizing
/// capability and sanctioning human identity (Phase III P3-1).
///
/// **Skeleton:** the `signature` is empty and no field is hash-bound yet;
/// [`ActionReceipt::signable_preimage`] returns the provisional byte layout that
/// a future signer will cover, but nothing signs it today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionReceipt {
    /// Wire version; equals [`ACTION_RECEIPT_VERSION`] for receipts minted by
    /// this build.
    pub version: u16,
    /// BLAKE3 commit over the external action payload (e.g. the tool call /
    /// effect descriptor). Provisional; the action-encoding is frozen at the gate.
    pub action_commit: [u8; 32],
    /// Commit of the capability token body that authorized the action
    /// (`hash_cap` domain). Empty-of-meaning until the gate binds it.
    pub capability_commit: [u8; 32],
    /// Sanctioning human identity — an Ed25519 public key (NIST non-repudiation).
    pub sanctioner: [u8; 32],
    /// Signed root the action was bound against (chain-of-custody anchor).
    pub root_bound: [u8; 32],
    /// HLC at binding time, 14-byte wire form (matches `Root::hlc_max`).
    pub hlc: [u8; 14],
    /// OPTIONAL commit to the Phase II cognition certificate ("cert v2") the
    /// action consumed. `None` until cert v2 is finalized — never fabricated.
    pub cognition_cert_commit: Option<[u8; 32]>,
    /// Detached signature over [`ActionReceipt::signable_preimage`]. Empty in
    /// the skeleton (no signer wired yet).
    pub signature: Vec<u8>,
}

impl ActionReceipt {
    /// Provisional signable preimage: `version ‖ action_commit ‖
    /// capability_commit ‖ sanctioner ‖ root_bound ‖ hlc ‖ cert_present(1) ‖
    /// [cert_commit]`. Excludes `signature` (signed-over content), mirroring
    /// [`crate::interface::RootPreimage`]. **No domain tag is applied yet** —
    /// that is pinned when the Phase III seam is frozen.
    pub fn signable_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 * 4 + 14 + 1 + 32);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.action_commit);
        buf.extend_from_slice(&self.capability_commit);
        buf.extend_from_slice(&self.sanctioner);
        buf.extend_from_slice(&self.root_bound);
        buf.extend_from_slice(&self.hlc);
        match self.cognition_cert_commit {
            Some(commit) => {
                buf.push(1);
                buf.extend_from_slice(&commit);
            }
            None => buf.push(0),
        }
        buf
    }
}

/// Proof that a target was forgotten: crypto-shred witness plus proof-of-absence
/// under a signed root (Phase III P3-2, verifiable forgetting).
///
/// **Skeleton:** `shred_commit` and `absence_path` are placeholders for the real
/// key-destruction witness and SMT non-membership path; nothing populates or
/// verifies them yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgetProof {
    /// Wire version; equals [`FORGET_PROOF_VERSION`].
    pub version: u16,
    /// Commit of what was forgotten (logical-key hash or object id).
    pub target_commit: [u8; 32],
    /// Forget mode applied — shred vs accountable chameleon redaction (§13.3).
    pub mode: ForgetMode,
    /// Crypto-shred witness commit (destruction of the wrapping key). Deferred.
    pub shred_commit: [u8; 32],
    /// Proof-of-absence: SMT non-membership path against `root_bound`'s key
    /// index. Empty in the skeleton.
    pub absence_path: Vec<[u8; 32]>,
    /// Signed root the absence proof is bound to (A-REPLAY safe at the gate).
    pub root_bound: [u8; 32],
    /// OPTIONAL cognition-certificate ("cert v2") commit witnessing
    /// not-used-after. `None` until cert v2 is finalized — never fabricated.
    pub cognition_cert_commit: Option<[u8; 32]>,
}

impl ForgetProof {
    /// 1-byte mode tag: `Shred → 0`, `Redact → 1`.
    pub fn mode_tag(&self) -> u8 {
        match self.mode {
            ForgetMode::Shred => 0,
            ForgetMode::Redact => 1,
        }
    }

    /// Provisional canonical payload: `version ‖ target_commit ‖ mode_tag(1) ‖
    /// shred_commit ‖ root_bound ‖ absence_len(4 LE) ‖ absence_path* ‖
    /// cert_present(1) ‖ [cert_commit]`. **No domain tag yet** (pinned at freeze).
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(2 + 32 + 1 + 32 + 32 + 4 + self.absence_path.len() * 32 + 1);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.target_commit);
        buf.push(self.mode_tag());
        buf.extend_from_slice(&self.shred_commit);
        buf.extend_from_slice(&self.root_bound);
        buf.extend_from_slice(&(self.absence_path.len() as u32).to_le_bytes());
        for node in &self.absence_path {
            buf.extend_from_slice(node);
        }
        match self.cognition_cert_commit {
            Some(commit) => {
                buf.push(1);
                buf.extend_from_slice(&commit);
            }
            None => buf.push(0),
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_iii_wire_versions_are_provisionally_three() {
        assert_eq!(ACTION_RECEIPT_VERSION, 3);
        assert_eq!(FORGET_PROOF_VERSION, 3);
    }

    fn sample_action(cert: Option<[u8; 32]>) -> ActionReceipt {
        ActionReceipt {
            version: ACTION_RECEIPT_VERSION,
            action_commit: [0x11; 32],
            capability_commit: [0x22; 32],
            sanctioner: [0x33; 32],
            root_bound: [0x44; 32],
            hlc: [0x55; 14],
            cognition_cert_commit: cert,
            signature: Vec::new(),
        }
    }

    #[test]
    fn action_preimage_excludes_signature_and_is_deterministic() {
        let mut a = sample_action(None);
        let p1 = a.signable_preimage();
        // Signature is signed-over content, never part of its own preimage.
        a.signature = vec![0xAB; 64];
        let p2 = a.signable_preimage();
        assert_eq!(p1, p2);
    }

    #[test]
    fn action_optional_cert_changes_preimage_without_fabrication() {
        let without = sample_action(None).signable_preimage();
        let with = sample_action(Some([0x99; 32])).signable_preimage();
        // Presence flag + commit must be observable; absence is one byte `0`.
        assert_eq!(*without.last().unwrap(), 0u8);
        assert_eq!(with.len(), without.len() + 32);
        assert_ne!(without, with);
    }

    #[test]
    fn forget_proof_payload_is_deterministic_and_mode_tagged() {
        let proof = ForgetProof {
            version: FORGET_PROOF_VERSION,
            target_commit: [0x01; 32],
            mode: ForgetMode::Shred,
            shred_commit: [0x02; 32],
            absence_path: vec![[0x03; 32], [0x04; 32]],
            root_bound: [0x05; 32],
            cognition_cert_commit: None,
        };
        assert_eq!(proof.mode_tag(), 0);
        assert_eq!(proof.encode_payload(), proof.encode_payload());

        let redact = ForgetProof {
            mode: ForgetMode::Redact,
            ..proof.clone()
        };
        assert_eq!(redact.mode_tag(), 1);
        assert_ne!(proof.encode_payload(), redact.encode_payload());
    }
}
