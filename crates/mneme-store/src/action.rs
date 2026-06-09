//! Phase III external-action binding (P3-1). Gated by `phase_iii_bind` / `phase_iii_verify`.

use crate::Store;
use mneme_cap::Capability;
use mneme_core::{
    ACTION_RECEIPT_VERSION, ActionReceipt, Draft, ForgetMode, ForgetTarget, LogicalKey, MnemeError,
    ObjectId, Root, TrustTier,
};
use mneme_crypto::KeyPair;

fn target_commit(target: &ForgetTarget) -> [u8; 32] {
    match target {
        ForgetTarget::LogicalKey(k) => k.hash(),
        ForgetTarget::ObjectId(id) => id.0,
    }
}

/// Deterministic action commit for `Store::remember` (pre-signing preimage input).
pub fn action_commit_remember(draft: &Draft) -> [u8; 32] {
    let key = LogicalKey {
        namespace: draft.namespace.clone(),
        name: draft.logical_name.clone(),
    };
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-action-remember-v1\x00");
    h.update(&key.hash());
    h.update(&[draft.kind.as_u8()]);
    *h.finalize().as_bytes()
}

/// Deterministic action commit for `Store::forget`.
pub fn action_commit_forget(target: &ForgetTarget, mode: ForgetMode) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-action-forget-v1\x00");
    h.update(&target_commit(target));
    h.update(&[mode as u8]);
    *h.finalize().as_bytes()
}

/// Deterministic action commit for `Store::promote`.
pub fn action_commit_promote(id: &ObjectId, to: TrustTier) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-action-promote-v1\x00");
    h.update(id.as_bytes());
    h.update(&[to.as_u8()]);
    *h.finalize().as_bytes()
}

/// Enforce optional/mandatory `ActionReceipt` on external store paths (P3-1).
pub fn enforce_external_action(
    receipt: Option<&ActionReceipt>,
    action_commit: [u8; 32],
    cap: &Capability,
    root: &Root,
) -> Result<(), MnemeError> {
    #[cfg(not(feature = "phase_iii_verify"))]
    {
        #[cfg(feature = "phase_iii_require_action")]
        if receipt.is_none() {
            return Err(MnemeError::ProvenanceBroken);
        }
        let _ = (receipt, action_commit, cap, root);
        Ok(())
    }

    #[cfg(feature = "phase_iii_verify")]
    {
        match receipt {
            Some(r) => mneme_account::verify_action_receipt_bound(r, action_commit, cap, root),
            None => {
                #[cfg(feature = "phase_iii_require_action")]
                {
                    Err(MnemeError::ProvenanceBroken)
                }
                #[cfg(not(feature = "phase_iii_require_action"))]
                {
                    Ok(())
                }
            }
        }
    }
}

impl Store {
    pub fn bind_external_action(
        &self,
        action_commit: [u8; 32],
        cap: &Capability,
        sanctioner_signer: &KeyPair,
        cognition_cert_commit: Option<[u8; 32]>,
    ) -> Result<ActionReceipt, MnemeError> {
        #[cfg(not(feature = "phase_iii_bind"))]
        {
            let _ = (action_commit, cap, sanctioner_signer, cognition_cert_commit);
            Err(MnemeError::UnsupportedVersion {
                got: ACTION_RECEIPT_VERSION,
            })
        }

        #[cfg(feature = "phase_iii_bind")]
        {
            self.verify_cap(cap)?;
            let root = self.current_root()?;
            mneme_account::bind_action(
                action_commit,
                cap.inner(),
                sanctioner_signer,
                &root,
                cognition_cert_commit,
            )
        }
    }
}
