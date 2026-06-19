//! Phase III external-action binding (P3-1). Gated by `phase_iii_bind` / `phase_iii_verify`.

use crate::Store;
use mneme_cap::Capability;
use mneme_core::{
    ActionReceipt, Draft, ForgetMode, ForgetTarget, LogicalKey, MnemeError, ObjectId, Root,
    TrustTier,
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
    /// Mint an `ActionReceipt` for an external action commit (P3-1).
    ///
    /// Fail-closed unless the store's own **`phase_iii_bind`** feature is enabled.
    /// Workspace feature unification can make `mneme-account/phase_iii_bind_action`
    /// available transitively (e.g. via `phase_iii_prove_forget`); keying the gate
    /// to the store's own feature ensures the bind path does not silently open in a
    /// build that never asked for it.
    pub fn bind_external_action(
        &self,
        action_commit: [u8; 32],
        cap: &Capability,
        sanctioner_signer: &KeyPair,
        cognition_cert_commit: Option<[u8; 32]>,
    ) -> Result<ActionReceipt, MnemeError> {
        self.verify_cap(cap)?;
        let root = self.current_root()?;
        #[cfg(feature = "phase_iii_bind")]
        {
            mneme_account::bind_action(
                action_commit,
                cap.inner(),
                sanctioner_signer,
                &root,
                cognition_cert_commit,
            )
        }
        #[cfg(not(feature = "phase_iii_bind"))]
        {
            let _ = (
                action_commit,
                cap,
                sanctioner_signer,
                cognition_cert_commit,
                root,
            );
            // Fail closed: the action-provenance binding cannot be established when
            // the store was not built with phase_iii_bind.
            Err(MnemeError::ProvenanceBroken)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{ForgetMode, ForgetTarget, LogicalKey, MemoryKind, ObjectId, TrustTier};

    fn make_key(ns: &str, name: &str) -> LogicalKey {
        LogicalKey {
            namespace: ns.to_string(),
            name: name.to_string(),
        }
    }

    /// ACTION-1: action_commit_forget is deterministic.
    #[test]
    fn forget_commit_is_deterministic() {
        let target = ForgetTarget::LogicalKey(make_key("ns", "key"));
        let a = action_commit_forget(&target, ForgetMode::Shred);
        let b = action_commit_forget(&target, ForgetMode::Shred);
        assert_eq!(a, b, "action_commit_forget must be deterministic");
    }

    /// ACTION-2: Shred and Redact modes produce different commits.
    #[test]
    fn forget_commit_mode_distinguishes_shred_vs_redact() {
        let target = ForgetTarget::LogicalKey(make_key("ns", "key"));
        let shred = action_commit_forget(&target, ForgetMode::Shred);
        let redact = action_commit_forget(&target, ForgetMode::Redact);
        assert_ne!(
            shred, redact,
            "Shred and Redact must produce different action commits"
        );
    }

    /// ACTION-3: Different keys produce different forget commits.
    #[test]
    fn forget_commit_domain_separates_keys() {
        let t1 = ForgetTarget::LogicalKey(make_key("ns", "key1"));
        let t2 = ForgetTarget::LogicalKey(make_key("ns", "key2"));
        assert_ne!(
            action_commit_forget(&t1, ForgetMode::Shred),
            action_commit_forget(&t2, ForgetMode::Shred),
            "different keys must produce different action commits",
        );
    }

    /// ACTION-4: action_commit_remember is deterministic and separates MemoryKind.
    #[test]
    fn remember_commit_is_deterministic_and_kind_separates() {
        let draft_ep = mneme_core::Draft {
            namespace: "ns".to_string(),
            logical_name: "name".to_string(),
            kind: MemoryKind::Episodic,
            body: vec![],
            parent_ids: vec![],
            session: [0u8; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        let draft_id = mneme_core::Draft {
            namespace: "ns".to_string(),
            logical_name: "name".to_string(),
            kind: MemoryKind::Identity,
            body: vec![],
            parent_ids: vec![],
            session: [0u8; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        let a = action_commit_remember(&draft_ep);
        let b = action_commit_remember(&draft_ep);
        assert_eq!(a, b, "action_commit_remember must be deterministic");
        let c = action_commit_remember(&draft_id);
        assert_ne!(a, c, "different MemoryKind must produce different commits");
    }

    /// ACTION-5: remember, forget, promote commits are mutually domain-separated.
    #[test]
    fn action_commits_are_cross_domain_separated() {
        let target = ForgetTarget::LogicalKey(make_key("ns", "k"));
        let draft = mneme_core::Draft {
            namespace: "ns".to_string(),
            logical_name: "k".to_string(),
            kind: MemoryKind::Episodic,
            body: vec![],
            parent_ids: vec![],
            session: [0u8; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        let id = ObjectId([0x01u8; 32]);
        let r = action_commit_remember(&draft);
        let f = action_commit_forget(&target, ForgetMode::Shred);
        let p = action_commit_promote(&id, TrustTier::Trusted);
        assert_ne!(r, f, "remember and forget must be domain-separated");
        assert_ne!(r, p, "remember and promote must be domain-separated");
        assert_ne!(f, p, "forget and promote must be domain-separated");
    }
}
