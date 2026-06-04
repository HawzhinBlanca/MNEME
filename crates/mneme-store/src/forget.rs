//! Forget path with SMT tombstone + crypto-shred (§9.1, §13).

use crate::Store;
use crate::action::{action_commit_forget, enforce_external_action};
use crate::layout;
use crate::pause;
use mneme_cap::Capability;
use mneme_core::{ActionReceipt, ForgetMode, ForgetTarget, MnemeError};
use mneme_forget::{
    RedactForgetInput, ShredForgetInput, ShredOutcome, forget_redact, forget_shred,
    object_id_for_key,
};

/// Outcome of a verified shred forget when P3-2 store features are enabled.
#[cfg(feature = "phase_iii_prove_forget")]
pub struct ForgetProven {
    pub tombstone: layout::Tombstone,
    pub root: mneme_core::Root,
    pub proof: mneme_core::ForgetProof,
}

impl Store {
    pub fn forget(
        &mut self,
        target: ForgetTarget,
        cap: &Capability,
        mode: ForgetMode,
    ) -> Result<(layout::Tombstone, mneme_core::Root), MnemeError> {
        self.forget_with_action(target, cap, mode, None)
    }

    pub fn forget_with_action(
        &mut self,
        target: ForgetTarget,
        cap: &Capability,
        mode: ForgetMode,
        action_receipt: Option<&ActionReceipt>,
    ) -> Result<(layout::Tombstone, mneme_core::Root), MnemeError> {
        let outcome = self.forget_internal(target, cap, mode, action_receipt)?;
        Ok((outcome.tombstone, outcome.root))
    }

    /// Shred forget with a returned `ForgetProof` when `phase_iii_prove_forget` is enabled.
    #[cfg(feature = "phase_iii_prove_forget")]
    pub fn forget_with_proof(
        &mut self,
        target: ForgetTarget,
        cap: &Capability,
        mode: ForgetMode,
        action_receipt: Option<&ActionReceipt>,
    ) -> Result<ForgetProven, MnemeError> {
        let outcome = self.forget_internal(target, cap, mode, action_receipt)?;
        Ok(ForgetProven {
            tombstone: outcome.tombstone,
            root: outcome.root,
            proof: outcome.proof.ok_or(MnemeError::ProvenanceBroken)?,
        })
    }

    fn forget_internal(
        &mut self,
        target: ForgetTarget,
        cap: &Capability,
        mode: ForgetMode,
        action_receipt: Option<&ActionReceipt>,
    ) -> Result<ForgetInternalOutcome, MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_forget() {
            return Err(MnemeError::CapDenied);
        }
        let logical_key = match &target {
            ForgetTarget::LogicalKey(k) => k.clone(),
            ForgetTarget::ObjectId(_) => return Err(MnemeError::CapDenied),
        };
        let key_hash = logical_key.hash();
        if !self.key_index.contains_live(&logical_key) {
            return Err(MnemeError::Forgotten);
        }

        let pre_root = self.current_root()?;
        enforce_external_action(
            action_receipt,
            action_commit_forget(&target, mode),
            cap,
            &pre_root,
        )?;

        let object_id = object_id_for_key(self.key_index.tree(), &key_hash)?;
        let object_bytes = self.objects.get(&object_id).cloned();

        layout::begin_transaction(&self.path)?;
        pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
        let mut shred_outcome: Option<ShredOutcome> = None;
        let result = (|| -> Result<(layout::Tombstone, mneme_core::Root), MnemeError> {
            match mode {
                ForgetMode::Shred => {
                    let shred = forget_shred(ShredForgetInput {
                        logical_key: &logical_key,
                        key_index: self.key_index.tree_mut(),
                        vault: &mut *self.vault,
                        object_bytes: object_bytes.as_deref(),
                    })?;
                    shred_outcome = Some(shred);
                    self.key_to_object.remove(&key_hash);
                    self.embeddings.remove(&object_id);
                }
                ForgetMode::Redact => {
                    let bytes = object_bytes
                        .as_deref()
                        .ok_or(MnemeError::IndexPathInvalid)?;
                    let outcome = forget_redact(RedactForgetInput {
                        logical_key: &logical_key,
                        key_index: self.key_index.tree(),
                        object_bytes: bytes,
                        operator: &self.operator,
                        reason: "operator-redact",
                    })?;
                    self.objects
                        .insert(outcome.object_id, outcome.redacted_bytes.clone());
                    layout::write_object(&self.path, &outcome.object_id, &outcome.redacted_bytes)?;
                    layout::write_redaction_record(&self.path, &outcome.record)?;
                }
            }
            pause::checkpoint(pause::AFTER_KEY_INDEX)?;
            self.hlc.tick_local(self.hlc.wall_ms.saturating_add(1));
            layout::persist_key_index_tombstone(&self.path, &key_hash)?;
            if let ForgetMode::Shred = mode {
                layout::persist_embeddings_remove(&self.path, &object_id)?;
            }
            pause::checkpoint(pause::AFTER_PERSIST_INDEX)?;
            self.rebuild_semantic_index()?;
            self.commit_root_inner()?;
            pause::checkpoint(pause::BEFORE_COMMIT_INCOMPLETE)?;
            Ok((
                layout::Tombstone {
                    logical_key: logical_key.clone(),
                    key_hash,
                },
                self.current_root()?,
            ))
        })();

        match result {
            Ok((tombstone, root)) => {
                layout::commit_transaction(&self.path)?;
                #[cfg(feature = "phase_iii_prove_forget")]
                let proof = if mode != ForgetMode::Shred {
                    None
                } else {
                    let shred = shred_outcome.ok_or(MnemeError::ProvenanceBroken)?;
                    let absence = self.prove_absent(&logical_key)?;
                    let witness = mneme_account::ForgetProofWitness {
                        shred: &shred,
                        absence: &absence,
                    };
                    let proof = mneme_account::prove_forget(&target, mode, &root, None, &witness)?;
                    mneme_account::verify_forget_proof_bound(&proof, &root, &target, &shred)?;
                    if proof.root_bound != root.preimage_hash {
                        return Err(MnemeError::ReceiptRootMismatch);
                    }
                    if root.sequence <= pre_root.sequence {
                        return Err(MnemeError::RootReplayed);
                    }
                    Some(proof)
                };
                Ok(ForgetInternalOutcome {
                    tombstone,
                    root,
                    #[cfg(feature = "phase_iii_prove_forget")]
                    proof,
                })
            }
            Err(MnemeError::IncompleteTransaction) => Err(MnemeError::IncompleteTransaction),
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }
}

struct ForgetInternalOutcome {
    tombstone: layout::Tombstone,
    root: mneme_core::Root,
    #[cfg(feature = "phase_iii_prove_forget")]
    proof: Option<mneme_core::ForgetProof>,
}
