//! Forget path with SMT tombstone + crypto-shred (§9.1, §13).

use crate::Store;
use crate::layout;
use crate::pause;
use mneme_cap::Capability;
use mneme_core::{ForgetMode, ForgetTarget, MnemeError};
use mneme_forget::{
    RedactForgetInput, ShredForgetInput, forget_redact, forget_shred, object_id_for_key,
};

impl Store {
    pub fn forget(
        &mut self,
        target: ForgetTarget,
        cap: &Capability,
        mode: ForgetMode,
    ) -> Result<(layout::Tombstone, mneme_core::Root), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_forget() {
            return Err(MnemeError::CapDenied);
        }
        let logical_key = match target {
            ForgetTarget::LogicalKey(k) => k,
            ForgetTarget::ObjectId(_) => return Err(MnemeError::CapDenied),
        };
        let key_hash = logical_key.hash();
        if !self.key_index.contains_live(&logical_key) {
            return Err(MnemeError::Forgotten);
        }

        let object_id = object_id_for_key(self.key_index.tree(), &key_hash)?;
        let object_bytes = self.objects.get(&object_id).cloned();

        layout::begin_transaction(&self.path)?;
        pause::checkpoint(pause::AFTER_BEGIN_INCOMPLETE)?;
        let result = (|| -> Result<(layout::Tombstone, mneme_core::Root), MnemeError> {
            match mode {
                ForgetMode::Shred => {
                    forget_shred(ShredForgetInput {
                        logical_key: &logical_key,
                        key_index: self.key_index.tree_mut(),
                        vault: &mut self.vault,
                        object_bytes: object_bytes.as_deref(),
                    })?;
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
            layout::persist_embeddings(&self.path, self)?;
            pause::checkpoint(pause::AFTER_PERSIST_INDEX)?;
            self.rebuild_semantic_index()?;
            self.commit_root_inner()?;
            pause::checkpoint(pause::BEFORE_COMMIT_INCOMPLETE)?;
            Ok((
                layout::Tombstone {
                    logical_key: logical_key.clone(),
                    key_hash,
                },
                self.current_root(),
            ))
        })();

        match result {
            Ok(v) => {
                layout::commit_transaction(&self.path)?;
                Ok(v)
            }
            Err(MnemeError::IncompleteTransaction) => Err(MnemeError::IncompleteTransaction),
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }
}
