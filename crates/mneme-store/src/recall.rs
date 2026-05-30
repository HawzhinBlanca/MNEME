//! Key-index and semantic recall paths (blueprint §7, §9.2).

use crate::Recall;
use crate::Store;
use mneme_cap::Capability;
use mneme_core::{
    MnemeError, ObjectId, ObjectRecord, ObjectRef, Procedure, Query, TrustTier, from_bytes_strict,
};
use mneme_index::{SEMANTIC_BACKEND_ENABLED, is_key_index_procedure, procedure_id};

impl Store {
    /// Internal untrusted recall builder for [`Store::recall_verified`] (§7, INV-5).
    /// External callers must use [`Store::recall_verified`] or [`Store::recall_verified_default`].
    pub(crate) fn recall(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
    ) -> Result<Recall, MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_read(&query.logical_key.namespace, query.min_tier) {
            return Err(MnemeError::CapDenied);
        }
        let _pid = procedure_id(proc);
        let root = self.current_root()?;

        if is_key_index_procedure(proc) {
            let proof = self.key_index.prove_membership(&query.logical_key)?;
            self.enforce_min_tier(query, &ObjectId(proof.value))?;
            let receipt = mneme_core::Receipt {
                root_bound: root.preimage_hash,
                logical_key: query.logical_key.hash(),
                object_id: proof.value,
                membership_proof: proof.path,
                key_index_root: root.key_index_root,
                leaf_index: proof.leaf_index,
            };
            return Ok(Recall {
                entries: vec![ObjectRef {
                    id: mneme_core::ObjectId(proof.value),
                }],
                receipt: Some(receipt),
                semantic_receipt: None,
                root,
            });
        }

        if !SEMANTIC_BACKEND_ENABLED {
            return Err(MnemeError::ProcedureMismatch);
        }
        let embedding = query
            .embedding
            .as_ref()
            .ok_or(MnemeError::ProcedureMismatch)?;
        let (ids, _vo) = self
            .semantic
            .search_deterministic(proc, embedding)
            .map_err(index_err)?;
        if ids.is_empty() {
            return Err(MnemeError::IndexPathInvalid);
        }
        let receipt = self
            .semantic
            .recall_receipt(proc, embedding, root.preimage_hash)
            .map_err(index_err)?;
        Ok(Recall {
            entries: ids.iter().map(|id| ObjectRef { id: *id }).collect(),
            receipt: None,
            semantic_receipt: Some(receipt),
            root,
        })
    }
}

impl Store {
    fn enforce_min_tier(&self, query: &Query, id: &ObjectId) -> Result<(), MnemeError> {
        let bytes = self
            .objects
            .get(id.as_bytes())
            .ok_or(MnemeError::ObjectTampered)?;
        let record: ObjectRecord =
            from_bytes_strict(bytes).map_err(|_| MnemeError::ObjectTampered)?;
        let obj_tier = TrustTier::from_u8(record.trust_tier)?;
        if obj_tier < query.min_tier {
            return Err(MnemeError::BelowTierPolicy {
                required: query.min_tier.as_u8(),
                got: obj_tier.as_u8(),
            });
        }
        Ok(())
    }
}

fn index_err(e: mneme_index::IndexError) -> MnemeError {
    match e {
        mneme_index::IndexError::SemanticNotImplemented => MnemeError::ProcedureMismatch,
        mneme_index::IndexError::DuplicateObject | mneme_index::IndexError::ObjectNotIndexed => {
            MnemeError::IndexPathInvalid
        }
    }
}
