//! Cognition Certificate v1 issuance (Phase I P1-4).

use crate::Store;
use crate::layout;
use mneme_cap::Capability;
#[cfg(feature = "context_gate")]
use mneme_context::{
    ASSEMBLY_PROFILE_V1, assemble_verified_context, consumption_attestation_from_assembly,
};
use mneme_core::{AsOf, MnemeError, Procedure, Query, RetrievalProofLevel};
use mneme_index::assemble_cognition_certificate_v1;
#[cfg(feature = "context_gate")]
use mneme_index::{ContextAttestationDraft, assemble_cognition_certificate_v2_draft};

impl Store {
    /// Build a self-contained Certificate v1 for a semantic recall at the current HEAD.
    pub fn issue_cognition_certificate_v1(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        level: RetrievalProofLevel,
    ) -> Result<Vec<u8>, MnemeError> {
        self.authorize_read(query, cap)?;
        if query.embedding.is_none() {
            return Err(MnemeError::ProcedureMismatch);
        }
        let root = self.current_root()?;
        let stored = layout::read_head(&self.path)?;
        if stored.preimage_hash != root.preimage_hash {
            return Err(MnemeError::RootInconsistent);
        }
        let embedding = query
            .embedding
            .as_ref()
            .ok_or(MnemeError::ProcedureMismatch)?;
        let mut receipt = self
            .semantic
            .recall_receipt_zkann(proc, embedding, root.preimage_hash, level)
            .map_err(crate::index_err)?;
        let run_digest =
            mneme_robr::compute_run_digest_from_ids(&receipt.verification_object.result_ids);
        receipt.run_digest = Some(run_digest);
        assemble_cognition_certificate_v1(&stored, &receipt, Some(AsOf::RootSeq(root.sequence)))
    }

    #[cfg(feature = "context_gate")]
    pub fn issue_cognition_certificate_v2_strict(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        level: RetrievalProofLevel,
    ) -> Result<Vec<u8>, MnemeError> {
        self.authorize_read(query, cap)?;
        if query.embedding.is_none() {
            return Err(MnemeError::ProcedureMismatch);
        }
        let root = self.current_root()?;
        let stored = layout::read_head(&self.path)?;
        if stored.preimage_hash != root.preimage_hash {
            return Err(MnemeError::RootInconsistent);
        }
        let embedding = query
            .embedding
            .as_ref()
            .ok_or(MnemeError::ProcedureMismatch)?;
        let receipt = self
            .semantic
            .recall_receipt_zkann(proc, embedding, root.preimage_hash, level)
            .map_err(crate::index_err)?;
        let entries = self.recall_verified(query, proc, cap)?;
        let ids: Vec<_> = entries.iter().map(|e| e.id).collect();
        let att = consumption_attestation_from_assembly(&assemble_verified_context(
            &ids,
            &entries,
            ASSEMBLY_PROFILE_V1,
        )?);
        let attestation = ContextAttestationDraft::strict(att, None);
        assemble_cognition_certificate_v2_draft(
            &stored,
            &receipt,
            Some(AsOf::RootSeq(root.sequence)),
            attestation,
        )
    }
}
