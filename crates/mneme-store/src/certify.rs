//! Cognition Certificate v1 issuance (Phase I P1-4).

use crate::Store;
use crate::layout;
use mneme_cap::Capability;
use mneme_core::{AsOf, MnemeError, Procedure, Query, RetrievalProofLevel};
use mneme_index::assemble_cognition_certificate_v1;

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
        let receipt = self
            .semantic
            .recall_receipt_zkann(proc, embedding, root.preimage_hash, level)
            .map_err(crate::index_err)?;
        assemble_cognition_certificate_v1(&stored, &receipt, Some(AsOf::RootSeq(root.sequence)))
    }
}
