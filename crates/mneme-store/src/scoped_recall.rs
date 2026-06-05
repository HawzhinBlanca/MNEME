//! Provenance-scoped verified semantic recall (Phase I P1-3).

use crate::Store;
use mneme_cap::Capability;
use mneme_core::{Entry, MnemeError, Procedure, ProvenanceFilter, Query};
#[cfg(feature = "experimental_semantic")]
use mneme_index::{
    align_scoped_receipt_results, build_provenance_attestation, verify_provenance_attestation,
    verify_semantic_receipt_vo_zkann,
};
#[cfg(feature = "experimental_semantic")]
use mneme_verify::{RecallContext, SemanticRecallInput, verify_semantic_recall};

impl Store {
    /// Semantic recall whose receipt proves a provenance filter was honored (exact path).
    #[cfg(not(feature = "experimental_semantic"))]
    pub fn recall_verified_scoped(
        &self,
        _query: &Query,
        _proc: &Procedure,
        _cap: &Capability,
        _filter: &ProvenanceFilter,
    ) -> Result<Vec<Entry>, MnemeError> {
        Err(MnemeError::ProcedureMismatch)
    }

    /// Semantic recall whose receipt proves a provenance filter was honored (exact path).
    #[cfg(feature = "experimental_semantic")]
    pub fn recall_verified_scoped(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        filter: &ProvenanceFilter,
    ) -> Result<Vec<Entry>, MnemeError> {
        self.authorize_read(query, cap)?;
        let embedding = query
            .embedding
            .as_ref()
            .ok_or(MnemeError::ProcedureMismatch)?;
        let root = self.current_root()?;
        let mut receipt = self
            .semantic
            .recall_receipt_zkann(
                proc,
                embedding,
                root.preimage_hash,
                mneme_core::RetrievalProofLevel::ExactDominance,
            )
            .map_err(crate::index_err)?;
        let mut seed_ids: Vec<[u8; 32]> = receipt
            .verification_object
            .candidates
            .iter()
            .map(|(id, _, _)| *id.as_bytes())
            .collect();
        seed_ids.sort();
        seed_ids.dedup();
        let objects = crate::provenance_objects_for_ids(&self.objects, &seed_ids)?;
        receipt.provenance = Some(build_provenance_attestation(&receipt, filter, &objects)?);
        let committed = receipt.verification_object.candidates.len();
        verify_semantic_receipt_vo_zkann(&receipt, proc, committed)?;
        align_scoped_receipt_results(&mut receipt, proc)?;
        verify_provenance_attestation(&receipt, proc, &objects)?;
        let ctx = RecallContext {
            key_index: self.key_index.tree(),
            dag: &self.dag,
            objects: &objects,
            previous_root: self.roots.get(self.roots.len().wrapping_sub(2)),
        };
        let input = SemanticRecallInput { receipt, root };
        let mut entries = verify_semantic_recall(&input, proc, query, &self.trust, &ctx)?;
        self.decrypt_entries(&mut entries)?;
        Ok(entries)
    }
}
