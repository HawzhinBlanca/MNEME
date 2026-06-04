//! Phase II strict context-gate recall (production-adjacent; `context_gate` feature).

use crate::Store;
use mneme_cap::Capability;
use mneme_core::{
    ContextConsumptionAttestation, Entry, MnemeError, OutputBinding, Procedure, Query,
};
use mneme_gate::PHASE_II_GATE_OPEN;
use mneme_index::apply_context_gate_strict;

pub struct ContextGateRecallOpts<'a> {
    pub attestation: &'a ContextConsumptionAttestation,
    pub output_binding: Option<&'a OutputBinding>,
    pub model_output: Option<&'a [u8]>,
    pub model_identity: Option<&'a [u8; 32]>,
}

impl Store {
    pub fn recall_verified_context_gated(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        opts: &ContextGateRecallOpts<'_>,
    ) -> Result<Vec<Entry>, MnemeError> {
        if !PHASE_II_GATE_OPEN {
            return Err(MnemeError::UnsupportedVersion { got: 0 });
        }
        let entries = self.recall_verified(query, proc, cap)?;
        let ids: Vec<_> = entries.iter().map(|e| e.id).collect();
        apply_context_gate_strict(
            &ids,
            &entries,
            opts.attestation,
            opts.output_binding,
            opts.model_output,
            opts.model_identity,
        )?;
        Ok(entries)
    }
}
