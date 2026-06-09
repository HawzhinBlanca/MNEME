//! Phase II strict context-gate recall (production-adjacent; `context_gate` feature).

use crate::Store;
use mneme_cap::Capability;
use mneme_core::{
    ContextConsumptionAttestation, Entry, MnemeError, OutputBinding, Procedure, Query,
};
use mneme_gate::PHASE_II_GATE_OPEN;
use mneme_index::apply_context_gate_strict;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreContextGateFailure {
    PhaseGateClosed,
}

fn store_context_gate_failure_to_mneme(failure: StoreContextGateFailure) -> MnemeError {
    match failure {
        StoreContextGateFailure::PhaseGateClosed => MnemeError::UnsupportedVersion { got: 0 },
    }
}

fn store_context_gate_closed_error() -> MnemeError {
    store_context_gate_failure_to_mneme(StoreContextGateFailure::PhaseGateClosed)
}

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
            return Err(store_context_gate_closed_error());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store_context_gate_production_source() -> &'static str {
        include_str!("context_gate.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("context_gate.rs should keep tests after production code")
    }

    #[test]
    fn store_context_gate_failures_are_classified_not_unsupported_version_collapsed() {
        let production = store_context_gate_production_source();

        for forbidden in [
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !production.contains(forbidden),
                "store context-gate production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum StoreContextGateFailure",
            "fn store_context_gate_failure_to_mneme(",
            "fn store_context_gate_closed_error(",
            "StoreContextGateFailure::PhaseGateClosed",
        ] {
            assert!(
                production.contains(required),
                "store context-gate production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn store_context_gate_failure_classifier_preserves_public_error() {
        assert_eq!(
            store_context_gate_failure_to_mneme(StoreContextGateFailure::PhaseGateClosed),
            MnemeError::UnsupportedVersion { got: 0 }
        );
        assert_eq!(
            store_context_gate_closed_error(),
            MnemeError::UnsupportedVersion { got: 0 }
        );
    }
}
