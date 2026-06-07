//! Phase II strict context-gate helpers (production-adjacent paths behind `context_gate`).

use mneme_context::ASSEMBLY_PROFILE_V1;
use mneme_core::{ContextConsumptionAttestation, Entry, MnemeError, ObjectId, OutputBinding};
use mneme_gate::{
    PHASE_II_GATE_OPEN, verify_consumption_attestation_strict, verify_output_binding_strict,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexContextGateFailure {
    PhaseGateClosed,
    ModelOutputMissing,
    ModelIdentityMissing,
}

fn index_context_gate_failure_to_mneme(failure: IndexContextGateFailure) -> MnemeError {
    match failure {
        IndexContextGateFailure::PhaseGateClosed => MnemeError::UnsupportedVersion { got: 0 },
        IndexContextGateFailure::ModelOutputMissing
        | IndexContextGateFailure::ModelIdentityMissing => MnemeError::CertificateInvalid,
    }
}

fn index_context_gate_closed_error() -> MnemeError {
    index_context_gate_failure_to_mneme(IndexContextGateFailure::PhaseGateClosed)
}

fn index_context_gate_invalid_error(failure: IndexContextGateFailure) -> MnemeError {
    index_context_gate_failure_to_mneme(failure)
}

pub const CONTEXT_GATE_STRICT_STATUS: &str = "strict_context_gate_v1";

pub fn apply_context_gate_strict(
    result_ids: &[ObjectId],
    entries: &[Entry],
    attestation: &ContextConsumptionAttestation,
    output_binding: Option<&OutputBinding>,
    model_output: Option<&[u8]>,
    model_identity: Option<&[u8; 32]>,
) -> Result<(), MnemeError> {
    if !PHASE_II_GATE_OPEN {
        return Err(index_context_gate_closed_error());
    }
    verify_consumption_attestation_strict(attestation, result_ids, entries, &ASSEMBLY_PROFILE_V1)?;
    if let Some(binding) = output_binding {
        verify_output_binding_strict(
            binding,
            result_ids,
            entries,
            model_output.ok_or_else(|| {
                index_context_gate_invalid_error(IndexContextGateFailure::ModelOutputMissing)
            })?,
            model_identity.ok_or_else(|| {
                index_context_gate_invalid_error(IndexContextGateFailure::ModelIdentityMissing)
            })?,
            &ASSEMBLY_PROFILE_V1,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_context_gate_production_source() -> &'static str {
        include_str!("context_gate.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("context_gate.rs should keep tests after production code")
    }

    #[test]
    fn index_context_gate_failures_are_classified_not_unsupported_version_collapsed() {
        let production = index_context_gate_production_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !production.contains(forbidden),
                "index context-gate production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum IndexContextGateFailure",
            "fn index_context_gate_failure_to_mneme(",
            "fn index_context_gate_closed_error(",
            "fn index_context_gate_invalid_error(",
            "IndexContextGateFailure::PhaseGateClosed",
            "IndexContextGateFailure::ModelOutputMissing",
            "IndexContextGateFailure::ModelIdentityMissing",
        ] {
            assert!(
                production.contains(required),
                "index context-gate production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn index_context_gate_failure_classifier_preserves_public_error() {
        assert_eq!(
            index_context_gate_failure_to_mneme(IndexContextGateFailure::PhaseGateClosed),
            MnemeError::UnsupportedVersion { got: 0 }
        );
        assert_eq!(
            index_context_gate_closed_error(),
            MnemeError::UnsupportedVersion { got: 0 }
        );
        for failure in [
            IndexContextGateFailure::ModelOutputMissing,
            IndexContextGateFailure::ModelIdentityMissing,
        ] {
            assert_eq!(
                index_context_gate_failure_to_mneme(failure),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                index_context_gate_invalid_error(failure),
                MnemeError::CertificateInvalid
            );
        }
    }
}
