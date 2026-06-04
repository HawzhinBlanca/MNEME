//! Phase II strict context-gate helpers (production-adjacent paths behind `context_gate`).

use mneme_context::ASSEMBLY_PROFILE_V1;
use mneme_core::{ContextConsumptionAttestation, Entry, MnemeError, ObjectId, OutputBinding};
use mneme_gate::{PHASE_II_GATE_OPEN, verify_consumption_attestation_strict, verify_output_binding_strict};

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
        return Err(MnemeError::UnsupportedVersion { got: 0 });
    }
    verify_consumption_attestation_strict(attestation, result_ids, entries, &ASSEMBLY_PROFILE_V1)?;
    if let Some(binding) = output_binding {
        verify_output_binding_strict(
            binding,
            result_ids,
            entries,
            model_output.ok_or(MnemeError::CertificateInvalid)?,
            model_identity.ok_or(MnemeError::CertificateInvalid)?,
            &ASSEMBLY_PROFILE_V1,
        )?;
    }
    Ok(())
}
