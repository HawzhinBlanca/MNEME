#![forbid(unsafe_code)]
#![deny(warnings)]

//! Context gate attestation helpers (Phase II/IV scaffolding).

use mneme_core::{
    AssemblyProfile, ContextConsumptionAttestation, ENCLAVE_REPORT_PLACEHOLDER_STATUS,
    EnclaveReportPlaceholder, MnemeError, OutputBinding, hash_certified_memory_set,
    hash_context_assembled, hash_model_output,
};

pub const PHASE_II_GATE_OPEN: bool = false;

pub const CONTEXT_GATE_STATUS: &str =
    "context gate attestation verifier stub - gate closed until remote attestation ships";

pub fn verify_consumption_attestation(
    attestation: &ContextConsumptionAttestation,
    assembled_context: &[u8],
    certified_memory_set_payload: &[u8],
    expected_profile: &AssemblyProfile,
) -> Result<(), MnemeError> {
    let _ = PHASE_II_GATE_OPEN;
    if &attestation.assembly_profile != expected_profile {
        return Err(MnemeError::SchemaDrift);
    }
    let context_hash = hash_context_assembled(assembled_context);
    if attestation.context_hash != context_hash {
        return Err(MnemeError::ProvenanceBroken);
    }
    let certified_hash = hash_certified_memory_set(certified_memory_set_payload);
    if attestation.certified_memory_set_hash != certified_hash {
        return Err(MnemeError::ProvenanceBroken);
    }
    Ok(())
}

pub fn verify_output_binding(
    binding: &OutputBinding,
    assembled_context: &[u8],
    model_output: &[u8],
    model_identity: &[u8; 32],
) -> Result<(), MnemeError> {
    if binding.context_hash != hash_context_assembled(assembled_context) {
        return Err(MnemeError::ProvenanceBroken);
    }
    if binding.output_hash != hash_model_output(model_output) {
        return Err(MnemeError::ProvenanceBroken);
    }
    if binding.model_identity != *model_identity {
        return Err(MnemeError::SchemaDrift);
    }
    Ok(())
}

pub fn verify_enclave_report_placeholder(
    report: &EnclaveReportPlaceholder,
) -> Result<(), MnemeError> {
    if report.status != ENCLAVE_REPORT_PLACEHOLDER_STATUS || report.report_digest != [0u8; 32] {
        return Err(MnemeError::CertificateInvalid);
    }
    let _ = PHASE_II_GATE_OPEN;
    Err(MnemeError::CertificateInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{
        decode_enclave_report_placeholder, decode_output_binding,
        encode_enclave_report_placeholder, encode_output_binding,
    };

    fn sample_attestation() -> (
        Vec<u8>,
        Vec<u8>,
        AssemblyProfile,
        ContextConsumptionAttestation,
    ) {
        let assembled = b"prompt-fragment".to_vec();
        let certified = assembled.clone();
        let profile = AssemblyProfile { id: [0x42; 32] };
        let attestation = ContextConsumptionAttestation {
            assembly_profile: profile,
            context_hash: hash_context_assembled(&assembled),
            certified_memory_set_hash: hash_certified_memory_set(&certified),
        };
        (assembled, certified, profile, attestation)
    }

    #[test]
    fn consumption_attestation_accepts_matching_hashes() {
        let (a, c, p, att) = sample_attestation();
        verify_consumption_attestation(&att, &a, &c, &p).unwrap();
    }

    #[test]
    fn enclave_placeholder_fails_closed() {
        let report = EnclaveReportPlaceholder::honest_absent();
        let wire = encode_enclave_report_placeholder(&report).unwrap();
        let decoded = decode_enclave_report_placeholder(&wire).unwrap();
        assert_eq!(
            verify_enclave_report_placeholder(&decoded),
            Err(MnemeError::CertificateInvalid)
        );
    }

    #[test]
    fn output_binding_roundtrip() {
        let assembled = b"ctx";
        let out = b"out";
        let id = [0x66; 32];
        let binding = OutputBinding {
            context_hash: hash_context_assembled(assembled),
            output_hash: hash_model_output(out),
            model_identity: id,
        };
        let wire = encode_output_binding(&binding).unwrap();
        verify_output_binding(&decode_output_binding(&wire).unwrap(), assembled, out, &id).unwrap();
    }
}
