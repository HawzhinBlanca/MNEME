#![forbid(unsafe_code)]
#![deny(warnings)]

//! Context gate attestation helpers (Phase II/IV scaffolding).
//!
//! This crate stays fail-closed: it only verifies that an attestation matches
//! the assembled prompt bytes and certified memory-set payload. It does **not**
//! open any production gate or claim remote-attestation coverage.

use mneme_core::{
    AssemblyProfile, ContextConsumptionAttestation, MnemeError, hash_certified_memory_set,
    hash_context_assembled,
};

/// Text status for observability surfaces; gate remains closed.
pub const CONTEXT_GATE_STATUS: &str =
    "context gate attestation verifier stub - gate closed until remote attestation ships";

/// Verify that the provided attestation matches the assembled context digests.
pub fn verify_consumption_attestation(
    attestation: &ContextConsumptionAttestation,
    assembled_context: &[u8],
    certified_memory_set_payload: &[u8],
    expected_profile: &AssemblyProfile,
) -> Result<(), MnemeError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{
        decode_context_consumption_attestation, encode_context_consumption_attestation,
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
        let context_hash = hash_context_assembled(&assembled);
        let certified_memory_set_hash = hash_certified_memory_set(&certified);
        let attestation = ContextConsumptionAttestation {
            assembly_profile: profile,
            context_hash,
            certified_memory_set_hash,
        };
        (assembled, certified, profile, attestation)
    }

    #[test]
    fn consumption_attestation_accepts_matching_hashes() {
        let (assembled, certified, profile, attestation) = sample_attestation();
        verify_consumption_attestation(&attestation, &assembled, &certified, &profile).unwrap();
    }

    #[test]
    fn context_and_certified_memory_hashes_are_domain_separated() {
        let payload = b"same bytes";
        assert_ne!(
            hash_context_assembled(payload),
            hash_certified_memory_set(payload)
        );
    }

    #[test]
    fn consumption_attestation_rejects_tampering() {
        let (assembled, certified, profile, mut attestation) = sample_attestation();
        attestation.context_hash[0] ^= 0x01;
        assert_eq!(
            verify_consumption_attestation(&attestation, &assembled, &certified, &profile),
            Err(MnemeError::ProvenanceBroken)
        );
    }

    #[test]
    fn profile_mismatch_fails_closed() {
        let (assembled, certified, _profile, attestation) = sample_attestation();
        let other_profile = AssemblyProfile { id: [0x99; 32] };
        assert_eq!(
            verify_consumption_attestation(&attestation, &assembled, &certified, &other_profile),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn certified_hash_mismatch_fails_closed() {
        let (assembled, mut certified, profile, attestation) = sample_attestation();
        certified[0] ^= 0x02;
        assert_eq!(
            verify_consumption_attestation(&attestation, &assembled, &certified, &profile),
            Err(MnemeError::ProvenanceBroken)
        );
    }

    #[test]
    fn status_string_marks_gate_closed() {
        assert!(
            CONTEXT_GATE_STATUS.contains("gate closed"),
            "status string must declare gate closed"
        );
    }

    #[test]
    fn malformed_cca_wire_fails_closed_before_verify() {
        let garbage_inputs: &[&[u8]] = &[b"", b"\xff\xfe", b"not-a-cca-wire"];
        for garbage in garbage_inputs {
            assert!(
                decode_context_consumption_attestation(garbage).is_err(),
                "malformed CCA wire must fail closed before verify"
            );
        }
    }

    #[test]
    fn cca_wire_roundtrip_then_verify_accepts_matching_digests() {
        let (assembled, certified, profile, attestation) = sample_attestation();
        let wire = encode_context_consumption_attestation(&attestation).unwrap();
        let decoded = decode_context_consumption_attestation(&wire).unwrap();
        verify_consumption_attestation(&decoded, &assembled, &certified, &profile).unwrap();
    }

    #[test]
    fn cca_wire_roundtrip_rejects_tampered_context_hash() {
        let (assembled, certified, profile, mut attestation) = sample_attestation();
        attestation.context_hash[0] ^= 0x01;
        let wire = encode_context_consumption_attestation(&attestation).unwrap();
        let decoded = decode_context_consumption_attestation(&wire).unwrap();
        assert_eq!(
            verify_consumption_attestation(&decoded, &assembled, &certified, &profile),
            Err(MnemeError::ProvenanceBroken)
        );
    }
}
