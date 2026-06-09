//! Deterministic context assembly (Phase II P2-3).

use mneme_core::{
    AssemblyProfile, ContextConsumptionAttestation, Entry, MnemeError, ObjectId, OutputBinding,
    hash_certified_memory_set, hash_context_assembled, hash_model_output,
};

/// Frozen assembly profile v1: canonical prompt layout `MNEME-CTX-ASM-v1`.
/// `id` = BLAKE3(`MNEME-ASM-PROFILE-v1\x00`).
pub const ASSEMBLY_PROFILE_V1: AssemblyProfile = AssemblyProfile {
    id: [
        0x81, 0x6a, 0x3d, 0x80, 0x6e, 0xc4, 0xb0, 0x4c, 0x3c, 0x69, 0x12, 0xe3, 0x5a, 0x7e, 0xcd,
        0x0f, 0xd5, 0x69, 0xce, 0x5b, 0x3e, 0x04, 0x02, 0x89, 0xdd, 0x41, 0x07, 0xbe, 0xa2, 0xc3,
        0xd1, 0x94,
    ],
};

const PROMPT_MAGIC: &[u8] = b"MNEME-CTX-ASM-v1\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssemblyFailure {
    UnsupportedProfile,
}

fn assembly_failure_to_mneme(failure: AssemblyFailure) -> MnemeError {
    match failure {
        AssemblyFailure::UnsupportedProfile => MnemeError::SchemaDrift,
    }
}

fn unsupported_assembly_profile_error() -> MnemeError {
    assembly_failure_to_mneme(AssemblyFailure::UnsupportedProfile)
}

/// Outcome of deterministic assembly: prompt bytes + domain-separated digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssemblyOutcome {
    pub assembled_bytes: Vec<u8>,
    pub context_hash: [u8; 32],
    pub certified_memory_set_hash: [u8; 32],
    pub profile: AssemblyProfile,
}

/// Build the canonical certified-set preimage: `count_le ‖ (object_id ‖ content_commit)*`.
pub fn certified_memory_set_payload(result_ids: &[ObjectId]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + result_ids.len() * 64);
    payload.extend_from_slice(&(result_ids.len() as u32).to_le_bytes());
    for id in result_ids {
        payload.extend_from_slice(id.as_bytes());
        // INV-1: content commit == object identity for object nodes.
        payload.extend_from_slice(id.as_bytes());
    }
    payload
}

/// Encode the v1 prompt wire: magic, then for each entry in `result_ids` order:
/// `object_id ‖ payload`.
pub fn encode_assembled_prompt_v1(result_ids: &[ObjectId], payloads: &[&[u8]]) -> Vec<u8> {
    debug_assert_eq!(result_ids.len(), payloads.len());
    let mut out = Vec::new();
    out.extend_from_slice(PROMPT_MAGIC);
    for (id, body) in result_ids.iter().zip(payloads) {
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Assemble the model context from verified entries in procedure-declared `result_ids` order.
///
/// Each entry's `id` must match the corresponding `result_ids` slot and its record identity.
/// Host clock, locale, and map iteration order must not influence the output.
pub fn assemble_verified_context(
    result_ids: &[ObjectId],
    entries: &[Entry],
    profile: AssemblyProfile,
) -> Result<AssemblyOutcome, MnemeError> {
    if result_ids.len() != entries.len() {
        return Err(MnemeError::ProcedureMismatch);
    }
    if profile != ASSEMBLY_PROFILE_V1 {
        return Err(unsupported_assembly_profile_error());
    }

    let mut payloads: Vec<&[u8]> = Vec::with_capacity(entries.len());
    for (expected, entry) in result_ids.iter().zip(entries) {
        if entry.id != *expected {
            return Err(MnemeError::ProcedureMismatch);
        }
        if entry.record.compute_id()? != entry.id {
            return Err(MnemeError::ObjectTampered);
        }
        payloads.push(&entry.plaintext);
    }

    let cms_payload = certified_memory_set_payload(result_ids);
    let certified_memory_set_hash = hash_certified_memory_set(&cms_payload);
    let assembled_bytes = encode_assembled_prompt_v1(result_ids, &payloads);
    let context_hash = hash_context_assembled(&assembled_bytes);

    Ok(AssemblyOutcome {
        assembled_bytes,
        context_hash,
        certified_memory_set_hash,
        profile,
    })
}

pub fn consumption_attestation_from_assembly(
    outcome: &AssemblyOutcome,
) -> ContextConsumptionAttestation {
    ContextConsumptionAttestation {
        assembly_profile: outcome.profile,
        context_hash: outcome.context_hash,
        certified_memory_set_hash: outcome.certified_memory_set_hash,
    }
}

pub fn output_binding_from_assembly(
    outcome: &AssemblyOutcome,
    model_output: &[u8],
    model_identity: [u8; 32],
) -> OutputBinding {
    OutputBinding {
        context_hash: outcome.context_hash,
        output_hash: hash_model_output(model_output),
        model_identity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::object::{MemoryKind, OBJECT_VERSION, ObjectRecord, PayloadEnc, TrustTier};
    use mneme_core::{HlcWire, hash_obj, to_bytes_canonical};

    fn sample_entry(id_byte: u8, plaintext: &[u8]) -> Entry {
        let mut writer = [0x11; 32];
        writer[0] = id_byte;
        let record = ObjectRecord {
            version: OBJECT_VERSION,
            kind: MemoryKind::Episodic.as_u8(),
            parent_ids: vec![],
            writer,
            session: [0x22; 16],
            hlc: HlcWire {
                wall_ms: 1,
                counter: 0,
                node_id: [0x33; 16],
            },
            trust_tier: TrustTier::Working.as_u8(),
            payload_enc: PayloadEnc {
                alg: 0,
                key_id: None,
                nonce: None,
                body: plaintext.to_vec(),
            },
            embedding_commit: None,
            redaction_slot: None,
            ext: None,
        };
        let canonical = to_bytes_canonical(&record).expect("canonical");
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = id_byte;
        let id = ObjectId(hash_obj(&canonical));
        Entry {
            id,
            record,
            plaintext: plaintext.to_vec(),
        }
    }

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn assembly_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("assembly.rs");
        let section = source_between_markers(
            source,
            "pub const ASSEMBLY_PROFILE_V1",
            "#[cfg(test)]",
            "context assembly production section",
        );

        for forbidden in [
            "return Err(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "context assembly should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum AssemblyFailure",
            "fn assembly_failure_to_mneme(",
            "fn unsupported_assembly_profile_error(",
            "AssemblyFailure::UnsupportedProfile",
        ] {
            assert!(
                section.contains(required),
                "context assembly failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn assembly_failure_classifier_preserves_public_schema_drift() {
        assert_eq!(
            assembly_failure_to_mneme(AssemblyFailure::UnsupportedProfile),
            MnemeError::SchemaDrift
        );
        assert_eq!(
            unsupported_assembly_profile_error(),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn profile_v1_id_is_frozen() {
        assert_eq!(
            ASSEMBLY_PROFILE_V1.id,
            *blake3::hash(b"MNEME-ASM-PROFILE-v1\x00").as_bytes()
        );
    }

    #[test]
    fn assembly_is_byte_stable() {
        let e1 = sample_entry(0x01, b"alpha memory");
        let e2 = sample_entry(0x02, b"beta memory");
        let ids = vec![e1.id, e2.id];
        let entries = vec![e1, e2];
        let a = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();
        let b = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();
        assert_eq!(a, b);
        assert!(a.assembled_bytes.starts_with(PROMPT_MAGIC));
        assert_ne!(a.context_hash, [0u8; 32]);
        assert_ne!(a.certified_memory_set_hash, a.context_hash);
    }

    #[test]
    fn order_mismatch_rejects() {
        let e1 = sample_entry(0x01, b"entry-one");
        let e2 = sample_entry(0x02, b"entry-two");
        let ids = vec![e1.id, e2.id];
        let entries = vec![e2, e1];
        assert_eq!(
            assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1),
            Err(MnemeError::ProcedureMismatch)
        );
    }
}
