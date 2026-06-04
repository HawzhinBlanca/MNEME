//! Cross-crate Phase II integration: assembly → CCA → gate verify → output binding.

use mneme_context::{
    ASSEMBLY_PROFILE_V1, assemble_verified_context, certified_memory_set_payload,
    consumption_attestation_from_assembly, output_binding_from_assembly,
};
use mneme_core::object::{MemoryKind, OBJECT_VERSION, ObjectRecord, PayloadEnc, TrustTier};
use mneme_core::{ContextConsumptionAttestation, hash_context_assembled};
use mneme_core::{
    EnclaveReportPlaceholder, Entry, HlcWire, MnemeError, ObjectId, hash_obj, to_bytes_canonical,
};
use mneme_core::{
    decode_context_consumption_attestation, encode_context_consumption_attestation,
    encode_enclave_report_placeholder,
};
use mneme_gate::{
    verify_consumption_attestation, verify_consumption_attestation_strict,
    verify_enclave_report_placeholder, verify_output_binding, verify_output_binding_strict,
};

fn sample_entry(body: &[u8]) -> Entry {
    let record = ObjectRecord {
        version: OBJECT_VERSION,
        kind: MemoryKind::Episodic.as_u8(),
        parent_ids: vec![],
        writer: [0x44; 32],
        session: [0x55; 16],
        hlc: HlcWire {
            wall_ms: 42,
            counter: 0,
            node_id: [0x66; 16],
        },
        trust_tier: TrustTier::Working.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: body.to_vec(),
        },
        embedding_commit: None,
        redaction_slot: None,
        ext: None,
    };
    let canonical = to_bytes_canonical(&record).expect("canonical");
    let id = ObjectId(hash_obj(&canonical));
    Entry {
        id,
        record,
        plaintext: body.to_vec(),
    }
}

#[test]
fn phase_ii_assembly_to_cca_to_gate_verify_roundtrip() {
    let e1 = sample_entry(b"memory-one");
    let e2 = sample_entry(b"memory-two");
    let ids = vec![e1.id, e2.id];
    let entries = vec![e1, e2];
    let outcome = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();
    let attestation = consumption_attestation_from_assembly(&outcome);
    let cms = certified_memory_set_payload(&ids);

    let wire = encode_context_consumption_attestation(&attestation).unwrap();
    let decoded = decode_context_consumption_attestation(&wire).unwrap();
    verify_consumption_attestation(
        &decoded,
        &outcome.assembled_bytes,
        &cms,
        &ASSEMBLY_PROFILE_V1,
    )
    .unwrap();
}

#[test]
fn phase_ii_output_binding_binds_model_output_to_context() {
    let entry = sample_entry(b"context-body");
    let id = entry.id;
    let outcome = assemble_verified_context(&[id], &[entry], ASSEMBLY_PROFILE_V1).unwrap();
    let model_out = b"generated tokens";
    let model_id = [0x77; 32];
    let binding = output_binding_from_assembly(&outcome, model_out, model_id);
    verify_output_binding(&binding, &outcome.assembled_bytes, model_out, &model_id).unwrap();
    let entry2 = sample_entry(b"context-body");
    verify_output_binding_strict(
        &binding,
        &[id],
        &[entry2],
        model_out,
        &model_id,
        &ASSEMBLY_PROFILE_V1,
    )
    .unwrap();
}

#[test]
fn phase_ii_strict_output_binding_rejects_injected_context_hash() {
    let entry = sample_entry(b"context-body");
    let id = entry.id;
    let outcome = assemble_verified_context(&[id], &[entry], ASSEMBLY_PROFILE_V1).unwrap();
    let model_out = b"generated tokens";
    let model_id = [0x77; 32];
    let mut binding = output_binding_from_assembly(&outcome, model_out, model_id);
    binding.context_hash = hash_context_assembled(b"MNEME-CTX-ASM-v1\nINJECTED");
    let entry2 = sample_entry(b"context-body");
    assert_eq!(
        verify_output_binding_strict(
            &binding,
            &[id],
            &[entry2],
            model_out,
            &model_id,
            &ASSEMBLY_PROFILE_V1,
        ),
        Err(MnemeError::ProvenanceBroken)
    );
}

#[test]
fn phase_ii_enclave_placeholder_never_opens_gate() {
    let report = EnclaveReportPlaceholder::honest_absent();
    let wire = encode_enclave_report_placeholder(&report).unwrap();
    assert!(!wire.is_empty());
    assert_eq!(
        verify_enclave_report_placeholder(&report),
        Err(MnemeError::CertificateInvalid)
    );
}

// --- Phase II no-injection: strict re-derivation gate (red-team #PHASE_II_CONTEXT_GATE_NO_INJECTION) ---

#[test]
fn phase_ii_strict_gate_accepts_genuine_assembly() {
    let e1 = sample_entry(b"alpha");
    let e2 = sample_entry(b"beta");
    let ids = vec![e1.id, e2.id];
    let entries = vec![e1, e2];
    let outcome = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();
    let att = consumption_attestation_from_assembly(&outcome);
    verify_consumption_attestation_strict(&att, &ids, &entries, &ASSEMBLY_PROFILE_V1).unwrap();
}

/// THE no-injection guarantee: a CCA whose context_hash is from an injected prompt — but with a
/// legit certified-set hash — is REJECTED because the gate re-derives the prompt from the
/// authenticated entries. (The bytes-only gate accepts this; see the contrast test below.)
#[test]
fn phase_ii_strict_gate_rejects_injected_context() {
    let e1 = sample_entry(b"alpha");
    let e2 = sample_entry(b"beta");
    let ids = vec![e1.id, e2.id];
    let entries = vec![e1, e2];
    let outcome = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();
    let forged = ContextConsumptionAttestation {
        assembly_profile: ASSEMBLY_PROFILE_V1,
        context_hash: hash_context_assembled(b"MNEME-CTX-ASM-v1\nINJECTED-PROMPT-BODY"),
        certified_memory_set_hash: outcome.certified_memory_set_hash,
    };
    assert_eq!(
        verify_consumption_attestation_strict(&forged, &ids, &entries, &ASSEMBLY_PROFILE_V1),
        Err(MnemeError::ProvenanceBroken),
        "injected prompt must fail closed when re-derived from the certified entries"
    );
}

#[test]
fn phase_ii_strict_gate_rejects_reordered_results() {
    let e1 = sample_entry(b"alpha");
    let e2 = sample_entry(b"beta");
    let ids = vec![e1.id, e2.id];
    let entries = vec![e1, e2];
    let outcome = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();
    let att = consumption_attestation_from_assembly(&outcome);
    let swapped = vec![ids[1], ids[0]];
    assert!(
        verify_consumption_attestation_strict(&att, &swapped, &entries, &ASSEMBLY_PROFILE_V1)
            .is_err(),
        "reordered results must fail closed"
    );
}

#[test]
fn phase_ii_strict_gate_rejects_dropped_entry() {
    let e1 = sample_entry(b"alpha");
    let e2 = sample_entry(b"beta");
    let outcome =
        assemble_verified_context(&[e1.id, e2.id], &[e1, e2], ASSEMBLY_PROFILE_V1).unwrap();
    let att = consumption_attestation_from_assembly(&outcome);
    // sample_entry is deterministic → rebuild e1 with the same id, verify the 2-entry CCA against
    // a dropped (1-entry) set: re-derived digests differ → reject.
    let e1b = sample_entry(b"alpha");
    assert_eq!(
        verify_consumption_attestation_strict(&att, &[e1b.id], &[e1b], &ASSEMBLY_PROFILE_V1),
        Err(MnemeError::ProvenanceBroken),
        "dropped entry must fail closed"
    );
}

/// Contrast that justifies the strict gate: the bytes-only `verify_consumption_attestation`
/// ACCEPTS an injected prompt (it never cross-binds plaintext to the certified set), while the
/// strict gate REJECTS the same forgery.
#[test]
fn phase_ii_bytes_only_gate_misses_injection_strict_catches_it() {
    let e1 = sample_entry(b"alpha");
    let ids = vec![e1.id];
    let outcome = assemble_verified_context(&ids, &[e1], ASSEMBLY_PROFILE_V1).unwrap();
    let certified = certified_memory_set_payload(&ids);
    let injected = b"MNEME-CTX-ASM-v1\nINJECTED".to_vec();
    let forged = ContextConsumptionAttestation {
        assembly_profile: ASSEMBLY_PROFILE_V1,
        context_hash: hash_context_assembled(&injected),
        certified_memory_set_hash: outcome.certified_memory_set_hash,
    };
    // Bytes-only gate accepts the injection (documents the limitation)...
    verify_consumption_attestation(&forged, &injected, &certified, &ASSEMBLY_PROFILE_V1).unwrap();
    // ...the strict gate rejects it by re-deriving from the authenticated entry.
    let e1b = sample_entry(b"alpha");
    assert_eq!(
        verify_consumption_attestation_strict(&forged, &[e1b.id], &[e1b], &ASSEMBLY_PROFILE_V1),
        Err(MnemeError::ProvenanceBroken)
    );
}
