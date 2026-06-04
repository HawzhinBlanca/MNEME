//! Cross-crate Phase II integration: assembly → CCA → gate verify → output binding.

use mneme_context::{
    ASSEMBLY_PROFILE_V1, assemble_verified_context, certified_memory_set_payload,
    consumption_attestation_from_assembly, output_binding_from_assembly,
};
use mneme_core::object::{MemoryKind, OBJECT_VERSION, ObjectRecord, PayloadEnc, TrustTier};
use mneme_core::{
    EnclaveReportPlaceholder, Entry, HlcWire, MnemeError, ObjectId, hash_obj, to_bytes_canonical,
};
use mneme_core::{
    decode_context_consumption_attestation, encode_context_consumption_attestation,
    encode_enclave_report_placeholder,
};
use mneme_gate::{
    verify_consumption_attestation, verify_enclave_report_placeholder, verify_output_binding,
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
    let outcome = assemble_verified_context(&[entry.id], &[entry], ASSEMBLY_PROFILE_V1).unwrap();
    let model_out = b"generated tokens";
    let model_id = [0x77; 32];
    let binding = output_binding_from_assembly(&outcome, model_out, model_id);
    verify_output_binding(&binding, &outcome.assembled_bytes, model_out, &model_id).unwrap();
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
