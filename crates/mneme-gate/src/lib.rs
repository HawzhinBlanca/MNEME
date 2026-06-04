#![forbid(unsafe_code)]
#![deny(warnings)]

//! Context gate attestation helpers (Phase II/IV scaffolding).

use mneme_context::assemble_verified_context;
use mneme_core::{
    AssemblyProfile, ContextConsumptionAttestation, ENCLAVE_REPORT_PLACEHOLDER_STATUS,
    EnclaveReportPlaceholder, Entry, MnemeError, ObjectId, OutputBinding,
    hash_certified_memory_set, hash_context_assembled, hash_model_output,
};

pub const PHASE_II_GATE_OPEN: bool = false;

pub const CONTEXT_GATE_STATUS: &str =
    "context gate attestation verifier stub - gate closed until remote attestation ships";

/// Bind a CCA to caller-supplied `assembled_context` + `certified_memory_set_payload` bytes
/// (digest consistency only).
///
/// SECURITY (see `docs/redteam/PHASE_II_CONTEXT_GATE_NO_INJECTION.md`): this DOES NOT prove the
/// "nothing injected" invariant on its own — it never cross-binds the assembled prompt's plaintext
/// to the certified set, so an injected `assembled_context` paired with a legit certified payload
/// passes. It is sound only when the caller has *itself* produced `assembled_context` from
/// authenticated entries. For the offline no-injection proof use
/// [`verify_consumption_attestation_strict`], which re-derives from the verified entries.
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

/// SOUND "nothing injected" check: re-derive the assembled prompt and certified-set digest from
/// the AUTHENTICATED verified-recall entries and require the CCA digests to match.
///
/// `assemble_verified_context` re-hashes every entry (`record.compute_id() == id`) and rebuilds the
/// prompt in `result_ids` order, so a prover cannot inject content, reorder, drop, or substitute an
/// entry: any deviation changes the re-derived `context_hash` (or fails entry authentication) and
/// this gate fails closed. Unlike [`verify_consumption_attestation`], the prompt bytes are NOT
/// supplied by (and therefore not trusted from) the prover — they are reconstructed from the
/// authenticated certified set. This is the offline proof that the model was fed *exactly* the
/// certified context and nothing else.
///
/// Trust assumption: `entries` are the verified recall result (membership proven upstream by the
/// receipt/zkANN gate); this function additionally re-checks each `record.compute_id() == id`.
pub fn verify_consumption_attestation_strict(
    attestation: &ContextConsumptionAttestation,
    result_ids: &[ObjectId],
    entries: &[Entry],
    expected_profile: &AssemblyProfile,
) -> Result<(), MnemeError> {
    if &attestation.assembly_profile != expected_profile {
        return Err(MnemeError::SchemaDrift);
    }
    let outcome = assemble_verified_context(result_ids, entries, *expected_profile)?;
    if attestation.context_hash != outcome.context_hash
        || attestation.certified_memory_set_hash != outcome.certified_memory_set_hash
    {
        return Err(MnemeError::ProvenanceBroken);
    }
    Ok(())
}

/// Bind an `OutputBinding` to caller-supplied assembled context bytes (digest consistency only).
///
/// Like [`verify_consumption_attestation`], this does **not** prove no-injection: a forged
/// `assembled_context` can match `binding.context_hash` while diverging from the certified
/// recall set. Use [`verify_output_binding_strict`] for the offline proof.
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

/// SOUND output binding: re-derive `context_hash` from authenticated entries; verify output digest
/// and model identity against caller-supplied values (output bytes are not re-derived here).
pub fn verify_output_binding_strict(
    binding: &OutputBinding,
    result_ids: &[ObjectId],
    entries: &[Entry],
    model_output: &[u8],
    model_identity: &[u8; 32],
    expected_profile: &AssemblyProfile,
) -> Result<(), MnemeError> {
    let outcome = assemble_verified_context(result_ids, entries, *expected_profile)?;
    if binding.context_hash != outcome.context_hash {
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

    fn honest_binding(assembled: &[u8], out: &[u8], id: [u8; 32]) -> OutputBinding {
        OutputBinding {
            context_hash: hash_context_assembled(assembled),
            output_hash: hash_model_output(out),
            model_identity: id,
        }
    }

    /// Forgery: bind output hash from a different model output (hash swap).
    #[test]
    fn forgery_output_hash_swap_rejects() {
        let assembled = b"assembled-context";
        let honest_out = b"honest-output";
        let forged_out = b"forged-output";
        let id = [0x77; 32];
        let mut binding = honest_binding(assembled, honest_out, id);
        binding.output_hash = hash_model_output(forged_out);
        assert_eq!(
            verify_output_binding(&binding, assembled, honest_out, &id),
            Err(MnemeError::ProvenanceBroken)
        );
    }

    /// Forgery: bind context hash from a different assembled prompt.
    #[test]
    fn forgery_context_hash_swap_rejects() {
        let honest_ctx = b"honest-context";
        let forged_ctx = b"injected-context";
        let out = b"model-output";
        let id = [0x88; 32];
        let mut binding = honest_binding(honest_ctx, out, id);
        binding.context_hash = hash_context_assembled(forged_ctx);
        assert_eq!(
            verify_output_binding(&binding, honest_ctx, out, &id),
            Err(MnemeError::ProvenanceBroken)
        );
    }

    /// Forgery: claim a different model identity than the one that produced output.
    #[test]
    fn forgery_model_identity_mismatch_rejects() {
        let assembled = b"ctx";
        let out = b"out";
        let honest_id = [0x11; 32];
        let forged_id = [0x22; 32];
        let binding = honest_binding(assembled, out, forged_id);
        assert_eq!(
            verify_output_binding(&binding, assembled, out, &honest_id),
            Err(MnemeError::SchemaDrift)
        );
    }

    /// Forgery: splice an honest context hash with a forged output hash.
    #[test]
    fn forgery_spliced_binding_fields_reject() {
        let ctx_a = b"context-a";
        let ctx_b = b"context-b";
        let out_a = b"output-a";
        let out_b = b"output-b";
        let id = [0x99; 32];
        let mut spliced = honest_binding(ctx_a, out_a, id);
        spliced.output_hash = hash_model_output(out_b);
        assert_eq!(
            verify_output_binding(&spliced, ctx_a, out_a, &id),
            Err(MnemeError::ProvenanceBroken)
        );
        spliced = honest_binding(ctx_a, out_a, id);
        spliced.context_hash = hash_context_assembled(ctx_b);
        assert_eq!(
            verify_output_binding(&spliced, ctx_a, out_a, &id),
            Err(MnemeError::ProvenanceBroken)
        );
    }
}
