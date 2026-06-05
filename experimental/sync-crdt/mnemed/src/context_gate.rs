//! Optional Phase II context-gate headers / JSON fields (`context_gate` feature).

use mneme_cap::Capability;
use mneme_core::{
    ContextConsumptionAttestation, DistanceMetric, FixedPointEmbedding, MnemeError, OutputBinding,
    Procedure, ProcedureAlgo, Query, decode_context_consumption_attestation, decode_output_binding,
};
use mneme_store::{ContextGateRecallOpts, Store};

pub fn decode_cca_b64(b64: &str) -> Result<ContextConsumptionAttestation, MnemeError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .map_err(|_| MnemeError::SchemaDrift)?;
    decode_context_consumption_attestation(&bytes)
}

pub fn decode_output_binding_b64(b64: &str) -> Result<OutputBinding, MnemeError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .map_err(|_| MnemeError::SchemaDrift)?;
    decode_output_binding(&bytes)
}

pub const HEADER_CONTEXT_ATTESTATION: &str = "x-mneme-context-attestation";
pub const HEADER_OUTPUT_BINDING: &str = "x-mneme-output-binding";
pub const HEADER_MODEL_OUTPUT: &str = "x-mneme-model-output";
pub const HEADER_MODEL_IDENTITY: &str = "x-mneme-model-identity";

pub struct GatedRecallInput<'a> {
    pub attestation_b64: &'a str,
    pub output_binding_b64: Option<&'a str>,
    pub model_output_b64: Option<&'a str>,
    pub model_identity_b64: Option<&'a str>,
    pub embedding_b64: &'a str,
}

pub fn recall_verified_context_gated_from_b64(
    store: &Store,
    query: &Query,
    cap: &Capability,
    input: &GatedRecallInput<'_>,
) -> Result<Vec<mneme_core::Entry>, MnemeError> {
    let attestation = decode_cca_b64(input.attestation_b64)?;
    let output_binding = match input.output_binding_b64 {
        Some(b64) => Some(decode_output_binding_b64(b64)?),
        None => None,
    };
    let emb_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        input.embedding_b64.trim(),
    )
    .map_err(|_| MnemeError::SchemaDrift)?;
    let embedding = FixedPointEmbedding::from_bytes(&emb_bytes)?;
    let model_output = match input.model_output_b64 {
        Some(b64) => Some(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
                .map_err(|_| MnemeError::SchemaDrift)?,
        ),
        None => None,
    };
    let model_identity = match input.model_identity_b64 {
        Some(b64) => {
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
                    .map_err(|_| MnemeError::SchemaDrift)?;
            Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| MnemeError::SchemaDrift)?)
        }
        None => None,
    };
    let mut semantic_query = query.clone();
    semantic_query.embedding = Some(embedding);
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let output_binding_ref = output_binding.as_ref();
    let opts = ContextGateRecallOpts {
        attestation: &attestation,
        output_binding: output_binding_ref,
        model_output: model_output.as_deref(),
        model_identity: model_identity.as_ref(),
    };
    store.recall_verified_context_gated(&semantic_query, &proc, cap, &opts)
}
