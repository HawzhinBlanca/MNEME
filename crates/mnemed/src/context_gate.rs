use mneme_cap::Capability;
use mneme_core::{
    ContextConsumptionAttestation, DistanceMetric, Entry, FixedPointEmbedding, MnemeError,
    Procedure, ProcedureAlgo, Query, decode_context_consumption_attestation,
};
use mneme_store::{ContextGateRecallOpts, Store};
pub const HEADER_CONTEXT_ATTESTATION: &str = "x-mneme-context-attestation";
pub fn decode_cca_b64(b64: &str) -> Result<ContextConsumptionAttestation, MnemeError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .map_err(|_| MnemeError::SchemaDrift)?;
    decode_context_consumption_attestation(&bytes)
}
pub struct GatedRecallInput<'a> {
    pub attestation_b64: &'a str,
    pub embedding: FixedPointEmbedding,
}
pub fn recall_verified_context_gated_from_b64(
    store: &Store,
    query: &Query,
    cap: &Capability,
    input: &GatedRecallInput<'_>,
) -> Result<Vec<Entry>, MnemeError> {
    let attestation = decode_cca_b64(input.attestation_b64)?;
    let mut q = query.clone();
    q.embedding = Some(input.embedding.clone());
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    store.recall_verified_context_gated(
        &q,
        &proc,
        cap,
        &ContextGateRecallOpts {
            attestation: &attestation,
            output_binding: None,
            model_output: None,
            model_identity: None,
        },
    )
}
