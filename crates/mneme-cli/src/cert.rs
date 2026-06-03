//! `certify` / `verify-cert` — Cognition Certificate v1 (Phase I).

use mneme_cap::Capability;
use mneme_core::{
    FixedPointEmbedding, MnemeError, Procedure, ProcedureAlgo, Query, RetrievalProofLevel,
    TrustTier,
};
use mneme_crypto::TrustConfig;
use mneme_index::verify_cognition_certificate_v1;
use mneme_store::Store;
use std::fs;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub fn run_certify(
    store: &Store,
    trust: &TrustConfig,
    cap: &Capability,
    components: &[i16],
    dim: u16,
    scale: i8,
    level: RetrievalProofLevel,
    out: &Path,
) -> Result<(), MnemeError> {
    let embedding = FixedPointEmbedding::new(u32::from(dim), scale, components.to_vec())
        .map_err(|_| MnemeError::SchemaDrift)?;
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: mneme_core::DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let query = Query {
        logical_key: mneme_core::LogicalKey {
            namespace: "cert".into(),
            name: "semantic".into(),
        },
        min_tier: TrustTier::Trusted,
        embedding: Some(embedding.clone()),
    };
    let bytes = store.issue_cognition_certificate_v1(&query, &proc, cap, level)?;
    fs::write(out, &bytes).map_err(|e| MnemeError::IoFailed {
        path: out.display().to_string(),
        kind: e.to_string(),
    })?;
    let _ = trust;
    Ok(())
}

pub fn run_verify_cert(
    path: &Path,
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<(), MnemeError> {
    let bytes = fs::read(path).map_err(|e| MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    })?;
    verify_cognition_certificate_v1(&bytes, trust, proc)?;
    Ok(())
}
