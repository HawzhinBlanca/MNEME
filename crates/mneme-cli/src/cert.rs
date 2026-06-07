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
    let embedding = certify_embedding_from_components(components, dim, scale)?;
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

fn certify_embedding_from_components(
    components: &[i16],
    dim: u16,
    scale: i8,
) -> Result<FixedPointEmbedding, MnemeError> {
    FixedPointEmbedding::new(u32::from(dim), scale, components.to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_production_source() -> &'static str {
        include_str!("cert.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("cert.rs should keep tests after production code")
    }

    #[test]
    fn certify_embedding_errors_are_preserved_not_schema_drift_collapsed() {
        let production = cert_production_source();

        for forbidden in [
            "map_err(|_| MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !production.contains(forbidden),
                "cert production code still collapses embedding errors directly through {forbidden}"
            );
        }

        for required in [
            "fn certify_embedding_from_components(",
            "FixedPointEmbedding::new(u32::from(dim), scale, components.to_vec())",
        ] {
            assert!(
                production.contains(required),
                "cert production code is missing embedding preservation marker {required}"
            );
        }
    }

    #[test]
    fn certify_embedding_from_components_rejects_dimension_mismatch() {
        assert_eq!(
            certify_embedding_from_components(&[1], 2, 0).err(),
            Some(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn certify_embedding_from_components_accepts_matching_shape() {
        let embedding =
            certify_embedding_from_components(&[1, -2], 2, 0).expect("matching embedding shape");

        assert_eq!(embedding.dim, 2);
        assert_eq!(embedding.scale, 0);
        assert_eq!(embedding.components, vec![1, -2]);
    }
}
