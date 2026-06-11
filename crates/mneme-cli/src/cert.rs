//! `certify` / `verify-cert` — Cognition Certificate v1 (Phase I).

use mneme_cap::Capability;
use mneme_core::{
    FixedPointEmbedding, MnemeError, Procedure, ProcedureAlgo, Query, RetrievalProofLevel,
    TrustTier,
};
use mneme_crypto::TrustConfig;
use mneme_index::{
    BEACON_SPOT_CHECK_HONESTY, BYZANTINE_INFERENCE_HONESTY, DEFAULT_AUDIT_RATE_PPM,
    SpotCheckContext, audit_lottery_selected, load_store_embeddings, parse_cognition_certificate,
    verify_audit_beacon_offline, verify_byzantine_inference, verify_cognition_certificate_v1,
    verify_cognition_certificate_v1_with_spot_check,
};
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

pub(crate) fn certify_embedding_from_components(
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

pub struct VerifyCertAuditOptions<'a> {
    pub store: Option<&'a Path>,
    pub query: Option<&'a FixedPointEmbedding>,
}

pub fn run_verify_cert_audit(
    path: &Path,
    trust: &TrustConfig,
    proc: &Procedure,
    opts: VerifyCertAuditOptions<'_>,
) -> Result<String, MnemeError> {
    let bytes = fs::read(path).map_err(|e| MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    })?;
    let parsed = parse_cognition_certificate(&bytes)?;
    let beacon = parsed
        .audit_beacon
        .as_ref()
        .ok_or(MnemeError::CertificateInvalid)?;
    verify_audit_beacon_offline(beacon, &parsed.receipt)?;

    let selected = audit_lottery_selected(
        &beacon.beacon_randomness,
        &beacon.binding_digest,
        DEFAULT_AUDIT_RATE_PPM,
    );

    let spot_check = if selected {
        let store = opts.store.ok_or(MnemeError::ProcedureMismatch)?;
        let query = opts.query.ok_or(MnemeError::ProcedureMismatch)?;
        let embeddings = load_store_embeddings(store)?;
        let mut entries = Vec::with_capacity(parsed.receipt.verification_object.candidates.len());
        for (id, _, _) in &parsed.receipt.verification_object.candidates {
            let embedding = embeddings
                .get(id)
                .ok_or(MnemeError::RetrievalDominanceFailed)?;
            entries.push((*id, embedding.clone()));
        }
        let ctx = SpotCheckContext {
            query,
            entries: &entries,
        };
        let root =
            verify_cognition_certificate_v1_with_spot_check(&bytes, trust, proc, Some(&ctx))?;
        return Ok(format!(
            "verify-cert ok: cognition certificate v1 valid offline (audit: selected, true-distance dominance verified; seq {})",
            root.sequence
        ));
    };

    let _ = spot_check;
    let root = verify_cognition_certificate_v1_with_spot_check(&bytes, trust, proc, None)?;
    Ok(format!(
        "verify-cert ok: cognition certificate v1 valid offline (audit: not selected; seq {})",
        root.sequence
    ))
}

pub fn verify_cert_audit_honesty_footer() -> &'static str {
    BEACON_SPOT_CHECK_HONESTY
}

pub fn run_verify_cert_byzantine(
    path: &Path,
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<String, MnemeError> {
    let bytes = fs::read(path).map_err(|e| MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    })?;
    let parsed = parse_cognition_certificate(&bytes)?;
    let witness = parsed
        .inference_consistency
        .as_ref()
        .ok_or(MnemeError::CertificateInvalid)?;
    verify_byzantine_inference(witness, &parsed.receipt)?;
    let root = verify_cognition_certificate_v1_with_spot_check(&bytes, trust, proc, None)?;
    Ok(format!(
        "verify-cert ok: cognition certificate v1 valid offline (byzantine: unanimous inference consistency; seq {})",
        root.sequence
    ))
}

pub fn verify_cert_byzantine_honesty_footer() -> &'static str {
    BYZANTINE_INFERENCE_HONESTY
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
