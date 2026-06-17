use thiserror::Error;

/// Closed error enum for the trusted path (INV-9, blueprint §16).
///
/// No `Other(String)` escape hatch. Variants are frozen in `interface::CONTRACT_VERSION`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MnemeError {
    #[error("root signature invalid")]
    RootSigInvalid,
    #[error("root inconsistent with prior checkpoint")]
    RootInconsistent,
    #[error("root replayed (older than last seen HLC)")]
    RootReplayed,
    #[error("receipt root mismatch")]
    ReceiptRootMismatch,
    #[error("index merkle path invalid")]
    IndexPathInvalid,
    #[error(
        "procedure replay mismatch: receipt proves procedure-faithfulness over committed data, not exact nearest-neighbor optimality and not true nearest neighbors. Phase I ProcedureFaithfulTopK proves membership/completeness plus top-k over prover-asserted distances; true top-k ranking is not proven and it is not top-k by true query-to-embedding distance until verifiers recompute candidate distances (§3 honesty boundary)"
    )]
    ProcedureMismatch,
    #[error("commitment binding proof invalid (not a SNARK verifier)")]
    ZkProofInvalid,
    #[error("object tampered (content hash mismatch)")]
    ObjectTampered,
    #[error("schema drift")]
    SchemaDrift,
    #[error("provenance broken")]
    ProvenanceBroken,
    #[error("unauthorized writer")]
    UnauthorizedWriter,
    #[error("capability denied")]
    CapDenied,
    #[error("capability expired")]
    CapExpired,
    #[error("capability malformed")]
    CapMalformed,
    #[error(
        "below tier policy (required {required}, got {got}): authenticated recall proves integrity and provenance, not truth—entry blocked from this min_tier (§3 honesty boundary)"
    )]
    BelowTierPolicy { required: u8, got: u8 },
    #[error("promote denied")]
    PromoteDenied,
    #[error("forgotten")]
    Forgotten,
    #[error("tombstone conflict")]
    TombstoneConflict,
    #[error("clock regression")]
    ClockRegression,
    #[error("HLC malformed")]
    HlcMalformed,
    #[error("IO failed at {path}: {kind}")]
    IoFailed { path: String, kind: String },
    #[error("incomplete transaction")]
    IncompleteTransaction,
    #[error("lock held")]
    LockHeld,
    #[error("storage full")]
    StorageFull,
    #[error("serialization non-canonical")]
    SerializationNonCanonical,
    #[error("unknown field {field}")]
    UnknownField { field: u16 },
    #[error("unsupported version {got}")]
    UnsupportedVersion { got: u16 },
    #[error("key vault missing")]
    KeyVaultMissing,
    #[error("key vault corrupt")]
    KeyVaultCorrupt,
    #[error("cognition certificate invalid")]
    CertificateInvalid,
    #[error(
        "retrieval dominance proof failed: receipt proves procedure-faithfulness over committed data, not exact nearest-neighbor optimality and not true nearest neighbors. Phase I ProcedureFaithfulTopK proves membership/completeness plus top-k over prover-asserted distances; true top-k ranking is not proven and it is not top-k by true query-to-embedding distance until verifiers recompute candidate distances (§3 honesty boundary)"
    )]
    RetrievalDominanceFailed,
    #[error("historical recall anchor invalid or not in verified checkpoint chain")]
    HistoricalRecallInvalid,
    #[error("provenance filter attestation violated")]
    ProvenanceFilterViolation,
}

#[cfg(test)]
mod tests {
    use super::MnemeError;

    #[test]
    fn procedure_mismatch_message_preserves_exact_dominance_distance_caveat() {
        assert_distance_caveat(
            "ProcedureMismatch",
            &MnemeError::ProcedureMismatch.to_string(),
        );
        assert_distance_caveat(
            "RetrievalDominanceFailed",
            &MnemeError::RetrievalDominanceFailed.to_string(),
        );
        assert_distance_caveat(
            "mneme-core docs contract",
            include_str!("../docs/CONTRACT.md"),
        );
        assert_distance_caveat(
            "mneme-core interface contract",
            include_str!("../CONTRACT.md"),
        );
    }

    fn assert_distance_caveat(surface: &str, text: &str) {
        for phrase in [
            "procedure-faithfulness",
            "not exact",
            "not true nearest neighbors",
            "membership/completeness",
            "top-k over prover-asserted distances",
            "top-k ranking is not proven",
            "not top-k by true query-to-embedding distance",
        ] {
            assert!(
                text.contains(phrase),
                "{surface} missing required honesty phrase `{phrase}`: {text}"
            );
        }
    }
}
