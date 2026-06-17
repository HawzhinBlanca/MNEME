//! zkRAG-style PIOP research seam — **Phase IV-A (experimental / dead code / NOT implemented)**.
//!
//! See `docs/research/PHASE_IV_A_PIOP_SPIKE.md`. This module is a *labelled
//! placeholder for a research direction*, not a feature.

use mneme_core::MnemeError;

/// Research-seam version tag (not a shipped wire version).
pub const PIOP_RESEARCH_VERSION: u16 = 0;

/// Honesty boundary for the `piop_research` seam (asserted by a regression test).
pub const PIOP_RESEARCH_HONESTY: &str = concat!(
    "Phase IV-A zkRAG-style PIOP is UNIMPLEMENTED research. This seam proves NOTHING: ",
    "not exact-NN / not exact nearest-neighbor, not procedure-faithfulness, not semantic truth, ",
    "and it is NOT Plonky2/FRI and NOT a SNARK. It does not retire the current Phase I ",
    "ProcedureFaithfulTopK caveat: current v1 proves membership/completeness plus top-k over ",
    "prover-asserted distances; true top-k ranking is not proven and it is not top-k by true ",
    "query-to-embedding distance until verifiers recompute candidate distances. ",
    "The entry point returns UnsupportedVersion and is wired into no recall, receipt, or verification path. ",
    "See docs/research/PHASE_IV_A_PIOP_SPIKE.md."
);

/// Status tag for the Phase IV-A milestone (documentation / honesty exports).
pub const PIOP_RESEARCH_STATUS: &str = concat!(
    "UNIMPLEMENTED (Phase IV-A research spike): global exact-NN over the committed set via a ",
    "zkRAG-style PIOP is a RESEARCH DIRECTION, not a feature and not exact-NN proof in this repo. ",
    "Current Phase I ProcedureFaithfulTopK proves membership/completeness plus top-k over prover-asserted ",
    "distances; true top-k ranking is not proven and it is not top-k by true query-to-embedding ",
    "distance until verifiers recompute candidate distances. Three blockers remain ",
    "(stable-buildable succinct-argument stack; field-friendly commitment bridge for the BLAKE3 ",
    "semantic_commit; out-of-TCB verifier architecture). No prover exists; this entry point returns ",
    "UnsupportedVersion. Honest retrieval level remains dominance over the committed/visited set."
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PiopResearchFailure {
    UnimplementedResearchSeam,
}

fn piop_research_failure_to_mneme(failure: PiopResearchFailure) -> MnemeError {
    match failure {
        PiopResearchFailure::UnimplementedResearchSeam => MnemeError::UnsupportedVersion {
            got: PIOP_RESEARCH_VERSION,
        },
    }
}

fn piop_research_unimplemented_error() -> MnemeError {
    piop_research_failure_to_mneme(PiopResearchFailure::UnimplementedResearchSeam)
}

/// Research-only entry point for a future exact-NN PIOP prover (always fails closed).
pub fn prove_exact_nn_piop(
    _semantic_commit: &[u8; 32],
    _procedure_id: &[u8; 32],
    _query_commit: &[u8; 32],
    _k: u32,
) -> Result<(), MnemeError> {
    Err(piop_research_unimplemented_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_strings_preserve_boundary() {
        assert!(PIOP_RESEARCH_HONESTY.contains("UNIMPLEMENTED"));
        assert!(PIOP_RESEARCH_HONESTY.contains("UnsupportedVersion"));
        assert!(PIOP_RESEARCH_STATUS.contains("RESEARCH DIRECTION"));
    }

    #[test]
    fn honesty_strings_preserve_exact_dominance_distance_caveat() {
        assert_distance_caveat("PIOP_RESEARCH_HONESTY", PIOP_RESEARCH_HONESTY);
        assert_distance_caveat("PIOP_RESEARCH_STATUS", PIOP_RESEARCH_STATUS);
    }

    fn assert_distance_caveat(surface: &str, text: &str) {
        for phrase in [
            "not exact",
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

    #[test]
    fn entry_point_fails_closed_with_unsupported_version() {
        assert_eq!(
            prove_exact_nn_piop(&[0u8; 32], &[0u8; 32], &[0u8; 32], 1),
            Err(MnemeError::UnsupportedVersion {
                got: PIOP_RESEARCH_VERSION
            })
        );
    }

    #[test]
    fn research_entrypoint_failure_is_classified_not_unsupported_version_collapsed() {
        let source = include_str!("piop_research.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("piop_research tests should follow production code");

        for forbidden in [
            "Err(MnemeError::UnsupportedVersion",
            "return Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !source.contains(forbidden),
                "PIOP research seam should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum PiopResearchFailure",
            "UnimplementedResearchSeam",
            "fn piop_research_failure_to_mneme(",
            "fn piop_research_unimplemented_error(",
        ] {
            assert!(
                source.contains(required),
                "PIOP research failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn piop_research_classifier_preserves_public_unsupported_version() {
        assert_eq!(
            piop_research_failure_to_mneme(PiopResearchFailure::UnimplementedResearchSeam),
            MnemeError::UnsupportedVersion {
                got: PIOP_RESEARCH_VERSION
            }
        );
        assert_eq!(
            piop_research_unimplemented_error(),
            MnemeError::UnsupportedVersion {
                got: PIOP_RESEARCH_VERSION
            }
        );
    }
}
