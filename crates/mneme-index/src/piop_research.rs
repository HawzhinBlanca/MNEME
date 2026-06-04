//! zkRAG-style PIOP research seam — **Phase IV-A (research only, NOT implemented)**.
//!
//! See `docs/research/PHASE_IV_A_PIOP_SPIKE.md`. This module is a *labelled
//! placeholder for a research direction*, not a feature.

use mneme_core::MnemeError;

/// Research-seam version tag (not a shipped wire version).
pub const PIOP_RESEARCH_VERSION: u16 = 0;

/// Honesty boundary for the `piop_research` seam (asserted by a regression test).
pub const PIOP_RESEARCH_HONESTY: &str = "Phase IV-A zkRAG-style PIOP is UNIMPLEMENTED research. This seam proves NOTHING: \
     not exact-NN, not procedure-faithfulness, not semantic truth, and it is NOT Plonky2/FRI and NOT a SNARK. \
     The entry point returns UnsupportedVersion and is wired into no recall, receipt, or verification path. \
     See docs/research/PHASE_IV_A_PIOP_SPIKE.md.";

/// Status tag for the Phase IV-A milestone (documentation / honesty exports).
pub const PIOP_RESEARCH_STATUS: &str = "UNIMPLEMENTED (Phase IV-A research spike): global exact-NN over the committed set via a \
     zkRAG-style PIOP is a RESEARCH DIRECTION, not a feature. Three blockers remain (stable-buildable succinct-argument \
     stack; field-friendly commitment bridge for the BLAKE3 semantic_commit; out-of-TCB verifier architecture). No prover \
     exists; this entry point returns UnsupportedVersion. Honest retrieval level remains dominance over the committed/visited set.";

/// Research-only entry point for a future exact-NN PIOP prover (always fails closed).
pub fn prove_exact_nn_piop(
    _semantic_commit: &[u8; 32],
    _procedure_id: &[u8; 32],
    _query_commit: &[u8; 32],
    _k: u32,
) -> Result<(), MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: PIOP_RESEARCH_VERSION,
    })
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
    fn entry_point_fails_closed_with_unsupported_version() {
        assert_eq!(
            prove_exact_nn_piop(&[0u8; 32], &[0u8; 32], &[0u8; 32], 1),
            Err(MnemeError::UnsupportedVersion {
                got: PIOP_RESEARCH_VERSION
            })
        );
    }
}
