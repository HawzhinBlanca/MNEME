//! zkRAG-style PIOP research seam — **Phase IV-A (research only, NOT implemented)**.
//!
//! See `docs/research/PHASE_IV_A_PIOP_SPIKE.md`. This module is a *labelled
//! placeholder for a research direction*, not a feature. It exists so that a
//! future spike has a single, honestly-named entry point — and so that the
//! honesty boundary is asserted by a regression test even before any prover
//! exists.
//!
//! ## Why this is safe to ship behind a flag (zero honesty risk)
//!
//! - It is **off by default** (`piop_research` is not in `default`) and is wired
//!   into **no** recall, receipt, or verification path. `recall_receipt`,
//!   `verify_ads_vo`, and `verify_semantic_receipt_vo` never reference it.
//! - The entry point [`prove_exact_nn_piop`] **panics via `unimplemented!()`**.
//!   It can therefore never return a (fabricated) proof object. A research stub
//!   that *returned* a fake `Ok(..)` would be a fabricated result; a stub that
//!   *panics* is an explicit "not implemented" marker and is fail-closed by
//!   construction.
//! - It introduces no new dependency.
//!
//! ## What a real implementation would prove (NOT what this does)
//!
//! Global *exact* top-k over the committed vector set fixed by `semantic_commit`
//! under the declared distance metric and procedure P — succinctly. This module
//! proves **nothing**. It is **not** Plonky2/FRI, **not** a SNARK, **not** a
//! proof of any kind. It is unbuilt.

/// Honesty boundary for the `piop_research` seam (asserted by a regression test).
pub const PIOP_RESEARCH_HONESTY: &str = "Phase IV-A zkRAG-style PIOP is UNIMPLEMENTED research. This seam proves NOTHING: \
     not exact-NN, not procedure-faithfulness, not semantic truth, and it is NOT Plonky2/FRI and NOT a SNARK. \
     The entry point panics (unimplemented!) and is wired into no recall, receipt, or verification path. \
     See docs/research/PHASE_IV_A_PIOP_SPIKE.md.";

/// Status tag for the Phase IV-A milestone (documentation / honesty exports).
pub const PIOP_RESEARCH_STATUS: &str = "UNIMPLEMENTED (Phase IV-A research spike): global exact-NN over the committed set via a \
     zkRAG-style PIOP is a RESEARCH DIRECTION, not a feature. Three blockers remain (stable-buildable succinct-argument \
     stack; field-friendly commitment bridge for the BLAKE3 semantic_commit; out-of-TCB verifier architecture). No prover \
     exists; this entry point panics. Honest retrieval level remains dominance over the committed/visited set.";

/// Research-only, **unimplemented** entry point for a future exact-NN PIOP prover.
///
/// This always panics with `unimplemented!()`. It exists to give the Phase IV-A
/// spike a single honestly-named seam; it produces no proof and must never be
/// called from a recall, receipt, or verification path. Parameters are reserved
/// for the eventual statement (see the memo §2) and are intentionally unused.
///
/// # Panics
///
/// Always — the prover is unimplemented.
pub fn prove_exact_nn_piop(
    _semantic_commit: &[u8; 32],
    _procedure_id: &[u8; 32],
    _query_commit: &[u8; 32],
    _k: u32,
) -> ! {
    unimplemented!(
        "Phase IV-A zkRAG-style exact-NN PIOP is a research direction, not an implementation. \
         No proof is produced. See docs/research/PHASE_IV_A_PIOP_SPIKE.md."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_strings_preserve_boundary() {
        assert!(PIOP_RESEARCH_HONESTY.contains("UNIMPLEMENTED"));
        assert!(PIOP_RESEARCH_HONESTY.contains("proves NOTHING"));
        assert!(PIOP_RESEARCH_HONESTY.contains("not exact-NN"));
        assert!(PIOP_RESEARCH_HONESTY.contains("NOT Plonky2/FRI"));
        assert!(PIOP_RESEARCH_HONESTY.contains("NOT a SNARK"));
        assert!(PIOP_RESEARCH_STATUS.contains("UNIMPLEMENTED"));
        assert!(PIOP_RESEARCH_STATUS.contains("RESEARCH DIRECTION"));
    }

    #[test]
    #[should_panic(expected = "research direction")]
    fn entry_point_is_unimplemented_and_fails_loud() {
        // Must panic, never return a fabricated proof.
        prove_exact_nn_piop(&[0u8; 32], &[0u8; 32], &[0u8; 32], 1);
    }
}
