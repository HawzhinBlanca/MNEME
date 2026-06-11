//! T8 counterexample — accumulator non-use does not bound σ_max (max wall-clock gap).
//!
//! VCP §5 A: VDF pace proves **minimum** sequential interval only. Jewel C proves set
//! non-membership only. Together they still leave **maximum** spacing between certified
//! cognition events unbounded (σ_max OPEN).

use crate::jewel_c::{
    AccumulatorParams, accumulate_commit, prove_nonuse_after_forget, test_accumulator_prover,
    verify_nonuse_after_forget,
};

/// Status export for the T8 limitation demo.
pub const T8_COUNTEREXAMPLE_STATUS: &str = concat!(
    "T8 COUNTEREXAMPLE: two operator timelines with identical valid Jewel C non-use witnesses ",
    "but unbounded wall-clock gap between certified cognition events — σ_max is not proved ",
    "by the accumulator (nor by minimum-pace VDF alone)."
);

pub const T8_COUNTEREXAMPLE_HONESTY: &str = concat!(
    "Non-membership in an accumulated used-set is invariant under arbitrary idle time between ",
    "certified cognition events. Jewel C therefore cannot certify a maximum wall-clock spacing ",
    "(σ_max); that requires a separate anchor (VDF pace minima bound from below only). ",
    "Operator equivocation on which certificates to present remains (T10)."
);

/// Wall-clock labels for the counterexample (not verified on chain — illustrative only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CognitionTimeline {
    pub first_cert_unix: u64,
    pub second_cert_unix: u64,
}

impl CognitionTimeline {
    pub fn gap_secs(&self) -> u64 {
        self.second_cert_unix.saturating_sub(self.first_cert_unix)
    }
}

/// Demonstrate σ_max is unbounded: two timelines, same accumulator witness verifies.
pub fn t8_sigma_max_gap_unbounded(
    params: &AccumulatorParams,
    forgotten: [u8; 32],
    used_a: [u8; 32],
    used_b: [u8; 32],
    timeline_fast: CognitionTimeline,
    timeline_slow: CognitionTimeline,
) -> Result<(Vec<u8>, crate::jewel_c::NonMembershipWitness), String> {
    if timeline_fast.gap_secs() >= timeline_slow.gap_secs() {
        return Err("timeline_fast must have strictly smaller gap than timeline_slow".into());
    }

    let mut prover = test_accumulator_prover().map_err(|e| format!("prover: {e}"))?;
    accumulate_commit(&mut prover, &used_a).map_err(|e| format!("accumulate a: {e}"))?;
    accumulate_commit(&mut prover, &used_b).map_err(|e| format!("accumulate b: {e}"))?;
    let acc = crate::jewel_c::accumulator_value(&prover);
    let proof =
        prove_nonuse_after_forget(&prover, &forgotten).map_err(|e| format!("prove: {e}"))?;

    verify_nonuse_after_forget(params, &acc, &forgotten, &proof)
        .map_err(|e| format!("verify fast timeline: {e}"))?;
    verify_nonuse_after_forget(params, &acc, &forgotten, &proof)
        .map_err(|e| format!("verify slow timeline: {e}"))?;

    let _ = (timeline_fast, timeline_slow);
    Ok((acc, proof))
}
