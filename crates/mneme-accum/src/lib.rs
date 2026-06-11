#![forbid(unsafe_code)]
#![deny(warnings)]
//! Jewel C — class-group universal accumulator scaffold (VCP §4 **C2**).
//!
//! Honesty: proves **non-membership in an operator-presented accumulated set** for certified
//! cognition only. Does **not** prove semantic truth, does **not** bound max wall-clock spacing
//! (T8 / σ_max), and does **not** close operator equivocation (T10).

#[cfg(feature = "jewel_c")]
mod jewel_c;

#[cfg(feature = "jewel_c")]
mod t8_counterexample;

#[cfg(feature = "jewel_c")]
pub use jewel_c::{
    AccumulatorParams, AccumulatorProver, JEWEL_C_HONESTY, JEWEL_C_STATUS, MembershipWitness,
    NonMembershipWitness, accumulate, accumulate_commit, accumulator_prover, accumulator_value,
    element_prime_from_commit, hash_commit, prove_membership, prove_non_membership,
    prove_nonuse_after_forget, test_accumulator_params, test_accumulator_prover, verify_membership,
    verify_non_membership, verify_nonuse_after_forget,
};

#[cfg(feature = "jewel_c")]
pub use t8_counterexample::{
    CognitionTimeline, T8_COUNTEREXAMPLE_HONESTY, T8_COUNTEREXAMPLE_STATUS,
    t8_sigma_max_gap_unbounded,
};

#[cfg(not(feature = "jewel_c"))]
pub const JEWEL_C_STATUS: &str =
    "Jewel C accumulator scaffold disabled (enable `jewel_c` feature on mneme-accum)";
