//! Pillar B floor constants (B1).
pub const FLOOR_ATTRIBUTION_HONESTY: &str = "computational online memory checking floor is Ω(log n / log log n) (Dwork–Naor–Rothblum–Vaikuntanathan TCC'09, deterministic non-adaptive); fully general Merkle-matching floor is OPEN";
pub const FLOOR_GAP_HONESTY: &str =
    "MNEME SMT recall is O(log n) probes — at the floor up to O(log log n); exact match is OPEN";
pub const EXACT_DOMINANCE_FLOOR_HONESTY: &str = "ExactDominance verification is Θ(n) in committed candidate count under the transparent non-succinct model";
pub const NON_USE_EPOCH_FLOOR_HONESTY: &str = "non-use after deletion costs Ω(N) epoch scans without per-epoch aggregation (Jewel C changes model)";
#[must_use]
pub const fn log2_ceil(n: u64) -> u32 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    let mut bits = 0u32;
    let mut v = n;
    while v > 1 {
        v >>= 1;
        bits += 1;
    }
    if (1u64 << bits) < n { bits + 1 } else { bits }
}
#[must_use]
pub fn computational_online_floor_queries(n: u64) -> u64 {
    if n <= 1 {
        return 1;
    }
    let log_n = log2_ceil(n) as u64;
    let log_log_n = log2_ceil(log_n) as u64;
    (log_n / log_log_n.max(1)).max(1)
}
#[must_use]
pub fn open_log_log_gap_factor(n: u64) -> u64 {
    if n <= 1 {
        return 1;
    }
    log2_ceil(log2_ceil(n) as u64) as u64
}
#[must_use]
pub fn smt_recall_within_named_gap(actual_probes: u64, key_universe_size: u64) -> bool {
    let floor = computational_online_floor_queries(key_universe_size);
    let gap = open_log_log_gap_factor(key_universe_size);
    actual_probes >= floor && actual_probes <= floor.saturating_mul(gap)
}
