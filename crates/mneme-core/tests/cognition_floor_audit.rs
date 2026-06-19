use mneme_core::cognition_bounds::{
    FLOOR_ATTRIBUTION_HONESTY, FLOOR_GAP_HONESTY, NON_USE_EPOCH_FLOOR_HONESTY,
    PROCEDURE_FAITHFUL_TOPK_FLOOR_HONESTY, computational_online_floor_queries, log2_ceil,
    open_log_log_gap_factor,
};
const DOC: &str = include_str!("../../../docs/theory/PRICE_OF_VERIFIABLE_COGNITION.md");
#[test]
fn doc_honesty() {
    for p in [
        "Ω(log n / log log n)",
        "Dwork–Naor–Rothblum–Vaikuntanathan",
        "deterministic non-adaptive",
        "fully general computational floor matching Merkle",
        "OPEN",
        "up to an `O(log log n)` factor",
        "exact floor match is an overclaim",
        "Θ(n)",
        "transparent non-succinct",
        "Ω(N)",
        "non-aggregating epoch model",
        "Authenticated ≠ true",
        "validation-lane.sh bounds",
        "recall_floor",
        "procedure_faithful_topk_floor",
    ] {
        assert!(DOC.contains(p), "{p}");
    }
}
#[test]
fn no_overclaim() {
    for f in [
        "matches the floor exactly",
        "beats the memory-checking floor",
    ] {
        assert!(!DOC.contains(f), "{f}");
    }
}
#[test]
fn strings() {
    assert!(FLOOR_ATTRIBUTION_HONESTY.contains("Ω(log n / log log n)"));
    assert!(FLOOR_GAP_HONESTY.contains("OPEN"));
    assert!(PROCEDURE_FAITHFUL_TOPK_FLOOR_HONESTY.contains("Θ(n)"));
    assert!(NON_USE_EPOCH_FLOOR_HONESTY.contains("Ω(N)"));
}
#[test]
fn blueprint_universe_audit() {
    const TREE_DEPTH: u64 = 256;
    const BLUEPRINT_FLOOR: u64 = TREE_DEPTH / 8;
    const BLUEPRINT_GAP: u64 = 8;
    assert_eq!(TREE_DEPTH, BLUEPRINT_FLOOR * BLUEPRINT_GAP);
    let n = 1u64 << 48;
    assert_eq!(log2_ceil(n) as u64, 48);
    assert_eq!(open_log_log_gap_factor(n), 6);
    assert_eq!(computational_online_floor_queries(n), 8);
}
