use mneme_core::cognition_bounds::{
    FLOOR_ATTRIBUTION_HONESTY, FLOOR_GAP_HONESTY, computational_online_floor_queries,
    open_log_log_gap_factor,
};
use mneme_smt::{SparseMerkleTree, TREE_DEPTH};
fn key(s: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0..8].copy_from_slice(&s.to_be_bytes());
    k
}
#[test]
fn smt_proof_depth() {
    let mut t = SparseMerkleTree::new();
    for i in 0..8 {
        t.upsert(key(i), [i as u8; 32]);
    }
    t.rebuild_root_cache();
    assert_eq!(t.prove_membership(key(1)).unwrap().path.len(), TREE_DEPTH);
}
#[test]
fn smt_gap() {
    assert_eq!(TREE_DEPTH as u64, 256);
    assert_eq!(256 / 8, 32);
    assert_eq!(8 * 32, 256);
    let n = 1u64 << 48;
    assert_eq!(computational_online_floor_queries(n), 8);
    assert_eq!(open_log_log_gap_factor(n), 6);
}
#[test]
fn honesty() {
    assert!(FLOOR_ATTRIBUTION_HONESTY.contains("Ω(log n / log log n)"));
    assert!(FLOOR_GAP_HONESTY.contains("OPEN"));
}
