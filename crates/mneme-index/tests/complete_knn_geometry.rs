//! CR-1 acceptance: proptest — pruning-frontier k-NN == brute-force k-NN.

use mneme_index::{BallTree, brute_force_knn, knn_with_pruning};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn pruning_matches_brute_force_proptest(
        dim in 2usize..=6,
        n in 1usize..=24,
        k in 1usize..=8,
        raw_points in prop::collection::vec(-10.0f64..10.0, 2..=144),
        raw_query in prop::collection::vec(-10.0f64..10.0, 2..=24),
    ) {
        let dim = dim.max(2);
        let max_n = raw_points.len() / dim;
        prop_assume!(max_n >= 1);
        let n = n.min(max_n);
        prop_assume!(raw_query.len() >= dim);
        let pts: Vec<Vec<f64>> = (0..n)
            .map(|i| {
                let start = i * dim;
                raw_points[start..start + dim].to_vec()
            })
            .collect();
        let q: Vec<f64> = raw_query.into_iter().take(dim).collect();
        let k = k.min(pts.len());
        let tree = BallTree::build(pts.clone());
        let bf = brute_force_knn(&pts, &q, k);
        let pr = knn_with_pruning(&tree, &q, k);
        prop_assert_eq!(bf, pr);
    }
}

#[test]
fn thousand_random_queries_match_brute_force() {
    let dim = 3usize;
    let pts: Vec<Vec<f64>> = (0..20)
        .map(|i| vec![(i as f64) * 0.7, (i as f64).sin(), (i as f64).cos()])
        .collect();
    let tree = BallTree::build(pts.clone());
    let mut seed: u64 = 0x00C0_FFEE_BABE_0001;
    for _ in 0..1000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let q: Vec<f64> = (0..dim)
            .map(|d| {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((seed >> 33) as f64 / u32::MAX as f64) * 20.0 - 10.0 + d as f64 * 0.01
            })
            .collect();
        let k = 1 + ((seed >> 40) as usize) % pts.len().clamp(1, 5);
        let bf = brute_force_knn(&pts, &q, k);
        let pr = knn_with_pruning(&tree, &q, k);
        assert_eq!(bf, pr, "seed={seed} k={k} q={q:?}");
    }
}
