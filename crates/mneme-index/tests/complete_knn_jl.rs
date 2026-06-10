//! CR-5: JL projection — conservative never wrongly prunes; probabilistic empirical bound.

use mneme_index::{
    BallTree, BeaconSeed, JlProjector, JlPruningMode, brute_force_knn, conservative_matches_exact,
    knn_with_jl_pruning,
};
use proptest::prelude::*;

fn beacon(seed_byte: u8) -> BeaconSeed {
    BeaconSeed {
        round: 42,
        seed: [seed_byte; 32],
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn conservative_jl_matches_brute_force(
        dim in 2usize..=6,
        n in 3usize..=12,
        k in 1usize..=4,
        epsilon in 0.05f64..0.35,
        points in prop::collection::vec(prop::collection::vec(-8.0f64..8.0, 2..=6), 3..=12),
        q in prop::collection::vec(-8.0f64..8.0, 2..=6),
    ) {
        let dim = dim.max(2);
        let pts: Vec<Vec<f64>> = points
            .into_iter()
            .take(n)
            .map(|mut p| {
                p.truncate(dim);
                while p.len() < dim {
                    p.push(0.0);
                }
                p
            })
            .collect();
        prop_assume!(pts.len() >= 3);
        let mut q: Vec<f64> = q.into_iter().take(dim).collect();
        while q.len() < dim {
            q.push(0.0);
        }
        let k = k.min(pts.len());
        let projector = JlProjector::from_beacon(
            beacon(0xA5),
            dim,
            JlProjector::recommended_target_dim(pts.len(), epsilon),
        );
        prop_assert_eq!(
            brute_force_knn(&pts, &q, k),
            knn_with_jl_pruning(
                &pts,
                &q,
                k,
                &projector,
                JlPruningMode::SoundConservative { epsilon },
            )
        );
    }
}

#[test]
fn conservative_jl_thousand_random_queries() {
    let dim = 4usize;
    let pts: Vec<Vec<f64>> = (0..16)
        .map(|i| {
            vec![
                (i as f64) * 0.3,
                (i as f64).sin(),
                (i as f64).cos(),
                (i as f64) * 0.1,
            ]
        })
        .collect();
    let epsilon = 0.2;
    let projector = JlProjector::from_beacon(
        beacon(0xB7),
        dim,
        JlProjector::recommended_target_dim(pts.len(), epsilon),
    );
    let mut seed: u64 = 0x4A4C_0001;
    for _ in 0..1000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let q: Vec<f64> = (0..dim)
            .map(|d| {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((seed >> 33) as f64 / u32::MAX as f64) * 16.0 - 8.0 + d as f64 * 0.02
            })
            .collect();
        let k = 1 + ((seed >> 40) as usize) % pts.len().clamp(1, 6);
        assert!(
            conservative_matches_exact(&pts, &q, k, &projector, epsilon),
            "seed={seed} k={k}"
        );
    }
}

#[test]
fn beacon_binding_is_stable_and_rederivable() {
    let b = beacon(0xCC);
    let p1 = JlProjector::from_beacon(b.clone(), 8, 4);
    let p2 = JlProjector::from_beacon(b, 8, 4);
    assert_eq!(p1.commitment(), p2.commitment());
    let v = vec![1.0, 0.0, -1.0, 0.5, 2.0, -0.5, 1.0, 0.0];
    assert_eq!(p1.project(&v), p2.project(&v));
}

#[test]
fn probabilistic_jl_empirical_error_within_delta_heuristic() {
    let dim = 6usize;
    let n = 24usize;
    let pts: Vec<Vec<f64>> = (0..n)
        .map(|i| {
            (0..dim)
                .map(|d| ((i * dim + d) as f64) * 0.17 - 2.0)
                .collect()
        })
        .collect();
    let epsilon = 0.25;
    let delta = 0.15;
    let projector = JlProjector::from_beacon(
        beacon(0xD1),
        dim,
        JlProjector::recommended_target_dim(n, epsilon),
    );
    let mode = JlPruningMode::Probabilistic { epsilon, delta };
    let mut mismatches = 0usize;
    let trials = 400usize;
    for t in 0..trials {
        let q: Vec<f64> = (0..dim)
            .map(|d| ((t * 17 + d * 3) as f64) * 0.11 - 3.0)
            .collect();
        let k = 3;
        let exact = brute_force_knn(&pts, &q, k);
        let jl = knn_with_jl_pruning(&pts, &q, k, &projector, mode);
        if exact != jl {
            mismatches += 1;
        }
    }
    let rate = mismatches as f64 / trials as f64;
    assert!(
        rate <= delta + 0.05,
        "empirical mismatch rate {rate} exceeded δ+margin (δ={delta})"
    );
}

#[test]
fn projected_tree_build_is_deterministic() {
    let pts = vec![vec![0.0, 1.0], vec![2.0, 3.0], vec![4.0, 5.0]];
    let projector = JlProjector::from_beacon(beacon(1), 2, 3);
    let a = BallTree::build(projector.project_points(&pts));
    let b = BallTree::build(projector.project_points(&pts));
    assert_eq!(format!("{:?}", a.root), format!("{:?}", b.root));
}
