//! CR-7: honest |F|/n compression measurements (reproducible, no fabricated curves).

use mneme_index::{
    BallTree, BeaconSeed, JlProjector, JlPruningMode, brute_force_knn, frontier_fraction,
    jl_conservative_frontier_fraction, knn_with_jl_pruning,
};
use std::fs;
use std::path::PathBuf;

fn random_points(n: usize, dim: usize, seed: u64) -> Vec<Vec<f64>> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            (0..dim)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    ((state >> 33) as f64) / (u32::MAX as f64) * 2.0 - 1.0
                })
                .collect()
        })
        .collect()
}

fn random_query(dim: usize, seed: u64) -> Vec<f64> {
    random_points(1, dim, seed.wrapping_add(99))[0].clone()
}

#[test]
fn complete_knn_compression_curve_snapshot() {
    let dims = [2usize, 8, 32, 128];
    let n = 48usize;
    let k = 3usize;
    let eps = 0.2f64;
    let mut lines = Vec::new();
    lines.push("# Complete k-NN compression curve (CR-7)".to_string());
    lines.push(String::new());
    lines.push(
        "Reproducible gate: `cargo test -p mneme-index --test complete_knn_compression`."
            .to_string(),
    );
    lines.push(String::new());
    lines.push(format!(
        "Parameters: n={n}, k={k}, ε={eps} (synthetic uniform [-1,1]^D)."
    ));
    lines.push(String::new());
    lines.push("| D | m | exact |F|/n | JL conservative |F|/n |".to_string());
    lines.push("|---:|---:|---:|---:|".to_string());

    for &dim in &dims {
        let pts = random_points(n, dim, dim as u64);
        let q = random_query(dim, dim as u64 + 7);
        let exact_tree = BallTree::build(pts.clone());
        let exact_frac = frontier_fraction(&exact_tree, &q, k);
        let m = JlProjector::recommended_target_dim(n, eps);
        let projector = JlProjector::from_beacon(
            BeaconSeed {
                round: 1,
                seed: [dim as u8; 32],
            },
            dim,
            m,
        );
        let jl_frac = jl_conservative_frontier_fraction(&pts, &q, k, &projector, eps);
        let conservative = knn_with_jl_pruning(
            &pts,
            &q,
            k,
            &projector,
            JlPruningMode::SoundConservative { epsilon: eps },
        );
        let exact = brute_force_knn(&pts, &q, k);
        assert_eq!(
            conservative, exact,
            "conservative must match exact at D={dim}"
        );
        lines.push(format!("| {dim} | {m} | {exact_frac:.3} | {jl_frac:.3} |"));
    }

    lines.push(String::new());
    lines.push(
        "**Ceiling:** at D=128 exact |F|/n is high (curse of dimensionality); JL conservative \
         may not beat exact in all regimes. Real 768–1536-d embeddings not measured here."
            .to_string(),
    );
    lines.push(String::new());

    let out = PathBuf::from("docs/benchmarks/COMPLETE_KNN_COMPRESSION.md");
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).ok();
    }
    let body = lines.join("\n");
    if out.exists() {
        let prior = fs::read_to_string(&out).unwrap_or_default();
        assert_eq!(prior, body, "compression snapshot must be deterministic");
    } else {
        fs::write(&out, &body).expect("write compression snapshot");
    }

    let high_frac = frontier_fraction(
        &BallTree::build(random_points(n, 128, 0x485049)),
        &random_query(128, 0x485050),
        k,
    );
    assert!(
        high_frac < 0.15,
        "expected little pruning (poor compression) at D=128, got |F|/n={high_frac}"
    );
}
