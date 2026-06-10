//! Beacon-seeded Johnson–Lindenstrauss projection for complete-kNN pruning (CR-5).
//!
//! **Honesty ceiling:** JL distortion is probabilistic on finite samples. Conservative mode
//! inflates the pruning threshold by `(1+ε)` on **original-space** τ so search never drops a
//! true top-k neighbor — see `docs/research/JL_DISTORTION_BOUND.md`. Probabilistic mode uses the
//! raw projected bound and may prune incorrectly with rate ≤ `δ` under the standard JL model —
//! not proven on arbitrary embedding distributions.

use super::geometry::{BallTree, Neighbor, brute_force_knn, knn_with_pruning, squared_euclidean};
use blake3::Hasher;

const JL_DOMAIN: &[u8] = b"MNEME-jl-v1\x00";

/// Public beacon binding (round + seed); re-derivable offline from committed values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconSeed {
    pub round: u64,
    pub seed: [u8; 32],
}

/// JL pruning mode (spec §3a).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum JlPruningMode {
    /// Prune only when projected lower bound exceeds `(1+ε)·√τ_orig` — never wrongly prunes.
    SoundConservative { epsilon: f64 },
    /// Raw projected bound vs projected τ; completeness w.h.p. with failure probability ≤ `delta`.
    Probabilistic { epsilon: f64, delta: f64 },
}

/// Deterministic `Φ: R^D → R^m` from beacon + dimensions.
#[derive(Clone, Debug)]
pub struct JlProjector {
    pub beacon: BeaconSeed,
    pub source_dim: usize,
    pub target_dim: usize,
    matrix: Vec<f64>,
    commitment: [u8; 32],
}

impl JlProjector {
    pub fn from_beacon(beacon: BeaconSeed, source_dim: usize, target_dim: usize) -> Self {
        assert!(source_dim > 0 && target_dim > 0);
        let matrix = derive_matrix(&beacon, source_dim, target_dim);
        let commitment = hash_beacon_binding(&beacon, source_dim, target_dim);
        Self {
            beacon,
            source_dim,
            target_dim,
            matrix,
            commitment,
        }
    }

    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    pub fn project(&self, point: &[f64]) -> Vec<f64> {
        assert_eq!(point.len(), self.source_dim);
        let mut out = vec![0.0; self.target_dim];
        for (row, chunk) in out.iter_mut().zip(self.matrix.chunks(self.source_dim)) {
            *row = point.iter().zip(chunk).map(|(x, w)| x * w).sum();
        }
        out
    }

    pub fn project_points(&self, points: &[Vec<f64>]) -> Vec<Vec<f64>> {
        points.iter().map(|p| self.project(p)).collect()
    }

    /// Recommended projected dimension from standard JL heuristic: `m = ⌈8·ε⁻²·ln n⌉`.
    pub fn recommended_target_dim(n: usize, epsilon: f64) -> usize {
        let n = n.max(2);
        let eps = epsilon.max(1e-6);
        let m = (8.0 * eps.powi(-2) * (n as f64).ln()).ceil() as usize;
        m.max(2)
    }
}

fn hash_beacon_binding(beacon: &BeaconSeed, source_dim: usize, target_dim: usize) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(JL_DOMAIN);
    h.update(b"beacon-bind\x00");
    h.update(&beacon.round.to_be_bytes());
    h.update(&beacon.seed);
    h.update(&(source_dim as u64).to_be_bytes());
    h.update(&(target_dim as u64).to_be_bytes());
    *h.finalize().as_bytes()
}

fn derive_matrix(beacon: &BeaconSeed, source_dim: usize, target_dim: usize) -> Vec<f64> {
    let scale = 1.0 / (target_dim as f64).sqrt();
    let mut out = Vec::with_capacity(target_dim * source_dim);
    for row in 0..target_dim {
        for col in 0..source_dim {
            let mut h = Hasher::new();
            h.update(JL_DOMAIN);
            h.update(&beacon.round.to_be_bytes());
            h.update(&beacon.seed);
            h.update(&(row as u64).to_be_bytes());
            h.update(&(col as u64).to_be_bytes());
            let sign = if h.finalize().as_bytes()[0] & 1 == 0 {
                1.0
            } else {
                -1.0
            };
            out.push(sign * scale);
        }
    }
    out
}

/// Build a ball tree in projected space.
pub fn build_projected_tree(projector: &JlProjector, points: &[Vec<f64>]) -> BallTree {
    BallTree::build(projector.project_points(points))
}

/// k-NN in original space; pruning uses projected geometry per `mode`.
pub fn knn_with_jl_pruning(
    original_points: &[Vec<f64>],
    query: &[f64],
    k: usize,
    projector: &JlProjector,
    mode: JlPruningMode,
) -> Vec<Neighbor> {
    let projected = projector.project_points(original_points);
    let projected_query = projector.project(query);
    let tree = BallTree::build(projected);
    let mut heap = Vec::with_capacity(k + 1);
    let ctx = JlSearchCtx {
        projected_query: &projected_query,
        projected: &tree.points,
        original_query: query,
        original_points,
        k,
        mode,
    };
    jl_search_node(&tree.root, &ctx, &mut heap);
    heap.sort();
    let k_eff = k.min(original_points.len());
    if heap.len() > k_eff {
        heap.truncate(k_eff);
    }
    heap
}

struct JlSearchCtx<'a> {
    projected_query: &'a [f64],
    projected: &'a [Vec<f64>],
    original_query: &'a [f64],
    original_points: &'a [Vec<f64>],
    k: usize,
    mode: JlPruningMode,
}

fn jl_search_node(
    node: &super::geometry::BallNode,
    ctx: &JlSearchCtx<'_>,
    heap: &mut Vec<Neighbor>,
) {
    match node {
        super::geometry::BallNode::Leaf { index } => {
            push_jl_neighbor(
                heap,
                ctx.k,
                Neighbor {
                    index: *index,
                    distance_sq: squared_euclidean(
                        &ctx.original_points[*index],
                        ctx.original_query,
                    ),
                },
            );
        }
        super::geometry::BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            let pivot = &ctx.projected[*pivot_index];
            let d_qp = squared_euclidean(ctx.projected_query, pivot).sqrt();
            let radius = radius_sq.sqrt();
            let lower = (d_qp - radius).max(0.0);

            let visit = match ctx.mode {
                JlPruningMode::SoundConservative { epsilon } => {
                    if heap.len() < ctx.k {
                        true
                    } else {
                        let tau_orig_sq = jl_worst_distance_sq(heap, ctx.k);
                        let inflated = (1.0 + epsilon.max(0.0)) * tau_orig_sq.sqrt();
                        lower <= inflated
                    }
                }
                JlPruningMode::Probabilistic { .. } => {
                    if heap.len() < ctx.k {
                        true
                    } else {
                        let tau_phi_sq = jl_worst_projected_distance_sq(
                            heap,
                            ctx.projected,
                            ctx.projected_query,
                        );
                        lower <= tau_phi_sq.sqrt()
                    }
                }
            };

            if visit {
                jl_search_node(left, ctx, heap);
                jl_search_node(right, ctx, heap);
            }
        }
    }
}

fn jl_worst_distance_sq(heap: &[Neighbor], k: usize) -> f64 {
    if heap.len() < k {
        return f64::INFINITY;
    }
    heap.iter().map(|n| n.distance_sq).fold(0.0_f64, f64::max)
}

fn jl_worst_projected_distance_sq(
    heap: &[Neighbor],
    projected: &[Vec<f64>],
    projected_query: &[f64],
) -> f64 {
    if heap.is_empty() {
        return f64::INFINITY;
    }
    heap.iter()
        .map(|n| squared_euclidean(projected_query, &projected[n.index]))
        .fold(0.0_f64, f64::max)
}

fn push_jl_neighbor(heap: &mut Vec<Neighbor>, k: usize, candidate: Neighbor) {
    if let Some(pos) = heap.iter().position(|n| n.index == candidate.index) {
        if candidate < heap[pos] {
            heap[pos] = candidate;
        }
    } else {
        heap.push(candidate);
    }
    heap.sort();
    if heap.len() > k {
        heap.truncate(k);
    }
}

/// Conservative JL search must match brute-force k-NN (exact completeness).
pub fn conservative_matches_exact(
    points: &[Vec<f64>],
    query: &[f64],
    k: usize,
    projector: &JlProjector,
    epsilon: f64,
) -> bool {
    let exact = brute_force_knn(points, query, k);
    let jl = knn_with_jl_pruning(
        points,
        query,
        k,
        projector,
        JlPruningMode::SoundConservative { epsilon },
    );
    exact == jl
}

/// Exact pruning frontier fraction `|F|/n` on a ball tree (compression metric).
pub fn frontier_fraction(tree: &BallTree, query: &[f64], k: usize) -> f64 {
    let n = tree.len();
    if n == 0 {
        return 0.0;
    }
    let neighbors = brute_force_knn(&tree.points, query, k);
    let tau_sq = neighbors
        .iter()
        .map(|n| n.distance_sq)
        .fold(0.0_f64, f64::max);
    let mut frontier = 0usize;
    count_exact_frontier(&tree.root, query, &tree.points, tau_sq, &mut frontier);
    frontier as f64 / n as f64
}

/// JL conservative frontier fraction (projected tree, inflated bound).
pub fn jl_conservative_frontier_fraction(
    original_points: &[Vec<f64>],
    query: &[f64],
    k: usize,
    projector: &JlProjector,
    epsilon: f64,
) -> f64 {
    let n = original_points.len();
    if n == 0 {
        return 0.0;
    }
    let projected = projector.project_points(original_points);
    let projected_query = projector.project(query);
    let tree = BallTree::build(projected);
    let neighbors = brute_force_knn(original_points, query, k);
    let tau_orig_sq = neighbors
        .iter()
        .map(|n| n.distance_sq)
        .fold(0.0_f64, f64::max);
    let inflated = (1.0 + epsilon.max(0.0)) * tau_orig_sq.sqrt();
    let mut frontier = 0usize;
    count_jl_frontier(
        &tree.root,
        &projected_query,
        &tree.points,
        inflated,
        &mut frontier,
    );
    frontier as f64 / n as f64
}

fn count_exact_frontier(
    node: &super::geometry::BallNode,
    query: &[f64],
    points: &[Vec<f64>],
    tau_sq: f64,
    frontier: &mut usize,
) {
    match node {
        super::geometry::BallNode::Leaf { .. } => {}
        super::geometry::BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            let pivot = &points[*pivot_index];
            let d_qp = squared_euclidean(query, pivot).sqrt();
            let radius = radius_sq.sqrt();
            let lower = (d_qp - radius).max(0.0);
            if lower * lower > tau_sq {
                *frontier += 1;
                return;
            }
            count_exact_frontier(left, query, points, tau_sq, frontier);
            count_exact_frontier(right, query, points, tau_sq, frontier);
        }
    }
}

fn count_jl_frontier(
    node: &super::geometry::BallNode,
    projected_query: &[f64],
    projected: &[Vec<f64>],
    inflated_tau_sqrt: f64,
    frontier: &mut usize,
) {
    match node {
        super::geometry::BallNode::Leaf { .. } => {}
        super::geometry::BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            let pivot = &projected[*pivot_index];
            let d_qp = squared_euclidean(projected_query, pivot).sqrt();
            let radius = radius_sq.sqrt();
            let lower = (d_qp - radius).max(0.0);
            if lower > inflated_tau_sqrt {
                *frontier += 1;
                return;
            }
            count_jl_frontier(
                left,
                projected_query,
                projected,
                inflated_tau_sqrt,
                frontier,
            );
            count_jl_frontier(
                right,
                projected_query,
                projected,
                inflated_tau_sqrt,
                frontier,
            );
        }
    }
}

/// Baseline exact pruning (no JL) — validates geometry path.
pub fn exact_pruning_matches_brute(tree: &BallTree, query: &[f64], k: usize) -> bool {
    brute_force_knn(&tree.points, query, k) == knn_with_pruning(tree, query, k)
}
