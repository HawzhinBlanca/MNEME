//! Honest prover for complete k-NN proofs (CR-3).

use super::auth_tree::{AuthNodeProof, AuthenticatedBallTree};
use super::geometry::{BallNode, Neighbor, brute_force_knn, squared_euclidean};
use mneme_core::MnemeError;

/// Complete k-NN proof: returned set `R`, pruning frontier `F`, and authentication paths.
#[derive(Clone, Debug, PartialEq)]
pub struct CompleteKnnProof {
    pub total_points: usize,
    pub returned: Vec<ReturnedPoint>,
    pub frontier: Vec<FrontierNode>,
    /// Leaves not in `R` that were reached without a pruned ancestor (loose bounds).
    pub excluded: Vec<ExcludedLeaf>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExcludedLeaf {
    pub index: usize,
    pub point: Vec<f64>,
    pub auth: AuthNodeProof,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReturnedPoint {
    pub index: usize,
    pub point: Vec<f64>,
    pub distance_sq: f64,
    pub auth: AuthNodeProof,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FrontierNode {
    pub pivot_index: usize,
    pub pivot: Vec<f64>,
    pub radius_sq: f64,
    pub left_hash: [u8; 32],
    pub right_hash: [u8; 32],
    pub subtree_leaf_indices: Vec<usize>,
    pub auth: AuthNodeProof,
}

/// Build an honest complete-kNN proof for `(query, k)`.
pub fn prove_complete_knn(
    tree: &AuthenticatedBallTree,
    query: &[f64],
    k: usize,
) -> Result<CompleteKnnProof, MnemeError> {
    let n = tree.tree.len();
    if k == 0 || n == 0 {
        return Err(prove_failure(ProveFailure::InvalidK));
    }
    let k = k.min(n);
    let neighbors = brute_force_knn(&tree.tree.points, query, k);
    let tau_sq = neighbors
        .iter()
        .map(|n| n.distance_sq)
        .fold(0.0_f64, f64::max);

    let mut frontier = Vec::new();
    let mut returned_indices = Vec::new();
    let ctx = FrontierCtx {
        points: &tree.tree.points,
        query,
        tau_sq,
        neighbors: &neighbors,
        tree,
    };
    collect_frontier(&tree.tree.root, &ctx, &mut frontier, &mut returned_indices)?;

    let returned = neighbors
        .iter()
        .map(|n| {
            let point = tree.tree.points[n.index].clone();
            let auth = tree
                .prove_leaf(n.index)
                .ok_or_else(|| prove_failure(ProveFailure::PathMissing))?;
            Ok(ReturnedPoint {
                index: n.index,
                point,
                distance_sq: n.distance_sq,
                auth,
            })
        })
        .collect::<Result<Vec<_>, MnemeError>>()?;

    let excluded = build_excluded(&returned, &frontier, tree)?;

    Ok(CompleteKnnProof {
        total_points: n,
        returned,
        frontier,
        excluded,
    })
}

fn build_excluded(
    returned: &[ReturnedPoint],
    frontier: &[FrontierNode],
    tree: &AuthenticatedBallTree,
) -> Result<Vec<ExcludedLeaf>, MnemeError> {
    let mut covered = std::collections::BTreeSet::new();
    for r in returned {
        covered.insert(r.index);
    }
    for f in frontier {
        for &idx in &f.subtree_leaf_indices {
            covered.insert(idx);
        }
    }
    let mut out = Vec::new();
    for i in 0..tree.tree.len() {
        if covered.contains(&i) {
            continue;
        }
        let point = tree.tree.points[i].clone();
        let auth = tree
            .prove_leaf(i)
            .ok_or_else(|| prove_failure(ProveFailure::PathMissing))?;
        out.push(ExcludedLeaf {
            index: i,
            point,
            auth,
        });
    }
    Ok(out)
}

struct FrontierCtx<'a> {
    points: &'a [Vec<f64>],
    query: &'a [f64],
    tau_sq: f64,
    neighbors: &'a [Neighbor],
    tree: &'a AuthenticatedBallTree,
}

fn collect_frontier(
    node: &BallNode,
    ctx: &FrontierCtx<'_>,
    frontier: &mut Vec<FrontierNode>,
    returned_seen: &mut Vec<usize>,
) -> Result<(), MnemeError> {
    match node {
        BallNode::Leaf { index } => {
            if ctx.neighbors.iter().any(|n| n.index == *index) {
                returned_seen.push(*index);
                return Ok(());
            }
            let d = squared_euclidean(ctx.query, &ctx.points[*index]);
            if d < ctx.tau_sq {
                return Err(prove_failure(ProveFailure::CoverIncomplete));
            }
            if (d - ctx.tau_sq).abs() <= 1e-9 {
                let worse_tie = ctx
                    .neighbors
                    .iter()
                    .all(|n| n.index < *index || n.distance_sq < d);
                if !worse_tie {
                    return Err(prove_failure(ProveFailure::CoverIncomplete));
                }
            }
            Ok(())
        }
        BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            let pivot = &ctx.points[*pivot_index];
            let d_qp = squared_euclidean(ctx.query, pivot).sqrt();
            let radius = radius_sq.sqrt();
            let lower = (d_qp - radius).max(0.0);
            if lower * lower > ctx.tau_sq {
                let subtree_hash = super::auth_tree::commit_node(node, ctx.points);
                let auth = ctx
                    .tree
                    .prove_internal_hash(subtree_hash)
                    .ok_or_else(|| prove_failure(ProveFailure::PathMissing))?;
                let (pivot_coords, _, left_hash, right_hash) = internal_open(node, ctx.points);
                frontier.push(FrontierNode {
                    pivot_index: *pivot_index,
                    pivot: pivot_coords,
                    radius_sq: *radius_sq,
                    left_hash,
                    right_hash,
                    subtree_leaf_indices: leaf_indices_in_subtree(node),
                    auth,
                });
                return Ok(());
            }
            collect_frontier(left, ctx, frontier, returned_seen)?;
            collect_frontier(right, ctx, frontier, returned_seen)
        }
    }
}

fn internal_open(node: &BallNode, points: &[Vec<f64>]) -> (Vec<f64>, f64, [u8; 32], [u8; 32]) {
    match node {
        BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => (
            points[*pivot_index].clone(),
            *radius_sq,
            super::auth_tree::commit_node(left, points),
            super::auth_tree::commit_node(right, points),
        ),
        BallNode::Leaf { .. } => unreachable!(),
    }
}

fn leaf_indices_in_subtree(node: &BallNode) -> Vec<usize> {
    match node {
        BallNode::Leaf { index } => vec![*index],
        BallNode::Internal { left, right, .. } => {
            let mut out = leaf_indices_in_subtree(left);
            out.extend(leaf_indices_in_subtree(right));
            out.sort_unstable();
            out
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProveFailure {
    InvalidK,
    PathMissing,
    CoverIncomplete,
}

fn prove_failure(f: ProveFailure) -> MnemeError {
    match f {
        ProveFailure::InvalidK | ProveFailure::PathMissing | ProveFailure::CoverIncomplete => {
            MnemeError::CertificateInvalid
        }
    }
}
