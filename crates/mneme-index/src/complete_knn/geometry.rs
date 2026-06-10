//! Exact ball-tree geometry: brute-force k-NN + pruning-frontier search (CR-1).

use std::cmp::Ordering;

/// Squared Euclidean distance in `R^m` (exact, no sqrt).
#[inline]
pub fn squared_euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| {
            let d = x - y;
            d * d
        })
        .sum()
}

/// A neighbor candidate with deterministic index tie-break.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Neighbor {
    pub index: usize,
    pub distance_sq: f64,
}

impl Eq for Neighbor {}

impl PartialOrd for Neighbor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Neighbor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.distance_sq
            .partial_cmp(&other.distance_sq)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.index.cmp(&other.index))
    }
}

/// Binary ball tree over point indices (deterministic build).
#[derive(Clone, Debug)]
pub enum BallNode {
    Leaf {
        index: usize,
    },
    Internal {
        pivot_index: usize,
        radius_sq: f64,
        left: Box<BallNode>,
        right: Box<BallNode>,
    },
}

/// Built ball tree + original points (immutable after build).
#[derive(Clone, Debug)]
pub struct BallTree {
    pub points: Vec<Vec<f64>>,
    pub root: BallNode,
}

impl BallTree {
    /// Build a deterministic ball tree from `points` (indices 0..n-1).
    pub fn build(points: Vec<Vec<f64>>) -> Self {
        let n = points.len();
        if n == 0 {
            return Self {
                points,
                root: BallNode::Leaf { index: 0 },
            };
        }
        let indices: Vec<usize> = (0..n).collect();
        let root = build_node(&indices, &points);
        Self { points, root }
    }

    pub fn dim(&self) -> usize {
        self.points.first().map(|p| p.len()).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

fn build_node(indices: &[usize], points: &[Vec<f64>]) -> BallNode {
    assert!(!indices.is_empty());
    if indices.len() == 1 {
        return BallNode::Leaf { index: indices[0] };
    }

    let (pole_a, pole_b) = farthest_pair(indices, points);
    let mut left_idx = Vec::new();
    let mut right_idx = Vec::new();
    for &i in indices {
        let da = squared_euclidean(&points[i], &points[pole_a]);
        let db = squared_euclidean(&points[i], &points[pole_b]);
        if da < db || (da == db && i <= pole_b) {
            left_idx.push(i);
        } else {
            right_idx.push(i);
        }
    }
    if left_idx.is_empty() {
        left_idx.push(right_idx.pop().expect("non-empty"));
    }
    if right_idx.is_empty() {
        right_idx.push(left_idx.pop().expect("non-empty"));
    }

    let pivot_index = *indices.iter().min().expect("non-empty");
    let radius_sq = indices
        .iter()
        .map(|&i| squared_euclidean(&points[pivot_index], &points[i]))
        .fold(0.0_f64, f64::max);

    let left = Box::new(build_node(&left_idx, points));
    let right = Box::new(build_node(&right_idx, points));

    BallNode::Internal {
        pivot_index,
        radius_sq,
        left,
        right,
    }
}

fn farthest_pair(indices: &[usize], points: &[Vec<f64>]) -> (usize, usize) {
    let mut best = (indices[0], indices[1.min(indices.len() - 1)], 0.0_f64);
    for (i, &a) in indices.iter().enumerate() {
        for &b in indices.iter().skip(i + 1) {
            let d = squared_euclidean(&points[a], &points[b]);
            if d > best.2 || (d == best.2 && (a, b) < (best.0, best.1)) {
                best = (a, b, d);
            }
        }
    }
    (best.0, best.1)
}

/// Brute-force exact k-NN with deterministic index tie-break.
pub fn brute_force_knn(points: &[Vec<f64>], query: &[f64], k: usize) -> Vec<Neighbor> {
    let n = points.len();
    if n == 0 || k == 0 {
        return Vec::new();
    }
    let k = k.min(n);
    let mut all: Vec<Neighbor> = points
        .iter()
        .enumerate()
        .map(|(index, p)| Neighbor {
            index,
            distance_sq: squared_euclidean(p, query),
        })
        .collect();
    all.sort();
    all.truncate(k);
    all
}

/// Ball-tree k-NN with reverse-triangle pruning; returns same set as brute-force.
pub fn knn_with_pruning(tree: &BallTree, query: &[f64], k: usize) -> Vec<Neighbor> {
    let n = tree.len();
    if n == 0 || k == 0 {
        return Vec::new();
    }
    let k = k.min(n);
    let mut heap: Vec<Neighbor> = Vec::with_capacity(k + 1);
    search_node(&tree.root, query, &tree.points, k, &mut heap);
    heap.sort();
    heap.truncate(k);
    heap
}

fn search_node(
    node: &BallNode,
    query: &[f64],
    points: &[Vec<f64>],
    k: usize,
    heap: &mut Vec<Neighbor>,
) {
    match node {
        BallNode::Leaf { index } => {
            push_neighbor(
                heap,
                k,
                Neighbor {
                    index: *index,
                    distance_sq: squared_euclidean(&points[*index], query),
                },
            );
        }
        BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            let pivot = &points[*pivot_index];
            let d_qp = squared_euclidean(query, pivot);
            let radius = radius_sq.sqrt();
            let d_qp_sqrt = d_qp.sqrt();
            let tau = worst_distance_sq(heap, k);

            let lb_left = lower_bound(d_qp_sqrt, radius);
            let lb_right = lower_bound(d_qp_sqrt, radius);

            let visit_left = lb_left * lb_left <= tau || heap.len() < k;
            let visit_right = lb_right * lb_right <= tau || heap.len() < k;

            if visit_left {
                search_node(left, query, points, k, heap);
            }
            let tau_after_left = worst_distance_sq(heap, k);
            if visit_right || worst_distance_sq(heap, k) > tau_after_left {
                search_node(right, query, points, k, heap);
            }
        }
    }
}

/// Reverse-triangle lower bound: `d(q,p) - R` (non-negative).
#[inline]
fn lower_bound(d_qp: f64, radius: f64) -> f64 {
    (d_qp - radius).max(0.0)
}

fn worst_distance_sq(heap: &[Neighbor], k: usize) -> f64 {
    if heap.len() < k {
        return f64::INFINITY;
    }
    heap.iter().map(|n| n.distance_sq).fold(0.0_f64, f64::max)
}

fn push_neighbor(heap: &mut Vec<Neighbor>, k: usize, candidate: Neighbor) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset_2d() -> Vec<Vec<f64>> {
        vec![
            vec![0.0, 0.0],
            vec![1.0, 0.0],
            vec![3.0, 1.0],
            vec![7.0, 2.0],
            vec![2.0, 9.0],
            vec![11.0, 4.0],
            vec![5.0, 5.0],
        ]
    }

    #[test]
    fn brute_force_knn_basic() {
        let pts = dataset_2d();
        let q = vec![0.0, 0.0];
        let got = brute_force_knn(&pts, &q, 3);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].index, 0);
        assert_eq!(got[1].index, 1);
    }

    #[test]
    fn pruning_matches_brute_force_on_fixed_queries() {
        let pts = dataset_2d();
        let tree = BallTree::build(pts.clone());
        let queries: Vec<Vec<f64>> = vec![
            vec![0.0, 0.0],
            vec![5.0, 5.0],
            vec![10.0, 10.0],
            vec![-1.0, 2.0],
        ];
        for q in queries {
            for k in 1..=pts.len() {
                let bf = brute_force_knn(&pts, &q, k);
                let pr = knn_with_pruning(&tree, &q, k);
                assert_eq!(bf, pr, "k={k} q={q:?}");
            }
        }
    }

    #[test]
    fn ball_tree_build_is_deterministic() {
        let pts = dataset_2d();
        let a = BallTree::build(pts.clone());
        let b = BallTree::build(pts);
        assert_eq!(format!("{:?}", a.root), format!("{:?}", b.root));
    }
}
