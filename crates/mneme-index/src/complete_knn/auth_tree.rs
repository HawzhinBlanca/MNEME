//! Authenticated ball tree: Merkle commitment over pivot, radius, and child hashes (CR-2).

use super::geometry::{BallNode, BallTree};
use blake3::Hasher;
use mneme_core::MnemeError;

const KNN_DOMAIN: &[u8] = b"MNEME-cknn-v1\x00";
const LEAF_TAG: u8 = 0x20;
const INTERNAL_TAG: u8 = 0x21;
const EMPTY_TAG: u8 = 0x22;

pub fn empty_child_hash() -> [u8; 32] {
    hash_knn_domain(&[EMPTY_TAG])
}

fn hash_knn_domain(payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(KNN_DOMAIN);
    h.update(payload);
    *h.finalize().as_bytes()
}

fn encode_f64(v: f64) -> [u8; 8] {
    v.to_bits().to_be_bytes()
}

pub fn hash_auth_leaf(index: usize, point: &[f64]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + 8 + point.len() * 8);
    payload.push(LEAF_TAG);
    payload.extend_from_slice(&(index as u64).to_be_bytes());
    for &c in point {
        payload.extend_from_slice(&encode_f64(c));
    }
    hash_knn_domain(&payload)
}

pub fn hash_auth_internal(
    pivot: &[f64],
    radius_sq: f64,
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + pivot.len() * 8 + 8 + 64);
    payload.push(INTERNAL_TAG);
    for &c in pivot {
        payload.extend_from_slice(&encode_f64(c));
    }
    payload.extend_from_slice(&encode_f64(radius_sq));
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);
    hash_knn_domain(&payload)
}

/// One step from child to parent along the authentication path.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthPathStep {
    pub pivot: Vec<f64>,
    pub radius_sq: f64,
    pub sibling_hash: [u8; 32],
    pub is_left_child: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthNodeProof {
    pub path: Vec<AuthPathStep>,
    pub leaf_index: Option<usize>,
    pub pivot: Vec<f64>,
    pub radius_sq: Option<f64>,
    pub left_hash: [u8; 32],
    pub right_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AuthenticatedBallTree {
    pub tree: BallTree,
    pub root_hash: [u8; 32],
}

impl AuthenticatedBallTree {
    pub fn from_points(points: Vec<Vec<f64>>) -> Self {
        let tree = BallTree::build(points);
        let root_hash = commit_node(&tree.root, &tree.points);
        Self { tree, root_hash }
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.root_hash
    }

    pub fn prove_leaf(&self, index: usize) -> Option<AuthNodeProof> {
        let point = self.tree.points.get(index)?;
        let mut path = Vec::new();
        if !collect_path(
            &self.tree.root,
            &self.tree.points,
            &NodeTarget::Leaf(index),
            &mut path,
        ) {
            return None;
        }
        Some(AuthNodeProof {
            path,
            leaf_index: Some(index),
            pivot: point.clone(),
            radius_sq: None,
            left_hash: empty_child_hash(),
            right_hash: empty_child_hash(),
        })
    }

    pub fn prove_internal_hash(&self, subtree_hash: [u8; 32]) -> Option<AuthNodeProof> {
        let node = find_internal_by_hash(&self.tree.root, &self.tree.points, &subtree_hash)?;
        let mut path = Vec::new();
        if !collect_path(
            &self.tree.root,
            &self.tree.points,
            &NodeTarget::InternalHash(subtree_hash),
            &mut path,
        ) {
            return None;
        }
        let (pivot, radius_sq, left_hash, right_hash) = internal_payload(node, &self.tree.points);
        Some(AuthNodeProof {
            path,
            leaf_index: None,
            pivot,
            radius_sq: Some(radius_sq),
            left_hash,
            right_hash,
        })
    }

    /// Prove membership for the internal node with `pivot_index` (root-most if ambiguous).
    pub fn prove_internal(&self, pivot_index: usize) -> Option<AuthNodeProof> {
        let node = find_internal(&self.tree.root, pivot_index)?;
        let hash = commit_node(node, &self.tree.points);
        self.prove_internal_hash(hash)
    }

    pub fn verify_leaf_proof(
        commitment: &[u8; 32],
        index: usize,
        point: &[f64],
        proof: &AuthNodeProof,
    ) -> Result<(), MnemeError> {
        if proof.leaf_index != Some(index) {
            return Err(auth_failure(AuthFailure::LeafIndex));
        }
        let mut current = hash_auth_leaf(index, point);
        for step in &proof.path {
            current = parent_hash(step, &current);
        }
        if current != *commitment {
            return Err(auth_failure(AuthFailure::Commitment));
        }
        Ok(())
    }

    pub fn verify_internal_proof(
        commitment: &[u8; 32],
        pivot: &[f64],
        radius_sq: f64,
        left_hash: &[u8; 32],
        right_hash: &[u8; 32],
        proof: &AuthNodeProof,
    ) -> Result<(), MnemeError> {
        if proof.radius_sq != Some(radius_sq) {
            return Err(auth_failure(AuthFailure::Radius));
        }
        let mut current = hash_auth_internal(pivot, radius_sq, left_hash, right_hash);
        for step in &proof.path {
            current = parent_hash(step, &current);
        }
        if current != *commitment {
            return Err(auth_failure(AuthFailure::Commitment));
        }
        Ok(())
    }
}

fn parent_hash(step: &AuthPathStep, child_hash: &[u8; 32]) -> [u8; 32] {
    if step.is_left_child {
        hash_auth_internal(&step.pivot, step.radius_sq, child_hash, &step.sibling_hash)
    } else {
        hash_auth_internal(&step.pivot, step.radius_sq, &step.sibling_hash, child_hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeTarget {
    Leaf(usize),
    InternalHash([u8; 32]),
}

fn find_internal_by_hash<'a>(
    node: &'a BallNode,
    points: &[Vec<f64>],
    hash: &[u8; 32],
) -> Option<&'a BallNode> {
    if commit_node(node, points) == *hash {
        return match node {
            BallNode::Internal { .. } => Some(node),
            BallNode::Leaf { .. } => None,
        };
    }
    match node {
        BallNode::Leaf { .. } => None,
        BallNode::Internal { left, right, .. } => find_internal_by_hash(left, points, hash)
            .or_else(|| find_internal_by_hash(right, points, hash)),
    }
}

fn find_internal(node: &BallNode, pivot_index: usize) -> Option<&BallNode> {
    match node {
        BallNode::Leaf { .. } => None,
        BallNode::Internal {
            pivot_index: pi,
            left,
            right,
            ..
        } => {
            if *pi == pivot_index {
                Some(node)
            } else {
                find_internal(left, pivot_index).or_else(|| find_internal(right, pivot_index))
            }
        }
    }
}

fn internal_payload(node: &BallNode, points: &[Vec<f64>]) -> (Vec<f64>, f64, [u8; 32], [u8; 32]) {
    match node {
        BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => (
            points[*pivot_index].clone(),
            *radius_sq,
            commit_node(left, points),
            commit_node(right, points),
        ),
        BallNode::Leaf { .. } => unreachable!("internal_payload on leaf"),
    }
}

pub(crate) fn commit_node(node: &BallNode, points: &[Vec<f64>]) -> [u8; 32] {
    match node {
        BallNode::Leaf { index } => hash_auth_leaf(*index, &points[*index]),
        BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            let lh = commit_node(left, points);
            let rh = commit_node(right, points);
            hash_auth_internal(&points[*pivot_index], *radius_sq, &lh, &rh)
        }
    }
}

fn collect_path(
    node: &BallNode,
    points: &[Vec<f64>],
    target: &NodeTarget,
    path: &mut Vec<AuthPathStep>,
) -> bool {
    if node_matches(node, points, target) {
        return true;
    }
    match node {
        BallNode::Leaf { .. } => false,
        BallNode::Internal {
            pivot_index,
            radius_sq,
            left,
            right,
        } => {
            if collect_path(left, points, target, path) {
                path.push(AuthPathStep {
                    pivot: points[*pivot_index].clone(),
                    radius_sq: *radius_sq,
                    sibling_hash: commit_node(right, points),
                    is_left_child: true,
                });
                return true;
            }
            if collect_path(right, points, target, path) {
                path.push(AuthPathStep {
                    pivot: points[*pivot_index].clone(),
                    radius_sq: *radius_sq,
                    sibling_hash: commit_node(left, points),
                    is_left_child: false,
                });
                return true;
            }
            false
        }
    }
}

fn node_matches(node: &BallNode, points: &[Vec<f64>], target: &NodeTarget) -> bool {
    match (node, target) {
        (BallNode::Leaf { index: li }, NodeTarget::Leaf(ri)) => li == ri,
        (node, NodeTarget::InternalHash(h)) => commit_node(node, points) == *h,
        _ => false,
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub enum TamperKind {
    FlipPivot,
    InflateRadius,
    FlipLeftChild,
    FlipRightChild,
}

#[cfg(test)]
pub fn commitment_flips_on_tamper(
    tree: &AuthenticatedBallTree,
    pivot_index: usize,
    tamper: TamperKind,
) -> bool {
    let Some(proof) = tree.prove_internal(pivot_index) else {
        return true;
    };
    let mut pivot = proof.pivot.clone();
    let mut radius_sq = proof.radius_sq.unwrap_or(0.0);
    let mut left = proof.left_hash;
    let mut right = proof.right_hash;
    match tamper {
        TamperKind::FlipPivot => {
            if !pivot.is_empty() {
                pivot[0] += 1.0;
            }
        }
        TamperKind::InflateRadius => radius_sq *= 4.0,
        TamperKind::FlipLeftChild => left[0] ^= 0xff,
        TamperKind::FlipRightChild => right[0] ^= 0xff,
    }
    hash_auth_internal(&pivot, radius_sq, &left, &right) != tree.commitment()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthFailure {
    LeafIndex,
    Radius,
    Commitment,
}

fn auth_failure(f: AuthFailure) -> MnemeError {
    match f {
        AuthFailure::LeafIndex | AuthFailure::Radius | AuthFailure::Commitment => {
            MnemeError::IndexPathInvalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pts() -> Vec<Vec<f64>> {
        vec![
            vec![0.0, 0.0],
            vec![1.0, 0.0],
            vec![3.0, 1.0],
            vec![7.0, 2.0],
            vec![2.0, 9.0],
        ]
    }

    #[test]
    fn commitment_is_deterministic() {
        let a = AuthenticatedBallTree::from_points(pts());
        let b = AuthenticatedBallTree::from_points(pts());
        assert_eq!(a.commitment(), b.commitment());
    }

    #[test]
    fn leaf_membership_verifies() {
        let tree = AuthenticatedBallTree::from_points(pts());
        for i in 0..pts().len() {
            let proof = tree.prove_leaf(i).expect("leaf proof");
            AuthenticatedBallTree::verify_leaf_proof(&tree.commitment(), i, &pts()[i], &proof)
                .expect("verify");
        }
    }

    #[test]
    fn internal_membership_verifies() {
        let tree = AuthenticatedBallTree::from_points(pts());
        // Root internal node uses pivot_index 0 for this dataset.
        let proof = tree.prove_internal(0).expect("internal proof");
        AuthenticatedBallTree::verify_internal_proof(
            &tree.commitment(),
            &proof.pivot,
            proof.radius_sq.expect("radius"),
            &proof.left_hash,
            &proof.right_hash,
            &proof,
        )
        .expect("verify internal");
    }

    #[test]
    fn tamper_rejects_or_changes_root() {
        let tree = AuthenticatedBallTree::from_points(pts());
        let root = tree.commitment();
        for kind in [
            TamperKind::FlipPivot,
            TamperKind::InflateRadius,
            TamperKind::FlipLeftChild,
            TamperKind::FlipRightChild,
        ] {
            assert!(commitment_flips_on_tamper(&tree, 0, kind));
        }
        let mut proof = tree.prove_leaf(1).expect("proof");
        let mut bad_point = pts()[1].clone();
        bad_point[0] += 99.0;
        assert_eq!(
            AuthenticatedBallTree::verify_leaf_proof(&root, 1, &bad_point, &proof),
            Err(MnemeError::IndexPathInvalid)
        );
        let _ = &mut proof;
    }
}
