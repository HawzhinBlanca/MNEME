//! CR-2/CR-3 acceptance: authenticated tree round-trip + honest prover/verifier.

use mneme_index::{
    AuthenticatedBallTree, prove_complete_knn, verify_complete_knn,
    verify_complete_knn_cost_bounded,
};

fn sample_tree() -> AuthenticatedBallTree {
    let pts = vec![
        vec![0.0, 0.0],
        vec![1.0, 0.0],
        vec![3.0, 1.0],
        vec![7.0, 2.0],
        vec![2.0, 9.0],
        vec![11.0, 4.0],
    ];
    AuthenticatedBallTree::from_points(pts)
}

#[test]
fn commitment_byte_identical_across_two_builds() {
    let a = sample_tree();
    let b = sample_tree();
    assert_eq!(a.commitment(), b.commitment());
}

#[test]
fn honest_prover_verifier_roundtrip() {
    let tree = sample_tree();
    let q = vec![0.5, 0.5];
    let k = 3;
    let proof = prove_complete_knn(&tree, &q, k).expect("prove");
    verify_complete_knn(&tree.commitment(), &q, k, &proof).expect("verify");
}

#[test]
fn debug_verify_steps() {
    let tree = AuthenticatedBallTree::from_points(vec![
        vec![0.0, 0.0],
        vec![1.0, 0.0],
        vec![3.0, 1.0],
        vec![7.0, 2.0],
        vec![2.0, 9.0],
        vec![11.0, 4.0],
        vec![5.0, 5.0],
        vec![8.0, 8.0],
    ]);
    let q = vec![1.0, 1.0];
    let k = 3;
    let proof = prove_complete_knn(&tree, &q, k).expect("prove");
    for r in &proof.returned {
        AuthenticatedBallTree::verify_leaf_proof(&tree.commitment(), r.index, &r.point, &r.auth)
            .expect("leaf auth");
    }
    let tau_sq = proof
        .returned
        .iter()
        .map(|r| r.distance_sq)
        .fold(0.0_f64, f64::max);
    for f in &proof.frontier {
        AuthenticatedBallTree::verify_internal_proof(
            &tree.commitment(),
            &f.pivot,
            f.radius_sq,
            &f.left_hash,
            &f.right_hash,
            &f.auth,
        )
        .expect("frontier auth");
        let d_qp = mneme_index::squared_euclidean(&q, &f.pivot).sqrt();
        let lower = (d_qp - f.radius_sq.sqrt()).max(0.0);
        assert!(
            lower * lower > tau_sq,
            "frontier pivot={} lower={} tau={}",
            f.pivot_index,
            lower,
            tau_sq.sqrt()
        );
    }
    verify_complete_knn(&tree.commitment(), &q, k, &proof).expect("full verify");
}

#[test]
fn verifier_cost_is_o_k_plus_frontier() {
    let tree = sample_tree();
    let q = vec![5.0, 5.0];
    let k = 2;
    let proof = prove_complete_knn(&tree, &q, k).expect("prove");
    let (dist, merkle) =
        verify_complete_knn_cost_bounded(&tree.commitment(), &q, k, &proof).expect("verify");
    assert_eq!(dist, k + proof.frontier.len());
    assert_eq!(merkle, k + proof.frontier.len());
    assert!(proof.frontier.len() <= tree.tree.len());
}
