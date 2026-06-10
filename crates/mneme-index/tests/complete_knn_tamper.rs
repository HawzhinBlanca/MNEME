//! CR-4 generative tamper suite: ≥150 adversarial cases, 100% fail-closed.

use mneme_core::MnemeError;
use mneme_index::{
    AuthenticatedBallTree, CompleteKnnProof, ReturnedPoint, prove_complete_knn, verify_complete_knn,
};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn fixture() -> (AuthenticatedBallTree, Vec<f64>, usize, CompleteKnnProof) {
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
    let proof = prove_complete_knn(&tree, &q, k).expect("honest proof");
    (tree, q, k, proof)
}

#[derive(Clone, Copy, Debug)]
enum TamperClass {
    OmitFrontierBranch,
    InflateRadius,
    UnderstateTau,
    NonMember,
    ForgePivot,
}

const CLASSES: [TamperClass; 5] = [
    TamperClass::OmitFrontierBranch,
    TamperClass::InflateRadius,
    TamperClass::UnderstateTau,
    TamperClass::NonMember,
    TamperClass::ForgePivot,
];

fn apply_tamper(proof: &mut CompleteKnnProof, class: TamperClass, rng: &mut Lcg) {
    match class {
        TamperClass::OmitFrontierBranch => {
            if !proof.frontier.is_empty() {
                proof.frontier.remove(rng.pick(proof.frontier.len()));
            } else if !proof.returned.is_empty() {
                proof.returned.remove(rng.pick(proof.returned.len()));
            }
        }
        TamperClass::InflateRadius => {
            let idx = rng.pick(proof.frontier.len().max(1));
            if let Some(f) = proof.frontier.get_mut(idx) {
                f.radius_sq *= 0.01;
                f.auth.radius_sq = Some(f.radius_sq);
            }
        }
        TamperClass::UnderstateTau => {
            let idx = rng.pick(proof.returned.len().max(1));
            if let Some(r) = proof.returned.get_mut(idx) {
                r.distance_sq = 0.0;
            }
        }
        TamperClass::NonMember => {
            let idx = rng.pick(proof.returned.len().max(1));
            if let Some(r) = proof.returned.get_mut(idx) {
                r.index = 999;
                r.point = vec![99.0, 99.0];
            }
        }
        TamperClass::ForgePivot => {
            let idx = rng.pick(proof.frontier.len().max(1));
            if let Some(f) = proof.frontier.get_mut(idx) {
                f.pivot[0] += 42.0;
                f.auth.pivot[0] += 42.0;
            }
        }
    }
}

#[test]
fn complete_knn_honest_proof_verifies() {
    let (tree, q, k, proof) = fixture();
    verify_complete_knn(&tree.commitment(), &q, k, &proof).expect("genuine verifies");
}

#[test]
fn complete_knn_generative_tamper_suite() {
    let (tree, q, k, genuine) = fixture();
    verify_complete_knn(&tree.commitment(), &q, k, &genuine).expect("sanity");

    let mut rng = Lcg(0xAC00_0000_0150);
    let iterations = 180;
    let mut accepted = 0usize;
    let mut by_class = [0usize; 5];

    for i in 0..iterations {
        let mut proof = genuine.clone();
        let class_idx = rng.pick(CLASSES.len());
        let class = CLASSES[class_idx];
        apply_tamper(&mut proof, class, &mut rng);
        if verify_complete_knn(&tree.commitment(), &q, k, &proof).is_ok() {
            accepted += 1;
            by_class[class_idx] += 1;
            eprintln!("FORGERY ACCEPTED iter={i} class={class:?}");
        }
    }

    assert_eq!(
        accepted, 0,
        "complete-kNN tamper suite accepted {accepted} forgeries: {by_class:?}"
    );
    assert!(
        iterations >= 150,
        "suite must execute ≥150 cases, got {iterations}"
    );
}

#[test]
fn typed_errors_on_named_attack_vectors() {
    let (tree, q, k, mut proof) = fixture();

    // (a) omit frontier
    proof.frontier.clear();
    assert!(matches!(
        verify_complete_knn(&tree.commitment(), &q, k, &proof),
        Err(MnemeError::RetrievalDominanceFailed) | Err(MnemeError::IndexPathInvalid)
    ));

    let (_, _, _, mut proof) = fixture();
    // (b) inflate radius (understate bound → prune too aggressively)
    if let Some(f) = proof.frontier.first_mut() {
        f.radius_sq *= 0.001;
        f.auth.radius_sq = Some(f.radius_sq);
    }
    assert_eq!(
        verify_complete_knn(&tree.commitment(), &q, k, &proof),
        Err(MnemeError::IndexPathInvalid)
    );

    let (_, _, _, mut proof) = fixture();
    // (c) understate tau
    proof.returned[0].distance_sq = 0.0;
    assert_eq!(
        verify_complete_knn(&tree.commitment(), &q, k, &proof),
        Err(MnemeError::RetrievalDominanceFailed)
    );

    let (_, _, _, mut proof) = fixture();
    // (d) non-member
    proof.returned[0] = ReturnedPoint {
        index: 999,
        point: vec![99.0, 99.0],
        distance_sq: 1.0,
        auth: proof.returned[0].auth.clone(),
    };
    assert_eq!(
        verify_complete_knn(&tree.commitment(), &q, k, &proof),
        Err(MnemeError::IndexPathInvalid)
    );

    let (_, _, _, mut proof) = fixture();
    // (e) forge pivot
    if let Some(f) = proof.frontier.first_mut() {
        f.pivot[0] += 10.0;
        f.auth.pivot[0] += 10.0;
    }
    assert_eq!(
        verify_complete_knn(&tree.commitment(), &q, k, &proof),
        Err(MnemeError::IndexPathInvalid)
    );
}
