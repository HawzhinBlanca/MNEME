//! E2E Integration tests for the Optimistic Fraud-Proof layer (Task A).

use mneme_cap::{Capability, Permissions};
use mneme_core::{
    DistanceMetric, Draft, FixedPointEmbedding, MemoryKind, Procedure, ProcedureAlgo, TrustTier,
};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use tempfile::TempDir;

fn setup_store_and_cap() -> (TempDir, Store, Capability) {
    let dir = TempDir::new().unwrap();
    let operator = KeyPair::generate();
    let store = Store::create(dir.path(), operator.clone()).unwrap();
    let cap = Capability::issue(
        &operator,
        operator.public_key_bytes(),
        vec!["app".into()],
        vec![MemoryKind::Semantic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap();
    (dir, store, cap)
}

#[test]
fn test_optimistic_e2e_flow() {
    let (_dir, mut store, cap) = setup_store_and_cap();

    // 1. Populate the store with a structured set of vectors.
    // We will insert 15 vectors with coordinates [i, i] for i in 0..15.
    let mut ids = Vec::new();
    for i in 0..15 {
        let draft = Draft {
            namespace: "app".into(),
            logical_name: format!("obj-{}", i),
            kind: MemoryKind::Semantic,
            body: format!("body-{}", i).into_bytes(),
            parent_ids: vec![],
            session: [0x42; 16],
            trust_tier: None,
            embedding: Some(FixedPointEmbedding::new(2, 0, vec![i as i16, i as i16]).unwrap()),
            valid_time_ms: None,
            embargo_round: None,
        };
        let (id, _) = store.remember(draft, &cap).unwrap();
        ids.push(id);
    }

    // 2. Perform a semantic query top-k with k = 5.
    // Query vector at [0, 0]. The 5 nearest neighbors should be obj-0, obj-1, obj-2, obj-3, obj-4.
    let query_vector = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 5,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };

    // Create an honest claim
    let honest_claim = store
        .create_topk_claim(query_vector.clone(), &proc)
        .unwrap();
    assert_eq!(honest_claim.returned_ids.len(), 5);

    // Verify the honest claim has the correct nearest neighbors (obj-0 to obj-4)
    for id in ids.iter().take(5) {
        assert!(honest_claim.returned_ids.contains(id));
    }

    // 3. Audit the honest claim. Watcher should NOT find any fraud.
    let audit_honest = store.audit_topk_claim(&honest_claim, &proc).unwrap();
    assert!(
        audit_honest.is_none(),
        "Honest claim must not produce a challenge"
    );

    // 4. Create a cheated claim by omission.
    // Prover cheats by omitting obj-0 (the absolute closest) and returning obj-5 instead.
    let mut cheated_ids = honest_claim.returned_ids.clone();
    // find the index of ids[0] in cheated_ids and replace it with ids[5]
    let pos = cheated_ids.iter().position(|&x| x == ids[0]).unwrap();
    cheated_ids[pos] = ids[5];

    // Compute the boundary distance for the cheated set.
    // The query is [0, 0]. The vectors are obj-1 [1,1], obj-2 [2,2], obj-3 [3,3], obj-4 [4,4], obj-5 [5,5].
    // obj-5 distance: 5^2 + 5^2 = 50.
    let cheated_d_k = 50;

    let cheated_claim = mneme_optimistic::TopKClaim {
        query: query_vector.clone(),
        d_k: cheated_d_k,
        returned_ids: cheated_ids,
        semantic_commit: honest_claim.semantic_commit,
    };

    // 5. Audit the cheated claim. Watcher MUST detect the fraud because ids[0] is omitted
    // and its distance (0) is strictly less than cheated_d_k (50).
    let audit_cheated = store.audit_topk_claim(&cheated_claim, &proc).unwrap();
    assert!(
        audit_cheated.is_some(),
        "Fraud must be detected for the cheated claim"
    );

    let challenge = audit_cheated.unwrap();
    assert_eq!(
        challenge.object_id, ids[0],
        "Challenge must identify the omitted closer object"
    );

    // 6. Verify the challenge against the cheated claim.
    // Verification should succeed (return true), proving cheating occurred.
    let verify_cheated = cheated_claim.verify_challenge(&challenge).unwrap();
    assert!(
        verify_cheated,
        "Verification of a valid challenge against cheated claim must return true"
    );

    // 7. Verify the challenge against the honest claim.
    // Verification should fail (return false), because ids[0] is already in the honest claim's returned_ids.
    let verify_honest = honest_claim.verify_challenge(&challenge).unwrap();
    assert!(
        !verify_honest,
        "Verification of the challenge against the honest claim must return false"
    );
}
