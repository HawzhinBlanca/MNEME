//! Generative tamper suite (blueprint §17.2, §19 90-day ≥120 executed cases).

#[path = "e2e/helpers.rs"]
mod helpers;

use helpers::{agent_store, semantic_draft, theme_key};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_smt::{SparseMerkleTree, TREE_DEPTH};

#[test]
fn tamper_suite_generative_byte_mutations() {
    let mut cases = 0u32;

    for _ in 0..30 {
        let (mut store, cap, _dir) = agent_store();
        let (id, _) = store
            .remember(
                semantic_draft("tamper", "payload", b"mneme-tamper-fixture-bytes"),
                &cap,
            )
            .unwrap();
        let query = Query {
            logical_key: theme_key("tamper", "payload"),
            min_tier: TrustTier::Working,
            embedding: None,
        };
        store.tamper_object_bytes(id.as_bytes()).unwrap();
        let err = store.recall_verified_default(&query, &cap).unwrap_err();
        assert_eq!(err, MnemeError::ObjectTampered);
        cases += 1;
    }

    let (mut store, cap, _dir) = agent_store();
    let query = Query {
        logical_key: theme_key("tamper", "payload"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    store
        .remember(
            semantic_draft("tamper", "payload", b"mneme-tamper-fixture-bytes"),
            &cap,
        )
        .unwrap();

    let proof = store
        .prove_membership(&query.logical_key)
        .expect("membership proof");

    for i in 0..proof.path.len() {
        let mut bad = proof.clone();
        bad.path[i][0] ^= 0x01;
        assert!(
            SparseMerkleTree::verify_membership(&bad).is_err(),
            "membership path tamper {i}"
        );
        cases += 1;
    }

    for i in 0..32 {
        let mut bad = proof.clone();
        bad.root[i % 32] ^= 0x01;
        assert!(
            SparseMerkleTree::verify_membership(&bad).is_err(),
            "membership root tamper {i}"
        );
        cases += 1;
    }

    for i in 0..proof.path.len() {
        let mut bad = proof.clone();
        bad.value[i % 32] ^= 0x02;
        assert!(
            SparseMerkleTree::verify_membership(&bad).is_err(),
            "membership value tamper {i}"
        );
        cases += 1;
    }

    let absent_key = theme_key("tamper", "never-written");
    let absent = store.prove_absent(&absent_key).unwrap();
    for i in 0..absent.path.len() {
        let mut bad = absent.clone();
        bad.path[i][0] ^= 0x01;
        assert!(
            SparseMerkleTree::verify_non_membership(&bad).is_err(),
            "non-membership tamper {i}"
        );
        cases += 1;
    }

    assert!(
        cases >= 120,
        "tamper suite must cover ≥120 distinct cases (got {cases})"
    );
    eprintln!("tamper_suite (store): {cases} cases passed");
}

#[test]
fn tamper_suite_path_depth_covers_tree() {
    assert_eq!(TREE_DEPTH, 256, "SMT depth must match blueprint §5.6");
}
