//! Generative tamper suite (blueprint §17.2, §19 90-day ≥120 executed cases).

#[path = "e2e/helpers.rs"]
mod helpers;

use helpers::{agent_store, semantic_draft, theme_key};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_smt::{SparseMerkleTree, TREE_DEPTH};

#[test]
fn tamper_suite_generative_byte_mutations() {
    let mut cases = 0u32;

    // (1) Object-byte tamper through the real fail-closed recall path. Each case
    // stores a DISTINCT object (varied body) so these are not identical repeats;
    // `recall_verified` re-hashes the bytes before decode, so any mutation surfaces
    // as exactly `ObjectTampered`. Asserts the exact typed variant, not `is_err()`.
    for i in 0..30u32 {
        let (mut store, cap, _dir) = agent_store();
        let body = format!("mneme-tamper-fixture-{i:02}");
        let (id, _) = store
            .remember(semantic_draft("tamper", "payload", body.as_bytes()), &cap)
            .unwrap();
        let query = Query {
            logical_key: theme_key("tamper", "payload"),
            min_tier: TrustTier::Working,
            embedding: None,
        };
        store.tamper_object_bytes(id.as_bytes()).unwrap();
        assert_eq!(
            store.recall_verified_default(&query, &cap).unwrap_err(),
            MnemeError::ObjectTampered,
            "object tamper case {i}"
        );
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

    // (2) Membership auth-path siblings: flip every depth at a depth-dependent byte
    // position (covers positions across the 32-byte node, not just byte 0) and
    // assert the EXACT `IndexPathInvalid` variant.
    for i in 0..proof.path.len() {
        let mut bad = proof.clone();
        bad.path[i][i % 32] ^= 0x01;
        assert_eq!(
            SparseMerkleTree::verify_membership(&bad).unwrap_err(),
            MnemeError::IndexPathInvalid,
            "membership path tamper depth {i}"
        );
        cases += 1;
    }

    // (3) Membership committed root — every byte position, exact variant.
    for b in 0..32usize {
        let mut bad = proof.clone();
        bad.root[b] ^= 0x01;
        assert_eq!(
            SparseMerkleTree::verify_membership(&bad).unwrap_err(),
            MnemeError::IndexPathInvalid,
            "membership root tamper byte {b}"
        );
        cases += 1;
    }

    // (4) Membership leaf value — every byte position, exact variant. (A single bit
    // flip cannot collide with the TOMBSTONE sentinel, so this is never `Forgotten`.)
    for b in 0..32usize {
        let mut bad = proof.clone();
        bad.value[b] ^= 0x02;
        assert_eq!(
            SparseMerkleTree::verify_membership(&bad).unwrap_err(),
            MnemeError::IndexPathInvalid,
            "membership value tamper byte {b}"
        );
        cases += 1;
    }

    // (5) Non-membership proof path — every depth, depth-dependent position, exact
    // variant. Proves a forged "absent" proof for a present-or-arbitrary key fails.
    let absent_key = theme_key("tamper", "never-written");
    let absent = store.prove_absent(&absent_key).unwrap();
    for i in 0..absent.path.len() {
        let mut bad = absent.clone();
        bad.path[i][(i * 7 + 3) % 32] ^= 0x01;
        assert_eq!(
            SparseMerkleTree::verify_non_membership(&bad).unwrap_err(),
            MnemeError::IndexPathInvalid,
            "non-membership path tamper depth {i}"
        );
        cases += 1;
    }

    assert!(
        cases >= 150,
        "store generative tamper must cover ≥150 distinct cases (got {cases})"
    );
    eprintln!("tamper_suite (store): {cases} distinct cases passed, exact typed variants");
}

#[test]
fn tamper_suite_path_depth_covers_tree() {
    assert_eq!(TREE_DEPTH, 256, "SMT depth must match blueprint §5.6");
}
