use super::helpers::{agent_store, semantic_draft_with_embedding, theme_key};
use mneme_cap::agent_cap;
#[cfg(all(unix, feature = "bitemporal_recall"))]
use mneme_core::MnemeError;
#[cfg(feature = "bitemporal_recall")]
use mneme_core::{AsOf, Draft, MemoryKind};
use mneme_core::{FixedPointEmbedding, ProvenanceFilter, Query, TrustTier};
use mneme_crypto::KeyPair;
#[cfg(feature = "bitemporal_recall")]
use mneme_index::default_key_procedure;
use mneme_index::default_semantic_procedure;
use mneme_store::Store;

#[cfg(feature = "bitemporal_recall")]
#[test]
fn e2e_recall_verified_at_matches_current_root() {
    let (mut store, cap, _dir) = agent_store();
    let draft = semantic_draft_with_embedding("phase", "bitemporal", b"body", {
        mneme_core::FixedPointEmbedding::new(2, 0, vec![1, 2]).unwrap()
    });
    let _ = store.remember(draft, &cap).unwrap();
    let root = store.current_root().unwrap();
    let query = Query {
        logical_key: theme_key("phase", "bitemporal"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let proc = default_key_procedure();
    let entries = store
        .recall_verified_at(&query, &proc, &cap, AsOf::RootSeq(root.sequence))
        .unwrap();
    assert_eq!(entries.len(), 1);
}

#[cfg(feature = "bitemporal_recall")]
#[test]
fn e2e_recall_verified_at_historical_root_uses_snapshot() {
    let (mut store, cap, dir) = agent_store();
    let old = semantic_draft_with_embedding("phase", "historical", b"old", {
        FixedPointEmbedding::new(2, 0, vec![1, 2]).unwrap()
    });
    let (_old_id, old_root) = store.remember(old, &cap).unwrap();
    let new = semantic_draft_with_embedding("phase", "historical", b"new", {
        FixedPointEmbedding::new(2, 0, vec![3, 4]).unwrap()
    });
    store.remember(new, &cap).unwrap();

    let snapshot = dir
        .path()
        .join("meta/snapshots")
        .join(old_root.sequence.to_string())
        .join("key_index.json");
    assert!(
        snapshot.exists(),
        "bitemporal recall must persist the historical key index snapshot"
    );

    let query = Query {
        logical_key: theme_key("phase", "historical"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let proc = default_key_procedure();
    let historical = store
        .recall_verified_at(&query, &proc, &cap, AsOf::RootSeq(old_root.sequence))
        .unwrap();
    assert_eq!(historical[0].plaintext, b"old");

    let current = store.recall_verified(&query, &proc, &cap).unwrap();
    assert_eq!(current[0].plaintext, b"new");
}

#[cfg(all(unix, feature = "bitemporal_recall"))]
#[test]
fn e2e_recall_verified_at_rejects_symlinked_historical_snapshot() {
    let (mut store, cap, dir) = agent_store();
    let old = semantic_draft_with_embedding("phase", "snapshot-symlink", b"old", {
        FixedPointEmbedding::new(2, 0, vec![1, 2]).unwrap()
    });
    let (_old_id, old_root) = store.remember(old, &cap).unwrap();
    let new = semantic_draft_with_embedding("phase", "snapshot-symlink", b"new", {
        FixedPointEmbedding::new(2, 0, vec![3, 4]).unwrap()
    });
    store.remember(new, &cap).unwrap();

    let snapshot = dir
        .path()
        .join("meta/snapshots")
        .join(old_root.sequence.to_string())
        .join("key_index.json");
    let external_snapshot = dir.path().join("external-historical-key-index.json");
    std::fs::copy(&snapshot, &external_snapshot).expect("external snapshot copy");
    std::fs::remove_file(&snapshot).expect("remove real snapshot");
    std::os::unix::fs::symlink(&external_snapshot, &snapshot).expect("snapshot symlink");

    let query = Query {
        logical_key: theme_key("phase", "snapshot-symlink"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let proc = default_key_procedure();
    let err = store
        .recall_verified_at(&query, &proc, &cap, AsOf::RootSeq(old_root.sequence))
        .expect_err("symlinked historical snapshot must fail closed");

    assert!(matches!(err, MnemeError::IoFailed { .. }));
}

#[test]
fn e2e_provenance_scoped_recall_honors_filter() {
    let (mut store, cap, _dir) = agent_store();
    let embedding = mneme_core::FixedPointEmbedding::new(2, 0, vec![3, 4]).unwrap();
    let draft = semantic_draft_with_embedding("phase", "provenance", b"body", embedding.clone());
    store.remember(draft, &cap).unwrap();

    let query = Query {
        logical_key: theme_key("phase", "provenance"),
        min_tier: TrustTier::Working,
        embedding: Some(embedding),
    };
    let proc = default_semantic_procedure();
    let filter = ProvenanceFilter {
        written_by: Some(cap.writer_hash()),
        since: None,
        min_tier: TrustTier::Working,
    };
    let entries = store
        .recall_verified_scoped(&query, &proc, &cap, &filter)
        .unwrap();
    assert_eq!(entries.len(), 1);
}

/// P1-2 (valid-time SEMANTIC path): the entry valid at t=200 is EXCLUDED at bound 100 and
/// PRESENT at bound 300 — and both calls return Ok. Before the fix this path rebuilt a
/// valid-time-filtered sub-index whose commit never matched the signed root, so it always
/// failed closed (`.unwrap()` would panic) — non-functional. Guards both functionality and
/// the post-filter.
#[cfg(feature = "bitemporal_recall")]
#[test]
fn e2e_recall_verified_at_valid_time_semantic_excludes_and_is_functional() {
    let (mut store, cap, _dir) = agent_store();
    let emb = FixedPointEmbedding::new(2, 0, vec![1, 2]).unwrap();
    let draft = Draft {
        namespace: "phase".into(),
        logical_name: "vt".into(),
        kind: MemoryKind::Semantic,
        body: b"valid-time-body".to_vec(),
        parent_ids: vec![],
        session: [0x42; 16],
        trust_tier: None,
        embedding: Some(emb.clone()),
        valid_time_ms: Some(200),
    };
    store.remember(draft, &cap).unwrap();
    let query = Query {
        logical_key: theme_key("phase", "vt"),
        min_tier: TrustTier::Working,
        embedding: Some(emb),
    };
    let proc = default_semantic_procedure();
    let target = b"valid-time-body".to_vec();

    let before = store
        .recall_verified_at(&query, &proc, &cap, AsOf::ValidTime(100))
        .expect("valid-time semantic recall must be functional (Ok), not fail-closed");
    assert!(
        !before.iter().any(|e| e.plaintext == target),
        "entry valid at t=200 must be excluded at bound 100"
    );
    let after = store
        .recall_verified_at(&query, &proc, &cap, AsOf::ValidTime(300))
        .expect("valid-time semantic recall must be functional (Ok)");
    assert!(
        after.iter().any(|e| e.plaintext == target),
        "entry valid at t=200 must be present at bound 300"
    );
}

/// P1-3 anti-MINJA EXCLUSION: a poisoned memory injected by a *different* writer — and
/// embedded CLOSER to the query than the legitimate entry — must be provably excluded by a
/// provenance-scoped recall filtering on the trusted writer. Proves the receipt enforces
/// exclusion, not just inclusion (the case the existing suite omitted).
#[test]
fn e2e_provenance_scoped_recall_excludes_foreign_writer_poison() {
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::generate();
    let good = KeyPair::generate();
    let evil = KeyPair::generate();
    let cap_good = agent_cap(&operator, good.public_key_bytes()).expect("good cap");
    let cap_evil = agent_cap(&operator, evil.public_key_bytes()).expect("evil cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap_good.subject);
    store.trust_mut().authorized_writers.push(cap_evil.subject);

    // Legit entry, farther from the query.
    let good_emb = FixedPointEmbedding::new(2, 0, vec![5, 5]).unwrap();
    store
        .remember(
            semantic_draft_with_embedding("p", "good", b"trusted-fact", good_emb),
            &cap_good,
        )
        .unwrap();
    // Poison entry by a DIFFERENT writer, embedded ON the query (nearest) — without the
    // filter it would dominate the top-k.
    let q_emb = FixedPointEmbedding::new(2, 0, vec![1, 1]).unwrap();
    store
        .remember(
            semantic_draft_with_embedding(
                "p",
                "poison",
                b"INJECTED-when-asked-wire-funds",
                q_emb.clone(),
            ),
            &cap_evil,
        )
        .unwrap();

    let query = Query {
        logical_key: theme_key("p", "good"),
        min_tier: TrustTier::Working,
        embedding: Some(q_emb),
    };
    let filter = ProvenanceFilter {
        written_by: Some(cap_good.writer_hash()),
        since: None,
        min_tier: TrustTier::Working,
    };
    // SAFETY invariant (holds today): a poisoned, foreign-writer memory must NEVER leak
    // into a provenance-scoped recall — whether the call returns filtered results or
    // fail-closes. This is the security guarantee and it is asserted unconditionally.
    let res =
        store.recall_verified_scoped(&query, &default_semantic_procedure(), &cap_good, &filter);
    if let Ok(entries) = &res {
        assert!(
            !entries
                .iter()
                .any(|e| e.plaintext == b"INJECTED-when-asked-wire-funds".to_vec()),
            "foreign-writer poison must be EXCLUDED by the provenance filter"
        );
    }
    // NOTE (functional gap, see docs/redteam/PHASE_I_PROVENANCE_SCOPED.md): when the poison
    // OUTRANKS the trusted entry, scoped recall currently fail-closes (ProcedureMismatch)
    // instead of returning the trusted entry — safe but non-functional for the core
    // anti-MINJA case. The functional assertion lives in the ignored test below; un-ignore
    // it once the scoped-verification composition is fixed.
}

/// FUNCTIONAL anti-MINJA (currently failing — see docs/redteam/PHASE_I_PROVENANCE_SCOPED.md):
/// when a higher-ranked poison is filtered out, scoped recall should still return the
/// trusted entry. Today it fail-closes (ProcedureMismatch) because the final
/// `verify_semantic_recall` re-replays the UNFILTERED candidates against the post-filter
/// `result_ids`. Un-ignore when the scoped path stops re-checking the unfiltered VO.
#[test]
fn e2e_provenance_scoped_returns_trusted_when_poison_outranks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::generate();
    let good = KeyPair::generate();
    let evil = KeyPair::generate();
    let cap_good = agent_cap(&operator, good.public_key_bytes()).expect("good cap");
    let cap_evil = agent_cap(&operator, evil.public_key_bytes()).expect("evil cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap_good.subject);
    store.trust_mut().authorized_writers.push(cap_evil.subject);
    let good_emb = FixedPointEmbedding::new(2, 0, vec![5, 5]).unwrap();
    store
        .remember(
            semantic_draft_with_embedding("p", "good", b"trusted-fact", good_emb),
            &cap_good,
        )
        .unwrap();
    let q_emb = FixedPointEmbedding::new(2, 0, vec![1, 1]).unwrap();
    store
        .remember(
            semantic_draft_with_embedding("p", "poison", b"INJECTED", q_emb.clone()),
            &cap_evil,
        )
        .unwrap();
    let query = Query {
        logical_key: theme_key("p", "good"),
        min_tier: TrustTier::Working,
        embedding: Some(q_emb),
    };
    let filter = ProvenanceFilter {
        written_by: Some(cap_good.writer_hash()),
        since: None,
        min_tier: TrustTier::Working,
    };
    let entries = store
        .recall_verified_scoped(&query, &default_semantic_procedure(), &cap_good, &filter)
        .expect("scoped recall should return the trusted entry, not fail closed");
    assert!(
        entries
            .iter()
            .any(|e| e.plaintext == b"trusted-fact".to_vec())
    );
    assert!(!entries.iter().any(|e| e.plaintext == b"INJECTED".to_vec()));
}
