use super::helpers::{agent_store, semantic_draft_with_embedding, theme_key};
use mneme_core::{AsOf, ProvenanceFilter, Query, TrustTier};
use mneme_index::{default_key_procedure, default_semantic_procedure};

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
