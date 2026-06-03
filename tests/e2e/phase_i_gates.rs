use super::helpers::{agent_store, theme_key};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_index::default_key_procedure;
use mneme_store::AsOf;

#[test]
fn e2e_recall_verified_at_is_fail_closed() {
    let (store, cap, _dir) = agent_store();
    let query = Query {
        logical_key: theme_key("phase", "bitemporal"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let proc = default_key_procedure();
    let err = store
        .recall_verified_at(&query, &proc, &cap, AsOf::RootSeq(0))
        .unwrap_err();
    assert!(matches!(err, MnemeError::UnsupportedVersion { .. }));
}

#[test]
fn e2e_provenance_scoped_recall_is_fail_closed() {
    let (store, cap, _dir) = agent_store();
    let query = Query {
        logical_key: theme_key("phase", "provenance"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let proc = default_key_procedure();
    let err = store
        .provenance_scoped_recall(&query, &proc, &cap)
        .unwrap_err();
    assert!(matches!(err, MnemeError::UnsupportedVersion { .. }));
}
