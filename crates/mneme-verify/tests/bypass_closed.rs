//! Adversarial audit B1/B2 closure — unverified recall and head-only verify bypasses.

use mneme_cap::agent_cap;
use mneme_core::{Draft, LogicalKey, MemoryKind, MnemeError, Query, TrustTier};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use mneme_verify::{verify_signed_head_only, verify_store};
use tempfile::tempdir;

fn theme_key(ns: &str, name: &str) -> LogicalKey {
    LogicalKey {
        namespace: ns.into(),
        name: name.into(),
    }
}

#[test]
fn b1_verify_signed_head_only_signature_only_full_verify_rejects_tamper() {
    let dir = tempdir().unwrap();
    let operator = KeyPair::generate();
    let agent = KeyPair::generate();
    let cap = agent_cap(&operator, agent.public_key_bytes()).unwrap();
    let mut store = Store::create(dir.path(), operator.clone()).unwrap();
    store.trust_mut().authorized_writers.push(cap.subject);

    let draft = Draft {
        namespace: "audit".into(),
        logical_name: "b1".into(),
        kind: MemoryKind::Semantic,
        body: b"tamper-me".to_vec(),
        parent_ids: vec![],
        session: [0x01; 16],
        trust_tier: Some(TrustTier::Working),
        embedding: None,
        valid_time_ms: None,
    };
    let (id, _) = store.remember(draft, &cap).unwrap();
    let (root, _) = store.head().unwrap();
    let trust = store.trust().clone();

    store.tamper_object_bytes(id.as_bytes()).unwrap();

    let head =
        verify_signed_head_only(&root, &trust).expect("head-only checks signature, not objects");
    assert_eq!(head.root.sequence, root.sequence);

    assert!(
        verify_store(dir.path(), &trust).is_err(),
        "full verify_store must reject tampered object at committed path"
    );
}

#[test]
fn b2_recall_verified_blocks_oob_tamper_direct_recall_unavailable() {
    let dir = tempdir().unwrap();
    let operator = KeyPair::generate();
    let agent = KeyPair::generate();
    let cap = agent_cap(&operator, agent.public_key_bytes()).unwrap();
    let mut store = Store::create(dir.path(), operator.clone()).unwrap();
    store.trust_mut().authorized_writers.push(cap.subject);

    let draft = Draft {
        namespace: "audit".into(),
        logical_name: "b2".into(),
        kind: MemoryKind::Semantic,
        body: b"verified-only".to_vec(),
        parent_ids: vec![],
        session: [0x02; 16],
        trust_tier: Some(TrustTier::Working),
        embedding: None,
        valid_time_ms: None,
    };
    let (id, _) = store.remember(draft, &cap).unwrap();
    store.tamper_object_bytes(id.as_bytes()).unwrap();

    let query = Query {
        logical_key: theme_key("audit", "b2"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    assert_eq!(
        store.recall_verified_default(&query, &cap).unwrap_err(),
        MnemeError::ObjectTampered
    );
}
