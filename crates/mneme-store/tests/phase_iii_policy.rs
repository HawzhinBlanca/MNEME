//! Mandatory ActionReceipt policy on external store paths (P3-1).

use mneme_cap::{Capability, Permissions};
use mneme_core::{Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, TrustTier};
use mneme_crypto::KeyPair;
use mneme_store::{Store, action_commit_forget, action_commit_promote, action_commit_remember};
use tempfile::TempDir;

fn setup() -> (TempDir, Store, KeyPair, Capability) {
    let dir = TempDir::new().unwrap();
    let operator = KeyPair::generate();
    let store = Store::create(dir.path(), operator.clone()).unwrap();
    let cap = Capability::issue(
        &operator,
        operator.public_key_bytes(),
        vec!["app".into(), "gdpr".into()],
        vec![MemoryKind::Episodic, MemoryKind::Semantic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap();
    (dir, store, operator, cap)
}

fn sample_draft(ns: &str, name: &str) -> Draft {
    Draft {
        namespace: ns.into(),
        logical_name: name.into(),
        kind: MemoryKind::Episodic,
        body: b"data".to_vec(),
        parent_ids: vec![],
        session: [0x03; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
    }
}

fn bind_remember(
    store: &Store,
    draft: &Draft,
    cap: &Capability,
    operator: &KeyPair,
) -> mneme_core::ActionReceipt {
    let commit = action_commit_remember(draft);
    store
        .bind_external_action(commit, cap, operator, None)
        .unwrap()
}

#[test]
fn remember_without_receipt_rejects_under_mandatory_policy() {
    let (_dir, mut store, _op, cap) = setup();
    let draft = sample_draft("app", "k");
    assert!(matches!(
        store.remember_with_action(draft, &cap, None).unwrap_err(),
        MnemeError::ProvenanceBroken
    ));
}

#[test]
fn remember_with_bound_receipt_succeeds() {
    let (_dir, mut store, operator, cap) = setup();
    let draft = sample_draft("app", "bound");
    let receipt = bind_remember(&store, &draft, &cap, &operator);
    store
        .remember_with_action(draft, &cap, Some(&receipt))
        .unwrap();
}

#[test]
fn forget_without_receipt_rejects_under_mandatory_policy() {
    let (_dir, mut store, operator, cap) = setup();
    let draft = sample_draft("gdpr", "pii");
    let receipt = bind_remember(&store, &draft, &cap, &operator);
    store
        .remember_with_action(draft, &cap, Some(&receipt))
        .unwrap();
    let target = ForgetTarget::LogicalKey(LogicalKey {
        namespace: "gdpr".into(),
        name: "pii".into(),
    });
    assert!(matches!(
        store
            .forget_with_action(target.clone(), &cap, ForgetMode::Shred, None)
            .unwrap_err(),
        MnemeError::ProvenanceBroken
    ));
}

#[test]
fn forget_with_bound_receipt_succeeds() {
    let (_dir, mut store, operator, cap) = setup();
    let draft = sample_draft("gdpr", "erase");
    let remember_receipt = bind_remember(&store, &draft, &cap, &operator);
    store
        .remember_with_action(draft, &cap, Some(&remember_receipt))
        .unwrap();
    let target = ForgetTarget::LogicalKey(LogicalKey {
        namespace: "gdpr".into(),
        name: "erase".into(),
    });
    let commit = action_commit_forget(&target, ForgetMode::Shred);
    let forget_receipt = store
        .bind_external_action(commit, &cap, &operator, None)
        .unwrap();
    store
        .forget_with_action(target, &cap, ForgetMode::Shred, Some(&forget_receipt))
        .unwrap();
}

#[test]
fn promote_without_receipt_rejects_under_mandatory_policy() {
    let (_dir, mut store, operator, cap) = setup();
    let draft = sample_draft("app", "tier");
    let receipt = bind_remember(&store, &draft, &cap, &operator);
    let (id, _) = store
        .remember_with_action(draft, &cap, Some(&receipt))
        .unwrap();
    assert!(matches!(
        store
            .promote_with_action(&id, TrustTier::Trusted, &cap, None)
            .unwrap_err(),
        MnemeError::ProvenanceBroken
    ));
}

#[test]
fn promote_with_bound_receipt_succeeds() {
    let (_dir, mut store, operator, cap) = setup();
    let draft = sample_draft("app", "up");
    let remember_receipt = bind_remember(&store, &draft, &cap, &operator);
    let (id, _) = store
        .remember_with_action(draft, &cap, Some(&remember_receipt))
        .unwrap();
    let commit = action_commit_promote(&id, TrustTier::Trusted);
    let promote_receipt = store
        .bind_external_action(commit, &cap, &operator, None)
        .unwrap();
    store
        .promote_with_action(&id, TrustTier::Trusted, &cap, Some(&promote_receipt))
        .unwrap();
}
