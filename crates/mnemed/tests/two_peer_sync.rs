//! Two on-disk stores converge via `Store::merge_from_path` (§19 12-month).

use mneme_cap::{Capability, agent_cap};
use mneme_core::{Draft, LogicalKey, MemoryKind};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use std::path::Path;
use tempfile::{TempDir, tempdir};

fn assert_membership_proof<T, E: std::fmt::Debug>(proof: Result<T, E>, context: &str) {
    proof.unwrap_or_else(|err| panic!("{context}: membership proof failed: {err:?}"));
}

fn expect_current_root<T, E: std::fmt::Debug>(root: Result<T, E>, context: &str) -> T {
    root.unwrap_or_else(|err| panic!("{context}: current root failed: {err:?}"))
}

fn expect_two_peer_tempdir(context: &str) -> TempDir {
    tempdir().unwrap_or_else(|err| panic!("{context}: two-peer tempdir failed: {err}"))
}

fn expect_two_peer_store(path: &Path, operator: &KeyPair, context: &str) -> Store {
    Store::create(path, operator.clone())
        .unwrap_or_else(|err| panic!("{context}: two-peer store create failed: {err:?}"))
}

fn expect_two_peer_agent_cap(operator: &KeyPair, context: &str) -> Capability {
    agent_cap(operator, operator.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: two-peer capability creation failed: {err:?}"))
}

fn expect_two_peer_remember<T, E: std::fmt::Debug>(remembered: Result<T, E>, context: &str) -> T {
    remembered.unwrap_or_else(|err| panic!("{context}: two-peer remember failed: {err:?}"))
}

fn expect_two_peer_store_merge<T, E: std::fmt::Debug>(merged: Result<T, E>, context: &str) -> T {
    merged.unwrap_or_else(|err| panic!("{context}: two-peer merge failed: {err:?}"))
}

fn remember(store: &mut Store, ns: &str, name: &str, body: &[u8], cap: &Capability) {
    let draft = Draft {
        namespace: ns.into(),
        logical_name: name.into(),
        kind: MemoryKind::Episodic,
        body: body.to_vec(),
        parent_ids: vec![],
        session: [0x01; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
        embargo_round: None,
    };
    let context = format!("remembering {ns}/{name}");
    expect_two_peer_remember(store.remember(draft, cap), &context);
}

#[test]
fn two_peer_stores_anti_entropy_converges_keys() {
    let dir = expect_two_peer_tempdir("two-peer store sync workspace");
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    let operator = KeyPair::from_seed([0x42; 32]);
    let mut store_a = expect_two_peer_store(&path_a, &operator, "store A");
    let mut store_b = expect_two_peer_store(&path_b, &operator, "store B");
    let cap = expect_two_peer_agent_cap(&operator, "two-peer store sync capability");

    remember(&mut store_a, "peer", "only-a", b"alpha", &cap);
    remember(&mut store_b, "peer", "only-b", b"beta", &cap);

    expect_two_peer_store_merge(
        store_a.merge_from_path(&path_b),
        "merge store B into store A",
    );
    expect_two_peer_store_merge(
        store_b.merge_from_path(&path_a),
        "merge store A into store B",
    );

    let key_a = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };
    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-a".into(),
    };
    assert_membership_proof(
        store_a.prove_membership(&key_a),
        "store A received only-b from B",
    );
    assert_membership_proof(
        store_b.prove_membership(&key_b),
        "store B received only-a from A",
    );

    let root_a = expect_current_root(
        store_a.current_root(),
        "store A current root after mutual merge",
    );
    let root_b = expect_current_root(
        store_b.current_root(),
        "store B current root after mutual merge",
    );
    assert_eq!(
        root_a.key_index_root, root_b.key_index_root,
        "MST key-index roots converge after mutual merge"
    );
}
