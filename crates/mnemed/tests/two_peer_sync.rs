//! Two on-disk stores converge via `Store::merge_from_path` (§19 12-month).

use mneme_core::{Draft, LogicalKey, MemoryKind};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use tempfile::tempdir;

fn remember(store: &mut Store, ns: &str, name: &str, body: &[u8], cap: &mneme_cap::Capability) {
    let draft = Draft {
        namespace: ns.into(),
        logical_name: name.into(),
        kind: MemoryKind::Episodic,
        body: body.to_vec(),
        parent_ids: vec![],
        session: [0x01; 16],
        trust_tier: None,
        embedding: None,
    };
    store.remember(draft, cap).expect("remember");
}

#[test]
fn two_peer_stores_anti_entropy_converges_keys() {
    let dir = tempdir().expect("tempdir");
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    let operator = KeyPair::from_seed([0x42; 32]);
    let mut store_a = Store::create(&path_a, operator.clone()).expect("create a");
    let mut store_b = Store::create(&path_b, operator.clone()).expect("create b");
    let cap = mneme_cap::agent_cap(&operator, operator.public_key_bytes()).expect("cap");

    remember(&mut store_a, "peer", "only-a", b"alpha", &cap);
    remember(&mut store_b, "peer", "only-b", b"beta", &cap);

    store_a.merge_from_path(&path_b).expect("merge b into a");
    store_b.merge_from_path(&path_a).expect("merge a into b");

    let key_a = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };
    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-a".into(),
    };
    assert!(store_a.prove_membership(&key_a).is_ok());
    assert!(store_b.prove_membership(&key_b).is_ok());

    assert_eq!(
        store_a.current_root().key_index_root,
        store_b.current_root().key_index_root,
        "MST key-index roots converge after mutual merge"
    );
}
