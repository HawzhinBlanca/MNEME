//! `Store::checkpoint_log_statements` returns the kernel's authoritative committed root
//! history (genesis is sequence 1), oldest first — the drift-proof basis for an MTL
//! transparency log. HONESTY: a single-operator list of these statements proves
//! append-order and inclusion, NOT non-equivocation.

use mneme_cap::{Capability, Permissions};
use mneme_core::{Draft, MemoryKind, TrustTier};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use tempfile::TempDir;

fn setup() -> (TempDir, Store, Capability) {
    let dir = TempDir::new().unwrap();
    let operator = KeyPair::generate();
    let store = Store::create(dir.path(), operator.clone()).unwrap();
    let cap = Capability::issue(
        &operator,
        operator.public_key_bytes(),
        vec!["mtl".into()],
        vec![MemoryKind::Semantic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap();
    (dir, store, cap)
}

fn remember(store: &mut Store, cap: &Capability, name: &str) {
    let draft = Draft {
        namespace: "mtl".into(),
        logical_name: name.into(),
        kind: MemoryKind::Semantic,
        body: format!("body-{name}").into_bytes(),
        parent_ids: vec![],
        session: [0x01; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
    };
    store.remember(draft, cap).unwrap();
}

#[test]
fn checkpoint_log_statements_cover_all_committed_roots_in_order() {
    let (_dir, mut store, cap) = setup();

    // Store::create commits the genesis root at sequence 1.
    let genesis = store.checkpoint_log_statements().unwrap();
    assert_eq!(genesis.len(), 1, "genesis is the only committed root");
    assert_eq!(genesis[0].0, 1, "genesis sequence is 1");

    remember(&mut store, &cap, "a");
    remember(&mut store, &cap, "b");

    let stmts = store.checkpoint_log_statements().unwrap();
    assert_eq!(stmts.len(), 3, "genesis + two remembers");
    assert_eq!(
        stmts.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "sequences are contiguous and ordered oldest-first"
    );

    // The last statement must equal the live current root (no drift).
    let root = store.current_root().unwrap();
    assert_eq!(
        stmts.last().unwrap(),
        &(root.sequence, root.preimage_hash),
        "the final statement binds the current signed root"
    );

    // Every committed root has a distinct preimage (the log is non-degenerate).
    let mut preimages: Vec<[u8; 32]> = stmts.iter().map(|(_, p)| *p).collect();
    preimages.sort();
    preimages.dedup();
    assert_eq!(
        preimages.len(),
        3,
        "each committed root has a distinct preimage"
    );
}
