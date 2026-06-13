//! Coverage for the optional, default-off `root_pace_log` feature: every commit
//! appends the just-committed root to a crash-safe, hash-chained `meta/root-pace.log`.
//!
//! HONESTY: this log is NOT an RFC6962 transparency log — it carries no inclusion or
//! consistency proofs and, being single-operator, does not prevent equivocation. It is a
//! derived, rebuildable artifact. These tests assert the write is crash-safe (no stray
//! `.incomplete` temp), the chain verifies, and the segment labels bind the root preimages.

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
        vec!["pace".into()],
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
        namespace: "pace".into(),
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
fn root_pace_log_chain_verifies_and_binds_each_root() {
    let (dir, mut store, cap) = setup();
    let log_path = dir.path().join("meta/root-pace.log");

    // Store::create already committed the genesis root → the log exists with one segment.
    assert!(
        log_path.exists(),
        "genesis commit must seed the root pace-log"
    );

    remember(&mut store, &cap, "a");
    remember(&mut store, &cap, "b");

    // The atomic temp must never survive a successful commit.
    assert!(
        !dir.path().join("meta/root-pace.log.incomplete").exists(),
        "crash-safe write must leave no .incomplete temp behind"
    );

    let bytes = std::fs::read(&log_path).unwrap();
    let log = mneme_pace::load_log(&bytes).unwrap();
    // The hash chain must verify under the pace reference verifier.
    mneme_pace::verify_log(&log, None).unwrap();

    // genesis + two remembers = three committed roots = three segments.
    assert_eq!(log.segments.len(), 3, "one segment per committed root");

    // The last segment label must bind the current signed root (seq:preimage_hex).
    let root = store.current_root().unwrap();
    let expected = format!("{}:{}", root.sequence, hex::encode(root.preimage_hash));
    assert_eq!(
        log.segments.last().unwrap().label.as_deref(),
        Some(expected.as_str()),
        "last segment label must carry the current root preimage"
    );
}

#[test]
fn root_pace_log_is_derivable_and_grows_monotonically() {
    let (dir, mut store, cap) = setup();
    let log_path = dir.path().join("meta/root-pace.log");

    let seg_count = || {
        mneme_pace::load_log(&std::fs::read(&log_path).unwrap())
            .unwrap()
            .segments
            .len()
    };

    let before = seg_count();
    remember(&mut store, &cap, "x");
    assert_eq!(
        seg_count(),
        before + 1,
        "each commit appends exactly one segment"
    );
}
