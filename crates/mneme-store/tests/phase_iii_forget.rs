//! Store-path ForgetProof emit + verify (P3-2).

use mneme_account::{PHASE_III_PROVE_FORGET_OPEN, verify_forget_proof, verify_forget_proof_wire};
use mneme_cap::{Capability, Permissions};
use mneme_core::{
    Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, TrustTier, encode_forget_proof,
};
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
        vec!["gdpr".into()],
        vec![MemoryKind::Semantic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap();
    (dir, store, cap)
}

#[test]
fn forget_with_proof_emits_and_binds_post_commit_root() {
    assert!(std::hint::black_box(PHASE_III_PROVE_FORGET_OPEN));
    let (_dir, mut store, cap) = setup();
    let key = LogicalKey {
        namespace: "gdpr".into(),
        name: "pii".into(),
    };
    let draft = Draft {
        namespace: key.namespace.clone(),
        logical_name: key.name.clone(),
        kind: MemoryKind::Semantic,
        body: b"secret".to_vec(),
        parent_ids: vec![],
        session: [0x01; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
        embargo_round: None,
    };
    store.remember(draft, &cap).unwrap();
    let pre_seq = store.current_root().unwrap().sequence;
    let target = ForgetTarget::LogicalKey(key.clone());
    let proven = store
        .forget_with_proof(target, &cap, ForgetMode::Shred, None)
        .unwrap();
    assert!(proven.root.sequence > pre_seq);
    assert_eq!(proven.proof.root_bound, proven.root.preimage_hash);
    verify_forget_proof(&proven.proof, &proven.root).unwrap();
    verify_forget_proof_wire(&encode_forget_proof(&proven.proof).unwrap(), &proven.root).unwrap();
    store.prove_absent(&key).unwrap();
}

#[test]
fn forget_proof_rejects_stale_root_binding() {
    let (_dir, mut store, cap) = setup();
    let key = LogicalKey {
        namespace: "gdpr".into(),
        name: "replay".into(),
    };
    let draft = Draft {
        namespace: key.namespace.clone(),
        logical_name: key.name.clone(),
        kind: MemoryKind::Semantic,
        body: b"x".to_vec(),
        parent_ids: vec![],
        session: [0x02; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
        embargo_round: None,
    };
    store.remember(draft, &cap).unwrap();
    let proven = store
        .forget_with_proof(ForgetTarget::LogicalKey(key), &cap, ForgetMode::Shred, None)
        .unwrap();
    let mut stale = proven.root.clone();
    stale.preimage_hash[0] ^= 0x01;
    assert!(verify_forget_proof(&proven.proof, &stale).is_err());
}
