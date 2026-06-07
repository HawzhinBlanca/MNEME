//! Root invariant tests (§17.1 red→green, INV-4, INV-6).

use mneme_core::{Hlc, MnemeError, NodeId, RootPreimage};
use mneme_crypto::KeyPair;
use mneme_root::{CheckpointLog, ROOT_VERSION, StoredRoot, check_replay, verify_root_chain};
use std::path::Path;

fn sample_hlc(n: u8) -> [u8; 14] {
    let mut out = [0u8; 14];
    out[0] = n;
    out
}

fn hlc_wire(wall_ms: u64, counter: u32) -> [u8; 14] {
    Hlc {
        wall_ms,
        counter,
        node_id: NodeId([0; 16]),
    }
    .to_bytes()
}

fn sample_roots() -> ([u8; 32], [u8; 32], [u8; 32]) {
    ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32])
}

fn operator() -> KeyPair {
    KeyPair::from_seed([0x42; 32])
}

#[test]
fn root_preimage_hash_matches_domain_tag_layout() {
    let (dag, key, sem) = sample_roots();
    let preimage = RootPreimage {
        version: ROOT_VERSION,
        dag_head_root: dag,
        key_index_root: key,
        semantic_commit: sem,
        hlc_max: sample_hlc(1),
        prev_root: [0u8; 32],
    };
    let payload = preimage.encode_payload();
    assert_eq!(payload.len(), 2 + 32 * 4 + 14);
    assert_eq!(payload[0..2], ROOT_VERSION.to_le_bytes());
    let hash_a = preimage.hash();
    let hash_b = preimage.hash();
    assert_eq!(hash_a, hash_b);
    assert_ne!(hash_a, [0u8; 32]);
}

#[test]
fn assemble_sign_verify_roundtrip() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(2), [0u8; 32], 1, &op).expect("assemble");
    stored.verify(&op.verifying_key()).expect("verify");
    assert_eq!(stored.preimage().hash(), stored.preimage_hash);
}

#[test]
fn fault_injection_rejects_tampered_signature() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let mut stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(3), [0u8; 32], 1, &op).expect("assemble");
    stored.signature[0] ^= 0xff;
    let err = stored.verify(&op.verifying_key()).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn fault_injection_rejects_tampered_preimage_hash() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let mut stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(4), [0u8; 32], 1, &op).expect("assemble");
    stored.preimage_hash[0] ^= 0xff;
    let err = stored.verify(&op.verifying_key()).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn dcbor_roundtrip_is_canonical() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(5), [0u8; 32], 7, &op).expect("assemble");
    let bytes = stored.to_bytes().expect("encode");
    let decoded = StoredRoot::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, stored);
    let again = StoredRoot::from_bytes(&bytes).expect("re-decode");
    assert_eq!(
        stored.to_bytes().expect("re-encode"),
        again.to_bytes().expect("re-encode2")
    );
}

#[test]
fn root_chain_links_prev_hash_and_sequence() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(10), [0u8; 32], 1, &op).expect("first");
    let second = StoredRoot::assemble(dag, key, sem, sample_hlc(11), first.preimage_hash, 2, &op)
        .expect("second");
    verify_root_chain(&second.to_root(), Some(&first.to_root())).expect("chain");
}

#[test]
fn root_chain_rejects_sequence_regression() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(12), [0u8; 32], 2, &op).expect("first");
    let stale = StoredRoot::assemble(dag, key, sem, sample_hlc(13), first.preimage_hash, 2, &op)
        .expect("stale");
    let err = verify_root_chain(&stale.to_root(), Some(&first.to_root())).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn check_replay_rejects_older_hlc() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let root = StoredRoot::assemble(dag, key, sem, sample_hlc(1), [0u8; 32], 1, &op).expect("root");
    check_replay(&root.to_root(), Some(sample_hlc(2))).unwrap_err();
    check_replay(&root.to_root(), Some(sample_hlc(1))).expect("equal ok");
    check_replay(&root.to_root(), Some(sample_hlc(0))).expect("older ok");
}

#[test]
fn check_replay_rejects_numeric_hlc_regression_across_byte_boundary() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let advanced =
        StoredRoot::assemble(dag, key, sem, hlc_wire(256, 0), [0u8; 32], 1, &op).expect("root");
    let regressed =
        StoredRoot::assemble(dag, key, sem, hlc_wire(255, 0), [0u8; 32], 2, &op).expect("root");
    let err = check_replay(&regressed.to_root(), Some(hlc_wire(256, 0))).unwrap_err();
    assert_eq!(err, MnemeError::RootReplayed);
    check_replay(&advanced.to_root(), Some(hlc_wire(255, 0))).expect("advance ok");
}

#[test]
fn checkpoint_log_append_is_create_new() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let root =
        StoredRoot::assemble(dag, key, sem, sample_hlc(20), [0u8; 32], 1, &op).expect("root");
    CheckpointLog::append(store, &root).expect("append");
    let loaded = CheckpointLog::read_checkpoint(store, 1).expect("read");
    assert_eq!(loaded, root);
    let err = CheckpointLog::append(store, &root).unwrap_err();
    assert!(matches!(err, MnemeError::IoFailed { kind, .. } if kind == "exists"));
}

#[test]
fn head_write_and_read_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let root =
        StoredRoot::assemble(dag, key, sem, sample_hlc(21), [0u8; 32], 3, &op).expect("root");
    CheckpointLog::commit(store, &root).expect("commit");
    let head = CheckpointLog::read_head(store).expect("head");
    assert_eq!(head, root);
    assert!(checkpoint_file(store, 3).exists());
}

#[test]
fn pinned_root_preimage_hash_for_fixture_seed() {
    let (dag, key, sem) = sample_roots();
    let preimage = RootPreimage {
        version: ROOT_VERSION,
        dag_head_root: dag,
        key_index_root: key,
        semantic_commit: sem,
        hlc_max: sample_hlc(0),
        prev_root: [0u8; 32],
    };
    let hash = preimage.hash();
    // Byte-pinned once computed from MNEME-root-v1 domain tag + §5.7 layout.
    assert_eq!(
        hash,
        hex32("9194a7f3d98cf4aa8e3f3094bc886e5ab71bee9097b467f42a57bbe52509aa69")
    );
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("hex32");
    out
}

fn checkpoint_file(store: &Path, sequence: u64) -> std::path::PathBuf {
    store.join(format!("roots/{sequence}.root.cbor"))
}
