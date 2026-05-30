//! SMT invariant tests (§17.1 red→green, Appendix B item 3).

use mneme_core::MnemeError;
use mneme_smt::{
    ParsedProof, SparseMerkleTree, TOMBSTONE, TREE_DEPTH, default_hashes, empty_root,
    encode_membership_wire, encode_non_membership_wire, fuzz_parse_and_verify, parse_proof_blob,
    root_from_leaves,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("hex32");
    out
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SmtFixture {
    name: String,
    entries: Vec<SmtEntry>,
    root: String,
    #[serde(default)]
    membership: Vec<MembershipCase>,
    #[serde(default)]
    non_membership: Vec<NonMembershipCase>,
}

#[derive(serde::Deserialize)]
struct SmtEntry {
    key: String,
    value: String,
}

#[derive(serde::Deserialize)]
struct MembershipCase {
    key: String,
    value: String,
    path: Vec<String>,
    root: String,
    leaf_index: usize,
}

#[derive(serde::Deserialize)]
struct NonMembershipCase {
    key: String,
    path: Vec<String>,
    root: String,
    #[serde(default)]
    conflicting_key: Option<String>,
    #[serde(default)]
    conflicting_value: Option<String>,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../proof/vectors/smt")
        .join(name)
}

fn load_fixture(name: &str) -> SmtFixture {
    let path = fixture_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn tree_from_fixture(fixture: &SmtFixture) -> SparseMerkleTree {
    let mut smt = SparseMerkleTree::new();
    for entry in &fixture.entries {
        smt.upsert(hex32(&entry.key), hex32(&entry.value));
    }
    smt.rebuild_root_cache();
    smt
}

#[test]
fn appendix_b_empty_tree_root_is_byte_exact() {
    let fixture = load_fixture("empty_tree.json");
    let smt = tree_from_fixture(&fixture);
    assert_eq!(hex::encode(smt.root()), fixture.root);
    assert_eq!(smt.root(), empty_root());
}

#[test]
fn appendix_b_empty_tree_non_membership_proof_is_byte_exact() {
    let fixture = load_fixture("empty_tree.json");
    let smt = tree_from_fixture(&fixture);
    assert_eq!(fixture.non_membership.len(), 1);
    let case = &fixture.non_membership[0];
    let key = hex32(&case.key);
    let proof = smt.prove_non_membership(key).expect("prove");
    assert_eq!(hex::encode(proof.root), case.root);
    assert_eq!(
        proof.path.iter().map(hex::encode).collect::<Vec<_>>(),
        case.path
    );
    assert!(proof.conflicting_leaf.is_none());
    SparseMerkleTree::verify_non_membership(&proof).expect("verify");
}

#[test]
fn appendix_b_single_member_root_and_membership_proof_byte_exact() {
    let fixture = load_fixture("single_member.json");
    let smt = tree_from_fixture(&fixture);
    assert_eq!(hex::encode(smt.root()), fixture.root);
    let case = &fixture.membership[0];
    let key = hex32(&case.key);
    let proof = smt.prove_membership(key).expect("prove");
    assert_eq!(hex::encode(proof.value), case.value);
    assert_eq!(hex::encode(proof.root), case.root);
    assert_eq!(
        proof.path.iter().map(hex::encode).collect::<Vec<_>>(),
        case.path
    );
    assert_eq!(proof.leaf_index, case.leaf_index);
    SparseMerkleTree::verify_membership(&proof).expect("verify");
}

#[test]
fn appendix_b_single_member_non_membership_for_absent_key_byte_exact() {
    let fixture = load_fixture("single_member.json");
    let smt = tree_from_fixture(&fixture);
    let case = &fixture.non_membership[0];
    let key = hex32(&case.key);
    let proof = smt.prove_non_membership(key).expect("prove");
    assert_eq!(hex::encode(proof.root), case.root);
    assert_eq!(
        proof.path.iter().map(hex::encode).collect::<Vec<_>>(),
        case.path
    );
    SparseMerkleTree::verify_non_membership(&proof).expect("verify");
}

#[test]
fn appendix_b_multi_member_roots_and_proofs_byte_exact() {
    let fixture = load_fixture("multi_member.json");
    let smt = tree_from_fixture(&fixture);
    assert_eq!(hex::encode(smt.root()), fixture.root);
    for case in &fixture.membership {
        let proof = smt
            .prove_membership(hex32(&case.key))
            .expect("membership prove");
        assert_eq!(hex::encode(proof.value), case.value);
        assert_eq!(hex::encode(proof.root), case.root);
        assert_eq!(
            proof.path.iter().map(hex::encode).collect::<Vec<_>>(),
            case.path
        );
        SparseMerkleTree::verify_membership(&proof).expect("verify membership");
    }
    for case in &fixture.non_membership {
        let proof = smt
            .prove_non_membership(hex32(&case.key))
            .expect("non-membership prove");
        assert_eq!(hex::encode(proof.root), case.root);
        assert_eq!(
            proof.path.iter().map(hex::encode).collect::<Vec<_>>(),
            case.path
        );
        SparseMerkleTree::verify_non_membership(&proof).expect("verify non-membership");
    }
}

#[test]
fn appendix_b_tombstone_non_membership_proof_byte_exact() {
    let fixture = load_fixture("tombstone.json");
    let smt = tree_from_fixture(&fixture);
    assert_eq!(hex::encode(smt.root()), fixture.root);
    let case = &fixture.non_membership[0];
    let key = hex32(&case.key);
    let proof = smt.prove_non_membership(key).expect("prove");
    assert_eq!(hex::encode(proof.root), case.root);
    assert_eq!(
        proof.path.iter().map(hex::encode).collect::<Vec<_>>(),
        case.path
    );
    let (ck, cv) = proof.conflicting_leaf.expect("tombstone leaf");
    assert_eq!(
        hex::encode(ck),
        case.conflicting_key
            .as_ref()
            .expect("conflict key")
            .as_str()
    );
    assert_eq!(
        hex::encode(cv),
        case.conflicting_value
            .as_ref()
            .expect("conflict val")
            .as_str()
    );
    SparseMerkleTree::verify_non_membership(&proof).expect("verify");
}

#[test]
fn deterministic_root_recompute_from_leaf_map() {
    let fixture = load_fixture("multi_member.json");
    let mut leaves = BTreeMap::new();
    for entry in &fixture.entries {
        leaves.insert(hex32(&entry.key), hex32(&entry.value));
    }
    assert_eq!(hex::encode(root_from_leaves(&leaves)), fixture.root);
}

#[test]
fn default_hashes_chain_is_deterministic() {
    let d = default_hashes();
    assert_eq!(d.len(), TREE_DEPTH + 1);
    assert_eq!(d[TREE_DEPTH], empty_root());
}

/// §17.1 red→green: non-membership must not accept a live key.
#[test]
fn non_membership_rejects_live_key_at_prove_time() {
    let mut smt = SparseMerkleTree::new();
    let key = hex32("0101010101010101010101010101010101010101010101010101010101010101");
    let val = hex32("0202020202020202020202020202020202020202020202020202020202020202");
    smt.upsert(key, val);
    assert_eq!(
        smt.prove_non_membership(key).unwrap_err(),
        MnemeError::TombstoneConflict
    );
}

/// §17.1 red→green: membership verification rejects tombstone values.
#[test]
fn membership_verify_rejects_tombstone_value_in_proof() {
    let key = hex32("0303030303030303030303030303030303030303030303030303030303030303");
    let proof = mneme_smt::MembershipProof {
        key,
        value: TOMBSTONE,
        path: vec![empty_root(); TREE_DEPTH],
        root: empty_root(),
        leaf_index: 0,
    };
    assert_eq!(
        SparseMerkleTree::verify_membership(&proof).unwrap_err(),
        MnemeError::Forgotten
    );
}

/// §17.1 red→green: tampered membership path fails closed.
#[test]
fn membership_verify_rejects_tampered_path_sibling() {
    let fixture = load_fixture("single_member.json");
    let smt = tree_from_fixture(&fixture);
    let case = &fixture.membership[0];
    let mut proof = smt.prove_membership(hex32(&case.key)).expect("prove");
    if !proof.path.is_empty() {
        proof.path[0][0] ^= 0xff;
    }
    assert_eq!(
        SparseMerkleTree::verify_membership(&proof).unwrap_err(),
        MnemeError::IndexPathInvalid
    );
}

/// §17.1 red→green: non-membership cannot claim a live conflicting leaf.
#[test]
fn non_membership_verify_rejects_live_conflicting_leaf() {
    let fixture = load_fixture("single_member.json");
    let smt = tree_from_fixture(&fixture);
    let case = &fixture.non_membership[0];
    let mut proof = smt.prove_non_membership(hex32(&case.key)).expect("prove");
    proof.conflicting_leaf = Some((
        hex32(&case.key),
        hex32("abababababababababababababababababababababababababababababababab"),
    ));
    assert_eq!(
        SparseMerkleTree::verify_non_membership(&proof).unwrap_err(),
        MnemeError::IndexPathInvalid
    );
}

/// §17.1 red→green: legacy non-zero leaf_index rejected (sorted-list gap closed).
#[test]
fn membership_verify_rejects_nonzero_leaf_index() {
    let fixture = load_fixture("single_member.json");
    let smt = tree_from_fixture(&fixture);
    let case = &fixture.membership[0];
    let mut proof = smt.prove_membership(hex32(&case.key)).expect("prove");
    proof.leaf_index = 1;
    assert_eq!(
        SparseMerkleTree::verify_membership(&proof).unwrap_err(),
        MnemeError::IndexPathInvalid
    );
}

/// §17.5 property: tombstoned key never verifies as present via membership.
#[test]
fn tombstoned_key_never_produces_membership_proof() {
    let mut smt = SparseMerkleTree::new();
    let key = hex32("0404040404040404040404040404040404040404040404040404040404040404");
    smt.tombstone(key);
    assert_eq!(
        smt.prove_membership(key).unwrap_err(),
        MnemeError::Forgotten
    );
}

/// §17.5 property: present key always produces valid membership proof.
#[test]
fn present_key_always_produces_valid_membership_proof() {
    let mut smt = SparseMerkleTree::new();
    let key = hex32("0505050505050505050505050505050505050505050505050505050505050505");
    let val = hex32("0606060606060606060606060606060606060606060606060606060606060606");
    smt.upsert(key, val);
    let proof = smt.prove_membership(key).expect("prove");
    SparseMerkleTree::verify_membership(&proof).expect("verify");
}

#[test]
fn wire_roundtrip_membership_and_non_membership() {
    let smt = tree_from_fixture(&load_fixture("multi_member.json"));
    let m = smt
        .prove_membership(hex32(
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        ))
        .expect("m");
    let wire = encode_membership_wire(&m);
    match parse_proof_blob(&wire).expect("parse") {
        ParsedProof::Membership(p) => {
            assert_eq!(p, m);
            SparseMerkleTree::verify_membership(&p).expect("verify");
        }
        _ => panic!("expected membership"),
    }

    let nm = smt
        .prove_non_membership(hex32(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ))
        .expect("nm");
    let wire = encode_non_membership_wire(&nm);
    match parse_proof_blob(&wire).expect("parse") {
        ParsedProof::NonMembership(p) => {
            assert_eq!(p, nm);
            SparseMerkleTree::verify_non_membership(&p).expect("verify");
        }
        _ => panic!("expected non-membership"),
    }
}

#[test]
fn wire_parse_rejects_malformed_blobs_fail_closed() {
    assert!(parse_proof_blob(&[]).is_err());
    assert!(parse_proof_blob(&[0xff]).is_err());
    let short = [0x01u8; 10];
    assert!(parse_proof_blob(&short).is_err());
}

/// §18 `crypto` lane filter: `cargo test fault_injection`.
#[test]
fn fault_injection_membership_rejects_tampered_root() {
    membership_verify_rejects_tampered_path_sibling();
}

#[test]
fn fuzz_parse_smoke_never_panics_on_random_bytes() {
    for seed in 0u64..512 {
        let mut bytes = seed.to_be_bytes().to_vec();
        bytes.extend_from_slice(&seed.to_le_bytes());
        bytes.resize(128 + (seed as usize % 64), (seed % 251) as u8);
        fuzz_parse_and_verify(&bytes);
    }
}

/// Deterministic distinct 256-bit keys via xorshift (no external rng dependency).
fn det_keys(n: usize) -> Vec<[u8; 32]> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut k = [0u8; 32];
        for chunk in k.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        out.push(k);
    }
    out
}

/// §5.6/§9.3 perf: the cached `auth_path` (built in `rebuild_root_cache`) must be
/// byte-identical to the from-scratch recompute AND drastically faster — proving the
/// membership proof is O(TREE_DEPTH) cache lookups, not an O(n) per-depth subtree rehash.
///
/// Ignored from the correctness lane (it allocates a 10k-leaf tree and is timing-sensitive).
/// Run honest numbers in release:
///   cargo test -p mneme-smt --release auth_path_cached -- --ignored --nocapture
#[test]
#[ignore = "perf micro-bench; run in release with --ignored --nocapture"]
fn auth_path_cached_matches_recompute_and_is_fast() {
    use std::time::Instant;

    const N: usize = 10_000;
    let keys = det_keys(N);

    // `smt_slow` never builds the node cache, so `prove_membership` exercises the
    // legacy O(n) recompute fallback. `smt_fast` builds the cache once.
    let mut smt_slow = SparseMerkleTree::new();
    for (i, k) in keys.iter().enumerate() {
        let mut v = [0u8; 32];
        v[..8].copy_from_slice(&(i as u64).to_le_bytes());
        smt_slow.upsert(*k, v);
    }
    let mut smt_fast = smt_slow.clone();
    smt_fast.rebuild_root_cache();

    assert_eq!(
        smt_slow.root(),
        smt_fast.root(),
        "cache build must not change the root"
    );

    let sample = keys[N / 2];

    // BEFORE: O(n) recompute (no node cache).
    let t0 = Instant::now();
    let proof_slow = smt_slow.prove_membership(sample).expect("slow prove");
    let before = t0.elapsed();

    // AFTER: O(TREE_DEPTH) cached lookups. Average over many calls for a stable per-op number.
    let proof_fast = smt_fast.prove_membership(sample).expect("fast prove");
    const ITERS: u32 = 1_000;
    let t1 = Instant::now();
    for _ in 0..ITERS {
        let _ = smt_fast.prove_membership(sample).expect("fast prove loop");
    }
    let after = t1.elapsed() / ITERS;

    // Equivalence: the cached path must be byte-identical to the recompute.
    assert_eq!(
        proof_slow.path, proof_fast.path,
        "cached auth_path diverged from recompute (proof would be invalid)"
    );
    assert_eq!(proof_slow.root, proof_fast.root);
    SparseMerkleTree::verify_membership(&proof_fast).expect("cached proof must verify");

    eprintln!(
        "auth_path @ {N} leaves: BEFORE(recompute)={before:?}  AFTER(cached avg/{ITERS})={after:?}"
    );

    // Honest budget: blueprint §19 aspires to <1ms. The cached path is O(256) hashes and
    // must be comfortably sub-millisecond on M-series hardware.
    assert!(
        after.as_micros() < 1_000,
        "cached auth_path proof took {after:?} (>=1ms); expected O(TREE_DEPTH) sub-ms"
    );
}
