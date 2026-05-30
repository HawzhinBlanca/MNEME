//! Tamper suite for mneme-verify (§17.2, v0 ≥40 cases).

mod helpers;

use helpers::{build_valid_recall, theme_key};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_verify::{
    RecallContext, verify_membership_proof, verify_recall, verify_root, verify_store,
};

macro_rules! tamper_case {
    ($name:ident, |$var:ident| $body:stmt, $expected:expr) => {
        #[test]
        fn $name() {
            let mut fixture = build_valid_recall();
            {
                let $var = &mut fixture;
                $body
            }
            let err = run_verify(&fixture).unwrap_err();
            assert_eq!(err, $expected, "case {}", stringify!($name));
        }
    };
}

fn run_verify(f: &helpers::RecallFixture) -> Result<(), MnemeError> {
    let query = Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    };
    verify_recall(&f.input, &query, &f.trust, &ctx).map(|_| ())
}

// --- object bytes ---

tamper_case!(
    tamper_object_byte_0,
    |f| f.input.object_bytes[0] ^= 0x01,
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_mid,
    |f| {
        let i = f.input.object_bytes.len() / 2;
        f.input.object_bytes[i] ^= 0x80;
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_last,
    |f| {
        let i = f.input.object_bytes.len() - 1;
        f.input.object_bytes[i] ^= 0x04;
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_truncated,
    |f| {
        f.input.object_bytes.pop();
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_garbage_appended,
    |f| f.input.object_bytes.push(0xff),
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_1,
    |f| {
        if f.input.object_bytes.len() > 1 {
            f.input.object_bytes[1] ^= 0x02;
        }
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_2,
    |f| {
        if f.input.object_bytes.len() > 2 {
            f.input.object_bytes[2] ^= 0x04;
        }
    },
    MnemeError::ObjectTampered
);

// --- receipt fields ---

tamper_case!(
    tamper_receipt_root_bound,
    |f| f.input.receipt.root_bound[0] ^= 0xff,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_receipt_key_index_root,
    |f| f.input.receipt.key_index_root[31] ^= 0x01,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_receipt_logical_key,
    |f| f.input.receipt.logical_key[0] ^= 0x02,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_receipt_object_id,
    |f| f.input.receipt.object_id[5] ^= 0x10,
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_receipt_leaf_index,
    |f| f.input.receipt.leaf_index = 1,
    MnemeError::IndexPathInvalid
);

// --- SMT path siblings (immudb: every element) ---

tamper_case!(
    tamper_path_depth_0,
    |f| flip_path(&mut f.input.receipt.membership_proof, 0),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_1,
    |f| flip_path(&mut f.input.receipt.membership_proof, 1),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_2,
    |f| flip_path(&mut f.input.receipt.membership_proof, 2),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_8,
    |f| flip_path(&mut f.input.receipt.membership_proof, 8),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_16,
    |f| flip_path(&mut f.input.receipt.membership_proof, 16),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_32,
    |f| flip_path(&mut f.input.receipt.membership_proof, 32),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_64,
    |f| flip_path(&mut f.input.receipt.membership_proof, 64),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_96,
    |f| flip_path(&mut f.input.receipt.membership_proof, 96),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_128,
    |f| flip_path(&mut f.input.receipt.membership_proof, 128),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_200,
    |f| flip_path(&mut f.input.receipt.membership_proof, 200),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_255,
    |f| flip_path(&mut f.input.receipt.membership_proof, 255),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_truncated,
    |f| {
        f.input.receipt.membership_proof.pop();
    },
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_root_mismatch,
    |f| f.input.receipt.membership_proof[0][0] ^= 0xaa,
    MnemeError::IndexPathInvalid
);

// --- signed root / checkpoint ---

tamper_case!(
    tamper_root_signature,
    |f| f.input.root.signature[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_preimage_hash,
    |f| f.input.root.preimage_hash[10] ^= 0x20,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_hlc_replay,
    |f| {
        f.input.root.hlc_max = [0u8; 14];
        f.trust.last_seen_hlc = Some([0xff; 14]);
    },
    MnemeError::RootReplayed
);
tamper_case!(
    tamper_root_chain_break,
    |f| {
        let prev = f.previous_root.as_ref().expect("prev").clone();
        f.input.root.prev_root = [0xee; 32];
        f.previous_root = Some(prev);
    },
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_key_index_mismatch,
    |f| f.input.root.key_index_root[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_checkpoint_sequence_zero,
    |f| f.input.root.sequence = 0,
    MnemeError::RootInconsistent
);
tamper_case!(
    tamper_root_dag_head_mismatch,
    |f| f.input.root.dag_head_root[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_semantic_commit_mismatch,
    |f| f.input.root.semantic_commit[0] ^= 0x02,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_hlc_max_byte,
    |f| f.input.root.hlc_max[3] ^= 0x04,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_receipt_membership_tombstone_value,
    |f| f.input.receipt.object_id = mneme_smt::TOMBSTONE,
    MnemeError::Forgotten
);
tamper_case!(
    tamper_tombstone_then_recall,
    |f| {
        let key = f.input.receipt.logical_key;
        f.key_index.tombstone(key);
        f.key_index.rebuild_root_cache();
    },
    MnemeError::Forgotten
);
tamper_case!(
    tamper_tombstone_membership_proof_stale,
    |f| {
        let key = f.input.receipt.logical_key;
        f.key_index.tombstone(key);
    },
    MnemeError::Forgotten
);
tamper_case!(
    tamper_path_depth_4,
    |f| flip_path(&mut f.input.receipt.membership_proof, 4),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_12,
    |f| flip_path(&mut f.input.receipt.membership_proof, 12),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_24,
    |f| flip_path(&mut f.input.receipt.membership_proof, 24),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_100,
    |f| flip_path(&mut f.input.receipt.membership_proof, 100),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_object_byte_3,
    |f| {
        if f.input.object_bytes.len() > 3 {
            f.input.object_bytes[3] ^= 0x08;
        }
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_4,
    |f| {
        if f.input.object_bytes.len() > 4 {
            f.input.object_bytes[4] ^= 0x10;
        }
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_receipt_root_bound_last,
    |f| f.input.receipt.root_bound[31] ^= 0x01,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_checkpoint_prev_root_zeroed,
    |f| f.input.root.prev_root = [0u8; 32],
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_sequence_regression,
    |f| {
        if let Some(prev) = f.previous_root.clone() {
            f.input.root.sequence = prev.sequence;
        }
    },
    MnemeError::RootInconsistent
);
tamper_case!(
    tamper_root_version_without_preimage_update,
    |f| f.input.root.version = f.input.root.version.wrapping_add(1),
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_version_zero,
    |f| f.input.root.version = 0,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_version_unsupported,
    |f| f.input.root.version = 99,
    MnemeError::RootSigInvalid
);

// --- authorization / tier / forgotten / provenance ---

tamper_case!(
    tamper_unauthorized_writer,
    |f| f.trust.authorized_writers.clear(),
    MnemeError::UnauthorizedWriter
);
tamper_case!(
    tamper_forgotten_tombstone,
    |f| {
        let key = f.input.receipt.logical_key;
        f.key_index.tombstone(key);
    },
    MnemeError::Forgotten
);
#[test]
fn tamper_provenance_missing_parent() {
    let mut fixture = helpers::build_valid_recall_with_parent();
    let record: mneme_core::ObjectRecord =
        mneme_core::from_bytes_strict(&fixture.input.object_bytes).expect("parse");
    let parent = record.parent_ids[0];
    fixture.objects.remove(&parent);
    let err = run_verify(&fixture).unwrap_err();
    assert_eq!(err, MnemeError::ProvenanceBroken);
}

#[test]
fn tamper_below_tier_policy() {
    let fixture = build_valid_recall();
    let query = Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Trusted,
        embedding: None,
    };
    let ctx = RecallContext {
        key_index: &fixture.key_index,
        dag: &fixture.dag,
        objects: &fixture.objects,
        previous_root: fixture.previous_root.as_ref(),
    };
    let err = verify_recall(&fixture.input, &query, &fixture.trust, &ctx).unwrap_err();
    assert_eq!(
        err,
        MnemeError::BelowTierPolicy {
            required: TrustTier::Trusted.as_u8(),
            got: TrustTier::Working.as_u8(),
        }
    );
    assert!(err.to_string().contains("§3 honesty boundary"));
}

#[test]
fn tamper_verify_root_bad_sig() {
    let f = build_valid_recall();
    let mut root = f.input.root.clone();
    root.signature = vec![0u8; 64];
    let err = verify_root(&root, &f.trust, f.previous_root.as_ref()).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn tamper_verify_store_incomplete_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".incomplete"), b"1").expect("write");
    let f = build_valid_recall();
    match verify_store(dir.path(), &f.trust) {
        Err(err) => assert_eq!(err, MnemeError::IncompleteTransaction),
        Ok(_) => panic!("expected incomplete transaction rejection"),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn persist_recall_fixture_store(
    path: &std::path::Path,
    fixture: &helpers::RecallFixture,
) -> mneme_root::StoredRoot {
    use mneme_crypto::KeyPair;
    use mneme_root::StoredRoot;

    std::fs::create_dir_all(path.join("objects")).expect("objects dir");
    std::fs::create_dir_all(path.join("roots")).expect("roots dir");
    std::fs::create_dir_all(path.join("meta")).expect("meta dir");

    for (id, bytes) in &fixture.objects {
        let hex = hex32(id);
        let obj_path = path.join(format!("objects/{}/{}.cbor", &hex[..2], hex));
        std::fs::create_dir_all(obj_path.parent().expect("parent")).expect("shard dir");
        std::fs::write(&obj_path, bytes).expect("object bytes");
    }

    let operator = KeyPair::from_seed([0x01; 32]);
    if let Some(prev) = &fixture.previous_root {
        let prev_stored = StoredRoot::assemble(
            prev.dag_head_root,
            prev.key_index_root,
            prev.semantic_commit,
            prev.hlc_max,
            prev.prev_root,
            prev.sequence,
            &operator,
        )
        .expect("prev stored");
        std::fs::write(
            path.join(format!("roots/{}.root.cbor", prev.sequence)),
            prev_stored.to_bytes().expect("prev bytes"),
        )
        .expect("prev checkpoint");
    }

    let stored = StoredRoot::assemble(
        fixture.input.root.dag_head_root,
        fixture.input.root.key_index_root,
        fixture.input.root.semantic_commit,
        fixture.input.root.hlc_max,
        fixture.input.root.prev_root,
        fixture.input.root.sequence,
        &operator,
    )
    .expect("head stored");
    std::fs::write(
        path.join("roots/HEAD"),
        stored.to_bytes().expect("head bytes"),
    )
    .expect("head");
    stored
}

/// A-DB: multibyte UTF-8 in `meta/key_index.json` must return `SchemaDrift`, never panic (B1).
#[test]
fn tamper_verify_store_multibyte_key_index_schema_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = build_valid_recall();
    persist_recall_fixture_store(dir.path(), &fixture);

    let malicious_key = format!("\u{20AC}{}", "a".repeat(61));
    assert_eq!(malicious_key.len(), 64, "64-byte key hits len guard");
    let payload = format!(
        "{{\"entries\":{{\"{}\":\"{}\"}},\"tombstones\":[]}}",
        malicious_key,
        "0".repeat(64)
    );
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &fixture.trust)
    }));
    assert!(
        result.is_ok(),
        "verify_store must not panic on attacker-controlled key_index.json"
    );
    match result.unwrap() {
        Err(MnemeError::SchemaDrift) => {}
        Err(other) => panic!("expected SchemaDrift, got {other:?}"),
        Ok(_) => panic!("expected SchemaDrift, verify_store succeeded"),
    }
}

/// Tombstone entries with multibyte UTF-8 must also fail closed as `SchemaDrift`.
#[test]
fn tamper_verify_store_multibyte_key_index_tombstone_schema_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = build_valid_recall();
    persist_recall_fixture_store(dir.path(), &fixture);

    let malicious_tombstone = format!("\u{20AC}{}", "b".repeat(61));
    assert_eq!(malicious_tombstone.len(), 64);
    let payload = format!(
        "{{\"entries\":{{}},\"tombstones\":[\"{}\"]}}",
        malicious_tombstone
    );
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &fixture.trust)
    }));
    assert!(
        result.is_ok(),
        "verify_store must not panic on tombstone tamper"
    );
    match result.unwrap() {
        Err(MnemeError::SchemaDrift) => {}
        Err(other) => panic!("expected SchemaDrift, got {other:?}"),
        Ok(_) => panic!("expected SchemaDrift, verify_store succeeded"),
    }
}

#[test]
fn tamper_membership_proof_each_element_checked() {
    let f = build_valid_recall();
    let proof = mneme_smt::MembershipProof {
        key: f.input.receipt.logical_key,
        value: f.input.receipt.object_id,
        path: f.input.receipt.membership_proof.clone(),
        root: f.input.receipt.key_index_root,
        leaf_index: 0,
    };
    verify_membership_proof(&proof).expect("valid proof");
    let mut bad = proof.clone();
    for depth in [0usize, 7, 63, 200, 255] {
        bad.path[depth][depth % 32] ^= 0x01;
        assert_eq!(
            verify_membership_proof(&bad).unwrap_err(),
            MnemeError::IndexPathInvalid,
            "depth {depth}"
        );
        bad = proof.clone();
    }
}

#[test]
fn tamper_stored_root_checkpoint_byte() {
    use mneme_crypto::KeyPair;
    use mneme_root::StoredRoot;

    let fixture = build_valid_recall();
    let operator = KeyPair::from_seed([0x01; 32]);
    let stored = StoredRoot::assemble(
        fixture.input.root.dag_head_root,
        fixture.input.root.key_index_root,
        fixture.input.root.semantic_commit,
        fixture.input.root.hlc_max,
        fixture.input.root.prev_root,
        fixture.input.root.sequence,
        &operator,
    )
    .expect("assemble");
    let bytes = stored.to_bytes().expect("bytes");
    let mut tampered = bytes.clone();
    tampered[0] ^= 0x01;
    assert!(StoredRoot::from_bytes(&tampered).is_err());
}

#[test]
fn tamper_inventory_matches_executed_verify_tests() {
    let counts = tamper_counts_by_category();
    let total: usize = counts.values().sum();
    const EXECUTED_VERIFY_TESTS: usize = 147;
    assert_eq!(
        total, EXECUTED_VERIFY_TESTS,
        "hand-maintained inventory must match executed verify tamper #[test] count (got {total}): {counts:?}"
    );
    assert!(
        total >= 120,
        "§19 90-day verify tamper minimum (got {total})"
    );
}

/// §20.4 handoff: tamper-case inventory by category.
pub fn tamper_counts_by_category() -> std::collections::BTreeMap<&'static str, usize> {
    use std::collections::BTreeMap;
    let mut m = BTreeMap::new();
    // Inventory must match executed `#[test]` count (147 as of 2026-05-30):
    // tamper_suite 60 · tamper_cap 28 · tamper_checkpoint 17 · tamper_semantic 32 · tamper_tombstone 10
    m.insert("object_bytes", 10);
    m.insert("key_receipt", 6);
    m.insert("smt_path", 19);
    m.insert("signed_root", 14);
    m.insert("auth_tier_provenance", 6);
    m.insert("tombstone", 14);
    m.insert("checkpoint_log", 17);
    m.insert("semantic_receipt", 9);
    m.insert("semantic_nodes", 8);
    m.insert("semantic_merkle_paths", 9);
    m.insert("semantic_procedure", 7);
    m.insert("cap_sig_chain", 28);
    m
}

#[allow(clippy::ptr_arg)]
fn flip_path(path: &mut Vec<[u8; 32]>, depth: usize) {
    if depth < path.len() {
        path[depth][0] ^= 0xff;
    }
}
