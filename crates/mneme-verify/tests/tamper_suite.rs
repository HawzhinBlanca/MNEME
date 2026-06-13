//! Tamper suite for mneme-verify (§17.2, v0 ≥40 cases).

mod helpers;
#[path = "../../../tests/support/source_inventory.rs"]
mod source_inventory;

use helpers::{build_valid_recall, theme_key};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_verify::{
    RecallContext, verify_membership_proof, verify_recall, verify_root, verify_store,
};
use source_inventory::{
    assert_no_local_source_inventory_helpers, source_contains_test_fn, test_function_names,
    test_functions_with_prefixes, test_generator_macro_names,
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

fn source_contains_tamper_case(source: &str, name: &str) -> bool {
    let invocation_name = format!("{name},");
    source.lines().any(|line| line.trim() == invocation_name)
}

#[test]
fn inventory_source_scan_counts_only_test_functions() {
    const SOURCE: &str = concat!(
        "fn tamper_verify_root_helper() {}\n",
        "\n",
        "#[test]\n",
        "fn tamper_verify_root_real_case() {}\n",
        "\n",
        "#[test]\n",
        "#[ignore]\n",
        "fn tamper_verify_root_ignored_but_compiled_case() {}\n",
    );

    assert_eq!(
        test_functions_with_prefixes(SOURCE, &["tamper_verify_root_"]),
        vec![
            "tamper_verify_root_real_case".to_string(),
            "tamper_verify_root_ignored_but_compiled_case".to_string(),
        ]
    );
    assert!(source_contains_test_fn(
        SOURCE,
        "tamper_verify_root_real_case"
    ));
    assert!(!source_contains_test_fn(
        SOURCE,
        "tamper_verify_root_helper"
    ));
}

#[test]
fn inventory_source_scan_helpers_remain_shared() {
    assert_no_local_source_inventory_helpers("tamper_suite.rs", include_str!("tamper_suite.rs"));
}

#[test]
fn verify_root_direct_inventory_is_mapped() {
    const TAMPER_SUITE: &str = include_str!("tamper_suite.rs");
    const PARITY: &[(&str, &str)] = &[("tamper_verify_root_bad_sig", "tamper_root_signature")];

    let direct_root_cases = test_functions_with_prefixes(TAMPER_SUITE, &["tamper_verify_root_"]);
    assert!(
        !direct_root_cases.is_empty(),
        "expected direct verify_root tamper cases in tamper_suite.rs"
    );

    let mapped_direct: std::collections::BTreeSet<&str> =
        PARITY.iter().map(|(direct_case, _)| *direct_case).collect();
    let missing: Vec<_> = direct_root_cases
        .iter()
        .filter(|case| !mapped_direct.contains(case.as_str()))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "direct verify_root tamper cases need explicit indirect root-tamper mapping: {missing:?}"
    );

    for (direct_case, indirect_case) in PARITY {
        assert!(
            source_contains_test_fn(TAMPER_SUITE, direct_case),
            "mapped direct verify_root case is missing: {direct_case}"
        );
        assert!(
            source_contains_tamper_case(TAMPER_SUITE, indirect_case),
            "mapped indirect root tamper case is missing: {indirect_case}"
        );
    }
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

fn multibyte_hex_64_bytes(prefix: char) -> String {
    let value = format!("\u{20AC}{}", "a".repeat(61));
    assert_eq!(value.len(), 64, "{prefix}: fixture must hit byte len guard");
    assert_ne!(
        value.chars().count(),
        64,
        "{prefix}: fixture must contain multibyte UTF-8"
    );
    value
}

fn assert_verify_store_schema_drift_without_panic(
    store: &std::path::Path,
    trust: &mneme_crypto::TrustConfig,
    context: &str,
) {
    assert_verify_store_error_without_panic(store, trust, MnemeError::SchemaDrift, context);
}

fn assert_verify_store_error_without_panic(
    store: &std::path::Path,
    trust: &mneme_crypto::TrustConfig,
    expected: MnemeError,
    context: &str,
) {
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_store(store, trust)));
    assert!(result.is_ok(), "verify_store panicked on {context}");
    match result.expect("panic checked") {
        Err(err) => assert_eq!(err, expected, "unexpected verifier error for {context}"),
        Ok(_) => panic!("verify_store accepted {context}"),
    }
}

fn write_journal_line(path: &std::path::Path, value: serde_json::Value, context: &str) {
    let mut line = serde_json::to_string(&value).expect(context);
    line.push('\n');
    std::fs::write(path, line).expect(context);
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
    // A real commit appends `roots/<seq>.root.cbor` before writing HEAD; mirror
    // that here so the store passes the F-3 head-checkpoint-existence gate and the
    // intended downstream tamper (key_index / tombstone) is what fails closed.
    std::fs::write(
        path.join(format!("roots/{}.root.cbor", stored.sequence)),
        stored.to_bytes().expect("head checkpoint bytes"),
    )
    .expect("head checkpoint");
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

    let malicious_key = multibyte_hex_64_bytes('k');
    let payload = format!(
        "{{\"entries\":{{\"{}\":\"{}\"}},\"tombstones\":[]}}",
        malicious_key,
        "0".repeat(64)
    );
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &fixture.trust,
        "attacker-controlled key_index.json entry key",
    );
}

/// Tombstone entries with multibyte UTF-8 must also fail closed as `SchemaDrift`.
#[test]
fn tamper_verify_store_multibyte_key_index_tombstone_schema_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = build_valid_recall();
    persist_recall_fixture_store(dir.path(), &fixture);

    let malicious_tombstone = multibyte_hex_64_bytes('t');
    let payload = format!(
        "{{\"entries\":{{}},\"tombstones\":[\"{}\"]}}",
        malicious_tombstone
    );
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &fixture.trust,
        "attacker-controlled key_index.json tombstone",
    );
}

/// Malformed key-index snapshots are canonicality failures for the SMT replay
/// surface and must fail closed without panic.
#[test]
fn tamper_verify_store_key_index_snapshot_malformed_json_serialization_noncanonical() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    std::fs::write(dir.path().join("meta/key_index.json"), b"{\n")
        .expect("malformed key_index snapshot");

    assert_verify_store_error_without_panic(
        dir.path(),
        &trust,
        MnemeError::SerializationNonCanonical,
        "malformed key_index.json",
    );
}

/// Valid JSON with a missing required key-index snapshot field is still a
/// canonicality failure, not an empty/default snapshot.
#[test]
fn tamper_verify_store_key_index_snapshot_missing_tombstones_serialization_noncanonical() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    std::fs::write(
        dir.path().join("meta/key_index.json"),
        serde_json::json!({ "entries": {} }).to_string(),
    )
    .expect("key_index snapshot missing tombstones");

    assert_verify_store_error_without_panic(
        dir.path(),
        &trust,
        MnemeError::SerializationNonCanonical,
        "key_index.json missing tombstones field",
    );
}

/// Object-key snapshot IDs with multibyte UTF-8 must fail closed as `SchemaDrift`,
/// not panic or fall through to a later root/object-key consistency error.
#[test]
fn tamper_verify_store_multibyte_object_keys_snapshot_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    let malicious_object = multibyte_hex_64_bytes('o');
    let payload = serde_json::json!({
        "entries": {
            malicious_object: {
                "namespace": "sidecar",
                "name": "obj",
            }
        }
    });
    std::fs::write(
        dir.path().join("meta/object_keys.json"),
        serde_json::to_string_pretty(&payload).expect("object_keys snapshot json"),
    )
    .expect("object_keys snapshot");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled object_keys.json object id",
    );
}

/// Malformed object-key snapshots are schema drift because this sidecar is a
/// plaintext reverse index, not the canonical SMT snapshot itself.
#[test]
fn tamper_verify_store_object_keys_snapshot_malformed_json_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    std::fs::write(dir.path().join("meta/object_keys.json"), b"{\n")
        .expect("malformed object_keys snapshot");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "malformed object_keys.json",
    );
}

/// Object-key snapshots missing the required entries map must fail as typed
/// schema drift and must not be interpreted as an empty sidecar.
#[test]
fn tamper_verify_store_object_keys_snapshot_missing_entries_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    std::fs::write(dir.path().join("meta/object_keys.json"), "{}")
        .expect("object_keys snapshot missing entries");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "object_keys.json missing entries field",
    );
}

/// Embedding snapshot IDs with multibyte UTF-8 must fail closed as `SchemaDrift`,
/// matching Store cold-open and the core fixed-width hex decoder behavior.
#[test]
fn tamper_verify_store_multibyte_embeddings_snapshot_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );

    let malicious_object = multibyte_hex_64_bytes('e');
    let payload = serde_json::json!({
        "entries": {
            malicious_object: {
                "dim": 2,
                "scale": 0,
                "components": [3, 1],
            }
        }
    });
    std::fs::write(
        dir.path().join("meta/embeddings.json"),
        serde_json::to_string_pretty(&payload).expect("embeddings snapshot json"),
    )
    .expect("embeddings snapshot");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled embeddings.json object id",
    );
}

/// Embedding snapshot entries whose declared dimension does not match the
/// component count must fail closed as `SchemaDrift` before semantic replay.
#[test]
fn tamper_verify_store_embeddings_snapshot_shape_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );
    let object_hex = sole_object_id_hex(dir.path());

    let payload = serde_json::json!({
        "entries": {
            object_hex: {
                "dim": 3,
                "scale": 0,
                "components": [3, 1],
            }
        }
    });
    std::fs::write(
        dir.path().join("meta/embeddings.json"),
        serde_json::to_string_pretty(&payload).expect("embeddings snapshot json"),
    )
    .expect("embeddings snapshot");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled embeddings.json shape",
    );
}

/// Malformed embedding snapshots must fail closed as schema drift before any
/// semantic commitment replay can treat them as meaningful index state.
#[test]
fn tamper_verify_store_embeddings_snapshot_malformed_json_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );

    std::fs::write(dir.path().join("meta/embeddings.json"), b"{\n")
        .expect("malformed embeddings snapshot");

    assert_verify_store_schema_drift_without_panic(dir.path(), &trust, "malformed embeddings.json");
}

/// Embedding snapshots missing the required entries map must fail as typed
/// schema drift and must not erase semantic state by becoming an empty map.
#[test]
fn tamper_verify_store_embeddings_snapshot_missing_entries_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );

    std::fs::write(dir.path().join("meta/embeddings.json"), "{}")
        .expect("embeddings snapshot missing entries");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "embeddings.json missing entries field",
    );
}

/// Embedding journal upserts with mismatched dimensions/components must fail
/// closed as `SchemaDrift`, not fall through as a semantic root mismatch.
#[test]
fn tamper_verify_store_embeddings_journal_upsert_shape_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );
    let object_hex = sole_object_id_hex(dir.path());

    write_journal_line(
        &dir.path().join("meta/embeddings.journal"),
        serde_json::json!({
            "op": "upsert",
            "id": object_hex,
            "dim": 3,
            "scale": 0,
            "components": [3, 1],
        }),
        "embeddings journal upsert shape json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled embeddings.journal upsert shape",
    );
}

/// Malformed object-key journal JSON must fail closed as `SchemaDrift`, before
/// any later object-key/root consistency path can run.
#[test]
fn tamper_verify_store_object_keys_journal_malformed_json_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    std::fs::write(dir.path().join("meta/object_keys.journal"), b"{\n")
        .expect("malformed object_keys journal");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "malformed object_keys.journal JSON",
    );
}

/// Syntactically valid object-key journal JSON that omits a required field is
/// still schema drift and must not be normalized into an empty/default key.
#[test]
fn tamper_verify_store_object_keys_journal_missing_field_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let object_hex = sole_object_id_hex(dir.path());

    write_journal_line(
        &dir.path().join("meta/object_keys.journal"),
        serde_json::json!({
            "id": object_hex,
            "namespace": "sidecar",
        }),
        "object_keys journal missing field json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "object_keys.journal missing name field",
    );
}

/// Malformed embedding journal JSON must fail closed as `SchemaDrift`, before
/// semantic commitment replay can interpret attacker-controlled state.
#[test]
fn tamper_verify_store_embeddings_journal_malformed_json_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );

    std::fs::write(dir.path().join("meta/embeddings.journal"), b"{\n")
        .expect("malformed embeddings journal");

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "malformed embeddings.journal JSON",
    );
}

/// Syntactically valid embedding journal upserts that omit components must fail
/// closed as `SchemaDrift`, not construct an empty or partial embedding.
#[test]
fn tamper_verify_store_embeddings_journal_missing_components_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );
    let object_hex = sole_object_id_hex(dir.path());

    write_journal_line(
        &dir.path().join("meta/embeddings.journal"),
        serde_json::json!({
            "op": "upsert",
            "id": object_hex,
            "dim": 2,
            "scale": 0,
        }),
        "embeddings journal missing components json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "embeddings.journal missing components field",
    );
}

/// Malformed key-index journal JSON is a canonicality failure for the SMT replay
/// surface, distinct from sidecar schema drift, and must still be no-panic.
#[test]
fn tamper_verify_store_key_index_journal_malformed_json_serialization_noncanonical() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    std::fs::write(dir.path().join("meta/key_index.journal"), b"{\n")
        .expect("malformed key_index journal");

    assert_verify_store_error_without_panic(
        dir.path(),
        &trust,
        MnemeError::SerializationNonCanonical,
        "malformed key_index.journal JSON",
    );
}

/// Syntactically valid key-index journal JSON with the wrong tagged shape must
/// also remain a typed canonicality failure, not get normalized into a no-op.
#[test]
fn tamper_verify_store_key_index_journal_missing_op_serialization_noncanonical() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    write_journal_line(
        &dir.path().join("meta/key_index.journal"),
        serde_json::json!({
            "key": logical_key_hash_hex("sidecar", "obj"),
            "object": sole_object_id_hex(dir.path()),
        }),
        "key_index journal missing op json",
    );

    assert_verify_store_error_without_panic(
        dir.path(),
        &trust,
        MnemeError::SerializationNonCanonical,
        "key_index.journal missing op field",
    );
}

/// Object-key journal IDs with multibyte UTF-8 must fail closed as `SchemaDrift`,
/// matching the snapshot path and store cold-open behavior.
#[test]
fn tamper_verify_store_multibyte_object_keys_journal_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    write_journal_line(
        &dir.path().join("meta/object_keys.journal"),
        serde_json::json!({
            "id": multibyte_hex_64_bytes('j'),
            "namespace": "sidecar",
            "name": "obj",
        }),
        "object_keys journal json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled object_keys.journal object id",
    );
}

/// Key-index journal upsert keys with multibyte UTF-8 must fail closed as
/// `SchemaDrift`, not panic or degrade into a later SMT root mismatch.
#[test]
fn tamper_verify_store_multibyte_key_index_journal_upsert_key_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let object_hex = sole_object_id_hex(dir.path());

    write_journal_line(
        &dir.path().join("meta/key_index.journal"),
        serde_json::json!({
            "op": "upsert",
            "key": multibyte_hex_64_bytes('u'),
            "object": object_hex,
        }),
        "key_index journal upsert key json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled key_index.journal upsert key",
    );
}

/// Key-index journal upsert object IDs with multibyte UTF-8 must fail closed as
/// `SchemaDrift`, covering the value side of the journal replay surface.
#[test]
fn tamper_verify_store_multibyte_key_index_journal_upsert_object_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    write_journal_line(
        &dir.path().join("meta/key_index.journal"),
        serde_json::json!({
            "op": "upsert",
            "key": logical_key_hash_hex("sidecar", "obj"),
            "object": multibyte_hex_64_bytes('v'),
        }),
        "key_index journal upsert object json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled key_index.journal upsert object",
    );
}

/// Key-index journal tombstone keys with multibyte UTF-8 must fail closed as
/// `SchemaDrift`, matching the snapshot tombstone boundary.
#[test]
fn tamper_verify_store_multibyte_key_index_journal_tombstone_schema_drift() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );

    write_journal_line(
        &dir.path().join("meta/key_index.journal"),
        serde_json::json!({
            "op": "tombstone",
            "key": multibyte_hex_64_bytes('d'),
        }),
        "key_index journal tombstone json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled key_index.journal tombstone key",
    );
}

/// Embedding journal upsert IDs with multibyte UTF-8 must fail closed as
/// `SchemaDrift`, preserving the typed loader boundary before semantic replay.
#[test]
fn tamper_verify_store_multibyte_embeddings_journal_upsert_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );

    write_journal_line(
        &dir.path().join("meta/embeddings.journal"),
        serde_json::json!({
            "op": "upsert",
            "id": multibyte_hex_64_bytes('p'),
            "dim": 2,
            "scale": 0,
            "components": [3, 1],
        }),
        "embeddings journal upsert json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled embeddings.journal upsert id",
    );
}

/// Embedding journal remove IDs with multibyte UTF-8 must fail closed as
/// `SchemaDrift`, covering both semantic journal variants.
#[test]
fn tamper_verify_store_multibyte_embeddings_journal_remove_schema_drift() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline semantic store must verify clean"
    );

    write_journal_line(
        &dir.path().join("meta/embeddings.journal"),
        serde_json::json!({
            "op": "remove",
            "id": multibyte_hex_64_bytes('r'),
        }),
        "embeddings journal remove json",
    );

    assert_verify_store_schema_drift_without_panic(
        dir.path(),
        &trust,
        "attacker-controlled embeddings.journal remove id",
    );
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

/// Hex object id of the sole object written by [`persisted_store_with_entry`],
/// read straight from the content-addressed `objects/<shard>/<hex>.cbor` layout
/// (independent of the sidecar persistence format).
fn sole_object_id_hex(store: &std::path::Path) -> String {
    for shard in std::fs::read_dir(store.join("objects"))
        .expect("objects dir")
        .flatten()
    {
        if shard.path().is_dir() {
            for f in std::fs::read_dir(shard.path())
                .expect("shard dir")
                .flatten()
            {
                let p = f.path();
                if p.extension().is_some_and(|e| e == "cbor") {
                    return p.file_stem().expect("stem").to_string_lossy().into_owned();
                }
            }
        }
    }
    panic!("no object found under objects/");
}

/// Build a real on-disk store (create + one `remember`) so the object-keys sidecar
/// (`meta/object_keys.{json,journal}`), the signed checkpoint log, and HEAD all
/// exist and are mutually consistent.
fn persisted_store_with_entry() -> (tempfile::TempDir, mneme_crypto::TrustConfig) {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x21; 32]);
    let agent = KeyPair::from_seed([0x22; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    store
        .remember(
            mneme_core::Draft {
                namespace: "sidecar".into(),
                logical_name: "obj".into(),
                kind: mneme_core::MemoryKind::Semantic,
                body: b"sidecar-body".to_vec(),
                parent_ids: vec![],
                session: [0x23; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            &cap,
        )
        .expect("remember");
    drop(store);
    (dir, trust)
}

fn persisted_store_with_semantic_entry() -> (tempfile::TempDir, mneme_crypto::TrustConfig) {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x24; 32]);
    let agent = KeyPair::from_seed([0x25; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    store
        .remember(
            mneme_core::Draft {
                namespace: "semantic-sidecar".into(),
                logical_name: "semantic-live".into(),
                kind: mneme_core::MemoryKind::Semantic,
                body: b"semantic sidecar body".to_vec(),
                parent_ids: vec![],
                session: [0x26; 16],
                trust_tier: None,
                embedding: Some(
                    mneme_core::FixedPointEmbedding::new(2, 0, vec![3, 1])
                        .expect("semantic embedding"),
                ),
                valid_time_ms: None,
            },
            &cap,
        )
        .expect("remember semantic");
    drop(store);
    (dir, trust)
}

fn persisted_store_after_shred_forget() -> (tempfile::TempDir, mneme_crypto::TrustConfig) {
    use mneme_cap::agent_cap;
    use mneme_core::{ForgetMode, ForgetTarget, LogicalKey};
    use mneme_crypto::KeyPair;
    use mneme_store::Store;

    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x31; 32]);
    let agent = KeyPair::from_seed([0x32; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let logical_key = LogicalKey {
        namespace: "sidecar".into(),
        name: "forgotten-obj".into(),
    };
    store
        .remember(
            mneme_core::Draft {
                namespace: logical_key.namespace.clone(),
                logical_name: logical_key.name.clone(),
                kind: mneme_core::MemoryKind::Semantic,
                body: b"forgotten sidecar body".to_vec(),
                parent_ids: vec![],
                session: [0x33; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            &cap,
        )
        .expect("remember");
    store
        .forget(
            ForgetTarget::LogicalKey(logical_key),
            &cap,
            ForgetMode::Shred,
        )
        .expect("shred forget");
    let trust = store.trust().clone();
    drop(store);
    (dir, trust)
}

fn persisted_store_with_two_entries() -> (tempfile::TempDir, mneme_crypto::TrustConfig) {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x41; 32]);
    let agent = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    for (name, body, session) in [
        ("obj-a", b"sidecar-body-a".as_slice(), [0x43; 16]),
        ("obj-b", b"sidecar-body-b".as_slice(), [0x44; 16]),
    ] {
        store
            .remember(
                mneme_core::Draft {
                    namespace: "sidecar".into(),
                    logical_name: name.into(),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: body.to_vec(),
                    parent_ids: vec![],
                    session,
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                },
                &cap,
            )
            .expect("remember");
    }
    drop(store);
    (dir, trust)
}

fn swap_object_key_journal_logical_names(store: &std::path::Path) {
    let journal = store.join("meta/object_keys.journal");
    let data = std::fs::read_to_string(&journal).expect("read object_keys.journal");
    let mut entries = data
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("journal json"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2, "expected two object-key journal entries");

    let first_namespace = entries[0]["namespace"].clone();
    let first_name = entries[0]["name"].clone();
    entries[0]["namespace"] = entries[1]["namespace"].clone();
    entries[0]["name"] = entries[1]["name"].clone();
    entries[1]["namespace"] = first_namespace;
    entries[1]["name"] = first_name;

    let mut rewritten = String::new();
    for entry in entries {
        rewritten.push_str(&serde_json::to_string(&entry).expect("journal json encode"));
        rewritten.push('\n');
    }
    std::fs::write(&journal, rewritten).expect("write swapped object_keys.journal");
}

fn persisted_store_with_live_and_tombstoned_entry() -> (tempfile::TempDir, mneme_crypto::TrustConfig)
{
    use mneme_cap::agent_cap;
    use mneme_core::{ForgetMode, ForgetTarget, LogicalKey};
    use mneme_crypto::KeyPair;
    use mneme_store::Store;

    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x51; 32]);
    let agent = KeyPair::from_seed([0x52; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    for (name, session) in [("live-obj", [0x53; 16]), ("forgotten-obj", [0x54; 16])] {
        store
            .remember(
                mneme_core::Draft {
                    namespace: "sidecar".into(),
                    logical_name: name.into(),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: format!("body-{name}").into_bytes(),
                    parent_ids: vec![],
                    session,
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                },
                &cap,
            )
            .expect("remember");
    }
    store
        .forget(
            ForgetTarget::LogicalKey(LogicalKey {
                namespace: "sidecar".into(),
                name: "forgotten-obj".into(),
            }),
            &cap,
            ForgetMode::Shred,
        )
        .expect("shred forget");
    let trust = store.trust().clone();
    drop(store);
    (dir, trust)
}

fn persisted_store_after_logical_key_overwrite() -> (tempfile::TempDir, mneme_crypto::TrustConfig) {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;

    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x61; 32]);
    let agent = KeyPair::from_seed([0x62; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    for (body, session) in [
        (b"first body".as_slice(), [0x63; 16]),
        (b"second body", [0x64; 16]),
    ] {
        store
            .remember(
                mneme_core::Draft {
                    namespace: "sidecar".into(),
                    logical_name: "rewritten-key".into(),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: body.to_vec(),
                    parent_ids: vec![],
                    session,
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                },
                &cap,
            )
            .expect("remember");
    }
    let trust = store.trust().clone();
    drop(store);
    (dir, trust)
}

fn rebind_live_object_key_to_tombstoned_logical_key(store: &std::path::Path) {
    let journal = store.join("meta/object_keys.journal");
    let data = std::fs::read_to_string(&journal).expect("read object_keys.journal");
    let mut entries = data
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("journal json"))
        .collect::<Vec<_>>();
    let live = entries
        .iter_mut()
        .find(|entry| entry["name"] == "live-obj")
        .expect("live object-key entry");
    live["name"] = serde_json::Value::String("forgotten-obj".into());

    let mut rewritten = String::new();
    for entry in entries {
        rewritten.push_str(&serde_json::to_string(&entry).expect("journal json encode"));
        rewritten.push('\n');
    }
    std::fs::write(&journal, rewritten).expect("write rebound object_keys.journal");
}

fn write_stale_object_key_snapshot_for_sole_object(
    store: &std::path::Path,
    namespace: &str,
    name: &str,
) {
    let id = sole_object_id_hex(store);
    let payload = serde_json::json!({
        "entries": {
            id: {
                "namespace": namespace,
                "name": name,
            }
        }
    });
    std::fs::write(
        store.join("meta/object_keys.json"),
        serde_json::to_string_pretty(&payload).expect("object_keys snapshot json"),
    )
    .expect("write stale object_keys snapshot");
}

fn logical_key_hash_hex(namespace: &str, name: &str) -> String {
    hex32(
        &mneme_core::LogicalKey {
            namespace: namespace.into(),
            name: name.into(),
        }
        .hash(),
    )
}

fn write_stale_key_index_snapshot(store: &std::path::Path, key_hex: &str, object_hex: &str) {
    let payload = serde_json::json!({
        "entries": {
            key_hex: object_hex,
        },
        "tombstones": [],
    });
    std::fs::write(
        store.join("meta/key_index.json"),
        serde_json::to_string_pretty(&payload).expect("key_index snapshot json"),
    )
    .expect("write stale key_index snapshot");
}

/// B-1: a byte flip in the persisted object-keys sidecar (the `object_keys.journal`
/// holds the single-`remember` mapping) must now make `verify_store` itself fail
/// closed (typed Err, no panic) — previously caught only by `Store::open`.
#[test]
fn tamper_verify_store_object_keys_byteflip_fails_closed() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let journal = dir.path().join("meta/object_keys.journal");
    let mut bytes = std::fs::read(&journal).expect("read object_keys.journal");
    assert!(!bytes.is_empty(), "journal must hold the remember mapping");
    bytes[0] ^= 0x55;
    std::fs::write(&journal, &bytes).expect("write corrupt journal");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &trust)
    }));
    assert!(
        result.is_ok(),
        "verify_store must not panic on a corrupted object_keys sidecar"
    );
    match result.unwrap() {
        Err(_) => {}
        Ok(_) => panic!("verify_store returned Ok on a corrupted object_keys sidecar (B-1 gap)"),
    }
}

/// F-A: a byte flip in a content-addressed object file must surface as
/// `ObjectTampered` from `verify_store`'s re-hash loop (previously the loop was
/// tautological — objects were re-keyed by their own recomputed hash — and the
/// flip was caught only indirectly as `RootInconsistent` via the rebuilt DAG).
#[test]
fn tamper_verify_store_object_byteflip_is_object_tampered() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let id_hex = sole_object_id_hex(dir.path());
    let obj_path = dir
        .path()
        .join(format!("objects/{}/{}.cbor", &id_hex[..2], id_hex));
    // Re-encode a valid-but-different record under the SAME filename so the bytes
    // still parse: this forces the re-hash loop (not the decoder) to reject, with
    // the filename id fixed while `hash_obj` of the new bytes differs.
    let bytes = std::fs::read(&obj_path).expect("read object");
    let mut record: mneme_core::ObjectRecord =
        mneme_core::from_bytes_strict(&bytes).expect("parse object");
    record.payload_enc.body.push(0xAB);
    let tampered = mneme_core::to_bytes_canonical(&record).expect("re-encode");
    assert_ne!(tampered, bytes, "tamper must change bytes");
    std::fs::write(&obj_path, &tampered).expect("write tampered object");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(
            e,
            MnemeError::ObjectTampered,
            "object byte flip must surface as ObjectTampered, not {e:?}"
        ),
        Ok(_) => panic!("tampered object must fail closed"),
    }
}

/// F-A: a `.cbor` file in `objects/` whose name is not a 64-hex content address
/// is a malformed (attacker-injected) store and must fail closed, not be silently
/// re-keyed by its content hash.
#[test]
fn tamper_verify_store_non_content_addressed_object_rejected() {
    let (dir, trust) = persisted_store_with_entry();
    let shard = dir.path().join("objects/zz");
    std::fs::create_dir_all(&shard).expect("shard");
    std::fs::write(shard.join("not-a-hash.cbor"), b"\x80").expect("rogue object");
    match verify_store(dir.path(), &trust) {
        Err(MnemeError::SchemaDrift) => {}
        Err(other) => panic!("expected SchemaDrift, got {other:?}"),
        Ok(_) => panic!("non-content-addressed object must fail closed"),
    }
}

/// B-1: rebinding an object to a well-formed logical key whose hash is unknown to
/// the verified key-index is rejected as `RootInconsistent`. The journal is the
/// authoritative (last-write-wins) source for the mapping, so we rewrite it.
#[test]
fn tamper_verify_store_object_keys_namespace_rebind() {
    let (dir, trust) = persisted_store_with_entry();
    let id = sole_object_id_hex(dir.path());
    let journal = dir.path().join("meta/object_keys.journal");
    let rebound = format!("{{\"id\":\"{id}\",\"namespace\":\"attacker\",\"name\":\"rebound\"}}\n");
    std::fs::write(&journal, rebound).expect("write rebound journal");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("rebound logical key must fail closed as RootInconsistent"),
    }
}

/// B-1: semantic sidecar replay is signed via `root.semantic_commit`; verifier
/// must reject a store whose embeddings journal no longer reconstructs that commit.
#[test]
fn tamper_verify_store_semantic_state_below_signed_head_fails_closed() {
    let (dir, trust) = persisted_store_with_semantic_entry();
    let journal = dir.path().join("meta/embeddings.journal");
    assert_eq!(
        std::fs::read_to_string(&journal)
            .expect("embeddings journal")
            .lines()
            .count(),
        1
    );
    std::fs::write(&journal, b"").expect("tamper embeddings journal below signed head");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("verify_store accepted semantic state below the signed HEAD"),
    }
}

/// B-1: swapping two valid live object-key mappings must still fail closed. A
/// weaker check that only asks "does this id exist?" and "does this key exist?"
/// misses this, because both sides are present while the binding is wrong.
#[test]
fn tamper_verify_store_object_keys_swapped_live_bindings() {
    let (dir, trust) = persisted_store_with_two_entries();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline two-entry store must verify clean"
    );
    swap_object_key_journal_logical_names(dir.path());
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("swapped live object-key bindings must fail closed as RootInconsistent"),
    }
}

/// B-1: object-key sidecars may retain the AAD mapping for a legitimately
/// tombstoned key after shred-forget. Verifier strictness must not turn that valid
/// lifecycle transition into a false-positive store rejection.
#[test]
fn verify_store_accepts_object_keys_for_tombstoned_key_after_shred_forget() {
    let (dir, trust) = persisted_store_after_shred_forget();
    match verify_store(dir.path(), &trust) {
        Ok(_) => {}
        Err(e) => panic!("valid post-shred-forget store must verify, got {e:?}"),
    }
}

/// B-1: a live object's object-key AAD cannot be rebound to an unrelated
/// tombstoned logical key. Tombstoned AAD may linger for its own object, but every
/// live key-index leaf must still have the exact reverse mapping.
#[test]
fn tamper_verify_store_object_keys_live_rebound_to_tombstone_fails_closed() {
    let (dir, trust) = persisted_store_with_live_and_tombstoned_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline live+tombstone store must verify clean"
    );
    rebind_live_object_key_to_tombstoned_logical_key(dir.path());
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("live object rebound to tombstoned object-key AAD must fail closed"),
    }
}

/// B-1: repeated writes to the same logical key leave an older object-key journal
/// entry for the superseded object. That stale AAD is legitimate only because the
/// current live key-index leaf still has an exact reverse mapping to the newest object.
#[test]
fn verify_store_accepts_superseded_object_key_after_logical_key_overwrite() {
    let (dir, trust) = persisted_store_after_logical_key_overwrite();
    match verify_store(dir.path(), &trust) {
        Ok(_) => {}
        Err(e) => panic!("valid logical-key overwrite must verify, got {e:?}"),
    }
}

/// B-1: key-index journal upserts must be replayed after the snapshot. A stale
/// snapshot value for the same logical-key hash would otherwise rebuild the wrong
/// SMT root and reject a valid signed head.
#[test]
fn verify_store_applies_key_index_journal_upsert_after_stale_snapshot_for_same_key() {
    let (dir, trust) = persisted_store_with_entry();
    write_stale_key_index_snapshot(
        dir.path(),
        &logical_key_hash_hex("sidecar", "obj"),
        &"a".repeat(64),
    );
    match verify_store(dir.path(), &trust) {
        Ok(_) => {}
        Err(e) => {
            panic!("verify_store ignored the key-index journal upsert over a stale snapshot: {e:?}")
        }
    }
}

/// B-1: key-index journal tombstones must also be replayed after the snapshot. A
/// stale snapshot live entry for the same key would resurrect forgotten state.
#[test]
fn verify_store_applies_key_index_journal_tombstone_after_stale_snapshot_for_same_key() {
    let (dir, trust) = persisted_store_after_shred_forget();
    write_stale_key_index_snapshot(
        dir.path(),
        &logical_key_hash_hex("sidecar", "forgotten-obj"),
        &sole_object_id_hex(dir.path()),
    );
    match verify_store(dir.path(), &trust) {
        Ok(_) => {}
        Err(e) => {
            panic!(
                "verify_store ignored the key-index journal tombstone over a stale snapshot: {e:?}"
            )
        }
    }
}

/// B-1: when an older `object_keys.json` snapshot and a newer journal both bind
/// the same object id, the journal must be replayed last. If the verifier trusts
/// the stale snapshot entry, the logical-key hash no longer matches the signed key-index.
#[test]
fn verify_store_applies_object_key_journal_after_stale_snapshot_for_same_object() {
    let (dir, trust) = persisted_store_with_entry();
    write_stale_object_key_snapshot_for_sole_object(dir.path(), "sidecar", "stale-snapshot-obj");
    match verify_store(dir.path(), &trust) {
        Ok(_) => {}
        Err(e) => {
            panic!("verify_store ignored the journal override for object_keys snapshot: {e:?}")
        }
    }
}

/// B-1: an entry whose object id is absent from the verified object set is rejected
/// as `RootInconsistent` (exercises the `object_keys.json` snapshot path too).
#[test]
fn tamper_verify_store_object_keys_unknown_object_id() {
    let (dir, trust) = persisted_store_with_entry();
    let sidecar = dir.path().join("meta/object_keys.json");
    let payload = format!(
        "{{\"entries\":{{\"{}\":{{\"namespace\":\"sidecar\",\"name\":\"obj\"}}}}}}",
        "0".repeat(64)
    );
    std::fs::write(&sidecar, payload).expect("write unknown-id snapshot");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("unknown object id must fail closed as RootInconsistent"),
    }
}

/// B-2: flipping ONLY the signature bytes after an otherwise-valid decode exercises
/// the genuine `RootSigInvalid` path (not the `schema drift` that a raw byte flip in
/// the CBOR framing produces).
#[test]
fn tamper_verify_signed_head_only_signature_only_rootsiginvalid() {
    use mneme_root::StoredRoot;
    let (dir, trust) = persisted_store_with_entry();
    let head = dir.path().join("roots/HEAD");
    let stored = StoredRoot::from_bytes(&std::fs::read(&head).expect("read head")).expect("decode");
    let mut tampered = stored.clone();
    assert!(!tampered.signature.is_empty(), "signature present");
    tampered.signature[0] ^= 0x01;
    std::fs::write(&head, tampered.to_bytes().expect("encode")).expect("write head");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(
            e,
            MnemeError::RootSigInvalid,
            "well-formed decode with a bad signature must surface RootSigInvalid"
        ),
        Ok(_) => panic!("bad signature must fail closed"),
    }
}

#[cfg(unix)]
#[test]
fn tamper_verify_store_rejects_symlinked_head_without_following_target() {
    let (dir, trust) = persisted_store_with_entry();
    let head = dir.path().join("roots/HEAD");
    let external = dir.path().join("external-head.cbor");
    std::fs::rename(&head, &external).expect("move HEAD fixture");
    std::os::unix::fs::symlink(&external, &head).expect("HEAD symlink");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &trust)
    }));

    assert!(result.is_ok(), "verify_store panicked on symlinked HEAD");
    match result.expect("panic checked") {
        Err(MnemeError::IoFailed { .. }) => {}
        Err(err) => panic!("expected IO failure for symlinked HEAD, got {err:?}"),
        Ok(_) => panic!("verify_store followed a symlinked HEAD to valid external bytes"),
    }
    assert!(
        std::fs::symlink_metadata(&head)
            .expect("HEAD symlink metadata")
            .file_type()
            .is_symlink(),
        "failed verification must not replace the symlink"
    );
    assert!(external.exists(), "external HEAD target must remain intact");
}

/// F-3: a tampered NON-adjacent intermediate checkpoint (`roots/1.root.cbor` while
/// HEAD is seq 3) must now fail closed; previously only HEAD's `seq-1` predecessor
/// was re-verified, so this left `verify_store == Ok`.
#[test]
fn tamper_verify_store_intermediate_checkpoint_fails_closed() {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x31; 32]);
    let agent = KeyPair::from_seed([0x32; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    for i in 0..2 {
        store
            .remember(
                mneme_core::Draft {
                    namespace: "chain".into(),
                    logical_name: format!("k{i}"),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: b"chain-body".to_vec(),
                    parent_ids: vec![],
                    session: [0x33; 16],
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                },
                &cap,
            )
            .expect("remember");
    }
    drop(store);
    let intermediate = dir.path().join("roots/1.root.cbor");
    assert!(
        intermediate.exists(),
        "non-adjacent intermediate checkpoint"
    );
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline 3-checkpoint store must verify clean"
    );
    let mut bytes = std::fs::read(&intermediate).expect("read checkpoint");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x55;
    std::fs::write(&intermediate, &bytes).expect("write corrupt checkpoint");
    match verify_store(dir.path(), &trust) {
        Err(err) => assert!(
            matches!(
                err,
                MnemeError::RootSigInvalid
                    | MnemeError::RootInconsistent
                    | MnemeError::SchemaDrift
                    | MnemeError::SerializationNonCanonical
            ),
            "tampered intermediate checkpoint must fail closed, got {err:?}"
        ),
        Ok(_) => panic!("tampered intermediate checkpoint must fail closed (F-3 gap)"),
    }
}

/// F-3: deleting the checkpoint file at HEAD's own sequence (`roots/<HEAD-seq>.root.cbor`)
/// must fail closed. HEAD is signature-gated, but a legitimate commit always appends the
/// current checkpoint before writing HEAD, so a missing current checkpoint is a truncated
/// / tampered append-only log — previously `verify_store` returned `Ok` (HEAD authoritative).
#[test]
fn tamper_verify_store_missing_head_checkpoint_fails_closed() {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x41; 32]);
    let agent = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    store
        .remember(
            mneme_core::Draft {
                namespace: "head".into(),
                logical_name: "k".into(),
                kind: mneme_core::MemoryKind::Semantic,
                body: b"head-body".to_vec(),
                parent_ids: vec![],
                session: [0x43; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            &cap,
        )
        .expect("remember");
    let head_seq = store.current_root().expect("root").sequence;
    drop(store);
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let head_checkpoint = dir.path().join(format!("roots/{head_seq}.root.cbor"));
    assert!(
        head_checkpoint.exists(),
        "current checkpoint present pre-attack"
    );
    std::fs::remove_file(&head_checkpoint).expect("delete current checkpoint");
    match verify_store(dir.path(), &trust) {
        Err(MnemeError::RootInconsistent) => {}
        Err(other) => {
            panic!("missing current checkpoint: expected RootInconsistent, got {other:?}")
        }
        Ok(_) => panic!("missing current checkpoint must fail closed (F-3 gap)"),
    }
}

/// F-C: the tamper count is derived **dynamically from the test sources**, never a
/// hand-typed constant that can silently drift from reality. For each `tamper_*.rs`
/// file we count adversarial cases only: literal tamper-classified `#[test]`
/// functions plus invocations of locally-defined macros that emit `#[test]`.
/// Self-audit inventory tests and positive controls are deliberately excluded so
/// the §19/§17.2 floor means ≥150 real tamper cases.
#[test]
fn tamper_suite_meets_150_floor_counted_from_source() {
    let counts = tamper_counts_by_file();
    let total: usize = counts.values().sum();
    assert!(
        total >= 150,
        "§19/§17.2 tamper floor: need ≥150 source-counted adversarial verify cases in the \
         test binary, source scan found {total}: {counts:?}"
    );
    eprintln!("verify tamper cases (counted from source): {total} {counts:?}");
}

#[test]
fn source_counter_excludes_inventory_and_positive_controls() {
    const SOURCE: &str = concat!(
        "macro_rules! generated_tamper {\n",
        "    ($name:ident) => {\n",
        "        #[test]\n",
        "        fn $name() {}\n",
        "    };\n",
        "}\n",
        "macro_rules! helper_macro {\n",
        "    ($name:ident) => {\n",
        "        fn $name() {}\n",
        "    };\n",
        "}\n",
        "generated_tamper!(tamper_generated_case);\n",
        "helper_macro!(tamper_helper_not_a_test);\n",
        "#[test]\n",
        "fn tamper_literal_case() {}\n",
        "#[test]\n",
        "fn cap_expired_not_after() {}\n",
        "#[test]\n",
        "fn ckpt_verify_wrong_previous_checkpoint() {}\n",
        "#[test]\n",
        "fn sem_honesty_on_procedure_mismatch() {}\n",
        "#[test]\n",
        "fn sem_valid_roundtrip() {}\n",
        "#[test]\n",
        "fn inventory_source_scan_counts_only_test_functions() {}\n",
        "#[test]\n",
        "fn verify_root_direct_inventory_is_mapped() {}\n",
        "#[test]\n",
        "fn verify_store_accepts_positive_control() {}\n",
        "#[test]\n",
        "fn verify_store_applies_positive_control() {}\n",
        "#[test]\n",
        "fn tamper_suite_meets_150_floor_counted_from_source() {}\n",
    );

    assert_eq!(tamper_count_from_source(SOURCE), 5);
}

/// Scan the verify `tests/` dir and count generated tamper `#[test]`s per
/// `tamper_*.rs` file directly from the source — single source of truth.
pub fn tamper_counts_by_file() -> std::collections::BTreeMap<String, usize> {
    use std::collections::BTreeMap;
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut m = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("read tests dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.starts_with("tamper_") || !name.ends_with(".rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        m.insert(name, tamper_count_from_source(&src));
    }
    m
}

fn tamper_count_from_source(source: &str) -> usize {
    let literal_cases = test_function_names(source)
        .iter()
        .filter(|name| is_tamper_case_name(name))
        .count();
    literal_cases + test_generator_invocation_count(source)
}

fn is_tamper_case_name(name: &str) -> bool {
    if name == "sem_valid_roundtrip"
        || name.starts_with("inventory_")
        || name.starts_with("tamper_suite_")
        || name.ends_with("_inventory_is_mapped")
        || name.starts_with("verify_store_accepts_")
        || name.starts_with("verify_store_applies_")
    {
        return false;
    }

    name.starts_with("tamper_")
        || name.starts_with("cap_")
        || name.starts_with("ckpt_")
        || name.starts_with("sem_")
        || name.starts_with("tomb_")
}

fn test_generator_invocation_count(source: &str) -> usize {
    test_generator_macro_names(source)
        .iter()
        .map(|macro_name| source.matches(&format!("{macro_name}!(")).count())
        .sum()
}

#[allow(clippy::ptr_arg)]
fn flip_path(path: &mut Vec<[u8; 32]>, depth: usize) {
    if depth < path.len() {
        path[depth][0] ^= 0xff;
    }
}
