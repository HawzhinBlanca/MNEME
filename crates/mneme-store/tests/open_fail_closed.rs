use std::{
    fs,
    path::{Path, PathBuf},
};

#[path = "../../../tests/support/source_inventory.rs"]
mod source_inventory;

use mneme_cap::{Capability, Permissions};
use mneme_core::{
    Draft, FixedPointEmbedding, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError,
    ObjectRecord, TrustTier, from_bytes_strict, to_bytes_canonical,
};
use mneme_crypto::KeyPair;
use mneme_store::Store;
use source_inventory::{
    assert_no_local_source_inventory_helpers, source_contains_test_fn, test_functions_with_prefixes,
};
use tempfile::TempDir;

fn write_capability(operator: &KeyPair) -> Capability {
    Capability::issue(
        operator,
        operator.public_key_bytes(),
        vec!["app".into()],
        vec![MemoryKind::Episodic, MemoryKind::Semantic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .expect("issue write capability")
}

fn episodic_draft(logical_name: &str, body: &[u8]) -> Draft {
    Draft {
        namespace: "app".into(),
        logical_name: logical_name.into(),
        kind: MemoryKind::Episodic,
        body: body.to_vec(),
        parent_ids: vec![],
        session: [0x42; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
    }
}

fn semantic_draft(logical_name: &str, body: &[u8]) -> Draft {
    Draft {
        kind: MemoryKind::Semantic,
        embedding: Some(FixedPointEmbedding::new(2, 0, vec![3, 1]).expect("embedding")),
        ..episodic_draft(logical_name, body)
    }
}

fn only_object_blob_path(store_dir: &Path) -> PathBuf {
    let objects_dir = store_dir.join("objects");
    let mut blobs = Vec::new();
    for shard in fs::read_dir(&objects_dir).expect("objects dir") {
        let shard = shard.expect("object shard entry").path();
        if !shard.is_dir() {
            continue;
        }
        for object in fs::read_dir(&shard).expect("object shard dir") {
            let path = object.expect("object entry").path();
            if path.extension().is_some_and(|ext| ext == "cbor") {
                blobs.push(path);
            }
        }
    }
    assert_eq!(blobs.len(), 1, "expected exactly one object blob");
    blobs.pop().expect("object blob path")
}

fn only_object_id_hex(store_dir: &Path) -> String {
    only_object_blob_path(store_dir)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("object id hex")
        .to_owned()
}

fn move_only_object_blob_to_wrong_shard(store_dir: &Path) {
    let object_blob = only_object_blob_path(store_dir);
    let object_hex = only_object_id_hex(store_dir);
    let wrong_shard = if &object_hex[..2] == "00" { "ff" } else { "00" };
    let wrong_dir = store_dir.join("objects").join(wrong_shard);
    fs::create_dir_all(&wrong_dir).expect("wrong shard dir");
    fs::rename(&object_blob, wrong_dir.join(format!("{object_hex}.cbor")))
        .expect("move object to wrong shard");
}

fn app_logical_key(logical_name: &str) -> LogicalKey {
    LogicalKey {
        namespace: "app".into(),
        name: logical_name.into(),
    }
}

fn app_key_hash_hex(logical_name: &str) -> String {
    hex::encode(app_logical_key(logical_name).hash())
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

fn assert_open_schema_drift_without_panic(store_dir: &Path, operator: KeyPair, context: &str) {
    assert_open_error_without_panic(store_dir, operator, MnemeError::SchemaDrift, context);
}

fn assert_open_error_without_panic(
    store_dir: &Path,
    operator: KeyPair,
    expected: MnemeError,
    context: &str,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Store::open(store_dir, operator)
    }));
    assert!(result.is_ok(), "cold-open panicked on {context}");
    match result.expect("panic checked") {
        Err(err) => assert_eq!(err, expected, "unexpected cold-open error for {context}"),
        Ok(_) => panic!("cold-open accepted {context}"),
    }
}

fn assert_open_io_failed_without_panic(store_dir: &Path, operator: KeyPair, context: &str) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Store::open(store_dir, operator)
    }));
    assert!(result.is_ok(), "cold-open panicked on {context}");
    match result.expect("panic checked") {
        Err(MnemeError::IoFailed { .. }) => {}
        Err(err) => panic!("expected IoFailed for {context}, got {err:?}"),
        Ok(_) => panic!("cold-open accepted {context}"),
    }
}

#[cfg(unix)]
#[test]
fn store_create_rejects_symlink_store_root_without_writing_target() {
    let dir = TempDir::new().expect("tempdir");
    let external = dir.path().join("external-store-target");
    fs::create_dir(&external).expect("external store target");
    let store_link = dir.path().join("store-link");
    std::os::unix::fs::symlink(&external, &store_link).expect("store root symlink");
    let operator = KeyPair::from_seed([0x31; 32]);

    match Store::create(&store_link, operator) {
        Err(MnemeError::IoFailed { kind, .. }) => {
            assert!(
                kind.contains("symlink"),
                "store-root alias rejection should mention symlink, got {kind}"
            );
        }
        Err(err) => panic!("expected IoFailed for symlinked store root, got {err:?}"),
        Ok(_) => panic!("Store::create accepted a symlinked store root"),
    }

    assert!(
        fs::read_dir(&external)
            .expect("external target readable")
            .next()
            .is_none(),
        "Store::create must reject the symlink before creating layout under its target"
    );
}

fn read_object_key_journal_entries(store_dir: &Path) -> Vec<serde_json::Value> {
    let journal = store_dir.join("meta/object_keys.journal");
    fs::read_to_string(&journal)
        .expect("object-keys journal")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("journal json"))
        .collect()
}

fn write_object_key_journal_entries(store_dir: &Path, entries: Vec<serde_json::Value>) {
    let journal = store_dir.join("meta/object_keys.journal");
    let mut encoded = String::new();
    for entry in entries {
        encoded.push_str(&serde_json::to_string(&entry).expect("object-keys journal json encode"));
        encoded.push('\n');
    }
    fs::write(&journal, encoded).expect("tamper object-keys journal");
}

fn rewrite_only_object_key_journal_name(store_dir: &Path, replacement_name: &str) {
    let mut entries = read_object_key_journal_entries(store_dir);
    assert_eq!(entries.len(), 1);
    entries[0]["name"] = serde_json::Value::String(replacement_name.into());
    write_object_key_journal_entries(store_dir, entries);
}

fn rewrite_only_object_key_journal_logical_key(
    store_dir: &Path,
    replacement_namespace: &str,
    replacement_name: &str,
) {
    let mut entries = read_object_key_journal_entries(store_dir);
    assert_eq!(entries.len(), 1);
    entries[0]["namespace"] = serde_json::Value::String(replacement_namespace.into());
    entries[0]["name"] = serde_json::Value::String(replacement_name.into());
    write_object_key_journal_entries(store_dir, entries);
}

fn swap_object_key_journal_logical_names(store_dir: &Path) {
    let mut entries = read_object_key_journal_entries(store_dir);
    assert_eq!(entries.len(), 2, "expected two object-key journal entries");

    let first_namespace = entries[0]["namespace"].clone();
    let first_name = entries[0]["name"].clone();
    entries[0]["namespace"] = entries[1]["namespace"].clone();
    entries[0]["name"] = entries[1]["name"].clone();
    entries[1]["namespace"] = first_namespace;
    entries[1]["name"] = first_name;

    write_object_key_journal_entries(store_dir, entries);
}

fn rebind_object_key_journal_name(store_dir: &Path, from_name: &str, replacement_name: &str) {
    let mut entries = read_object_key_journal_entries(store_dir);
    let entry = entries
        .iter_mut()
        .find(|entry| entry["name"] == from_name)
        .expect("object-key journal entry");
    entry["name"] = serde_json::Value::String(replacement_name.into());

    write_object_key_journal_entries(store_dir, entries);
}

fn append_object_key_journal_entry(store_dir: &Path, id: &str, name: &str) {
    let journal = store_dir.join("meta/object_keys.journal");
    let entry = serde_json::json!({
        "id": id,
        "namespace": "app",
        "name": name,
    });
    let mut journal_data = fs::read_to_string(&journal).expect("object-keys journal");
    journal_data.push_str(&serde_json::to_string(&entry).expect("object-keys journal json"));
    journal_data.push('\n');
    fs::write(&journal, journal_data).expect("append object-keys journal entry");
}

fn write_single_journal_entry(
    store_dir: &Path,
    journal_name: &str,
    entry: serde_json::Value,
    context: &str,
) {
    let encoded = serde_json::to_string(&entry).expect(context);
    fs::write(
        store_dir.join("meta").join(journal_name),
        format!("{encoded}\n"),
    )
    .expect(context);
}

fn write_stale_object_key_snapshot_for_only_object(store_dir: &Path, stale_name: &str) {
    let object_id = only_object_id_hex(store_dir);
    let sidecar = serde_json::json!({
        "entries": {
            object_id: {
                "namespace": "app",
                "name": stale_name,
            }
        }
    });
    let sidecar_path = store_dir.join("meta/object_keys.json");
    fs::write(
        &sidecar_path,
        serde_json::to_string_pretty(&sidecar).expect("object-keys sidecar json"),
    )
    .expect("write stale object-keys snapshot");
}

fn write_stale_key_index_snapshot(store_dir: &Path, key_hex: &str, object_hex: &str) {
    let sidecar = serde_json::json!({
        "entries": {
            key_hex: object_hex,
        },
        "tombstones": [],
    });
    fs::write(
        store_dir.join("meta/key_index.json"),
        serde_json::to_string_pretty(&sidecar).expect("key-index sidecar json"),
    )
    .expect("write stale key-index snapshot");
}

fn write_multibyte_key_index_snapshot(store_dir: &Path, key_hex: &str) {
    let sidecar = serde_json::json!({
        "entries": {
            key_hex: "0".repeat(64),
        },
        "tombstones": [],
    });
    fs::write(
        store_dir.join("meta/key_index.json"),
        serde_json::to_string_pretty(&sidecar).expect("key-index sidecar json"),
    )
    .expect("write multibyte key-index snapshot");
}

fn write_multibyte_key_index_tombstone_snapshot(store_dir: &Path, key_hex: &str) {
    let sidecar = serde_json::json!({
        "entries": {},
        "tombstones": [key_hex],
    });
    fs::write(
        store_dir.join("meta/key_index.json"),
        serde_json::to_string_pretty(&sidecar).expect("key-index sidecar json"),
    )
    .expect("write multibyte key-index tombstone snapshot");
}

fn write_multibyte_object_keys_snapshot(store_dir: &Path, object_hex: &str) {
    let sidecar = serde_json::json!({
        "entries": {
            object_hex: {
                "namespace": "app",
                "name": "multibyte-object-key",
            }
        }
    });
    fs::write(
        store_dir.join("meta/object_keys.json"),
        serde_json::to_string_pretty(&sidecar).expect("object-keys sidecar json"),
    )
    .expect("write multibyte object-keys snapshot");
}

fn write_multibyte_embeddings_snapshot(store_dir: &Path, object_hex: &str) {
    let sidecar = serde_json::json!({
        "entries": {
            object_hex: {
                "dim": 2,
                "scale": 0,
                "components": [3, 1],
            }
        }
    });
    fs::write(
        store_dir.join("meta/embeddings.json"),
        serde_json::to_string_pretty(&sidecar).expect("embeddings sidecar json"),
    )
    .expect("write multibyte embeddings snapshot");
}

#[test]
fn inventory_source_scan_counts_only_test_functions() {
    const SOURCE: &str = concat!(
        "fn tamper_verify_store_helper() {}\n",
        "\n",
        "#[test]\n",
        "fn tamper_verify_store_real_case() {}\n",
        "\n",
        "#[test]\n",
        "#[ignore]\n",
        "fn verify_store_ignored_but_compiled_case() {}\n",
        "\n",
        "fn verify_store_helper() {}\n",
    );

    assert_eq!(
        test_functions_with_prefixes(SOURCE, &["tamper_verify_store_", "verify_store_"]),
        vec![
            "tamper_verify_store_real_case".to_string(),
            "verify_store_ignored_but_compiled_case".to_string(),
        ]
    );
    assert!(source_contains_test_fn(
        SOURCE,
        "tamper_verify_store_real_case"
    ));
    assert!(!source_contains_test_fn(
        SOURCE,
        "tamper_verify_store_helper"
    ));
}

#[test]
fn inventory_source_scan_helpers_remain_shared() {
    assert_no_local_source_inventory_helpers(
        "open_fail_closed.rs",
        include_str!("open_fail_closed.rs"),
    );
}

#[test]
fn cold_open_matrix_covers_verify_store_inventory() {
    const VERIFY_TAMPER_SUITE: &str = include_str!("../../mneme-verify/tests/tamper_suite.rs");
    const COLD_OPEN_MATRIX: &str = include_str!("open_fail_closed.rs");
    const PARITY: &[(&str, &str)] = &[
        (
            "tamper_verify_store_incomplete_marker",
            "cold_open_rejects_incomplete_marker",
        ),
        (
            "tamper_verify_store_dangling_symlink_incomplete_marker",
            "cold_open_rejects_dangling_symlink_incomplete_marker",
        ),
        (
            "tamper_verify_store_multibyte_key_index_schema_drift",
            "cold_open_rejects_multibyte_key_index_snapshot_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_key_index_tombstone_schema_drift",
            "cold_open_rejects_multibyte_key_index_snapshot_tombstone_without_panic",
        ),
        (
            "tamper_verify_store_key_index_snapshot_malformed_json_serialization_noncanonical",
            "cold_open_rejects_malformed_key_index_snapshot_without_panic",
        ),
        (
            "tamper_verify_store_key_index_snapshot_missing_tombstones_serialization_noncanonical",
            "cold_open_rejects_key_index_snapshot_missing_tombstones_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_object_keys_snapshot_schema_drift",
            "cold_open_rejects_multibyte_object_keys_snapshot_without_panic",
        ),
        (
            "tamper_verify_store_object_keys_snapshot_malformed_json_schema_drift",
            "cold_open_rejects_malformed_object_keys_snapshot_without_panic",
        ),
        (
            "tamper_verify_store_object_keys_snapshot_missing_entries_schema_drift",
            "cold_open_rejects_object_keys_snapshot_missing_entries_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_embeddings_snapshot_schema_drift",
            "cold_open_rejects_multibyte_embeddings_snapshot_without_panic",
        ),
        (
            "tamper_verify_store_embeddings_snapshot_shape_schema_drift",
            "cold_open_rejects_embeddings_snapshot_shape_without_panic",
        ),
        (
            "tamper_verify_store_embeddings_snapshot_malformed_json_schema_drift",
            "cold_open_rejects_malformed_embeddings_snapshot_without_panic",
        ),
        (
            "tamper_verify_store_embeddings_snapshot_missing_entries_schema_drift",
            "cold_open_rejects_embeddings_snapshot_missing_entries_without_panic",
        ),
        (
            "tamper_verify_store_embeddings_journal_upsert_shape_schema_drift",
            "cold_open_rejects_embeddings_journal_upsert_shape_without_panic",
        ),
        (
            "tamper_verify_store_object_keys_journal_malformed_json_schema_drift",
            "cold_open_rejects_malformed_object_keys_journal_without_panic",
        ),
        (
            "tamper_verify_store_object_keys_journal_missing_field_schema_drift",
            "cold_open_rejects_object_keys_journal_missing_name_without_panic",
        ),
        (
            "tamper_verify_store_embeddings_journal_malformed_json_schema_drift",
            "cold_open_rejects_malformed_embeddings_journal_without_panic",
        ),
        (
            "tamper_verify_store_embeddings_journal_missing_components_schema_drift",
            "cold_open_rejects_embeddings_journal_missing_components_without_panic",
        ),
        (
            "tamper_verify_store_key_index_journal_malformed_json_serialization_noncanonical",
            "cold_open_rejects_malformed_key_index_journal_without_panic",
        ),
        (
            "tamper_verify_store_key_index_journal_missing_op_serialization_noncanonical",
            "cold_open_rejects_key_index_journal_missing_op_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_object_keys_journal_schema_drift",
            "cold_open_rejects_multibyte_object_keys_journal_id_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_key_index_journal_upsert_key_schema_drift",
            "cold_open_rejects_multibyte_key_index_journal_upsert_key_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_key_index_journal_upsert_object_schema_drift",
            "cold_open_rejects_multibyte_key_index_journal_upsert_object_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_key_index_journal_tombstone_schema_drift",
            "cold_open_rejects_multibyte_key_index_journal_tombstone_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_embeddings_journal_upsert_schema_drift",
            "cold_open_rejects_multibyte_embeddings_journal_upsert_id_without_panic",
        ),
        (
            "tamper_verify_store_multibyte_embeddings_journal_remove_schema_drift",
            "cold_open_rejects_multibyte_embeddings_journal_remove_id_without_panic",
        ),
        (
            "tamper_verify_store_object_keys_byteflip_fails_closed",
            "cold_open_rejects_object_keys_byteflip_without_panic",
        ),
        (
            "tamper_verify_store_object_byteflip_is_object_tampered",
            "cold_open_rejects_object_blob_bytes_not_matching_filename",
        ),
        (
            "tamper_verify_store_non_content_addressed_object_rejected",
            "cold_open_rejects_non_content_addressed_object_filename",
        ),
        (
            "tamper_verify_store_object_keys_namespace_rebind",
            "cold_open_rejects_object_key_namespace_rebind",
        ),
        (
            "tamper_verify_store_semantic_state_below_signed_head_fails_closed",
            "cold_open_rejects_semantic_state_below_signed_head",
        ),
        (
            "tamper_verify_store_object_keys_swapped_live_bindings",
            "cold_open_rejects_swapped_live_object_key_bindings",
        ),
        (
            "verify_store_accepts_object_keys_for_tombstoned_key_after_shred_forget",
            "cold_open_accepts_object_keys_for_tombstoned_key_after_shred_forget",
        ),
        (
            "tamper_verify_store_object_keys_live_rebound_to_tombstone_fails_closed",
            "cold_open_rejects_live_object_key_rebound_to_tombstone",
        ),
        (
            "verify_store_accepts_superseded_object_key_after_logical_key_overwrite",
            "cold_open_accepts_superseded_object_key_journal_entry_after_logical_key_overwrite",
        ),
        (
            "verify_store_applies_key_index_journal_upsert_after_stale_snapshot_for_same_key",
            "cold_open_applies_key_index_journal_upsert_after_stale_snapshot_for_same_key",
        ),
        (
            "verify_store_applies_key_index_journal_tombstone_after_stale_snapshot_for_same_key",
            "cold_open_applies_key_index_journal_tombstone_after_stale_snapshot_for_same_key",
        ),
        (
            "verify_store_applies_object_key_journal_after_stale_snapshot_for_same_object",
            "cold_open_applies_object_key_journal_after_stale_snapshot_for_same_object",
        ),
        (
            "tamper_verify_store_object_keys_unknown_object_id",
            "cold_open_rejects_object_keys_snapshot_unknown_object_id",
        ),
        (
            "tamper_verify_store_rejects_symlinked_head_without_following_target",
            "cold_open_rejects_symlinked_head_without_following_target",
        ),
        (
            "tamper_verify_store_rejects_symlinked_key_index_snapshot_without_following_target",
            "cold_open_rejects_symlinked_key_index_snapshot_without_following_target",
        ),
        (
            "tamper_verify_store_rejects_symlinked_semantic_journal_without_following_target",
            "cold_open_rejects_symlinked_semantic_journal_without_following_target",
        ),
        (
            "tamper_verify_store_intermediate_checkpoint_fails_closed",
            "cold_open_rejects_tampered_intermediate_checkpoint",
        ),
        (
            "tamper_verify_store_missing_head_checkpoint_fails_closed",
            "cold_open_rejects_missing_head_checkpoint",
        ),
    ];

    let verifier_cases = test_functions_with_prefixes(
        VERIFY_TAMPER_SUITE,
        &["tamper_verify_store_", "verify_store_"],
    );
    let mapped_verifier_cases = PARITY
        .iter()
        .map(|(verifier, _)| *verifier)
        .collect::<std::collections::BTreeSet<_>>();
    let missing_mappings = verifier_cases
        .iter()
        .filter(|case| !mapped_verifier_cases.contains(case.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_mappings.is_empty(),
        "verify_store cases missing cold-open parity mapping: {missing_mappings:?}"
    );

    for (verifier, cold_open) in PARITY {
        assert!(
            verifier_cases.iter().any(|case| case == verifier),
            "stale parity mapping references missing verifier case {verifier}"
        );
        assert!(
            source_contains_test_fn(COLD_OPEN_MATRIX, cold_open),
            "cold-open parity mapping for {verifier} references missing test {cold_open}"
        );
    }
}

#[test]
fn cold_open_matrix_covers_signed_head_inventory() {
    const VERIFY_TAMPER_SUITE: &str = include_str!("../../mneme-verify/tests/tamper_suite.rs");
    const COLD_OPEN_MATRIX: &str = include_str!("open_fail_closed.rs");
    const PARITY: &[(&str, &str)] = &[(
        "tamper_verify_signed_head_only_signature_only_rootsiginvalid",
        "cold_open_rejects_signature_only_head_tamper",
    )];

    let verifier_cases =
        test_functions_with_prefixes(VERIFY_TAMPER_SUITE, &["tamper_verify_signed_head_only_"]);
    let mapped_verifier_cases = PARITY
        .iter()
        .map(|(verifier, _)| *verifier)
        .collect::<std::collections::BTreeSet<_>>();
    let missing_mappings = verifier_cases
        .iter()
        .filter(|case| !mapped_verifier_cases.contains(case.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_mappings.is_empty(),
        "signed-head verifier cases missing cold-open parity mapping: {missing_mappings:?}"
    );

    for (verifier, cold_open) in PARITY {
        assert!(
            verifier_cases.iter().any(|case| case == verifier),
            "stale signed-head parity mapping references missing verifier case {verifier}"
        );
        assert!(
            source_contains_test_fn(COLD_OPEN_MATRIX, cold_open),
            "signed-head parity mapping for {verifier} references missing test {cold_open}"
        );
    }
}

#[test]
fn cold_open_rejects_incomplete_marker() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("incomplete-marker", b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    fs::write(dir.path().join(".incomplete"), b"1").expect("write incomplete marker");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::IncompleteTransaction,
        "incomplete transaction marker",
    );
}

#[cfg(unix)]
#[test]
fn cold_open_rejects_dangling_symlink_incomplete_marker() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("dangling-incomplete-marker", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    let missing = dir.path().join("missing-incomplete-marker");
    let marker = dir.path().join(".incomplete");
    std::os::unix::fs::symlink(&missing, &marker).expect("dangling marker symlink");
    assert!(!marker.exists(), "fixture should be a dangling symlink");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::IncompleteTransaction,
        "dangling symlink incomplete transaction marker",
    );
    assert!(
        !missing.exists(),
        "cold-open must not materialize a dangling marker target"
    );
}

#[test]
fn cold_open_rejects_signature_only_head_tamper() {
    use mneme_root::StoredRoot;

    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("signed-head-tamper", b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    let head = dir.path().join("roots/HEAD");
    let stored = StoredRoot::from_bytes(&fs::read(&head).expect("read head")).expect("decode head");
    let mut tampered = stored;
    assert!(!tampered.signature.is_empty(), "signature present");
    tampered.signature[0] ^= 0x01;
    fs::write(&head, tampered.to_bytes().expect("encode head")).expect("tamper head");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::RootSigInvalid,
        "signature-only HEAD tamper",
    );
}

#[test]
fn cold_open_rejects_tampered_intermediate_checkpoint() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("checkpoint-chain-a", b"durable body a"),
            &cap,
        )
        .expect("remember first object");
    store
        .remember(
            episodic_draft("checkpoint-chain-b", b"durable body b"),
            &cap,
        )
        .expect("remember second object");
    drop(store);

    let intermediate = dir.path().join("roots/1.root.cbor");
    assert!(
        intermediate.exists(),
        "non-adjacent intermediate checkpoint"
    );
    let mut bytes = fs::read(&intermediate).expect("read intermediate checkpoint");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x55;
    fs::write(&intermediate, bytes).expect("tamper intermediate checkpoint");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Store::open(dir.path(), operator)
    }));
    assert!(
        result.is_ok(),
        "cold-open panicked on tampered intermediate checkpoint"
    );
    match result.expect("panic checked") {
        Err(
            MnemeError::RootSigInvalid
            | MnemeError::RootInconsistent
            | MnemeError::SchemaDrift
            | MnemeError::SerializationNonCanonical,
        ) => {}
        Err(err) => panic!("unexpected cold-open error for tampered checkpoint: {err:?}"),
        Ok(_) => panic!("cold-open accepted a tampered intermediate checkpoint"),
    }
}

#[test]
fn cold_open_rejects_missing_head_checkpoint() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("missing-head-checkpoint", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let head_seq = store.current_root().expect("current root").sequence;
    drop(store);

    let head_checkpoint = dir.path().join(format!("roots/{head_seq}.root.cbor"));
    assert!(
        head_checkpoint.exists(),
        "current checkpoint present before tamper"
    );
    fs::remove_file(head_checkpoint).expect("delete current checkpoint");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::RootInconsistent,
        "missing current HEAD checkpoint",
    );
}

#[cfg(unix)]
#[test]
fn cold_open_rejects_symlinked_head_without_following_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("symlink-head", b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    let head = dir.path().join("roots/HEAD");
    let external_head = dir.path().join("external-head.cbor");
    fs::rename(&head, &external_head).expect("move HEAD fixture");
    std::os::unix::fs::symlink(&external_head, &head).expect("HEAD symlink");

    assert_open_io_failed_without_panic(dir.path(), operator, "symlinked HEAD");
    assert!(
        fs::symlink_metadata(&head)
            .expect("HEAD symlink metadata")
            .file_type()
            .is_symlink(),
        "failed cold-open must leave the symlink entry intact"
    );
    assert!(
        external_head.exists(),
        "failed cold-open must not remove the external HEAD target"
    );
}

#[test]
fn cold_open_rejects_key_index_state_below_signed_head() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("live", b"durable body"), &cap)
        .expect("remember object");

    let journal = dir.path().join("meta/key_index.journal");
    let journal_before = fs::read_to_string(&journal).expect("key-index journal");
    assert_eq!(journal_before.lines().count(), 1);
    drop(store);

    fs::write(&journal, b"").expect("tamper key-index journal below signed head");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::RootInconsistent) => {}
        Err(err) => panic!("expected RootInconsistent, got {err:?}"),
        Ok(_) => panic!("cold-open accepted key-index state below the signed HEAD"),
    }
}

#[test]
fn cold_open_rejects_multibyte_key_index_snapshot_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("multibyte-key-index", b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    let malicious_key = multibyte_hex_64_bytes('k');
    write_multibyte_key_index_snapshot(dir.path(), &malicious_key);

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte key_index.json entry key",
    );
}

#[test]
fn cold_open_rejects_multibyte_key_index_snapshot_tombstone_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("multibyte-key-index-snapshot-tombstone", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    let malicious_tombstone = multibyte_hex_64_bytes('t');
    write_multibyte_key_index_tombstone_snapshot(dir.path(), &malicious_tombstone);

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte key_index.json tombstone",
    );
}

#[test]
fn cold_open_rejects_malformed_key_index_snapshot_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("malformed-key-index", b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    fs::write(dir.path().join("meta/key_index.json"), b"{\n")
        .expect("write malformed key-index snapshot");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::SerializationNonCanonical,
        "malformed key_index.json",
    );
}

#[test]
fn cold_open_rejects_key_index_snapshot_missing_tombstones_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("key-index-missing-tombstones", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    fs::write(
        dir.path().join("meta/key_index.json"),
        serde_json::json!({ "entries": {} }).to_string(),
    )
    .expect("write key-index snapshot missing tombstones");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::SerializationNonCanonical,
        "key_index.json missing tombstones field",
    );
}

#[test]
fn cold_open_rejects_malformed_key_index_journal_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("malformed-key-index-journal", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    fs::write(dir.path().join("meta/key_index.journal"), b"{\n")
        .expect("write malformed key-index journal");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::SerializationNonCanonical,
        "malformed key_index.journal",
    );
}

#[test]
fn cold_open_rejects_key_index_journal_missing_op_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("key-index-journal-missing-op", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let object_hex = only_object_id_hex(dir.path());
    drop(store);

    fs::write(
        dir.path().join("meta/key_index.journal"),
        format!(
            "{}\n",
            serde_json::json!({
                "key": app_key_hash_hex("key-index-journal-missing-op"),
                "object": object_hex,
            })
        ),
    )
    .expect("write key-index journal missing op");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::SerializationNonCanonical,
        "key_index.journal missing op field",
    );
}

#[test]
fn cold_open_rejects_multibyte_key_index_journal_upsert_key_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("multibyte-key-index-journal-upsert-key", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let object_hex = only_object_id_hex(dir.path());
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "key_index.journal",
        serde_json::json!({
            "op": "upsert",
            "key": multibyte_hex_64_bytes('u'),
            "object": object_hex,
        }),
        "write multibyte key-index journal upsert key",
    );

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte key_index.journal upsert key",
    );
}

#[test]
fn cold_open_rejects_multibyte_key_index_journal_upsert_object_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let logical_name = "multibyte-key-index-journal-upsert-object";

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft(logical_name, b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "key_index.journal",
        serde_json::json!({
            "op": "upsert",
            "key": app_key_hash_hex(logical_name),
            "object": multibyte_hex_64_bytes('v'),
        }),
        "write multibyte key-index journal upsert object",
    );

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte key_index.journal upsert object",
    );
}

#[test]
fn cold_open_rejects_multibyte_key_index_journal_tombstone_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("multibyte-key-index-journal-tombstone", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "key_index.journal",
        serde_json::json!({
            "op": "tombstone",
            "key": multibyte_hex_64_bytes('d'),
        }),
        "write multibyte key-index journal tombstone",
    );

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte key_index.journal tombstone key",
    );
}

#[test]
fn cold_open_applies_key_index_journal_upsert_after_stale_snapshot_for_same_key() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let logical_name = "key-index-journal-upsert";

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft(logical_name, b"durable body"), &cap)
        .expect("remember object");
    let journal = dir.path().join("meta/key_index.journal");
    assert_eq!(
        fs::read_to_string(&journal)
            .expect("key-index journal")
            .lines()
            .count(),
        1
    );
    drop(store);

    write_stale_key_index_snapshot(dir.path(), &app_key_hash_hex(logical_name), &"a".repeat(64));

    match Store::open(dir.path(), operator) {
        Ok(_) => {}
        Err(err) => {
            panic!("cold-open ignored the key-index journal upsert over a stale snapshot: {err:?}")
        }
    }
}

#[test]
fn cold_open_applies_key_index_journal_tombstone_after_stale_snapshot_for_same_key() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let logical_name = "key-index-journal-tombstone";
    let logical_key = app_logical_key(logical_name);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft(logical_name, b"durable body"), &cap)
        .expect("remember object");
    let object_hex = only_object_id_hex(dir.path());
    store
        .forget(
            ForgetTarget::LogicalKey(logical_key.clone()),
            &cap,
            ForgetMode::Shred,
        )
        .expect("shred forget");
    let journal = dir.path().join("meta/key_index.journal");
    assert_eq!(
        fs::read_to_string(&journal)
            .expect("key-index journal")
            .lines()
            .count(),
        2
    );
    drop(store);

    write_stale_key_index_snapshot(dir.path(), &hex::encode(logical_key.hash()), &object_hex);

    match Store::open(dir.path(), operator) {
        Ok(_) => {}
        Err(err) => {
            panic!(
                "cold-open ignored the key-index journal tombstone over a stale snapshot: {err:?}"
            )
        }
    }
}

#[cfg(unix)]
#[test]
fn cold_open_rejects_symlinked_key_index_snapshot_without_following_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("symlink-key-index-snapshot", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let key_index = dir.path().join("meta/key_index.json");
    let external_key_index = dir.path().join("external-key-index.json");
    fs::copy(&key_index, &external_key_index).expect("external key-index copy");
    drop(store);

    fs::remove_file(&key_index).expect("remove real key-index snapshot");
    std::os::unix::fs::symlink(&external_key_index, &key_index)
        .expect("key-index snapshot symlink");

    assert_open_io_failed_without_panic(dir.path(), operator, "symlinked key_index.json");
}

#[cfg(unix)]
#[test]
fn cold_open_rejects_symlinked_semantic_journal_without_following_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("symlink-embeddings-journal", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    let embeddings = dir.path().join("meta/embeddings.journal");
    let external_embeddings = dir.path().join("external-embeddings.journal");
    fs::copy(&embeddings, &external_embeddings).expect("external embeddings journal copy");
    let external_before = fs::read(&external_embeddings).expect("external embeddings journal");
    drop(store);

    fs::remove_file(&embeddings).expect("remove real embeddings journal");
    std::os::unix::fs::symlink(&external_embeddings, &embeddings)
        .expect("embeddings journal symlink");

    assert_open_io_failed_without_panic(dir.path(), operator, "symlinked embeddings.journal");
    assert_eq!(
        fs::read(&external_embeddings).expect("external embeddings journal"),
        external_before,
        "failed cold-open must not rewrite the external embeddings target"
    );
}

#[cfg(unix)]
#[test]
fn cold_open_rejects_broken_symlink_object_keys_journal() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("broken-object-keys-journal", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let journal = dir.path().join("meta/object_keys.journal");
    let missing = dir.path().join("missing-object-keys.journal");
    drop(store);

    fs::remove_file(&journal).expect("remove real object-keys journal");
    std::os::unix::fs::symlink(&missing, &journal).expect("broken object-keys journal symlink");
    assert!(!journal.exists(), "fixture should be a dangling symlink");

    assert_open_io_failed_without_panic(dir.path(), operator, "broken symlink object_keys.journal");
    assert!(
        !missing.exists(),
        "cold-open must not materialize the dangling journal target"
    );
}

#[cfg(unix)]
#[test]
fn remember_rejects_symlinked_key_index_journal_without_appending_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let mut store = Store::create(dir.path(), operator).expect("create store");
    let journal = dir.path().join("meta/key_index.journal");
    let external = dir.path().join("external-key-index.journal");
    fs::write(&external, b"external").expect("external journal fixture");
    std::os::unix::fs::symlink(&external, &journal).expect("key-index journal symlink");

    let err = store
        .remember(
            episodic_draft("symlink-key-index-journal", b"durable body"),
            &cap,
        )
        .expect_err("symlinked key-index journal rejected");

    assert!(matches!(err, MnemeError::IoFailed { .. }));
    assert_eq!(
        fs::read(&external).expect("external journal target"),
        b"external",
        "remember must not append through the symlink target"
    );
}

#[cfg(unix)]
#[test]
fn remember_rejects_hardlinked_object_keys_journal_without_appending_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let mut store = Store::create(dir.path(), operator).expect("create store");
    let journal = dir.path().join("meta/object_keys.journal");
    let external = dir.path().join("external-object-keys.journal");
    fs::write(&external, b"external").expect("external journal fixture");
    fs::hard_link(&external, &journal).expect("object-keys journal hard link");

    let err = store
        .remember(
            episodic_draft("hardlinked-object-keys-journal", b"durable body"),
            &cap,
        )
        .expect_err("hard-linked object-keys journal rejected");

    assert!(matches!(err, MnemeError::IoFailed { .. }));
    assert_eq!(
        fs::read(&external).expect("external journal target"),
        b"external",
        "remember must not append through a hard-linked journal target"
    );
}

#[cfg(unix)]
#[test]
fn promote_rejects_symlinked_promotion_log_without_appending_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let mut store = Store::create(dir.path(), operator).expect("create store");
    let (id, _) = store
        .remember(
            episodic_draft("symlink-promotion-log", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let log = dir.path().join("meta/promotions.log");
    let external = dir.path().join("external-promotions.log");
    fs::write(&external, b"external").expect("external promotion log fixture");
    std::os::unix::fs::symlink(&external, &log).expect("promotion log symlink");

    let err = store
        .promote(&id, TrustTier::Trusted, &cap)
        .expect_err("symlinked promotion log rejected");

    assert!(matches!(err, MnemeError::IoFailed { .. }));
    assert_eq!(
        fs::read(&external).expect("external promotion log target"),
        b"external",
        "promote must not append through the symlink target"
    );
}

#[cfg(unix)]
#[test]
fn promote_removes_dangling_symlink_for_superseded_object_blob() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let mut store = Store::create(dir.path(), operator).expect("create store");
    let (id, _) = store
        .remember(
            episodic_draft("promote-dangling-object-blob", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let old_blob = only_object_blob_path(dir.path());
    let missing = dir.path().join("missing-old-object.cbor");

    fs::remove_file(&old_blob).expect("remove real object blob");
    std::os::unix::fs::symlink(&missing, &old_blob).expect("dangling object symlink");
    assert!(!old_blob.exists(), "fixture should be a dangling symlink");

    store
        .promote(&id, TrustTier::Trusted, &cap)
        .expect("promote should clean up the superseded object entry");

    assert!(
        std::fs::symlink_metadata(&old_blob).is_err(),
        "promote must remove a superseded dangling object entry"
    );
    assert!(
        !missing.exists(),
        "promote must not materialize the dangling object target"
    );
}

#[test]
fn cold_open_rejects_live_key_index_without_object_key_mapping() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("live-object-key", b"durable body"), &cap)
        .expect("remember object");

    let journal = dir.path().join("meta/object_keys.journal");
    let journal_before = fs::read_to_string(&journal).expect("object-keys journal");
    assert_eq!(journal_before.lines().count(), 1);
    drop(store);

    fs::write(&journal, b"").expect("tamper object-keys journal below signed head");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::RootInconsistent) => {}
        Err(err) => panic!("expected RootInconsistent, got {err:?}"),
        Ok(_) => panic!("cold-open accepted a live key-index entry without object-key AAD"),
    }
}

#[test]
fn cold_open_rejects_live_key_index_without_object_blob() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("live-object-blob", b"durable body"), &cap)
        .expect("remember object");

    let object_blob = only_object_blob_path(dir.path());
    drop(store);

    fs::remove_file(&object_blob).expect("tamper live object blob below signed head");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::RootInconsistent) => {}
        Err(err) => panic!("expected RootInconsistent, got {err:?}"),
        Ok(_) => panic!("cold-open accepted a live key-index entry without an object blob"),
    }
}

#[test]
fn cold_open_rejects_object_blob_in_wrong_shard() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("wrong-object-shard", b"durable body"), &cap)
        .expect("remember object");
    drop(store);

    move_only_object_blob_to_wrong_shard(dir.path());

    match Store::open(dir.path(), operator) {
        Err(MnemeError::SchemaDrift) => {}
        Err(err) => panic!("expected SchemaDrift, got {err:?}"),
        Ok(_) => panic!("cold-open accepted an object blob outside its canonical shard"),
    }
}

#[test]
fn cold_open_rejects_non_content_addressed_object_filename() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("rogue-object-filename", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    let rogue_shard = dir.path().join("objects/zz");
    fs::create_dir_all(&rogue_shard).expect("rogue shard");
    fs::write(rogue_shard.join("not-a-hash.cbor"), b"\x80").expect("rogue object");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::SchemaDrift,
        "non-content-addressed object filename",
    );
}

#[test]
fn cold_open_rejects_object_blob_bytes_not_matching_filename() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("content-address-mismatch", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let object_blob = only_object_blob_path(dir.path());
    drop(store);

    let bytes = fs::read(&object_blob).expect("read object");
    let mut record: ObjectRecord = from_bytes_strict(&bytes).expect("parse object");
    record.payload_enc.body.push(0xAB);
    let tampered = to_bytes_canonical(&record).expect("re-encode object");
    assert_ne!(tampered, bytes, "tamper must change canonical bytes");
    fs::write(&object_blob, tampered).expect("write tampered object");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::ObjectTampered) => {}
        Err(err) => panic!("expected ObjectTampered, got {err:?}"),
        Ok(_) => panic!("cold-open accepted object bytes that do not match the filename id"),
    }
}

#[cfg(unix)]
#[test]
fn cold_open_rejects_symlinked_object_blob_without_following_target() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("symlink-object-blob", b"durable body"), &cap)
        .expect("remember object");
    let object_blob = only_object_blob_path(dir.path());
    let external_blob = dir.path().join("external-object.cbor");
    fs::copy(&object_blob, &external_blob).expect("external object copy");
    drop(store);

    fs::remove_file(&object_blob).expect("remove real object blob");
    std::os::unix::fs::symlink(&external_blob, &object_blob).expect("object blob symlink");

    assert_open_io_failed_without_panic(dir.path(), operator, "symlinked object blob");
}

#[test]
fn cold_open_rejects_live_key_index_with_mismatched_object_key_mapping() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("live-object-key-hash", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    rewrite_only_object_key_journal_name(dir.path(), "different-live-object-key-hash");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::RootInconsistent) => {}
        Err(err) => panic!("expected RootInconsistent, got {err:?}"),
        Ok(_) => panic!("cold-open accepted a live key-index entry with mismatched object-key AAD"),
    }
}

#[test]
fn cold_open_rejects_object_key_namespace_rebind() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("object-key-namespace-rebind", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    rewrite_only_object_key_journal_logical_key(dir.path(), "attacker", "rebound");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::RootInconsistent,
        "object_keys.journal namespace rebind",
    );
}

#[test]
fn cold_open_rejects_swapped_live_object_key_bindings() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("object-key-a", b"durable body a"), &cap)
        .expect("remember first object");
    store
        .remember(episodic_draft("object-key-b", b"durable body b"), &cap)
        .expect("remember second object");
    drop(store);

    swap_object_key_journal_logical_names(dir.path());

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::RootInconsistent,
        "swapped live object_keys.journal bindings",
    );
}

#[test]
fn cold_open_rejects_live_object_key_rebound_to_tombstone() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("live-object-key", b"live durable body"),
            &cap,
        )
        .expect("remember live object");
    store
        .remember(
            episodic_draft("forgotten-object-key", b"forgotten durable body"),
            &cap,
        )
        .expect("remember forgotten object");
    store
        .forget(
            ForgetTarget::LogicalKey(app_logical_key("forgotten-object-key")),
            &cap,
            ForgetMode::Shred,
        )
        .expect("shred forget object");
    drop(store);

    rebind_object_key_journal_name(dir.path(), "live-object-key", "forgotten-object-key");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::RootInconsistent,
        "live object_keys.journal entry rebound to tombstone",
    );
}

#[test]
fn cold_open_accepts_object_keys_for_tombstoned_key_after_shred_forget() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);
    let logical_key = app_logical_key("forgotten-object-key");

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft(&logical_key.name, b"forgotten durable body"),
            &cap,
        )
        .expect("remember forgotten object");
    store
        .forget(
            ForgetTarget::LogicalKey(logical_key),
            &cap,
            ForgetMode::Shred,
        )
        .expect("shred forget object");
    drop(store);

    match Store::open(dir.path(), operator) {
        Ok(_) => {}
        Err(err) => panic!("cold-open rejected valid post-shred object-key AAD: {err:?}"),
    }
}

#[test]
fn cold_open_applies_object_key_journal_after_stale_snapshot_for_same_object() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("journal-authoritative-key", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    write_stale_object_key_snapshot_for_only_object(dir.path(), "stale-snapshot-key");

    match Store::open(dir.path(), operator) {
        Ok(_) => {}
        Err(err) => {
            panic!("cold-open ignored the journal override for object_keys snapshot: {err:?}")
        }
    }
}

#[test]
fn cold_open_rejects_multibyte_object_keys_snapshot_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("multibyte-object-keys", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    let malicious_object = multibyte_hex_64_bytes('o');
    write_multibyte_object_keys_snapshot(dir.path(), &malicious_object);

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte object_keys.json object id",
    );
}

#[test]
fn cold_open_rejects_malformed_object_keys_snapshot_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("malformed-object-keys", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    fs::write(dir.path().join("meta/object_keys.json"), b"{\n")
        .expect("write malformed object-keys snapshot");

    assert_open_schema_drift_without_panic(dir.path(), operator, "malformed object_keys.json");
}

#[test]
fn cold_open_rejects_object_keys_snapshot_missing_entries_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("object-keys-missing-entries", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    fs::write(dir.path().join("meta/object_keys.json"), "{}")
        .expect("write object-keys snapshot missing entries");

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "object_keys.json missing entries field",
    );
}

#[test]
fn cold_open_rejects_object_keys_snapshot_unknown_object_id() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("object-keys-unknown-object", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    fs::write(
        dir.path().join("meta/object_keys.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "entries": {
                "0".repeat(64): {
                    "namespace": "app",
                    "name": "object-keys-unknown-object",
                }
            }
        }))
        .expect("object-keys snapshot json"),
    )
    .expect("write object-keys unknown-object snapshot");

    assert_open_error_without_panic(
        dir.path(),
        operator,
        MnemeError::RootInconsistent,
        "object_keys.json unknown object id",
    );
}

#[test]
fn cold_open_rejects_malformed_object_keys_journal_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("malformed-object-keys-journal", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    fs::write(dir.path().join("meta/object_keys.journal"), b"{\n")
        .expect("write malformed object-keys journal");

    assert_open_schema_drift_without_panic(dir.path(), operator, "malformed object_keys.journal");
}

#[test]
fn cold_open_rejects_object_keys_byteflip_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("object-keys-byteflip", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    Store::open(dir.path(), operator.clone()).expect("baseline cold-open");
    let journal = dir.path().join("meta/object_keys.journal");
    let mut bytes = fs::read(&journal).expect("read object_keys.journal");
    assert!(!bytes.is_empty(), "journal must hold the remember mapping");
    bytes[0] ^= 0x55;
    fs::write(&journal, bytes).expect("write corrupt object_keys.journal");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Store::open(dir.path(), operator)
    }));
    assert!(
        result.is_ok(),
        "cold-open panicked on corrupted object_keys.journal"
    );
    match result.expect("panic checked") {
        Err(_) => {}
        Ok(_) => panic!("cold-open accepted corrupted object_keys.journal"),
    }
}

#[test]
fn cold_open_rejects_object_keys_journal_missing_name_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("object-keys-journal-missing-name", b"durable body"),
            &cap,
        )
        .expect("remember object");
    let object_hex = only_object_id_hex(dir.path());
    drop(store);

    fs::write(
        dir.path().join("meta/object_keys.journal"),
        format!(
            "{}\n",
            serde_json::json!({
                "id": object_hex,
                "namespace": "app",
            })
        ),
    )
    .expect("write object-keys journal missing name");

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "object_keys.journal missing name field",
    );
}

#[test]
fn cold_open_rejects_multibyte_object_keys_journal_id_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("multibyte-object-keys-journal", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "object_keys.journal",
        serde_json::json!({
            "id": multibyte_hex_64_bytes('j'),
            "namespace": "app",
            "name": "multibyte-object-keys-journal",
        }),
        "write multibyte object-keys journal id",
    );

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte object_keys.journal object id",
    );
}

#[test]
fn cold_open_rejects_object_key_mapping_without_object_blob() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            episodic_draft("live-extra-object-key", b"durable body"),
            &cap,
        )
        .expect("remember object");
    drop(store);

    append_object_key_journal_entry(dir.path(), &"a".repeat(64), "absent-object");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::RootInconsistent) => {}
        Err(err) => panic!("expected RootInconsistent, got {err:?}"),
        Ok(_) => panic!("cold-open accepted an object-key mapping for an absent object blob"),
    }
}

#[test]
fn cold_open_accepts_superseded_object_key_journal_entry_after_logical_key_overwrite() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(episodic_draft("rewritten-key", b"first body"), &cap)
        .expect("first remember");
    store
        .remember(episodic_draft("rewritten-key", b"second body"), &cap)
        .expect("second remember");
    let journal = dir.path().join("meta/object_keys.journal");
    assert_eq!(
        fs::read_to_string(&journal)
            .expect("object-keys journal")
            .lines()
            .count(),
        2,
        "overwrite should leave the superseded append-only object-key entry"
    );
    drop(store);

    match Store::open(dir.path(), operator) {
        Ok(_) => {}
        Err(err) => panic!("cold-open rejected a valid logical-key overwrite: {err:?}"),
    }
}

#[test]
fn cold_open_rejects_multibyte_embeddings_snapshot_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("multibyte-embeddings", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    drop(store);

    let malicious_object = multibyte_hex_64_bytes('e');
    write_multibyte_embeddings_snapshot(dir.path(), &malicious_object);

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte embeddings.json object id",
    );
}

#[test]
fn cold_open_rejects_malformed_embeddings_snapshot_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("malformed-embeddings", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    drop(store);

    fs::write(dir.path().join("meta/embeddings.json"), b"{\n")
        .expect("write malformed embeddings snapshot");

    assert_open_schema_drift_without_panic(dir.path(), operator, "malformed embeddings.json");
}

#[test]
fn cold_open_rejects_embeddings_snapshot_missing_entries_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("embeddings-missing-entries", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    drop(store);

    fs::write(dir.path().join("meta/embeddings.json"), "{}")
        .expect("write embeddings snapshot missing entries");

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "embeddings.json missing entries field",
    );
}

#[test]
fn cold_open_rejects_embeddings_snapshot_shape_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("embeddings-snapshot-shape", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    let object_hex = only_object_id_hex(dir.path());
    drop(store);

    fs::write(
        dir.path().join("meta/embeddings.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "entries": {
                object_hex: {
                    "dim": 3,
                    "scale": 0,
                    "components": [3, 1],
                }
            }
        }))
        .expect("embeddings snapshot json"),
    )
    .expect("write embeddings snapshot shape");

    assert_open_schema_drift_without_panic(dir.path(), operator, "embeddings.json entry shape");
}

#[test]
fn cold_open_rejects_malformed_embeddings_journal_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("malformed-embeddings-journal", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    drop(store);

    fs::write(dir.path().join("meta/embeddings.journal"), b"{\n")
        .expect("write malformed embeddings journal");

    assert_open_schema_drift_without_panic(dir.path(), operator, "malformed embeddings.journal");
}

#[test]
fn cold_open_rejects_embeddings_journal_missing_components_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft(
                "embeddings-journal-missing-components",
                b"durable semantic body",
            ),
            &cap,
        )
        .expect("remember semantic object");
    let object_hex = only_object_id_hex(dir.path());
    drop(store);

    fs::write(
        dir.path().join("meta/embeddings.journal"),
        format!(
            "{}\n",
            serde_json::json!({
                "op": "upsert",
                "id": object_hex,
                "dim": 2,
                "scale": 0,
            })
        ),
    )
    .expect("write embeddings journal missing components");

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "embeddings.journal missing components field",
    );
}

#[test]
fn cold_open_rejects_embeddings_journal_upsert_shape_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("embeddings-journal-upsert-shape", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");
    let object_hex = only_object_id_hex(dir.path());
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "embeddings.journal",
        serde_json::json!({
            "op": "upsert",
            "id": object_hex,
            "dim": 3,
            "scale": 0,
            "components": [3, 1],
        }),
        "write embeddings journal upsert shape",
    );

    assert_open_schema_drift_without_panic(dir.path(), operator, "embeddings.journal upsert shape");
}

#[test]
fn cold_open_rejects_multibyte_embeddings_journal_upsert_id_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft(
                "multibyte-embeddings-journal-upsert",
                b"durable semantic body",
            ),
            &cap,
        )
        .expect("remember semantic object");
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "embeddings.journal",
        serde_json::json!({
            "op": "upsert",
            "id": multibyte_hex_64_bytes('p'),
            "dim": 2,
            "scale": 0,
            "components": [3, 1],
        }),
        "write multibyte embeddings journal upsert id",
    );

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte embeddings.journal upsert id",
    );
}

#[test]
fn cold_open_rejects_multibyte_embeddings_journal_remove_id_without_panic() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft(
                "multibyte-embeddings-journal-remove",
                b"durable semantic body",
            ),
            &cap,
        )
        .expect("remember semantic object");
    drop(store);

    write_single_journal_entry(
        dir.path(),
        "embeddings.journal",
        serde_json::json!({
            "op": "remove",
            "id": multibyte_hex_64_bytes('r'),
        }),
        "write multibyte embeddings journal remove id",
    );

    assert_open_schema_drift_without_panic(
        dir.path(),
        operator,
        "multibyte embeddings.journal remove id",
    );
}

#[test]
fn cold_open_rejects_semantic_state_below_signed_head() {
    let dir = TempDir::new().expect("tempdir");
    let operator = KeyPair::generate();
    let cap = write_capability(&operator);

    let mut store = Store::create(dir.path(), operator.clone()).expect("create store");
    store
        .remember(
            semantic_draft("semantic-live", b"durable semantic body"),
            &cap,
        )
        .expect("remember semantic object");

    let journal = dir.path().join("meta/embeddings.journal");
    let journal_before = fs::read_to_string(&journal).expect("embedding journal");
    assert_eq!(journal_before.lines().count(), 1);
    drop(store);

    fs::write(&journal, b"").expect("tamper semantic journal below signed head");

    match Store::open(dir.path(), operator) {
        Err(MnemeError::RootInconsistent) => {}
        Err(err) => panic!("expected RootInconsistent, got {err:?}"),
        Ok(_) => panic!("cold-open accepted semantic state below the signed HEAD"),
    }
}
