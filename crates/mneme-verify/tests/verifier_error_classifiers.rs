//! Source-level guards for fail-closed verifier error classifiers.

#[path = "../../../tests/support/source_inventory.rs"]
mod source_inventory;

use source_inventory::{
    assert_no_local_source_scan_helpers, rust_function_name, source_between_markers,
};

fn production_source(path: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(path),
    )
    .unwrap_or_else(|err| panic!("read mneme-verify source {path}: {err}"))
}

fn workspace_source(path: &str) -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("mneme-verify crate under workspace crates dir");
    std::fs::read_to_string(workspace.join(path))
        .unwrap_or_else(|err| panic!("read workspace source {path}: {err}"))
}

#[test]
fn classifier_source_scan_helpers_remain_shared() {
    assert_no_local_source_scan_helpers(
        "verifier_error_classifiers.rs",
        include_str!("verifier_error_classifiers.rs"),
    );
}

#[test]
fn object_version_rejections_are_named_not_unsupported_version_collapsed() {
    let recall = production_source("recall.rs");
    let semantic = production_source("semantic.rs");

    for (name, source) in [("recall.rs", &recall), ("semantic.rs", &semantic)] {
        for forbidden in [
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} still collapses object version rejection directly through {forbidden}"
            );
        }
        assert!(
            source.contains("unsupported_object_version_error(record.version)"),
            "{name} should route object version rejection through the shared classifier"
        );
    }

    assert!(
        recall.contains("fn unsupported_object_version_error("),
        "recall.rs should define the shared object-version classifier"
    );
}

#[test]
fn verify_store_object_filename_rejection_is_named_not_schema_collapsed() {
    let store = production_source("store.rs");
    let dag = workspace_source("crates/mneme-dag/src/lib.rs");
    let object_path = workspace_source("crates/mneme-core/src/object_path.rs");

    let verify_store_body = source_between_markers(&store, "pub fn verify_store(", "fn read_head(");
    assert!(
        verify_store_body.contains("load_content_addressed_objects(path)?"),
        "verify_store should delegate object filename/path parsing to the shared DAG loader"
    );
    assert!(
        !verify_store_body.contains("decode_hex32(")
            && !verify_store_body.contains("MnemeError::SchemaDrift"),
        "verify_store should not inline object filename parsing or collapse it directly"
    );

    let dag_loader =
        source_between_markers(&dag, "pub fn load_content_addressed_objects(", "fn io_err(");
    assert!(
        dag_loader.contains("decode_content_addressed_object_path(objects_dir, &path)?"),
        "content-addressed object loading should use the canonical object path parser"
    );

    let object_path_parser = source_between_markers(
        &object_path,
        "pub fn decode_content_addressed_object_path(",
        "fn object_path_failure_to_mneme(",
    );
    assert!(
        !object_path_parser.contains("MnemeError::SchemaDrift"),
        "object path parser should return named failure helpers, not bare SchemaDrift"
    );

    let object_path_classifier = source_between_markers(
        &object_path,
        "enum ObjectPathFailure",
        "fn object_path_outside_objects_dir_error(",
    );
    for required in [
        "OutsideObjectsDir",
        "MissingShard",
        "MissingFile",
        "NonUtf8Shard",
        "NonUtf8File",
        "ExtraComponent",
        "MissingCborSuffix",
        "ShardLength",
        "IdLength",
        "ShardMismatch",
        "fn object_path_failure_to_mneme(",
    ] {
        assert!(
            object_path_classifier.contains(required),
            "object path failure classification should include `{required}`"
        );
    }

    let object_path_failure_tests = source_between_markers(
        &object_path,
        "fn object_path_failures_are_schema_drift()",
        "}",
    );
    assert!(
        object_path_failure_tests.contains("object_path_failure_to_mneme(failure)")
            && object_path_failure_tests.contains("MnemeError::SchemaDrift"),
        "object path failures should keep a focused classifier regression test"
    );

    let load_error_sites = source_between_markers(&store, "fn load_previous_root(", "fn io_err(");
    assert!(
        !load_error_sites.contains("MnemeError::SchemaDrift"),
        "verify_store local load helpers should not add a bare SchemaDrift bypass"
    );
}

#[test]
fn production_mneme_error_sites_are_audited() {
    let mut violations = Vec::new();

    for path in [
        "proof.rs",
        "recall.rs",
        "root.rs",
        "semantic.rs",
        "store.rs",
    ] {
        let source = production_source(path);
        let mut current_fn = None;
        for (idx, line) in source.lines().enumerate() {
            if let Some(fn_name) = rust_function_name(line) {
                current_fn = Some(fn_name.to_owned());
            }
            if line.contains("MnemeError::")
                && !is_audited_verifier_error_site(path, line, current_fn.as_deref())
            {
                violations.push(format!("{path}:{}:{}", idx + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "direct production verifier MnemeError sites must stay in audited TCB gates/helpers:\n{}",
        violations.join("\n")
    );
}

fn is_audited_verifier_error_site(path: &str, line: &str, current_fn: Option<&str>) -> bool {
    if line.trim_start().starts_with("//") {
        return true;
    }

    matches!(
        (path, current_fn),
        ("proof.rs", Some("verify_membership_proof"))
            | ("recall.rs", Some("verify_recall"))
            | ("recall.rs", Some("verify_receipt_binding"))
            | ("recall.rs", Some("unsupported_object_version_error"))
            | ("recall.rs", Some("verify_key_index_membership"))
            | ("recall.rs", Some("verify_provenance"))
            | ("recall.rs", Some("verify_writer_and_tier"))
            | ("recall.rs", Some("verify_not_forgotten"))
            | ("root.rs", Some("verify_root"))
            | ("semantic.rs", Some("verify_semantic_receipt"))
            | ("semantic.rs", Some("verify_semantic_recall"))
            | ("store.rs", Some("verify_store"))
            | ("store.rs", Some("verify_store_load_error"))
            | ("store.rs", Some("io_err"))
    )
}
