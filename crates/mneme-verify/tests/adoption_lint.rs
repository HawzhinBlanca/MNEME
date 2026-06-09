//! B1 adoption lint — production paths must not call signature-only head verify.

#[path = "../../../tests/support/source_inventory.rs"]
mod source_inventory;

use std::fs;
use std::path::{Path, PathBuf};

use source_inventory::{assert_no_local_source_scan_helpers, test_function_names_with_lines};

const FORBIDDEN_HEAD_VERIFY: &[&str] = &["verify_store_head", "verify_signed_head_only"];

const PRODUCTION_SRC_ROOTS: &[&str] = &[
    "crates/mneme-cli/src",
    "crates/mnemed/src",
    "crates/mneme-mcp/src",
    "crates/mneme-store/src",
];

const TEST_SURFACE_ROOTS: &[&str] = &["crates/mneme-verify/tests", "tests/e2e"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scan_rs_files(dir: &Path, hits: &mut Vec<String>) {
    if !dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            scan_rs_files(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            scan_file_for_forbidden(&path, hits);
        }
    }
}

fn scan_file_for_forbidden(path: &Path, hits: &mut Vec<String>) {
    let text = fs::read_to_string(path).expect("read");
    for (line_no, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        for sym in FORBIDDEN_HEAD_VERIFY {
            if line.contains(sym) {
                hits.push(format!("{}:{}: {}", path.display(), line_no + 1, trimmed));
            }
        }
    }
}

fn collect_legacy_head_verify_test_name_hits(path: &Path, hits: &mut Vec<String>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("read_dir") {
            let entry = entry.expect("entry");
            collect_legacy_head_verify_test_name_hits(&entry.path(), hits);
        }
        return;
    }
    if path.extension().is_none_or(|e| e != "rs") {
        return;
    }

    let text = fs::read_to_string(path).expect("read");
    for (line_no, name) in test_function_names_with_lines(&text) {
        if name.contains("verify_store_head") {
            hits.push(format!("{}:{}: fn {name}", path.display(), line_no));
        }
    }
}

#[test]
fn adoption_lint_source_scan_helpers_remain_shared() {
    assert_no_local_source_scan_helpers("adoption_lint.rs", include_str!("adoption_lint.rs"));
}

#[test]
fn b1_adoption_no_head_only_verify_in_production_src() {
    let root = workspace_root();
    let mut hits = Vec::new();
    for rel in PRODUCTION_SRC_ROOTS {
        scan_rs_files(&root.join(rel), &mut hits);
    }
    assert!(
        hits.is_empty(),
        "production src must not call signature-only head verify (use verify_store):\n{}",
        hits.join("\n")
    );
}

#[test]
fn b1_cli_verify_subcommand_uses_verify_store() {
    let cli_main = workspace_root().join("crates/mneme-cli/src/main.rs");
    let text = fs::read_to_string(&cli_main).expect("read cli main");
    assert!(
        text.contains("verify_store("),
        "mneme-cli Verify must call verify_store"
    );
    assert!(
        !text.contains("verify_store_head"),
        "mneme-cli must not import or call verify_store_head"
    );
    assert!(
        !text.contains("verify_signed_head_only"),
        "mneme-cli must not import or call verify_signed_head_only"
    );
}

#[test]
fn b1_e2e_bypass_diagnostics_use_current_head_only_name() {
    let e2e = workspace_root().join("tests/e2e/mod.rs");
    let text = fs::read_to_string(&e2e).expect("read e2e tests");
    assert!(
        !text.contains("verify_store_head"),
        "e2e bypass diagnostics must use verify_signed_head_only, not removed verify_store_head"
    );
    assert!(
        text.contains("verify_signed_head_only"),
        "e2e bypass diagnostics should name the current signature-only API"
    );
}

#[test]
fn b1_test_function_names_use_current_head_only_name() {
    let root = workspace_root();
    let mut hits = Vec::new();
    for rel in TEST_SURFACE_ROOTS {
        collect_legacy_head_verify_test_name_hits(&root.join(rel), &mut hits);
    }
    assert!(
        hits.is_empty(),
        "test names must use verify_signed_head_only, not stale verify_store_head:\n{}",
        hits.join("\n")
    );
}

#[test]
fn b1_contract_docs_do_not_advertise_removed_head_verify_alias() {
    let contract = workspace_root().join("crates/mneme-verify/docs/CONTRACT.md");
    let text = fs::read_to_string(&contract).expect("read verifier contract");
    assert!(
        !text.contains("Deprecated (hidden): `verify_store_head`"),
        "contract must not advertise removed verify_store_head as a hidden deprecated API"
    );
    assert!(
        !text.contains("deprecated under the old name `verify_store_head`"),
        "contract must describe verify_store_head as removed, not deprecated"
    );
    assert!(
        text.contains("Removed alias: `verify_store_head`"),
        "contract should explicitly point old-name readers at verify_signed_head_only"
    );
}
