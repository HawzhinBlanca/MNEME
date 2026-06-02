//! B1 adoption lint — production paths must not call signature-only head verify.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_HEAD_VERIFY: &[&str] = &["verify_store_head", "verify_signed_head_only"];

const PRODUCTION_SRC_ROOTS: &[&str] = &[
    "crates/mneme-cli/src",
    "crates/mnemed/src",
    "crates/mneme-mcp/src",
    "crates/mneme-store/src",
];

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
