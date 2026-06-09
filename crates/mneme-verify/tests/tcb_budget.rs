//! TCB line budget gate (§17.6).

#[path = "../../../tests/support/source_inventory.rs"]
mod source_inventory;

use mneme_verify::TCB_LINE_BUDGET;
use std::path::PathBuf;

use source_inventory::rust_source_files;

const TCB_REVIEW_HEADROOM: usize = 6;

#[test]
fn verify_tcb_stays_reviewable() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let lines = count_production_lines(&src);
    assert!(
        lines <= TCB_LINE_BUDGET,
        "mneme-verify TCB exceeded budget: {lines} > {TCB_LINE_BUDGET}"
    );
    assert!(
        lines + TCB_REVIEW_HEADROOM <= TCB_LINE_BUDGET,
        "mneme-verify TCB needs {TCB_REVIEW_HEADROOM} lines of review headroom: {lines} + {TCB_REVIEW_HEADROOM} > {TCB_LINE_BUDGET}"
    );
}

#[test]
fn line_budget_counts_nested_rust_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("lib.rs"), "pub fn root() {}\n").expect("write root source");
    std::fs::create_dir_all(dir.path().join("nested")).expect("create nested dir");
    std::fs::write(
        dir.path().join("nested/mod.rs"),
        "pub fn nested() {}\npub fn second_nested() {}\n",
    )
    .expect("write nested source");

    assert_eq!(count_production_lines(dir.path()), 3);
}

fn count_production_lines(dir: &std::path::Path) -> usize {
    rust_source_files(dir)
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .expect("read source")
                .lines()
                .count()
        })
        .sum()
}
