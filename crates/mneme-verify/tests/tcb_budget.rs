//! TCB line budget gate (§17.6).

use mneme_verify::TCB_LINE_BUDGET;
use std::path::PathBuf;

#[test]
fn verify_tcb_stays_reviewable() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let lines = count_production_lines(&src);
    assert!(
        lines <= TCB_LINE_BUDGET,
        "mneme-verify TCB exceeded budget: {lines} > {TCB_LINE_BUDGET}"
    );
}

fn count_production_lines(dir: &std::path::Path) -> usize {
    let mut total = 0usize;
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            total += std::fs::read_to_string(&path)
                .expect("read source")
                .lines()
                .count();
        }
    }
    total
}
