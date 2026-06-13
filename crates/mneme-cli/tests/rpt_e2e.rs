//! End-to-end CLI tests for RPT (Radioactive Provenance Tracer, experimental).

use assert_cmd::Command;

fn mneme() -> Command {
    Command::cargo_bin("mneme").expect("binary")
}

#[test]
fn rpt_detects_watermarked_stream() {
    mneme()
        .args(["rpt-probe", "--tokens", "400", "--gamma", "0.25"])
        .assert()
        .success()
        .stdout(predicates::str::contains("stream=watermarked"))
        .stdout(predicates::str::contains("detected=true"));
}

#[test]
fn rpt_does_not_detect_unmarked_stream() {
    mneme()
        .args([
            "rpt-probe",
            "--tokens",
            "400",
            "--gamma",
            "0.25",
            "--unmarked",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("stream=unmarked"))
        .stdout(predicates::str::contains("detected=false"));
}

#[test]
fn rpt_honesty_caveat_is_printed() {
    mneme()
        .args(["rpt-probe"])
        .assert()
        .success()
        .stdout(predicates::str::contains("NEVER proves non-use"))
        .stdout(predicates::str::contains("not cryptographic"));
}
