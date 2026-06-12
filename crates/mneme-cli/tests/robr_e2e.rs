//! End-to-end CLI tests for ROBR-1 (Recall-to-Output Binding Receipt).

use assert_cmd::Command;
use tempfile::tempdir;

const SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const WEIGHT: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn mneme() -> Command {
    let mut cmd = Command::cargo_bin("mneme").expect("binary");
    cmd.env("MNEME_OPERATOR_SEED", SEED);
    cmd
}

fn remember(store: &str, name: &str, body: &str) {
    mneme()
        .args([
            "remember",
            store,
            "--namespace",
            "user",
            "--name",
            name,
            "--body",
            body,
        ])
        .assert()
        .success();
}

#[test]
fn robr_receipt_binds_and_verifies_offline() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("robr.bin");
    let cert_s = cert.to_str().expect("path");
    let output = dir.path().join("output.txt");
    std::fs::write(&output, b"the bridge sensor reading was 91C; flagged").expect("write output");
    let output_s = output.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "alpha", "the sky was clear");
    remember(store_s, "beta", "the bridge sensor read 91C");

    mneme()
        .args([
            "robr",
            store_s,
            "--keys",
            "alpha,beta",
            "--prompt",
            "summarize the sensor situation",
            "--weight-measurement",
            WEIGHT,
            "--sampling",
            "model=claude-opus-4-8;temp=0;top_p=1;seed=42",
            "--output-file",
            output_s,
            "--out",
            cert_s,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("robr receipt written"))
        .stdout(predicates::str::contains("context_entries=2"));

    // Offline verification against the embedded key.
    let out = mneme()
        .args(["verify-robr", cert_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("verify-robr ok"))
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    let pk = text
        .split("operator_pk=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("pk")
        .to_string();
    // And against the pinned operator key.
    mneme()
        .args(["verify-robr", cert_s, "--operator-pk", &pk])
        .assert()
        .success();
}

#[test]
fn tampered_robr_receipt_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("robr.bin");
    let cert_s = cert.to_str().expect("path");
    let output = dir.path().join("o.txt");
    std::fs::write(&output, b"output tokens").expect("write");
    let output_s = output.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "alpha", "entry one");
    mneme()
        .args([
            "robr",
            store_s,
            "--keys",
            "alpha",
            "--prompt",
            "p",
            "--weight-measurement",
            WEIGHT,
            "--sampling",
            "model=m;seed=1",
            "--output-file",
            output_s,
            "--out",
            cert_s,
        ])
        .assert()
        .success();

    let mut bytes = std::fs::read(&cert).expect("cert bytes");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&cert, &bytes).expect("write tampered");

    mneme()
        .args(["verify-robr", cert_s])
        .assert()
        .failure()
        .code(4);
}

#[test]
fn robr_missing_key_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let output = dir.path().join("o.txt");
    std::fs::write(&output, b"x").expect("write");
    let output_s = output.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    mneme()
        .args([
            "robr",
            store_s,
            "--keys",
            "no_such_key",
            "--prompt",
            "p",
            "--weight-measurement",
            WEIGHT,
            "--sampling",
            "s",
            "--output-file",
            output_s,
            "--out",
            store.join("c.bin").to_str().expect("path"),
        ])
        .assert()
        .failure();
}
