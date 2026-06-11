//! End-to-end CLI tests for Certified Counterfactual Replay (weak mode).

use assert_cmd::Command;
use tempfile::tempdir;

const SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn mneme() -> Command {
    let mut cmd = Command::cargo_bin("mneme").expect("binary");
    cmd.env("MNEME_OPERATOR_SEED", SEED);
    cmd
}

fn remember(store: &str, name: &str, body: &str) -> String {
    let out = mneme()
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
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    // "remembered object_id=<hex> root_preimage_hash=<hex>"
    text.split("object_id=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("object id in output")
        .to_string()
}

#[test]
fn replay_counterfactual_differs_and_verifies_offline() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("replay-cert.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    let _a = remember(store_s, "alpha", "the sky was clear");
    let b = remember(store_s, "beta", "the bridge sensor read 91C");
    let _c = remember(store_s, "gamma", "maintenance was scheduled");

    // Factual context = [alpha, beta, gamma]; counterfactual excludes beta.
    mneme()
        .args([
            "replay",
            store_s,
            "--keys",
            "alpha,beta,gamma",
            "--without",
            &b,
            "--out",
            cert_s,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("differs=true"));

    // Offline verification with the pinned operator key succeeds.
    let pk_line = mneme()
        .args(["verify-replay", cert_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("verify-replay ok"))
        .stdout(predicates::str::contains("differs=true"))
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(pk_line).expect("utf8");
    let pk = text
        .split("operator_pk=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("pk")
        .to_string();
    mneme()
        .args(["verify-replay", cert_s, "--operator-pk", &pk])
        .assert()
        .success();
}

#[test]
fn replay_with_absent_exclusion_reports_no_difference() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("cert.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "alpha", "entry one");
    let absent = "ff".repeat(32);

    mneme()
        .args([
            "replay",
            store_s,
            "--keys",
            "alpha",
            "--without",
            &absent,
            "--out",
            cert_s,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("differs=false"));
    mneme().args(["verify-replay", cert_s]).assert().success();
}

#[test]
fn tampered_certificate_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("cert.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    let a = remember(store_s, "alpha", "entry one");
    mneme()
        .args([
            "replay",
            store_s,
            "--keys",
            "alpha",
            "--without",
            &a,
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
        .args(["verify-replay", cert_s])
        .assert()
        .failure()
        .code(4);
}

#[test]
fn replay_of_missing_key_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    let absent = "ee".repeat(32);
    mneme()
        .args([
            "replay",
            store_s,
            "--keys",
            "no_such_key",
            "--without",
            &absent,
        ])
        .assert()
        .failure();
}
