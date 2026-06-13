//! End-to-end CLI tests for FCC-1 (Forgetting-Closure Certificate).

use assert_cmd::Command;
use tempfile::tempdir;

const SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn mneme() -> Command {
    let mut cmd = Command::cargo_bin("mneme").expect("binary");
    cmd.env("MNEME_OPERATOR_SEED", SEED);
    cmd
}

#[test]
fn fcc_shred_emits_tier2_cert_and_verifies_offline() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("fcc.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    mneme()
        .args([
            "remember",
            store_s,
            "--namespace",
            "user",
            "--name",
            "secret",
            "--body",
            "pii",
        ])
        .assert()
        .success();

    // Crypto-shred + provable absence ⇒ T2 closure certificate.
    mneme()
        .args([
            "fcc",
            store_s,
            "--namespace",
            "user",
            "--name",
            "secret",
            "--out",
            cert_s,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("tier_achieved=2"));

    // Offline verification (embedded key, then pinned).
    let out = mneme()
        .args(["verify-fcc", cert_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("verify-fcc ok"))
        .stdout(predicates::str::contains(
            "T2 crypto-shred + provable absence",
        ))
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
    mneme()
        .args(["verify-fcc", cert_s, "--operator-pk", &pk])
        .assert()
        .success();
}

#[test]
fn tampered_fcc_cert_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("fcc.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    mneme()
        .args([
            "remember",
            store_s,
            "--namespace",
            "user",
            "--name",
            "k",
            "--body",
            "v",
        ])
        .assert()
        .success();
    mneme()
        .args([
            "fcc",
            store_s,
            "--namespace",
            "user",
            "--name",
            "k",
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
        .args(["verify-fcc", cert_s])
        .assert()
        .failure()
        .code(4);
}

#[test]
fn fcc_missing_key_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    mneme()
        .args([
            "fcc",
            store_s,
            "--namespace",
            "user",
            "--name",
            "never_existed",
            "--out",
            store.join("c.bin").to_str().expect("path"),
        ])
        .assert()
        .failure();
}
