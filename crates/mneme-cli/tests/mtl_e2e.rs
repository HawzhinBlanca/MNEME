//! End-to-end CLI tests for MTL-1 (Memory Transparency Log).

use assert_cmd::Command;
use tempfile::tempdir;

const SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";

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
fn mtl_logs_root_and_inclusion_receipt_verifies_offline() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let log = dir.path().join("transparency.log");
    let log_s = log.to_str().expect("path");
    let rcpt = dir.path().join("inclusion.bin");
    let rcpt_s = rcpt.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "a", "one");

    // Append the current root and emit an inclusion receipt.
    mneme()
        .args(["mtl", store_s, "--log", log_s, "--out", rcpt_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("mtl receipt written"));

    // Offline verification (embedded key, then pinned).
    let out = mneme()
        .args(["verify-mtl", rcpt_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("verify-mtl ok"))
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
        .args(["verify-mtl", rcpt_s, "--operator-pk", &pk])
        .assert()
        .success();
}

#[test]
fn mtl_log_grows_across_invocations_and_each_receipt_verifies() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let log = dir.path().join("t.log");
    let log_s = log.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();

    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        remember(store_s, name, "v");
        let rcpt = dir.path().join(format!("r{i}.bin"));
        let rcpt_s = rcpt.to_str().expect("path");
        mneme()
            .args(["mtl", store_s, "--log", log_s, "--out", rcpt_s])
            .assert()
            .success()
            .stdout(predicates::str::contains(format!("log_size={}", i + 1)));
        mneme().args(["verify-mtl", rcpt_s]).assert().success();
    }
}

#[test]
fn mtl_consistency_proves_append_only_extension() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let log = dir.path().join("t.log");
    let log_s = log.to_str().expect("path");
    let crcpt = dir.path().join("consistency.bin");
    let crcpt_s = crcpt.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    // Grow the log to size 3 across invocations.
    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        remember(store_s, name, "v");
        let rcpt = dir.path().join(format!("r{i}.bin"));
        mneme()
            .args([
                "mtl",
                store_s,
                "--log",
                log_s,
                "--out",
                rcpt.to_str().unwrap(),
            ])
            .assert()
            .success();
    }
    // Prove the size-1 head is an append-only prefix of the current (size-3) head.
    mneme()
        .args([
            "mtl-consistency",
            store_s,
            "--log",
            log_s,
            "--first",
            "1",
            "--out",
            crcpt_s,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("first_size=1"))
        .stdout(predicates::str::contains("second_size=3"));
    mneme()
        .args(["verify-mtl-consistency", crcpt_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("append-only proven"));

    // Tamper → fails closed.
    let mut bytes = std::fs::read(&crcpt).expect("bytes");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&crcpt, &bytes).expect("write");
    mneme()
        .args(["verify-mtl-consistency", crcpt_s])
        .assert()
        .failure()
        .code(4);
}

#[test]
fn tampered_mtl_receipt_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let log = dir.path().join("t.log");
    let log_s = log.to_str().expect("path");
    let rcpt = dir.path().join("r.bin");
    let rcpt_s = rcpt.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "a", "one");
    mneme()
        .args(["mtl", store_s, "--log", log_s, "--out", rcpt_s])
        .assert()
        .success();

    let mut bytes = std::fs::read(&rcpt).expect("receipt bytes");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&rcpt, &bytes).expect("write tampered");

    mneme()
        .args(["verify-mtl", rcpt_s])
        .assert()
        .failure()
        .code(4);
}
