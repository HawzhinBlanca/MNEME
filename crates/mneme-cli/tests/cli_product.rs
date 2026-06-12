//! Product-surface CLI tests for the default, operator-tools-off build.

use assert_cmd::Command;
use mneme_crypto::KeyPair;
use mneme_store::Store;
use predicates::prelude::*;
use tempfile::tempdir;

fn mneme() -> Command {
    let mut cmd = Command::cargo_bin("mneme").unwrap();
    cmd.env_remove("MNEME_OPERATOR_SEED")
        .env_remove("MNEME_KMS_MASTER_KEY_HEX");
    cmd
}

#[test]
fn default_help_hides_operator_tools() {
    mneme()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("recall"))
        .stdout(predicate::str::contains("remember"))
        .stdout(predicate::str::contains("forget"))
        .stdout(predicate::str::contains("audit").not())
        .stdout(predicate::str::contains("init").not())
        .stdout(predicate::str::contains("determinism").not());
}

#[test]
fn default_product_commands_work_against_existing_store() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let seed = [0x6b; 32];
    let seed_hex = hex::encode(seed);
    let operator = KeyPair::from_seed(seed);
    Store::create(&store, operator).expect("create fixture store");

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "verify",
            store.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify ok"));

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "mode",
            "--body",
            "strict",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("remembered object_id="));

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "recall",
            store.to_str().unwrap(),
            "-q",
            "mode",
            "--key",
            "mode",
            "--namespace",
            "user",
            "--min-tier",
            "working",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("strict"));

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "forget",
            store.to_str().unwrap(),
            "--key",
            "user/mode",
            "--mode",
            "shred",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("forgot key"));
}
