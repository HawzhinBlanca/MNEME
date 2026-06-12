//! Product-surface CLI tests for the default, operator-tools-off build.

use assert_cmd::Command;
use mneme_crypto::KeyPair;
use mneme_store::Store;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::fs;
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
fn default_verify_help_documents_peak_state_pin() {
    mneme()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pin-peak-state"));
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

#[test]
fn default_verify_accepts_external_peak_state_pin_and_rejects_rollback() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let rolled_back_store = dir.path().join("rolled-back-store");
    let pin = dir.path().join("pins").join("peak-state.json");
    let seed = [0x6c; 32];
    let seed_hex = hex::encode(seed);
    let operator = KeyPair::from_seed(seed);
    Store::create(&store, operator.clone()).expect("create fixture store");

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "base",
            "--body",
            "base",
        ])
        .assert()
        .success();

    let pinned_state = Store::open(&store, operator.clone())
        .expect("open store")
        .root_history_peak_state()
        .expect("peak state");
    write_peak_state_pin(&pin, &pinned_state);

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "next",
            "--body",
            "next",
        ])
        .assert()
        .success();

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "verify",
            store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify ok"));

    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "verify",
            store.to_str().unwrap(),
            "--pin-peak-state",
            store.join("inside-pin.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("outside STORE"));

    #[cfg(unix)]
    {
        let inside_pin = store.join("inside-valid-pin.json");
        let symlink_pin = dir.path().join("symlink-peak-state.json");
        fs::copy(&pin, &inside_pin).expect("inside pin fixture");
        std::os::unix::fs::symlink(&inside_pin, &symlink_pin).expect("symlink pin fixture");

        mneme()
            .args([
                "--operator-seed",
                &seed_hex,
                "verify",
                store.to_str().unwrap(),
                "--pin-peak-state",
                symlink_pin.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .code(2)
            .stderr(predicate::str::contains("not a symlink"));

        let hardlink_pin = dir.path().join("hardlink-peak-state.json");
        fs::hard_link(&inside_pin, &hardlink_pin).expect("hardlink pin fixture");
        mneme()
            .args([
                "--operator-seed",
                &seed_hex,
                "verify",
                store.to_str().unwrap(),
                "--pin-peak-state",
                hardlink_pin.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .code(2)
            .stderr(predicate::str::contains("hard-linked"));
    }

    Store::create(&rolled_back_store, KeyPair::from_seed(seed)).expect("rolled-back fixture");
    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "verify",
            rolled_back_store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));

    let mut tampered: Value =
        serde_json::from_slice(&fs::read(&pin).expect("pin json")).expect("pin json should parse");
    tampered["peak_bag_root"] = Value::String("00".repeat(32));
    fs::write(&pin, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    mneme()
        .args([
            "--operator-seed",
            &seed_hex,
            "verify",
            store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

fn write_peak_state_pin(path: &std::path::Path, state: &mneme_root::RootHistoryPeakState) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("pin parent");
    }
    let peaks = state
        .peaks
        .iter()
        .map(|peak| {
            json!({
                "height": peak.height,
                "hash": hex::encode(peak.hash),
            })
        })
        .collect::<Vec<_>>();
    let pin = json!({
        "schema": "mneme.audit.peak_state.v1",
        "version": state.version,
        "sequence": state.sequence,
        "head_preimage_hash": hex::encode(state.head_preimage_hash),
        "peak_bag_root": hex::encode(state.peak_bag_root),
        "peaks": peaks,
    });
    fs::write(path, serde_json::to_vec_pretty(&pin).unwrap()).expect("write pin");
}
