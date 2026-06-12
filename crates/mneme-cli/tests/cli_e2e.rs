//! CLI integration tests — blueprint §14.2 critical journeys.

use assert_cmd::Command;
use mneme_cap::agent_cap;
use mneme_core::{
    Draft, FixedPointEmbedding, MemoryKind, MnemeError, TrustTier, hash_ckpt, to_bytes_canonical,
};
use mneme_crypto::KeyPair;
use mneme_store::{Store, test_clear_pause};
use mneme_verify::{verify_signed_head_only, verify_store};
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use walkdir::WalkDir;

const TEST_OPERATOR_MASTER_HEX: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";

fn raw_mneme() -> Command {
    let mut cmd = Command::cargo_bin("mneme").unwrap();
    cmd.env_remove("MNEME_OPERATOR_SEED")
        .env_remove("MNEME_KMS_MASTER_KEY_HEX");
    cmd
}

fn mneme() -> Command {
    let mut cmd = raw_mneme();
    cmd.env("MNEME_KMS_MASTER_KEY_HEX", TEST_OPERATOR_MASTER_HEX);
    cmd
}

#[test]
fn help_lists_critical_subcommands() {
    mneme()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("recall"))
        .stdout(predicate::str::contains("forget"))
        .stdout(predicate::str::contains("remember"))
        .stdout(predicate::str::contains("merge"))
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("attest"))
        .stdout(predicate::str::contains("certify"))
        .stdout(predicate::str::contains("verify-cert"))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("sync"))
        .stdout(predicate::str::contains("--vault"));
}

#[test]
fn init_without_seed_or_master_rejects_without_plaintext_operator_seed() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");

    raw_mneme()
        .args(["init", store.to_str().unwrap()])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("operator seed custody missing"))
        .stderr(predicate::str::contains("invalid usage"));

    assert!(!store.join(".operator_seed").exists());
}

#[test]
fn sync_pull_help_documents_peer_url() {
    mneme()
        .args(["sync", "pull", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("peer-url"));
}

#[test]
fn verify_help_documents_store_argument() {
    mneme()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("STORE"));
}

#[test]
fn recall_requires_query() {
    let dir = tempdir().unwrap();
    mneme()
        .args([
            "recall",
            dir.path().to_str().unwrap(),
            "--min-tier",
            "trusted",
            "-q",
            "",
        ])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn verify_missing_store_path_exits_usage() {
    mneme()
        .args(["verify", "/nonexistent/mneme-store-e2e"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn certify_and_verify_cert_succeeds() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let output = dir.path().join("cert.cbor");
    let seed = [0x01; 32];
    let seed_hex = hex::encode(seed);
    let operator = KeyPair::from_seed(seed);
    let cap = agent_cap(&operator, operator.public_key_bytes()).unwrap();
    {
        let mut s = Store::create(&store, operator.clone()).unwrap();
        s.trust_mut().authorized_writers.push(cap.subject);
        let draft = Draft {
            namespace: "cert".into(),
            logical_name: "semantic".into(),
            kind: MemoryKind::Semantic,
            body: b"body".to_vec(),
            parent_ids: vec![],
            session: [0xab; 16],
            trust_tier: Some(TrustTier::Trusted),
            embedding: Some(FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap()),
            valid_time_ms: None,
        };
        s.remember(draft, &cap).unwrap();
    }

    mneme()
        .args([
            "certify",
            store.to_str().unwrap(),
            "--out",
            output.to_str().unwrap(),
            "--operator-seed",
            &seed_hex,
        ])
        .assert()
        .success();

    mneme()
        .args([
            "verify-cert",
            output.to_str().unwrap(),
            "--ef-search",
            "64",
            "--k",
            "1",
            "--operator-seed",
            &seed_hex,
        ])
        .assert()
        .success();
}

#[test]
fn verify_cert_is_fail_closed() {
    let dir = tempdir().unwrap();
    let cert = dir.path().join("cert.json");
    fs::write(&cert, b"{\"version\":1}").unwrap();

    mneme()
        .args([
            "verify-cert",
            cert.to_str().unwrap(),
            "--ef-search",
            "64",
            "--k",
            "1",
            "--operator-seed",
            &hex::encode([0x02; 32]),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("certificate invalid"));
}

#[test]
fn init_verify_recall_forget_journey() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    mneme()
        .args(["init", store.to_str().unwrap()])
        .assert()
        .success();

    mneme()
        .args(["verify", store.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify ok"));

    mneme()
        .args([
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "theme",
            "--body",
            "dark",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("remembered object_id="));

    mneme()
        .args([
            "recall",
            store.to_str().unwrap(),
            "-q",
            "theme",
            "--key",
            "theme",
            "--namespace",
            "user",
            "--min-tier",
            "working",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dark"));

    mneme()
        .args([
            "forget",
            store.to_str().unwrap(),
            "--key",
            "user/theme",
            "--mode",
            "shred",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("forgot key"));
}

#[test]
fn cli_envelope_vault_writes_wrapped_object_keys() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let seed = "22".repeat(32);
    let master = "33".repeat(32);

    mneme()
        .env("MNEME_KMS_MASTER_KEY_HEX", &master)
        .args([
            "--operator-seed",
            &seed,
            "--vault",
            "envelope",
            "init",
            store.to_str().unwrap(),
        ])
        .assert()
        .success();

    mneme()
        .env("MNEME_KMS_MASTER_KEY_HEX", &master)
        .args([
            "--operator-seed",
            &seed,
            "--vault",
            "envelope",
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "vaulted",
            "--body",
            "wrapped",
        ])
        .assert()
        .success();

    let key_file = first_vault_key_file(&store).expect("wrapped vault key file");
    let bytes = fs::read(&key_file).unwrap();
    assert_eq!(
        bytes.len(),
        24 + 32 + 16,
        "envelope vault persists nonce + ciphertext + tag"
    );
    assert_ne!(
        bytes[24..56],
        [0u8; 32],
        "wrapped key payload must not be plaintext zeros"
    );

    mneme()
        .env("MNEME_KMS_MASTER_KEY_HEX", &master)
        .args([
            "--operator-seed",
            &seed,
            "--vault",
            "envelope",
            "recall",
            store.to_str().unwrap(),
            "-q",
            "vaulted",
            "--namespace",
            "user",
            "--min-tier",
            "trusted",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrapped"));
}

#[test]
fn merge_two_stores_converges() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    mneme()
        .args(["init", a.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args(["init", b.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args(["merge", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn audit_missing_root_is_usage_error() {
    mneme()
        .args(["audit", "/no/such/root.cbor"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("store path not found"));
}

#[test]
fn audit_emits_root_history_json_and_verifies_saved_peak_state() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let peak_state = dir.path().join("peak-state.json");
    let peak_proof = dir.path().join("peak-proof.json");
    let seed = "44".repeat(32);
    let operator_pubkey = hex::encode(KeyPair::from_seed([0x44; 32]).public_key_bytes());

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "one",
            "--body",
            "v1",
        ])
        .assert()
        .success();

    let output = mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-state",
            peak_state.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("audit json");
    assert_eq!(report["schema"], "mneme.audit.root_history.v1");
    assert_eq!(report["verify_store"]["verified"], true);
    assert_eq!(report["root_history"]["sequence"], 2);
    assert_eq!(report["peak_digest"]["sequence"], 2);
    assert_eq!(report["peak_state"]["schema"], "mneme.audit.peak_state.v1");
    assert_eq!(report["peak_state"]["sequence"], 2);
    assert!(peak_state.exists());

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "two",
            "--body",
            "v2",
        ])
        .assert()
        .success();

    let output = mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--from-peak-state",
            peak_state.to_str().unwrap(),
            "--emit-peak-proof",
            peak_proof.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("audit json");
    assert_eq!(report["peak_consistency"]["verified"], true);
    assert_eq!(report["peak_consistency"]["from_sequence"], 2);
    assert_eq!(report["peak_consistency"]["to_sequence"], 3);
    assert_eq!(report["peak_consistency"]["appended_checkpoint_count"], 1);
    assert!(peak_proof.exists());

    mneme()
        .args(["audit", "--verify-peak-proof", peak_proof.to_str().unwrap()])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("requires --operator-pubkey"));

    let output = mneme()
        .args([
            "audit",
            "--verify-peak-proof",
            peak_proof.to_str().unwrap(),
            "--operator-pubkey",
            &operator_pubkey,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("proof verification json");
    assert_eq!(report["schema"], "mneme.audit.peak_proof_verification.v1");
    assert_eq!(report["verified"], true);
    assert_eq!(report["from_sequence"], 2);
    assert_eq!(report["to_sequence"], 3);
}

#[test]
fn audit_rejects_tampered_saved_peak_state() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let peak_state = dir.path().join("peak-state.json");
    let seed = "45".repeat(32);

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-state",
            peak_state.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut state: Value =
        serde_json::from_slice(&fs::read(&peak_state).expect("peak state")).expect("state json");
    state["peak_bag_root"] = Value::String("00".repeat(32));
    fs::write(&peak_state, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--from-peak-state",
            peak_state.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn audit_rejects_saved_peak_state_without_schema_or_with_extra_fields() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let peak_state = dir.path().join("peak-state.json");
    let missing_schema = dir.path().join("peak-state-missing-schema.json");
    let extra_field = dir.path().join("peak-state-extra-field.json");
    let seed = "48".repeat(32);

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-state",
            peak_state.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut state: Value =
        serde_json::from_slice(&fs::read(&peak_state).expect("peak state")).expect("state json");
    let mut without_schema = state.clone();
    without_schema
        .as_object_mut()
        .expect("state object")
        .remove("schema");
    fs::write(
        &missing_schema,
        serde_json::to_vec_pretty(&without_schema).unwrap(),
    )
    .unwrap();

    state["self_attested_verified"] = Value::Bool(true);
    fs::write(&extra_field, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    for invalid_state in [&missing_schema, &extra_field] {
        mneme()
            .args([
                "--operator-seed",
                &seed,
                "audit",
                store.to_str().unwrap(),
                "--from-peak-state",
                invalid_state.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .code(2)
            .stderr(predicate::str::contains("invalid usage"));
    }
}

#[test]
fn audit_exports_and_offline_verifies_peak_inclusion_proof() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let inclusion_proof = dir.path().join("peak-inclusion-proof.json");
    let seed = "49".repeat(32);
    let operator_pubkey = hex::encode(KeyPair::from_seed([0x49; 32]).public_key_bytes());

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    for name in ["one", "two", "three"] {
        mneme()
            .args([
                "--operator-seed",
                &seed,
                "remember",
                store.to_str().unwrap(),
                "--namespace",
                "audit",
                "--name",
                name,
                "--body",
                name,
            ])
            .assert()
            .success();
    }

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-inclusion-proof",
            inclusion_proof.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("requires --checkpoint-sequence"));

    let output = mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--checkpoint-sequence",
            "3",
            "--emit-peak-inclusion-proof",
            inclusion_proof.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("audit json");
    assert_eq!(report["peak_inclusion"]["verified"], true);
    assert_eq!(report["peak_inclusion"]["sequence"], 3);
    assert!(report["peak_inclusion"]["path_len"].as_u64().unwrap() > 0);
    assert!(inclusion_proof.exists());

    mneme()
        .args([
            "audit",
            "--verify-peak-inclusion-proof",
            inclusion_proof.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("requires --operator-pubkey"));

    let output = mneme()
        .args([
            "audit",
            "--verify-peak-inclusion-proof",
            inclusion_proof.to_str().unwrap(),
            "--operator-pubkey",
            &operator_pubkey,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verified: Value = serde_json::from_slice(&output).expect("verification json");
    assert_eq!(
        verified["schema"],
        "mneme.audit.peak_inclusion_proof_verification.v1"
    );
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["sequence"], 3);

    let mut tampered: Value =
        serde_json::from_slice(&fs::read(&inclusion_proof).expect("inclusion proof"))
            .expect("proof json");
    tampered["proof"]["path"][0]["sibling_hash"] = Value::String("00".repeat(32));
    fs::write(
        &inclusion_proof,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();

    mneme()
        .args([
            "audit",
            "--verify-peak-inclusion-proof",
            inclusion_proof.to_str().unwrap(),
            "--operator-pubkey",
            &operator_pubkey,
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn audit_exports_structural_frontier_proof_without_signature_overclaim() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let peak_state = dir.path().join("peak-state.json");
    let frontier_proof = dir.path().join("peak-frontier-proof.json");
    let extra_field_proof = dir.path().join("peak-frontier-extra-field.json");
    let seed = "4a".repeat(32);
    let operator_pubkey = hex::encode(KeyPair::from_seed([0x4a; 32]).public_key_bytes());

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "base",
            "--body",
            "base",
        ])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-state",
            peak_state.to_str().unwrap(),
        ])
        .assert()
        .success();

    for name in ["two", "three", "four", "five"] {
        mneme()
            .args([
                "--operator-seed",
                &seed,
                "remember",
                store.to_str().unwrap(),
                "--namespace",
                "audit",
                "--name",
                name,
                "--body",
                name,
            ])
            .assert()
            .success();
    }

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-frontier-proof",
            frontier_proof.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("requires --from-peak-state"));

    let output = mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--from-peak-state",
            peak_state.to_str().unwrap(),
            "--emit-peak-frontier-proof",
            frontier_proof.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("audit json");
    assert_eq!(report["peak_frontier"]["verified"], true);
    assert_eq!(
        report["peak_frontier"]["proof_kind"],
        "structural_frontier.v1"
    );
    assert_eq!(report["peak_frontier"]["claim"], "structural_frontier_only");
    assert_eq!(
        report["peak_frontier"]["signature_coverage"],
        "none_for_appended_subtrees"
    );
    assert_eq!(
        report["peak_frontier"]["signed_checkpoint_delta_required_for_signature_coverage"],
        true
    );
    assert_eq!(report["peak_frontier"]["from_sequence"], 2);
    assert_eq!(report["peak_frontier"]["to_sequence"], 6);
    assert_eq!(report["peak_frontier"]["appended_subtree_count"], 2);
    assert!(frontier_proof.exists());

    let proof: Value = serde_json::from_slice(&fs::read(&frontier_proof).expect("frontier proof"))
        .expect("frontier proof json");
    assert_eq!(proof["schema"], "mneme.audit.peak_frontier_proof.v1");
    assert_eq!(proof["proof_kind"], "structural_frontier.v1");
    assert_eq!(proof["signature_coverage"], "none_for_appended_subtrees");
    assert!(proof.get("operator_keys").is_none());

    let output = mneme()
        .args([
            "audit",
            "--verify-peak-frontier-proof",
            frontier_proof.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verified: Value = serde_json::from_slice(&output).expect("verification json");
    assert_eq!(
        verified["schema"],
        "mneme.audit.peak_frontier_proof_verification.v1"
    );
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["proof_kind"], "structural_frontier.v1");
    assert_eq!(verified["signature_coverage"], "none_for_appended_subtrees");
    assert_eq!(verified["requires_external_pin"], true);
    assert_eq!(verified["appended_subtree_count"], 2);

    mneme()
        .args([
            "audit",
            "--verify-peak-frontier-proof",
            frontier_proof.to_str().unwrap(),
            "--operator-pubkey",
            &operator_pubkey,
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("operator keys are not used"));

    let mut proof_with_extra = proof.clone();
    proof_with_extra["self_attested_verified"] = Value::Bool(true);
    fs::write(
        &extra_field_proof,
        serde_json::to_vec_pretty(&proof_with_extra).unwrap(),
    )
    .unwrap();
    mneme()
        .args([
            "audit",
            "--verify-peak-frontier-proof",
            extra_field_proof.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid usage"));

    let mut tampered = proof;
    tampered["proof"]["appended_subtrees"][0]["hash"] = Value::String("00".repeat(32));
    fs::write(
        &frontier_proof,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    mneme()
        .args([
            "audit",
            "--verify-peak-frontier-proof",
            frontier_proof.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn audit_pin_peak_state_creates_advances_and_rejects_rollback() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let rolled_back_store = dir.path().join("rolled-back-store");
    let pin = dir.path().join("pins").join("root-history-pin.json");
    let seed = "4b".repeat(32);

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "base",
            "--body",
            "base",
        ])
        .assert()
        .success();

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--pin-peak-state",
            store.join("bad-pin.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("outside STORE"));

    let output = mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("audit json");
    assert_eq!(report["peak_pin"]["verified"], true);
    assert_eq!(report["peak_pin"]["status"], "created");
    assert_eq!(
        report["peak_pin"]["proof_kind"],
        "initial_peak_state_pin.v1"
    );
    assert_eq!(report["peak_pin"]["from_sequence"], Value::Null);
    assert_eq!(report["peak_pin"]["to_sequence"], 2);
    assert_eq!(
        report["peak_pin"]["snapshot_rollback_resistance_requires_pin_outside_store"],
        true
    );
    assert_eq!(
        report["peak_pin"]["same_host_pin_file_can_be_rolled_back_with_store"],
        true
    );
    assert!(pin.exists());

    #[cfg(unix)]
    {
        let inside_pin = store.join("inside-valid-pin.json");
        let symlink_pin = dir.path().join("symlink-root-history-pin.json");
        fs::copy(&pin, &inside_pin).expect("inside pin fixture");
        std::os::unix::fs::symlink(&inside_pin, &symlink_pin).expect("symlink pin fixture");

        mneme()
            .args([
                "--operator-seed",
                &seed,
                "audit",
                store.to_str().unwrap(),
                "--pin-peak-state",
                symlink_pin.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .code(2)
            .stderr(predicate::str::contains("outside STORE"));
    }

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "next",
            "--body",
            "next",
        ])
        .assert()
        .success();

    let output = mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("audit json");
    assert_eq!(report["peak_pin"]["verified"], true);
    assert_eq!(report["peak_pin"]["status"], "advanced");
    assert_eq!(
        report["peak_pin"]["proof_kind"],
        "signed_delta_consistency.v1"
    );
    assert_eq!(report["peak_pin"]["from_sequence"], 2);
    assert_eq!(report["peak_pin"]["to_sequence"], 3);
    assert_eq!(report["peak_pin"]["appended_checkpoint_count"], 1);

    mneme()
        .args([
            "--operator-seed",
            &seed,
            "init",
            rolled_back_store.to_str().unwrap(),
        ])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            rolled_back_store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));

    let mut tampered: Value =
        serde_json::from_slice(&fs::read(&pin).expect("pin json")).expect("pin json");
    tampered["peak_bag_root"] = Value::String("00".repeat(32));
    fs::write(&pin, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--pin-peak-state",
            pin.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn audit_rejects_well_formed_but_false_peak_sidecar() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let seed = "47".repeat(32);

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "sidecar",
            "--body",
            "valid-log",
        ])
        .assert()
        .success();

    let mut state = mneme_root::read_root_history_peak_state(&store).expect("read peak sidecar");
    state.peaks[0].hash[0] ^= 0xff;
    state.peak_bag_root =
        test_peak_bag_root(state.sequence, &state.head_preimage_hash, &state.peaks);
    fs::write(
        store.join("roots/HISTORY_PEAKS.cbor"),
        to_bytes_canonical(&state).expect("canonical forged sidecar"),
    )
    .unwrap();

    mneme()
        .args(["--operator-seed", &seed, "audit", store.to_str().unwrap()])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn audit_offline_peak_proof_rejects_tampered_bundle() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let peak_state = dir.path().join("peak-state.json");
    let peak_proof = dir.path().join("peak-proof.json");
    let extra_field_proof = dir.path().join("peak-proof-extra-field.json");
    let seed = "46".repeat(32);
    let operator_pubkey = hex::encode(KeyPair::from_seed([0x46; 32]).public_key_bytes());

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--emit-peak-state",
            peak_state.to_str().unwrap(),
        ])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "audit",
            "--name",
            "proof",
            "--body",
            "delta",
        ])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "audit",
            store.to_str().unwrap(),
            "--from-peak-state",
            peak_state.to_str().unwrap(),
            "--emit-peak-proof",
            peak_proof.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut proof: Value =
        serde_json::from_slice(&fs::read(&peak_proof).expect("peak proof")).expect("proof json");
    let mut proof_with_extra = proof.clone();
    proof_with_extra["self_attested_verified"] = Value::Bool(true);
    fs::write(
        &extra_field_proof,
        serde_json::to_vec_pretty(&proof_with_extra).unwrap(),
    )
    .unwrap();
    mneme()
        .args([
            "audit",
            "--verify-peak-proof",
            extra_field_proof.to_str().unwrap(),
            "--operator-pubkey",
            &operator_pubkey,
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid usage"));

    proof["newer"]["peak_bag_root"] = Value::String("00".repeat(32));
    fs::write(&peak_proof, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();

    mneme()
        .args([
            "audit",
            "--verify-peak-proof",
            peak_proof.to_str().unwrap(),
            "--operator-pubkey",
            &operator_pubkey,
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn cli_verify_rejects_tampered_object_bytes() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    mneme()
        .args(["init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "tamper-target",
            "--body",
            "mneme-cli-verify-b3",
        ])
        .assert()
        .success();

    tamper_first_object_cbor(&store);

    mneme()
        .args(["verify", store.to_str().unwrap()])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("verify failed"));
}

#[test]
fn head_only_verify_misses_object_tamper_full_verify_and_cli_reject() {
    test_clear_pause();
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("store");
    let seed = [0x42; 32];
    let operator = KeyPair::from_seed(seed);

    let agent = KeyPair::generate();
    let cap = agent_cap(&operator, agent.public_key_bytes()).unwrap();
    let mut store = Store::create(&store_path, operator).unwrap();
    fs::write(store_path.join(".operator_seed"), hex::encode(seed)).unwrap();
    store.trust_mut().authorized_writers.push(cap.subject);

    let draft = Draft {
        namespace: "user".into(),
        logical_name: "b3-head-vs-full".into(),
        kind: MemoryKind::Episodic,
        body: b"mneme-b3-object-tamper".to_vec(),
        parent_ids: vec![],
        session: [0xab; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
    };
    let (id, _) = store.remember(draft, &cap).unwrap();
    let (root, _) = store.head().unwrap();
    let trust = store.trust().clone();

    store.tamper_object_bytes(id.as_bytes()).unwrap();

    let head_report = verify_signed_head_only(&root, &trust).expect("head-only accepts stale root");
    assert_eq!(
        head_report.root.sequence, root.sequence,
        "verify_signed_head_only must not walk persisted objects"
    );

    assert!(
        verify_store(&store_path, &trust).is_err(),
        "full verify_store must reject tampered object at committed path"
    );

    mneme()
        .args(["verify", store_path.to_str().unwrap()])
        .assert()
        .failure()
        .code(4);
}

fn tamper_first_object_cbor(store: &Path) {
    let path = find_first_object_cbor(store).expect("store must contain at least one object");
    let mut bytes = fs::read(&path).unwrap();
    assert!(!bytes.is_empty(), "object blob must be non-empty");
    bytes[0] ^= 0xff;
    fs::write(&path, bytes).unwrap();
}

fn find_first_object_cbor(store: &Path) -> Option<PathBuf> {
    let objects_dir = store.join("objects");
    for entry in WalkDir::new(&objects_dir)
        .min_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "cbor") {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn test_peak_bag_root(
    sequence: u64,
    head_preimage_hash: &[u8; 32],
    peaks: &[mneme_root::RootHistoryPeak],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(27 + 8 + 32 + 8 + peaks.len() * 36);
    payload.extend_from_slice(b"root-history-peak-bag-v1\x00");
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.extend_from_slice(head_preimage_hash);
    payload.extend_from_slice(&(peaks.len() as u64).to_le_bytes());
    for peak in peaks {
        payload.extend_from_slice(&peak.height.to_le_bytes());
        payload.extend_from_slice(&peak.hash);
    }
    hash_ckpt(&payload)
}

fn first_vault_key_file(store: &Path) -> Option<PathBuf> {
    let vault_dir = store.join("keys/vault");
    for entry in WalkDir::new(&vault_dir)
        .min_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.ends_with(".shred") && name != "vault.journal")
        {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    for entry in WalkDir::new(src)
        .min_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        let rel = entry.path().strip_prefix(src).unwrap();
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).unwrap();
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// F-2 (A-REPLAY / INV-6, §2.4): an A-DB adversary rolls HEAD back to a fully
/// self-consistent older signed snapshot while the newer checkpoint is still on
/// disk. Cold open, `mneme verify`, and `mneme recall` MUST all fail closed with
/// `RootReplayed` — exercised through the PUBLIC paths (CLI binary + `Store::open`),
/// not unit-test trust injection. Red before the fix (verify printed "verify ok"
/// and recall served the stale VALUE-1); green after wiring the checkpoint-log
/// max-sequence scan into `Store::open` / `verify_store`.
#[test]
fn f2_replay_rollback_to_signed_snapshot_rejected_through_public_paths() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    let seed = "11".repeat(32);

    mneme()
        .args(["--operator-seed", &seed, "init", store.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "secret",
            "--body",
            "VALUE-1",
        ])
        .assert()
        .success();

    // Full, self-consistent seq2 snapshot (HEAD + meta + objects + checkpoints 1..2).
    let snapshot = dir.path().join("rolled-back");
    copy_dir_recursive(&store, &snapshot);

    // seq3: secret = VALUE-2 (advances the live store, appending roots/3.root.cbor).
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "remember",
            store.to_str().unwrap(),
            "--namespace",
            "user",
            "--name",
            "secret",
            "--body",
            "VALUE-2",
        ])
        .assert()
        .success();

    // Attack: drop the newer validly-signed checkpoint into the rolled-back seq2 tree.
    fs::copy(
        store.join("roots/3.root.cbor"),
        snapshot.join("roots/3.root.cbor"),
    )
    .unwrap();

    // 1) Public `mneme verify` must reject (returned exit 0 "verify ok" before F-2 fix).
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "verify",
            snapshot.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(4);

    // 2) Public `mneme recall` must reject (served stale VALUE-1 before F-2 fix).
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "recall",
            snapshot.to_str().unwrap(),
            "-q",
            "secret",
            "--namespace",
            "user",
            "--min-tier",
            "trusted",
        ])
        .assert()
        .failure();

    // 3) Public Store::open must fail closed with the typed replay error.
    match Store::open(&snapshot, KeyPair::from_seed([0x11; 32])) {
        Ok(_) => panic!("rolled-back cold open must fail closed, but Store::open succeeded"),
        Err(e) => assert_eq!(
            e,
            MnemeError::RootReplayed,
            "expected RootReplayed, got {e:?}"
        ),
    }

    // Control (no false positive): the legitimate seq3 store still verifies and recalls VALUE-2.
    mneme()
        .args(["--operator-seed", &seed, "verify", store.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify ok"));
    mneme()
        .args([
            "--operator-seed",
            &seed,
            "recall",
            store.to_str().unwrap(),
            "-q",
            "secret",
            "--namespace",
            "user",
            "--min-tier",
            "trusted",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALUE-2"));
}

#[test]
fn sync_pull_requires_peer_url() {
    let dir = tempdir().unwrap();
    mneme()
        .args(["sync", "pull", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn sync_pull_rejects_non_websocket_peer_url() {
    let dir = tempdir().unwrap();
    mneme()
        .args([
            "sync",
            "pull",
            dir.path().to_str().unwrap(),
            "--peer-url",
            "http://127.0.0.1:7845/v1/sync",
        ])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn attest_emits_sigstore_statement() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("root.cbor");
    fs::write(&root, b"fixture-root-bytes").unwrap();
    mneme()
        .arg("attest")
        .arg(&root)
        .assert()
        .success()
        .stdout(predicate::str::contains("in-toto.io/Statement"))
        .stdout(predicate::str::contains("authenticated"))
        .stdout(predicate::str::contains("not truth"))
        .stdout(predicate::str::contains("not exact"))
        .stdout(predicate::str::contains(
            "top-k over prover-asserted distances",
        ))
        .stdout(predicate::str::contains("membership/completeness"))
        .stdout(predicate::str::contains("top-k ranking is not proven"))
        .stdout(predicate::str::contains(
            "not top-k by true query-to-embedding distance",
        ));
}
