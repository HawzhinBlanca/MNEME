//! CLI integration tests — blueprint §14.2 critical journeys.

use assert_cmd::Command;
use mneme_cap::agent_cap;
use mneme_core::{Draft, MemoryKind};
use mneme_crypto::KeyPair;
use mneme_store::{Store, test_clear_pause};
use mneme_verify::{verify_store, verify_store_head};
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use walkdir::WalkDir;

fn mneme() -> Command {
    Command::cargo_bin("mneme").unwrap()
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
        .stdout(predicate::str::contains("init"));
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
        .code(2);
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
    };
    let (id, _) = store.remember(draft, &cap).unwrap();
    let (root, _) = store.head().unwrap();
    let trust = store.trust().clone();

    store.tamper_object_bytes(id.as_bytes()).unwrap();

    let head_report = verify_store_head(&root, &trust).expect("head-only accepts stale root");
    assert_eq!(
        head_report.root.sequence, root.sequence,
        "verify_store_head must not walk persisted objects"
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
        .stdout(predicate::str::contains("in-toto.io/Statement"));
}
