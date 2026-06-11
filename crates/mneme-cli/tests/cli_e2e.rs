//! CLI integration tests — blueprint §14.2 critical journeys.

use assert_cmd::Command;
use mneme_cap::agent_cap;
use mneme_core::{Draft, FixedPointEmbedding, MemoryKind, MnemeError, TrustTier};
use mneme_crypto::KeyPair;
use mneme_store::{Store, test_clear_pause};
use mneme_verify::{verify_signed_head_only, verify_store};
use predicates::prelude::*;
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
        .stdout(predicate::str::contains("pace"))
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
fn verify_cert_audit_beacon_fixture_succeeds() {
    let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../proof/vectors/certs/cognition_cert_v1_audit_beacon.cbor");
    let seed = [0x42; 32];
    let seed_hex = hex::encode(seed);
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    fs::create_dir_all(store.join("index")).unwrap();
    let sidecar = serde_json::json!({
        "entries": {
            hex::encode([0xab; 32]): {
                "dim": 2,
                "scale": 0,
                "components": [1, 0],
            }
        }
    });
    fs::write(
        store.join("index/embeddings.json"),
        serde_json::to_string_pretty(&sidecar).unwrap(),
    )
    .unwrap();

    mneme()
        .args([
            "verify-cert",
            cert_path.to_str().unwrap(),
            "--audit",
            "--store",
            store.to_str().unwrap(),
            "--components",
            "0,0",
            "--ef-search",
            "64",
            "--k",
            "1",
            "--operator-seed",
            &seed_hex,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify-cert ok"));
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
        .stderr(predicate::str::contains("root checkpoint not found"));
}

#[test]
fn audit_stub_returns_store_unavailable_without_fake_path_check() {
    let dir = tempdir().unwrap();
    let root_path = dir.path().join("checkpoint.cbor");
    fs::write(&root_path, b"").unwrap();
    mneme()
        .args(["audit", root_path.to_str().unwrap()])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("audit is not yet implemented"))
        .stderr(predicate::str::contains("store kernel not available"));
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

#[test]
fn pace_calibrate_run_verify_journey() {
    let dir = tempdir().unwrap();
    let calib = dir.path().join("pace.calib.cbor");
    let log = dir.path().join("pace.log.cbor");
    let genesis = "aa".repeat(32);
    mneme()
        .args([
            "pace",
            "calibrate",
            "--out",
            calib.to_str().unwrap(),
            "--target-ms",
            "10",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "maximum elapsed time is impossible",
        ));
    mneme()
        .args([
            "pace",
            "run",
            "--log",
            log.to_str().unwrap(),
            "--calib",
            calib.to_str().unwrap(),
            "--genesis",
            &genesis,
            "--label",
            "event-a",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("pace run ok"));
    mneme()
        .args(["pace", "run", "--log", log.to_str().unwrap()])
        .assert()
        .success();
    mneme()
        .args(["pace", "verify", log.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pace verify ok"))
        .stderr(predicate::str::contains("post-quantum"));
}
