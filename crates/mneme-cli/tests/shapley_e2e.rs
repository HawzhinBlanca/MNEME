//! End-to-end CLI tests for CCR-Shapley certified attribution.

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
    String::from_utf8(out)
        .expect("utf8")
        .split("object_id=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("object id")
        .to_string()
}

#[test]
fn attribution_lands_on_the_load_bearing_entry() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("shapley.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "weather", "the sky was clear all day");
    let sensor = remember(store_s, "sensor", "the bridge sensor read 91C");
    remember(store_s, "schedule", "maintenance was scheduled");

    // Judge: emits the count of lines containing 91C — output changes exactly
    // when the sensor entry joins the coalition, regardless of join order.
    let out = mneme()
        .args([
            "shapley",
            store_s,
            "--keys",
            "weather,sensor,schedule",
            "--judge",
            "grep -c 91C",
            "--samples",
            "8",
            "--out",
            cert_s,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");

    // The sensor entry must carry full marginal impact; the others zero.
    assert!(
        text.contains(&format!("{sensor} marginal_impact=8/8")),
        "sensor should get 8/8, got:\n{text}"
    );
    let zero_lines = text
        .lines()
        .filter(|l| l.contains("marginal_impact=0/8"))
        .count();
    assert_eq!(zero_lines, 2, "weather and schedule should be 0/8:\n{text}");

    mneme()
        .args(["verify-shapley", cert_s])
        .assert()
        .success()
        .stdout(predicates::str::contains("verify-shapley ok"))
        .stdout(predicates::str::contains(format!(
            "{sensor} marginal_impact=8/8"
        )));
}

#[test]
fn deterministic_across_runs() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let c1 = dir.path().join("c1.bin");
    let c2 = dir.path().join("c2.bin");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "a", "alpha entry");
    remember(store_s, "b", "beta entry 91C");

    for c in [&c1, &c2] {
        mneme()
            .args([
                "shapley",
                store_s,
                "--keys",
                "a,b",
                "--judge",
                "grep -c 91C",
                "--samples",
                "4",
                "--out",
                c.to_str().expect("path"),
            ])
            .assert()
            .success();
    }
    let b1 = std::fs::read(&c1).expect("c1");
    let b2 = std::fs::read(&c2).expect("c2");
    assert_eq!(b1, b2, "same seed + same store must be byte-identical");
}

#[test]
fn tampered_certificate_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let store = dir.path().join("store");
    let store_s = store.to_str().expect("path");
    let cert = dir.path().join("cert.bin");
    let cert_s = cert.to_str().expect("path");

    mneme().args(["init", store_s]).assert().success();
    remember(store_s, "a", "alpha entry");
    mneme()
        .args([
            "shapley",
            store_s,
            "--keys",
            "a",
            "--judge",
            "cat",
            "--samples",
            "2",
            "--out",
            cert_s,
        ])
        .assert()
        .success();

    let mut bytes = std::fs::read(&cert).expect("bytes");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&cert, &bytes).expect("write");

    mneme()
        .args(["verify-shapley", cert_s])
        .assert()
        .failure()
        .code(4);
}
