//! Appendix B item 6: capability sig-chain + caveat evaluation cross-impl vectors.
//!
//! Byte-pinned, single-implementation conformance vectors: each committed `.cbor` is the
//! exact canonical capability encoding, re-decoded, sig-chain-verified, and exercised for
//! caveat pass/fail here. Seeds match the deterministic `cap_tamper` fixtures.

use mneme_cap::{Capability, Permissions, agent_cap};
use mneme_core::{Caveat, Hlc, MemoryKind, MnemeError, NodeId, TrustTier};
use mneme_crypto::KeyPair;
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("proof/vectors/capabilities")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn issuer() -> KeyPair {
    KeyPair::from_seed([0x01; 32])
}

fn subject() -> KeyPair {
    KeyPair::from_seed([0x02; 32])
}

fn hlc(wall_ms: u64) -> Hlc {
    Hlc {
        wall_ms,
        counter: 0,
        node_id: NodeId([0x02; 16]),
    }
}

/// Root agent capability (sig-chain length 1).
fn fixture_root_cap() -> Capability {
    agent_cap(&issuer(), subject().public_key_bytes()).expect("root cap")
}

/// Attenuated capability (sig-chain length 2, subject narrows namespace).
fn fixture_attenuated_cap() -> Capability {
    fixture_root_cap()
        .attenuate(&subject(), vec![Caveat::NamespacePrefix("tools/".into())])
        .expect("attenuate")
}

/// Capability with a near `NotAfter` caveat to pin caveat pass/fail evaluation.
fn fixture_expiring_cap() -> Capability {
    Capability::issue(
        &issuer(),
        subject().public_key_bytes(),
        vec!["*".into()],
        vec![MemoryKind::Working],
        TrustTier::Working,
        TrustTier::Working,
        Permissions::READ,
        vec![Caveat::NotAfter(hlc(50))],
    )
    .expect("expiring cap")
}

#[test]
#[ignore = "run manually to (re)generate proof/vectors/capabilities fixtures"]
fn dump_capability_fixtures() {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    for (name, cap) in [
        ("root_cap_v1", fixture_root_cap()),
        ("attenuated_cap_v1", fixture_attenuated_cap()),
        ("expiring_cap_v1", fixture_expiring_cap()),
    ] {
        let bytes = cap.to_bytes().expect("encode");
        fs::write(dir.join(format!("{name}.cbor")), &bytes).expect("write");
        eprintln!(
            "{name}.cbor len={} cap_id={} chain_len={}",
            bytes.len(),
            hex(&cap.cap_id().expect("cap_id")),
            cap.sig_chain().expect("chain").len()
        );
    }
    eprintln!("issuer_pubkey={}", hex(&issuer().public_key_bytes()));
    eprintln!("subject_pubkey={}", hex(&subject().public_key_bytes()));
}

fn load(name: &str) -> Capability {
    let bytes = fs::read(vectors_dir().join(format!("{name}.cbor")))
        .unwrap_or_else(|_| panic!("committed {name}.cbor present"));
    Capability::from_bytes(&bytes).expect("decode committed capability")
}

#[test]
fn appendix_b_root_cap_round_trips_and_verifies() {
    let committed = load("root_cap_v1");
    let rebuilt = fixture_root_cap();
    assert_eq!(
        committed.to_bytes().unwrap(),
        rebuilt.to_bytes().unwrap(),
        "committed root cap diverged from generator"
    );
    assert_eq!(committed.sig_chain().unwrap().len(), 1);
    assert_eq!(committed.cap_id().unwrap(), rebuilt.cap_id().unwrap());
    // Caveat pass: far-future NotAfter verifies under the pinned issuer.
    committed.verify(&issuer(), &hlc(1)).expect("verify");
    // Fault injection: flipped sig byte fails closed.
    let mut bad = committed.clone();
    bad.signature[0] ^= 0x01;
    assert_eq!(
        bad.verify(&issuer(), &hlc(1)).unwrap_err(),
        MnemeError::CapDenied
    );
}

#[test]
fn appendix_b_attenuated_cap_chain_verifies() {
    let committed = load("attenuated_cap_v1");
    assert_eq!(
        committed.to_bytes().unwrap(),
        fixture_attenuated_cap().to_bytes().unwrap()
    );
    assert_eq!(committed.sig_chain().unwrap().len(), 2);
    committed
        .verify(&issuer(), &hlc(1))
        .expect("verify attenuated chain");
}

#[test]
fn appendix_b_expiring_cap_caveat_pass_and_fail() {
    let committed = load("expiring_cap_v1");
    assert_eq!(
        committed.to_bytes().unwrap(),
        fixture_expiring_cap().to_bytes().unwrap()
    );
    // PASS: now strictly before NotAfter(50).
    committed.verify(&issuer(), &hlc(10)).expect("caveat pass");
    // FAIL: now at/after the NotAfter bound -> typed CapExpired.
    assert_eq!(
        committed.verify(&issuer(), &hlc(100)).unwrap_err(),
        MnemeError::CapExpired
    );
}
