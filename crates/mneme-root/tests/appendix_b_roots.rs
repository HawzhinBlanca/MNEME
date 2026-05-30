//! Appendix B item 4: signed `RootPreimage` + Ed25519 signature cross-impl vector.
//!
//! Fixtures are byte-pinned, single-implementation conformance vectors (same class as
//! `proof/vectors/objects` and `proof/vectors/smt`): the committed `.cbor` is the exact
//! canonical encoding produced by `StoredRoot`, re-derived and signature-verified here.

use mneme_core::RootPreimage;
use mneme_crypto::KeyPair;
use mneme_root::{ROOT_VERSION, StoredRoot};
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("proof/vectors/roots")
}

/// Deterministic operator key (matches `root_invariants` fixture seed).
fn operator() -> KeyPair {
    KeyPair::from_seed([0x42; 32])
}

/// Fixed inputs reused from the byte-pinned `pinned_root_preimage_hash_for_fixture_seed`
/// test so this vector and that invariant test stay mutually consistent.
fn fixture_stored_root() -> StoredRoot {
    StoredRoot::assemble(
        [0x11u8; 32],
        [0x22u8; 32],
        [0x33u8; 32],
        [0u8; 14],
        [0u8; 32],
        1,
        &operator(),
    )
    .expect("assemble fixture signed root")
}

#[test]
#[ignore = "run manually to (re)generate proof/vectors/roots fixtures"]
fn dump_signed_root_fixture() {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let stored = fixture_stored_root();
    let bytes = stored.to_bytes().expect("canonical bytes");
    fs::write(dir.join("signed_root_v1.cbor"), &bytes).expect("write cbor");
    eprintln!("signed_root_v1.cbor len={}", bytes.len());
    eprintln!("preimage_hash={}", hex::encode(stored.preimage_hash));
    eprintln!(
        "operator_pubkey={}",
        hex::encode(operator().public_key_bytes())
    );
    eprintln!("signature={}", hex::encode(&stored.signature));
}

#[test]
fn appendix_b_signed_root_vector_round_trips_and_verifies() {
    let bytes = fs::read(vectors_dir().join("signed_root_v1.cbor"))
        .expect("committed signed_root_v1.cbor present");

    // 1. Committed bytes decode to the same StoredRoot we re-derive from fixed inputs.
    let decoded = StoredRoot::from_bytes(&bytes).expect("decode committed bytes");
    let rebuilt = fixture_stored_root();
    assert_eq!(
        decoded, rebuilt,
        "committed root bytes diverged from generator"
    );

    // 2. Re-encoding is byte-identical (canonical, INV-10).
    assert_eq!(
        decoded.to_bytes().expect("re-encode"),
        bytes,
        "non-canonical committed encoding"
    );

    // 3. Preimage hash matches the §5.7 domain-tag layout pin.
    let expected_preimage = RootPreimage {
        version: ROOT_VERSION,
        dag_head_root: [0x11u8; 32],
        key_index_root: [0x22u8; 32],
        semantic_commit: [0x33u8; 32],
        hlc_max: [0u8; 14],
        prev_root: [0u8; 32],
    };
    assert_eq!(decoded.preimage_hash, expected_preimage.hash());
    assert_eq!(
        hex::encode(decoded.preimage_hash),
        "9194a7f3d98cf4aa8e3f3094bc886e5ab71bee9097b467f42a57bbe52509aa69"
    );

    // 4. Ed25519 signature verifies under the pinned operator key.
    decoded
        .verify(&operator().verifying_key())
        .expect("signature verifies");

    // 5. Fault injection: a flipped signature byte fails closed.
    let mut tampered = decoded.clone();
    tampered.signature[0] ^= 0xff;
    assert!(
        tampered.verify(&operator().verifying_key()).is_err(),
        "tampered signature must not verify"
    );
}
