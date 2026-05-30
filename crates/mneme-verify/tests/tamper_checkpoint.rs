//! Checkpoint log / stored-root tamper cases (§17.2).

mod helpers;

use helpers::build_root_chain_fixture;
use mneme_core::MnemeError;
use mneme_crypto::KeyPair;
use mneme_root::StoredRoot;
use mneme_verify::verify_root;

macro_rules! ckpt_tamper {
    ($name:ident, |$s:ident| $body:stmt, $expected:expr) => {
        #[test]
        fn $name() {
            let fixture = build_root_chain_fixture();
            let mut root = fixture.root.clone();
            {
                let $s = &mut root;
                $body
            }
            let err =
                verify_root(&root, &fixture.trust, fixture.previous_root.as_ref()).unwrap_err();
            assert_eq!(err, $expected, "case {}", stringify!($name));
        }
    };
}

ckpt_tamper!(
    ckpt_dag_head_byte,
    |r| r.dag_head_root[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_key_index_byte,
    |r| r.key_index_root[15] ^= 0x02,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_semantic_commit_byte,
    |r| r.semantic_commit[7] ^= 0x04,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_hlc_max_byte,
    |r| r.hlc_max[0] ^= 0x08,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_prev_root_byte,
    |r| r.prev_root[31] ^= 0x10,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_signature_mid,
    |r| {
        if !r.signature.is_empty() {
            let mid = r.signature.len() / 2;
            r.signature[mid] ^= 0x20;
        }
    },
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_preimage_hash_byte,
    |r| r.preimage_hash[20] ^= 0x40,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_sequence_skip,
    |r| r.sequence = 1,
    MnemeError::RootInconsistent
);
ckpt_tamper!(
    ckpt_sequence_zero,
    |r| r.sequence = 0,
    MnemeError::RootInconsistent
);
ckpt_tamper!(
    ckpt_root_version_mismatch,
    |r| r.version = r.version.wrapping_add(1),
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_root_version_zero,
    |r| r.version = 0,
    MnemeError::RootSigInvalid
);
ckpt_tamper!(
    ckpt_root_version_unsupported,
    |r| r.version = 99,
    MnemeError::RootSigInvalid
);

#[test]
fn ckpt_verify_wrong_previous_checkpoint() {
    let fixture = build_root_chain_fixture();
    let bogus_prev = fixture.root.clone();
    let err = verify_root(&fixture.root, &fixture.trust, Some(&bogus_prev)).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn ckpt_sequence_regression_against_head() {
    let fixture = build_root_chain_fixture();
    let mut root = fixture.root.clone();
    root.sequence = fixture.previous_root.as_ref().expect("prev").sequence;
    let err = verify_root(&root, &fixture.trust, fixture.previous_root.as_ref()).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn ckpt_stored_root_sequence_byte_tamper_rejected() {
    let fixture = build_root_chain_fixture();
    let operator = KeyPair::from_seed([0x01; 32]);
    let stored = StoredRoot::assemble(
        fixture.root.dag_head_root,
        fixture.root.key_index_root,
        fixture.root.semantic_commit,
        fixture.root.hlc_max,
        fixture.root.prev_root,
        fixture.root.sequence,
        &operator,
    )
    .expect("assemble");
    let bytes = stored.to_bytes().expect("bytes");
    for i in [0usize, 1, 8, 16, 32, 64, 96, 128] {
        if i >= bytes.len() {
            continue;
        }
        let mut tampered = bytes.clone();
        tampered[i] ^= 0x01;
        match StoredRoot::from_bytes(&tampered) {
            Err(_) => {}
            Ok(parsed) => {
                let root = parsed.to_root();
                let err =
                    verify_root(&root, &fixture.trust, fixture.previous_root.as_ref()).unwrap_err();
                assert!(
                    matches!(
                        err,
                        MnemeError::RootSigInvalid | MnemeError::RootInconsistent
                    ),
                    "byte {i}: expected root rejection, got {err:?}"
                );
            }
        }
    }
}

#[test]
fn ckpt_checkpoint_sequence_regression() {
    let fixture = build_root_chain_fixture();
    let mut root = fixture.root.clone();
    if let Some(prev) = fixture.previous_root.as_ref() {
        root.sequence = prev.sequence;
    }
    let err = verify_root(&root, &fixture.trust, fixture.previous_root.as_ref()).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn ckpt_hlc_replay_older_than_trust() {
    let mut fixture = build_root_chain_fixture();
    fixture.root.hlc_max = [0u8; 14];
    fixture.trust.last_seen_hlc = Some([0xff; 14]);
    let err = verify_root(
        &fixture.root,
        &fixture.trust,
        fixture.previous_root.as_ref(),
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootReplayed);
}
