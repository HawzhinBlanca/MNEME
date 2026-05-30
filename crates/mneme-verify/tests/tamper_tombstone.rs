//! Tombstone / non-membership conflicting_leaf tamper cases (§17.2).

mod helpers;

use helpers::{build_valid_recall, theme_key};
use mneme_core::MnemeError;
use mneme_smt::{NonMembershipProof, SparseMerkleTree, TOMBSTONE};

fn tombstone_non_membership() -> NonMembershipProof {
    let mut fixture = build_valid_recall();
    let key = theme_key("tamper", "key").hash();
    fixture.key_index.tombstone(key);
    fixture
        .key_index
        .prove_non_membership(key)
        .expect("tombstone proof")
}

macro_rules! nm_tamper {
    ($name:ident, |$p:ident| $body:stmt, $expected:expr) => {
        #[test]
        fn $name() {
            let mut proof = tombstone_non_membership();
            {
                let $p = &mut proof;
                $body
            }
            let err = SparseMerkleTree::verify_non_membership(&proof).unwrap_err();
            assert_eq!(err, $expected, "case {}", stringify!($name));
        }
    };
}

nm_tamper!(
    tomb_conflicting_key_byte_0,
    |p| {
        if let Some((k, v)) = p.conflicting_leaf.as_mut() {
            k[0] ^= 0x01;
            *v = TOMBSTONE;
        }
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_conflicting_key_byte_31,
    |p| {
        if let Some((k, v)) = p.conflicting_leaf.as_mut() {
            k[31] ^= 0x80;
            *v = TOMBSTONE;
        }
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_conflicting_value_not_tombstone,
    |p| {
        if let Some((k, v)) = p.conflicting_leaf.as_mut() {
            *v = [0xab; 32];
            *k = p.key;
        }
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_conflicting_key_mismatch,
    |p| {
        p.conflicting_leaf = Some(([0xee; 32], TOMBSTONE));
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_missing_conflicting_when_tombstone,
    |p| {
        p.conflicting_leaf = None;
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_conflicting_live_value,
    |p| {
        p.conflicting_leaf = Some((p.key, [0xcd; 32]));
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_conflicting_value_byte_flip,
    |p| {
        if let Some((k, v)) = p.conflicting_leaf.as_mut() {
            v[0] ^= 0x01;
            *k = p.key;
        }
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_conflicting_tombstone_wrong_key_hash,
    |p| {
        p.conflicting_leaf = Some((p.key, TOMBSTONE));
        p.key[0] ^= 0x01;
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_path_depth_0,
    |p| {
        if !p.path.is_empty() {
            p.path[0][0] ^= 0xff;
        }
    },
    MnemeError::IndexPathInvalid
);
nm_tamper!(
    tomb_path_depth_255,
    |p| {
        if p.path.len() > 255 {
            p.path[255][0] ^= 0xff;
        }
    },
    MnemeError::IndexPathInvalid
);
