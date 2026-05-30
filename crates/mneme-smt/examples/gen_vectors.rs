//! Generate Appendix B SMT fixtures (run once, commit output under proof/vectors/smt/).

use mneme_smt::{SparseMerkleTree, TOMBSTONE, TREE_DEPTH};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn key(bytes: u8) -> [u8; 32] {
    [bytes; 32]
}

#[derive(Serialize)]
struct SmtFixture {
    name: String,
    entries: Vec<SmtEntry>,
    root: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    membership: Vec<MembershipCase>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    non_membership: Vec<NonMembershipCase>,
}

#[derive(Serialize)]
struct SmtEntry {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct MembershipCase {
    key: String,
    value: String,
    path: Vec<String>,
    root: String,
    leaf_index: usize,
}

#[derive(Serialize)]
struct NonMembershipCase {
    key: String,
    path: Vec<String>,
    root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicting_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicting_value: Option<String>,
}

fn write_fixture(dir: &std::path::Path, fixture: &SmtFixture) {
    let path = dir.join(format!("{}.json", fixture.name));
    let json = serde_json::to_string_pretty(fixture).expect("json");
    fs::write(&path, json).expect("write");
    eprintln!("wrote {}", path.display());
}

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proof/vectors/smt");
    fs::create_dir_all(&dir).expect("mkdir");

    // empty tree
    let empty = SparseMerkleTree::new();
    let absent = key(0x99);
    let nm_empty = empty.prove_non_membership(absent).expect("nm");
    assert_eq!(nm_empty.path.len(), TREE_DEPTH);
    write_fixture(
        &dir,
        &SmtFixture {
            name: "empty_tree".into(),
            entries: vec![],
            root: hex32(&empty.root()),
            membership: vec![],
            non_membership: vec![NonMembershipCase {
                key: hex32(&absent),
                path: nm_empty.path.iter().map(hex32).collect(),
                root: hex32(&nm_empty.root),
                conflicting_key: None,
                conflicting_value: None,
            }],
        },
    );

    // single member
    let k1 = key(0x01);
    let v1 = key(0x02);
    let mut single = SparseMerkleTree::new();
    single.upsert(k1, v1);
    single.rebuild_root_cache();
    let m1 = single.prove_membership(k1).expect("m");
    let absent2 = key(0xbb);
    let nm1 = single.prove_non_membership(absent2).expect("nm");
    write_fixture(
        &dir,
        &SmtFixture {
            name: "single_member".into(),
            entries: vec![SmtEntry {
                key: hex32(&k1),
                value: hex32(&v1),
            }],
            root: hex32(&single.root()),
            membership: vec![MembershipCase {
                key: hex32(&k1),
                value: hex32(&v1),
                path: m1.path.iter().map(hex32).collect(),
                root: hex32(&m1.root),
                leaf_index: m1.leaf_index,
            }],
            non_membership: vec![NonMembershipCase {
                key: hex32(&absent2),
                path: nm1.path.iter().map(hex32).collect(),
                root: hex32(&nm1.root),
                conflicting_key: None,
                conflicting_value: None,
            }],
        },
    );

    // multi member
    let k_a = key(0x0a);
    let v_a = key(0x11);
    let k_b = key(0x55);
    let v_b = key(0x66);
    let k_c = [0x80u8; 32];
    let v_c = key(0x77);
    let mut multi = SparseMerkleTree::new();
    multi.upsert(k_a, v_a);
    multi.upsert(k_b, v_b);
    multi.upsert(k_c, v_c);
    multi.rebuild_root_cache();
    let absent3 = key(0xbb);
    write_fixture(
        &dir,
        &SmtFixture {
            name: "multi_member".into(),
            entries: vec![
                SmtEntry {
                    key: hex32(&k_a),
                    value: hex32(&v_a),
                },
                SmtEntry {
                    key: hex32(&k_b),
                    value: hex32(&v_b),
                },
                SmtEntry {
                    key: hex32(&k_c),
                    value: hex32(&v_c),
                },
            ],
            root: hex32(&multi.root()),
            membership: [k_a, k_b, k_c]
                .into_iter()
                .map(|k| {
                    let p = multi.prove_membership(k).expect("m");
                    MembershipCase {
                        key: hex32(&k),
                        value: hex32(&p.value),
                        path: p.path.iter().map(hex32).collect(),
                        root: hex32(&p.root),
                        leaf_index: p.leaf_index,
                    }
                })
                .collect(),
            non_membership: {
                let p = multi.prove_non_membership(absent3).expect("nm");
                vec![NonMembershipCase {
                    key: hex32(&absent3),
                    path: p.path.iter().map(hex32).collect(),
                    root: hex32(&p.root),
                    conflicting_key: None,
                    conflicting_value: None,
                }]
            },
        },
    );

    // tombstone
    let k_t = key(0x0d);
    let v_t = key(0x0e);
    let mut tomb = SparseMerkleTree::new();
    tomb.upsert(k_t, v_t);
    tomb.tombstone(k_t);
    tomb.rebuild_root_cache();
    let nm_t = tomb.prove_non_membership(k_t).expect("nm tomb");
    let (ck, cv) = nm_t.conflicting_leaf.expect("conflict");
    assert_eq!(cv, TOMBSTONE);
    write_fixture(
        &dir,
        &SmtFixture {
            name: "tombstone".into(),
            entries: vec![SmtEntry {
                key: hex32(&k_t),
                value: hex32(&TOMBSTONE),
            }],
            root: hex32(&tomb.root()),
            membership: vec![],
            non_membership: vec![NonMembershipCase {
                key: hex32(&k_t),
                path: nm_t.path.iter().map(hex32).collect(),
                root: hex32(&nm_t.root),
                conflicting_key: Some(hex32(&ck)),
                conflicting_value: Some(hex32(&cv)),
            }],
        },
    );
}
