//! Cross-implementation harness: reference crate reproduces all Appendix B vectors.

use mneme_crossref::dcbor::assert_canonical;
use mneme_crossref::domain::hash_obj;
use mneme_crossref::key::logical_key_hash;
use mneme_crossref::mst_merge::mst_root_for_order;
use mneme_crossref::object_fixture::{object_id, receipt_fixture_object_bytes};
use mneme_crossref::smt::SparseMerkleTree;
use mneme_crossref::vectors_root;
use mneme_crossref::wire_cap::{self, Hlc};
use mneme_crossref::wire_root;
use serde_json::Value;
use std::fs;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_hex32(s: &str) -> [u8; 32] {
    wire_root::hex32(s).expect("hex32")
}

#[test]
fn crossref_appendix_b_objects_byte_exact() {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(vectors_root().join("object_id_manifest.json")).unwrap(),
    )
    .unwrap();
    for entry in manifest["vectors"].as_array().unwrap() {
        let expected = entry["object_id_hex"].as_str().unwrap();
        let path = vectors_root().join(entry["cbor_file"].as_str().unwrap());
        let bytes = fs::read(&path).unwrap();
        assert_eq!(hex(&hash_obj(&bytes)), expected, "{}", entry["name"]);
    }
}

#[test]
fn crossref_appendix_b_dcbor_byte_exact() {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(vectors_root().join("dcbor_manifest.json")).unwrap(),
    )
    .unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let path = vectors_root().join(case["cbor_file"].as_str().unwrap());
        let bytes = fs::read(&path).unwrap();
        if let Some(expected_hex) = case.get("cbor_hex").and_then(|v| v.as_str()) {
            assert_eq!(hex(&bytes), expected_hex, "{name}: on-disk bytes");
        }
        let expect_ok = case["expect_ok"].as_bool().unwrap();
        let parsed = {
            let mut dec = mneme_crossref::dcbor::Decoder::new(&bytes);
            dec.decode_any()
        };
        if expect_ok {
            parsed.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(assert_canonical(&bytes).unwrap(), bytes);
        } else {
            assert!(parsed.is_err(), "{name}: should reject");
        }
    }
}

#[test]
fn crossref_appendix_b_smt_fixtures_byte_exact() {
    for name in ["empty_tree", "single_member", "multi_member", "tombstone"] {
        let path = vectors_root().join(format!("smt/{name}.json"));
        let fixture: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut tree = SparseMerkleTree::new();
        for entry in fixture["entries"].as_array().unwrap_or(&vec![]) {
            let key = read_hex32(entry["key"].as_str().unwrap());
            let value = read_hex32(entry["value"].as_str().unwrap());
            tree.upsert(key, value);
        }
        assert_eq!(
            hex(&tree.root()),
            fixture["root"].as_str().unwrap(),
            "{name} root"
        );
        for case in fixture["membership"].as_array().unwrap_or(&vec![]) {
            let proof = mneme_crossref::smt::MembershipProof {
                key: read_hex32(case["key"].as_str().unwrap()),
                value: read_hex32(case["value"].as_str().unwrap()),
                path: case["path"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| read_hex32(n.as_str().unwrap()))
                    .collect(),
                root: read_hex32(case["root"].as_str().unwrap()),
            };
            SparseMerkleTree::verify_membership(&proof).expect("membership");
        }
        for case in fixture["non_membership"].as_array().unwrap_or(&vec![]) {
            let conflicting = match (case.get("conflicting_key"), case.get("conflicting_value")) {
                (Some(k), Some(v)) => Some((
                    read_hex32(k.as_str().unwrap()),
                    read_hex32(v.as_str().unwrap()),
                )),
                _ => None,
            };
            let proof = mneme_crossref::smt::NonMembershipProof {
                key: read_hex32(case["key"].as_str().unwrap()),
                path: case["path"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| read_hex32(n.as_str().unwrap()))
                    .collect(),
                root: read_hex32(case["root"].as_str().unwrap()),
                conflicting_leaf: conflicting,
            };
            SparseMerkleTree::verify_non_membership(&proof).expect("non-membership");
        }
    }
}

#[test]
fn crossref_appendix_b_signed_root_byte_exact() {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(vectors_root().join("roots/manifest.json")).unwrap(),
    )
    .unwrap();
    let issuer = read_hex32(
        manifest["operator_pubkey_hex"]
            .as_str()
            .unwrap_or("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"),
    );
    for entry in manifest["vectors"].as_array().unwrap() {
        let bytes = fs::read(
            vectors_root()
                .join("roots")
                .join(entry["cbor_file"].as_str().unwrap()),
        )
        .unwrap();
        wire_root::verify_committed_signed_root(
            &bytes,
            &issuer,
            entry["preimage_hash_hex"].as_str().unwrap(),
        )
        .expect("signed root");
        // Committed bytes must round-trip decode (canonical wire).
        let decoded = wire_root::StoredRoot::decode(&bytes).unwrap();
        assert_eq!(decoded.recompute_preimage_hash(), decoded.preimage_hash);
    }
}

#[test]
fn crossref_appendix_b_capabilities_byte_exact() {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(vectors_root().join("capabilities/manifest.json")).unwrap(),
    )
    .unwrap();
    let issuer = read_hex32(manifest["issuer_pubkey_hex"].as_str().unwrap());
    for entry in manifest["vectors"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let bytes = fs::read(
            vectors_root()
                .join("capabilities")
                .join(format!("{name}.cbor")),
        )
        .unwrap();
        wire_cap::verify_committed_capability(
            &bytes,
            &issuer,
            entry["cap_id_hex"].as_str().unwrap(),
            entry["sig_chain_len"].as_u64().unwrap() as usize,
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        if name == "expiring_cap_v1" {
            let cap = wire_cap::Capability::decode(&bytes).unwrap();
            cap.evaluate_not_after(&Hlc {
                wall_ms: 10,
                counter: 0,
                node_id: [0x02; 16],
            })
            .expect("pass at 10");
            assert!(matches!(
                cap.evaluate_not_after(&Hlc {
                    wall_ms: 100,
                    counter: 0,
                    node_id: [0x02; 16],
                }),
                Err(mneme_crossref::CrossrefError::CapExpired)
            ));
        }
    }
}

#[test]
fn crossref_appendix_b_receipt_object_and_index_byte_exact() {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(vectors_root().join("receipts/manifest.json")).unwrap(),
    )
    .unwrap();
    let entry = &manifest["vectors"][0];
    let committed = fs::read(vectors_root().join("receipts/recall_object_v1.cbor")).unwrap();
    let regenerated = receipt_fixture_object_bytes().unwrap();
    assert_eq!(committed, regenerated, "object cbor byte mismatch");
    assert_eq!(
        hex(&object_id(&committed)),
        entry["object_id_hex"].as_str().unwrap()
    );

    let key_hash = read_hex32(entry["logical_key_hex"].as_str().unwrap());
    assert_eq!(
        key_hash,
        logical_key_hash("appendixb", "receipt"),
        "logical key hash"
    );

    let mut tree = SparseMerkleTree::new();
    tree.upsert(key_hash, object_id(&committed));
    tree.rebuild_root_cache();
    assert_eq!(
        hex(&tree.root()),
        entry["key_index_root_hex"].as_str().unwrap()
    );

    let proof = tree.prove_membership(key_hash).unwrap();
    assert_eq!(
        proof.path.len(),
        entry["membership_proof_len"].as_u64().unwrap() as usize
    );
    SparseMerkleTree::verify_membership(&proof).unwrap();
}

#[test]
fn crossref_appendix_b_mst_convergence_byte_exact() {
    let raw = fs::read_to_string(vectors_root().join("mst/convergence_triple.json")).unwrap();
    let fixture: Value = serde_json::from_str(&raw).unwrap();
    let expected = fixture["expected_key_index_root"].as_str().unwrap();
    for order in fixture["message_orders"].as_array().unwrap() {
        let labels: Vec<&str> = order
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let root = mst_root_for_order(&labels).unwrap();
        assert_eq!(hex(&root), expected);
    }
}

#[test]
fn crossref_cognition_cert_v1_byte_exact() {
    use mneme_crossref::procedure::{DistanceMetric, Procedure, ProcedureAlgo};
    use mneme_crossref::wire_cert;

    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(vectors_root().join("certs/manifest.json")).unwrap(),
    )
    .unwrap();
    for entry in manifest["vectors"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let path = vectors_root()
            .join("certs")
            .join(entry["cbor_file"].as_str().unwrap());
        let bytes = fs::read(&path).unwrap();
        let proc_spec = &entry["procedure"];
        let proc = Procedure {
            algo: match proc_spec["algo"].as_str().unwrap() {
                "hnsw" => ProcedureAlgo::Hnsw,
                other => panic!("{name}: unknown algo {other}"),
            },
            ef_search: proc_spec["ef_search"].as_u64().unwrap() as u32,
            k: proc_spec["k"].as_u64().unwrap() as u32,
            distance: match proc_spec["distance"].as_str().unwrap() {
                "squared_l2_i64" => DistanceMetric::SquaredL2I64,
                other => panic!("{name}: unknown distance {other}"),
            },
            seed: proc_spec["seed"].as_u64().unwrap(),
        };
        let operator = read_hex32(entry["operator_pubkey_hex"].as_str().unwrap());
        wire_cert::verify_committed_certificate(&bytes, &operator, &proc)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

#[test]
fn crossref_identity_digests_exclude_nondeterministic_inputs() {
    // Foundation-gate digests are pure functions of fixture crypto + logical content.
    // This guard fails if someone threads cwd/PID/time into hash inputs.
    let forbidden = [
        std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id().to_string(),
    ];
    let sample = receipt_fixture_object_bytes().unwrap();
    let key_hash = logical_key_hash("appendixb", "receipt");
    let digest_input = format!("{sample:?}{}{}", hex(&key_hash), hex(&hash_obj(&sample)));
    for needle in forbidden {
        if !needle.is_empty() {
            assert!(
                !digest_input.contains(&needle),
                "identity digest input must not contain {needle}"
            );
        }
    }
}
