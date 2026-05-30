//! Appendix B items 1–2: object→id and MNEME-dCBOR edge-case vectors.

use mneme_core::MnemeError;
use mneme_core::dcbor::{Decoder, Encoder, assert_canonical};
use mneme_core::domain::hash_obj;
use mneme_core::object::{MemoryKind, ObjectRecord};
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("proof/vectors")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "run manually to refresh proof/vectors fixtures"]
fn dump_fixture_vectors_for_manifest() {
    for kind in MemoryKind::ALL {
        let rec = ObjectRecord::fixture(kind);
        let bytes = rec.to_canonical_bytes().unwrap();
        let id = rec.compute_id().unwrap();
        println!(
            "kind={} id={} cbor={}",
            kind.as_u8(),
            hex(id.as_bytes()),
            hex(&bytes)
        );
    }
}

#[test]
fn appendix_b_object_id_vectors_match_manifest() {
    let manifest_path = vectors_dir().join("object_id_manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest")).expect("json");

    for entry in manifest["vectors"].as_array().expect("vectors array") {
        let name = entry["name"].as_str().expect("name");
        let kind = entry["kind"].as_u64().expect("kind") as u8;
        let expected_id = entry["object_id_hex"].as_str().expect("object_id_hex");
        let cbor_file = vectors_dir().join(entry["cbor_file"].as_str().expect("cbor_file"));
        let bytes = fs::read(&cbor_file).expect("cbor file");

        let record = ObjectRecord::from_canonical_bytes(&bytes).expect("parse object");
        assert_eq!(record.kind, kind, "{name}: kind mismatch");
        let id = record.compute_id().expect("compute id");
        assert_eq!(
            hex(id.as_bytes()),
            expected_id,
            "{name}: object_id mismatch"
        );
        assert_eq!(
            hex(&hash_obj(&bytes)),
            expected_id,
            "{name}: hash_obj mismatch"
        );
    }
}

#[test]
fn appendix_b_dcbor_edge_cases_match_manifest() {
    let manifest_path = vectors_dir().join("dcbor_manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest")).expect("json");

    for entry in manifest["cases"].as_array().expect("cases") {
        let name = entry["name"].as_str().expect("name");
        let cbor_file = vectors_dir().join(entry["cbor_file"].as_str().expect("cbor_file"));
        let bytes = fs::read(&cbor_file).expect("cbor");
        let expect_ok = entry["expect_ok"].as_bool().expect("expect_ok");

        let mut dec = Decoder::new(&bytes);
        let parsed = dec.decode_any();
        if expect_ok {
            parsed.unwrap_or_else(|e| panic!("{name}: should parse: {e:?}"));
            let canonical =
                assert_canonical(&bytes).unwrap_or_else(|e| panic!("{name}: canonical: {e:?}"));
            assert_eq!(canonical, bytes, "{name}: non-canonical input accepted");
        } else {
            let err = parsed.expect_err("{name}: should reject");
            let expected = entry["expect_error"].as_str().expect("expect_error");
            let got = format!("{err:?}");
            assert!(
                got.contains(expected),
                "{name}: expected error containing {expected}, got {got}"
            );
        }
    }
}

#[test]
fn inv2_canonical_serialization_is_stable_across_reencode() {
    for kind in MemoryKind::ALL {
        let rec = ObjectRecord::fixture(kind);
        let once = rec.to_canonical_bytes().unwrap();
        let again = ObjectRecord::from_canonical_bytes(&once)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert_eq!(once, again, "kind {}", kind.as_u8());
    }
}

#[test]
fn inv7_rejects_non_canonical_map_key_order() {
    // Map {1:0, 0:1} — keys out of encoded order
    let bytes = [0xa2, 0x01, 0x00, 0x00, 0x01];
    let mut dec = Decoder::new(&bytes);
    assert_eq!(
        dec.decode_any().unwrap_err(),
        MnemeError::SerializationNonCanonical
    );
}

#[test]
fn inv7_rejects_duplicate_map_keys() {
    let mut enc = Encoder::new();
    enc.begin_map(2).unwrap();
    enc.encode_unsigned(0).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(0).unwrap();
    enc.encode_unsigned(2).unwrap();
    let bytes = enc.finish();
    let mut dec = Decoder::new(&bytes);
    assert_eq!(
        dec.decode_any().unwrap_err(),
        MnemeError::SerializationNonCanonical
    );
}

#[test]
fn inv7_rejects_unsorted_parent_ids() {
    let mut rec = ObjectRecord::fixture(MemoryKind::Semantic);
    rec.parent_ids = vec![[0x02; 32], [0x01; 32]];
    assert_eq!(
        rec.to_canonical_bytes().unwrap_err(),
        MnemeError::SchemaDrift
    );
}

#[test]
fn inv10_embedding_distance_is_integer_only() {
    use mneme_core::FixedPointEmbedding;
    let a = FixedPointEmbedding::new(2, -2, vec![1000, -250]).unwrap();
    let b = FixedPointEmbedding::new(2, -2, vec![1000, -250]).unwrap();
    assert_eq!(a.squared_l2_distance(&b).unwrap(), 0);
}
