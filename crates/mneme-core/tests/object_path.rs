use std::path::Path;

use mneme_core::{MnemeError, decode_content_addressed_object_path, decode_hex32};

fn object_hex() -> &'static str {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

#[test]
fn content_addressed_object_path_accepts_canonical_layout() {
    let objects_dir = Path::new("/store/objects");
    let path = objects_dir
        .join("01")
        .join(format!("{}.cbor", object_hex()));

    let id = decode_content_addressed_object_path(objects_dir, &path).expect("canonical path");

    assert_eq!(id, decode_hex32(object_hex()).expect("fixture hex"));
}

#[test]
fn content_addressed_object_path_rejects_multibyte_filename_without_panic() {
    let objects_dir = Path::new("/store/objects");
    let bad_hex = format!("00{}\u{20AC}", "a".repeat(59));
    assert_eq!(bad_hex.len(), 64);
    assert_ne!(bad_hex.chars().count(), 64);
    let path = objects_dir.join("00").join(format!("{bad_hex}.cbor"));

    let err = decode_content_addressed_object_path(objects_dir, &path).unwrap_err();

    assert_eq!(err, MnemeError::SchemaDrift);
}

#[test]
fn content_addressed_object_path_rejects_non_canonical_layouts() {
    let objects_dir = Path::new("/store/objects");
    let id_hex = object_hex();

    for path in [
        objects_dir.join("ff").join(format!("{id_hex}.cbor")),
        objects_dir
            .join("01")
            .join("nested")
            .join(format!("{id_hex}.cbor")),
        objects_dir.join("01").join(id_hex),
        objects_dir.join("1").join(format!("{id_hex}.cbor")),
        objects_dir.join("01").join(format!("{}x.cbor", id_hex)),
    ] {
        let err = decode_content_addressed_object_path(objects_dir, &path).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift, "path={path:?}");
    }
}
