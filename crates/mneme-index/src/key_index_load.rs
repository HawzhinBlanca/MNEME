//! Reconstruct the key-index SMT from the on-disk sidecar + append-only journal.
//!
//! This reconstruction is **not** trust-critical: the verifier compares the
//! resulting SMT root against the operator-signed `key_index_root`, so a faulty
//! or tampered reconstruction fails closed (`RootInconsistent`) instead of
//! admitting forged state. It lives here (the key-index owner) to keep the
//! verifier TCB minimal (§17.6) and to avoid duplicating the sidecar/journal
//! format across crates. Error types are preserved verbatim for the tamper suite.

use mneme_core::{LogicalKey, MnemeError, decode_hex32};
use mneme_smt::SparseMerkleTree;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(serde::Deserialize)]
struct KeyIndexSidecar {
    entries: BTreeMap<String, String>,
    tombstones: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ObjectKeysSidecar {
    entries: BTreeMap<String, LogicalKeySidecarEntry>,
}

#[derive(serde::Deserialize)]
struct LogicalKeySidecarEntry {
    namespace: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct ObjectKeysJournalEntry {
    id: String,
    namespace: String,
    name: String,
}

fn push_tombstone_if_absent(tombstones: &mut Vec<String>, key: String) {
    for tombstone in &*tombstones {
        if tombstone == &key {
            return;
        }
    }
    tombstones.push(key);
}

fn remove_tombstone(tombstones: &mut Vec<String>, key: &str) {
    let mut retained_tombstones = Vec::new();
    for tombstone in &*tombstones {
        if tombstone != key {
            retained_tombstones.push(tombstone.clone());
        }
    }
    *tombstones = retained_tombstones;
}

fn remove_key_index_entry(entries: &mut BTreeMap<String, String>, key: &str) {
    let mut retained_entries = BTreeMap::new();
    for (entry_key, object_id) in &*entries {
        if entry_key != key {
            retained_entries.insert(entry_key.clone(), object_id.clone());
        }
    }
    *entries = retained_entries;
}

fn empty_key_index_sidecar() -> KeyIndexSidecar {
    KeyIndexSidecar {
        entries: BTreeMap::new(),
        tombstones: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyIndexLoadFailure {
    ObjectKeysSnapshot,
    ObjectKeysJournalLine,
    ObjectKeysSnapshotObjectIdHex,
    ObjectKeysJournalObjectIdHex,
    KeyIndexSnapshot,
    KeyIndexJournalLine,
    KeyIndexJournalKeyHex,
    KeyIndexJournalObjectHex,
    KeyIndexSnapshotKeyHex,
    KeyIndexSnapshotObjectHex,
    KeyIndexTombstoneHex,
}

fn key_index_load_failure_to_mneme(failure: KeyIndexLoadFailure) -> MnemeError {
    match failure {
        KeyIndexLoadFailure::ObjectKeysSnapshot
        | KeyIndexLoadFailure::ObjectKeysJournalLine
        | KeyIndexLoadFailure::ObjectKeysSnapshotObjectIdHex
        | KeyIndexLoadFailure::ObjectKeysJournalObjectIdHex
        | KeyIndexLoadFailure::KeyIndexJournalKeyHex
        | KeyIndexLoadFailure::KeyIndexJournalObjectHex
        | KeyIndexLoadFailure::KeyIndexSnapshotKeyHex
        | KeyIndexLoadFailure::KeyIndexSnapshotObjectHex
        | KeyIndexLoadFailure::KeyIndexTombstoneHex => MnemeError::SchemaDrift,
        KeyIndexLoadFailure::KeyIndexSnapshot | KeyIndexLoadFailure::KeyIndexJournalLine => {
            MnemeError::SerializationNonCanonical
        }
    }
}

fn key_index_load_json_error(failure: KeyIndexLoadFailure) -> MnemeError {
    key_index_load_failure_to_mneme(failure)
}

fn parse_key_index_load_json<T: serde::de::DeserializeOwned>(
    input: &str,
    failure: KeyIndexLoadFailure,
) -> Result<T, MnemeError> {
    serde_json::from_str(input).map_err(|_| key_index_load_json_error(failure))
}

fn parse_key_index_load_hex32(
    input: &str,
    failure: KeyIndexLoadFailure,
) -> Result<[u8; 32], MnemeError> {
    decode_hex32(input).map_err(|_| key_index_load_failure_to_mneme(failure))
}

fn read_optional_to_string(path: &Path) -> Result<Option<String>, MnemeError> {
    crate::store_file::read_optional_to_string(path)
}

fn key_index_load_journal_line_is_blank(line: &str) -> bool {
    line.trim().is_empty()
}

/// Replay the `meta/object_keys.json` snapshot + `meta/object_keys.journal` into
/// the reverse index (`object_id → LogicalKey`), mirroring `Store`'s loader.
///
/// This sidecar carries `object_id → (namespace, name)` plaintext that the store
/// trusts (e.g. as AEAD AAD on decrypt) but which is **not** recoverable from the
/// signed key-index (the SMT is keyed by `LogicalKey.hash()`). The verifier
/// cross-checks the decoded entries against already-verified state (§7, B-1), so
/// this reconstruction is not itself trust-critical: any parse/hex fault fails
/// closed with `SchemaDrift`, mirroring `Store::open`. It lives here (alongside
/// `load_key_index_tree`) to keep the verifier TCB minimal (§17.6). The journal is
/// applied after the snapshot (last write wins per object id), matching the store.
pub fn load_object_keys(store: &Path) -> Result<Vec<([u8; 32], LogicalKey)>, MnemeError> {
    let mut merged: BTreeMap<[u8; 32], LogicalKey> = BTreeMap::new();
    let snapshot = store.join("meta/object_keys.json");
    if let Some(data) = read_optional_to_string(&snapshot)? {
        let sidecar: ObjectKeysSidecar =
            parse_key_index_load_json(&data, KeyIndexLoadFailure::ObjectKeysSnapshot)?;
        for (id_hex, entry) in sidecar.entries {
            merged.insert(
                parse_key_index_load_hex32(
                    &id_hex,
                    KeyIndexLoadFailure::ObjectKeysSnapshotObjectIdHex,
                )?,
                LogicalKey {
                    namespace: entry.namespace,
                    name: entry.name,
                },
            );
        }
    }
    let journal = store.join("meta/object_keys.journal");
    if let Some(data) = read_optional_to_string(&journal)? {
        for line in data.lines() {
            if key_index_load_journal_line_is_blank(line) {
                continue;
            }
            let entry: ObjectKeysJournalEntry =
                parse_key_index_load_json(line, KeyIndexLoadFailure::ObjectKeysJournalLine)?;
            merged.insert(
                parse_key_index_load_hex32(
                    &entry.id,
                    KeyIndexLoadFailure::ObjectKeysJournalObjectIdHex,
                )?,
                LogicalKey {
                    namespace: entry.namespace,
                    name: entry.name,
                },
            );
        }
    }
    Ok(merged.into_iter().collect())
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum KeyIndexJournalEntry {
    Upsert { key: String, object: String },
    Tombstone { key: String },
}

/// Replay `meta/key_index.json` + `meta/key_index.journal` under `store` into an SMT.
pub fn load_key_index_tree(store: &Path) -> Result<SparseMerkleTree, MnemeError> {
    let sidecar_path = store.join("meta/key_index.json");
    let mut sidecar = if let Some(data) = read_optional_to_string(&sidecar_path)? {
        parse_key_index_load_json(&data, KeyIndexLoadFailure::KeyIndexSnapshot)?
    } else {
        empty_key_index_sidecar()
    };
    let journal_path = store.join("meta/key_index.journal");
    if let Some(data) = read_optional_to_string(&journal_path)? {
        for line in data.lines() {
            if key_index_load_journal_line_is_blank(line) {
                continue;
            }
            match parse_key_index_load_json(line, KeyIndexLoadFailure::KeyIndexJournalLine)? {
                KeyIndexJournalEntry::Upsert { key, object } => {
                    parse_key_index_load_hex32(&key, KeyIndexLoadFailure::KeyIndexJournalKeyHex)?;
                    parse_key_index_load_hex32(
                        &object,
                        KeyIndexLoadFailure::KeyIndexJournalObjectHex,
                    )?;
                    remove_tombstone(&mut sidecar.tombstones, &key);
                    sidecar.entries.insert(key, object);
                }
                KeyIndexJournalEntry::Tombstone { key } => {
                    parse_key_index_load_hex32(&key, KeyIndexLoadFailure::KeyIndexJournalKeyHex)?;
                    remove_key_index_entry(&mut sidecar.entries, &key);
                    push_tombstone_if_absent(&mut sidecar.tombstones, key);
                }
            }
        }
    }
    let mut tree = SparseMerkleTree::new();
    for (k, v) in sidecar.entries {
        tree.upsert(
            parse_key_index_load_hex32(&k, KeyIndexLoadFailure::KeyIndexSnapshotKeyHex)?,
            parse_key_index_load_hex32(&v, KeyIndexLoadFailure::KeyIndexSnapshotObjectHex)?,
        );
    }
    for t in sidecar.tombstones {
        tree.tombstone(parse_key_index_load_hex32(
            &t,
            KeyIndexLoadFailure::KeyIndexTombstoneHex,
        )?);
    }
    tree.rebuild_root_cache();
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_index_load_production_source() -> &'static str {
        include_str!("key_index_load.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("key_index_load.rs should keep tests after production code")
    }

    fn key_index_load_replay_source() -> &'static str {
        let production = key_index_load_production_source();
        let start = production
            .find("pub fn load_object_keys(")
            .expect("key-index load replay functions should stay in production source");
        &production[start..]
    }

    #[test]
    fn key_index_load_failures_are_classified_not_error_collapsed() {
        let production = key_index_load_production_source();

        for forbidden in [
            "map_err(|_| MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SerializationNonCanonical)",
        ] {
            assert!(
                !production.contains(forbidden),
                "key-index load production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum KeyIndexLoadFailure",
            "fn key_index_load_failure_to_mneme(",
            "fn key_index_load_json_error(",
            "fn parse_key_index_load_json<",
            "KeyIndexLoadFailure::ObjectKeysSnapshot",
            "KeyIndexLoadFailure::ObjectKeysJournalLine",
            "KeyIndexLoadFailure::KeyIndexSnapshot",
            "KeyIndexLoadFailure::KeyIndexJournalLine",
        ] {
            assert!(
                production.contains(required),
                "key-index load production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn key_index_load_hex_decoders_are_classified_not_core_propagated() {
        let production = key_index_load_production_source();
        let replay = key_index_load_replay_source();

        assert!(
            !replay.contains("decode_hex32("),
            "key-index load replay code should route hex decoding through loader classifiers"
        );

        for required in [
            "fn parse_key_index_load_hex32(",
            "KeyIndexLoadFailure::ObjectKeysSnapshotObjectIdHex",
            "KeyIndexLoadFailure::ObjectKeysJournalObjectIdHex",
            "KeyIndexLoadFailure::KeyIndexJournalKeyHex",
            "KeyIndexLoadFailure::KeyIndexJournalObjectHex",
            "KeyIndexLoadFailure::KeyIndexSnapshotKeyHex",
            "KeyIndexLoadFailure::KeyIndexSnapshotObjectHex",
            "KeyIndexLoadFailure::KeyIndexTombstoneHex",
        ] {
            assert!(
                production.contains(required),
                "key-index load production code is missing hex classifier marker {required}"
            );
        }
    }

    #[test]
    fn key_index_load_replay_source_avoids_collection_remove_and_pop_shortcuts() {
        let production = key_index_load_production_source();

        for method in ["remove", "pop"] {
            let forbidden = format!(".{method}(");
            assert!(
                !production.contains(&forbidden),
                "key-index load production code must avoid collection deletion shortcut {forbidden}"
            );
        }
    }

    #[test]
    fn key_index_load_replay_source_names_blank_journal_line_checks() {
        let production = key_index_load_production_source();

        assert!(
            production.contains("fn key_index_load_journal_line_is_blank("),
            "key-index load production code should name its journal blank-line predicate"
        );
        let forbidden = ["if line", ".trim()", ".is_empty()"].concat();
        assert!(
            !production.contains(&forbidden),
            "key-index load replay loops should call the named blank-line predicate"
        );
    }

    #[test]
    fn key_index_load_reads_sidecars_through_store_file_custody() {
        let production = key_index_load_production_source();

        assert!(
            production.contains("crate::store_file::read_optional_to_string(path)"),
            "key-index load optional reads should delegate to the single-link store-file reader"
        );
        assert!(
            !production.contains("fs::read_to_string("),
            "key-index load production code must not read store sidecars through path-following fs::read_to_string"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_index_load_rejects_symlinked_snapshot_without_following_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let meta = dir.path().join("meta");
        std::fs::create_dir_all(&meta).expect("meta");
        let external = dir.path().join("external-key-index.json");
        let snapshot = meta.join("key_index.json");
        std::fs::write(&external, r#"{"entries":{},"tombstones":[]}"#).expect("external snapshot");
        std::os::unix::fs::symlink(&external, &snapshot).expect("snapshot symlink");

        let err = load_key_index_tree(dir.path()).expect_err("symlinked snapshot rejected");

        assert!(matches!(err, MnemeError::IoFailed { .. }));
        assert_eq!(
            std::fs::read_to_string(&external).expect("external target"),
            r#"{"entries":{},"tombstones":[]}"#,
            "loader must not mutate the symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn object_key_load_rejects_symlinked_journal_without_following_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let meta = dir.path().join("meta");
        std::fs::create_dir_all(&meta).expect("meta");
        let external = dir.path().join("external-object-keys.journal");
        let journal = meta.join("object_keys.journal");
        std::fs::write(&external, b"").expect("external journal");
        std::os::unix::fs::symlink(&external, &journal).expect("journal symlink");

        let err = load_object_keys(dir.path()).expect_err("symlinked journal rejected");

        assert!(matches!(err, MnemeError::IoFailed { .. }));
        assert_eq!(
            std::fs::read(&external).expect("external target"),
            b"",
            "loader must not mutate the symlink target"
        );
    }

    #[test]
    fn key_index_load_failure_classifier_preserves_public_errors() {
        for failure in [
            KeyIndexLoadFailure::ObjectKeysSnapshot,
            KeyIndexLoadFailure::ObjectKeysJournalLine,
            KeyIndexLoadFailure::ObjectKeysSnapshotObjectIdHex,
            KeyIndexLoadFailure::ObjectKeysJournalObjectIdHex,
            KeyIndexLoadFailure::KeyIndexJournalKeyHex,
            KeyIndexLoadFailure::KeyIndexJournalObjectHex,
            KeyIndexLoadFailure::KeyIndexSnapshotKeyHex,
            KeyIndexLoadFailure::KeyIndexSnapshotObjectHex,
            KeyIndexLoadFailure::KeyIndexTombstoneHex,
        ] {
            assert_eq!(
                key_index_load_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }

        for failure in [
            KeyIndexLoadFailure::KeyIndexSnapshot,
            KeyIndexLoadFailure::KeyIndexJournalLine,
        ] {
            assert_eq!(
                key_index_load_failure_to_mneme(failure),
                MnemeError::SerializationNonCanonical
            );
            assert_eq!(
                key_index_load_json_error(failure),
                MnemeError::SerializationNonCanonical
            );
        }
    }

    #[test]
    fn key_index_load_hex_parser_preserves_public_errors() {
        assert_eq!(
            parse_key_index_load_hex32(
                "not-hex",
                KeyIndexLoadFailure::ObjectKeysSnapshotObjectIdHex
            )
            .err(),
            Some(MnemeError::SchemaDrift)
        );
        assert_eq!(
            parse_key_index_load_hex32("not-hex", KeyIndexLoadFailure::KeyIndexSnapshotKeyHex)
                .err(),
            Some(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn key_index_load_json_parser_preserves_object_keys_schema_drift() {
        assert_eq!(
            parse_key_index_load_json::<ObjectKeysSidecar>(
                "{",
                KeyIndexLoadFailure::ObjectKeysSnapshot
            )
            .err(),
            Some(MnemeError::SchemaDrift)
        );
        assert_eq!(
            parse_key_index_load_json::<ObjectKeysJournalEntry>(
                "{",
                KeyIndexLoadFailure::ObjectKeysJournalLine
            )
            .err(),
            Some(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn key_index_load_json_parser_preserves_key_index_noncanonical() {
        assert_eq!(
            parse_key_index_load_json::<KeyIndexSidecar>(
                "{",
                KeyIndexLoadFailure::KeyIndexSnapshot
            )
            .err(),
            Some(MnemeError::SerializationNonCanonical)
        );
        assert_eq!(
            parse_key_index_load_json::<KeyIndexJournalEntry>(
                "{",
                KeyIndexLoadFailure::KeyIndexJournalLine
            )
            .err(),
            Some(MnemeError::SerializationNonCanonical)
        );
    }
}
