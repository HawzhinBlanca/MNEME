//! Reconstruct the semantic commitment from the on-disk embedding sidecar.
//!
//! The verifier compares this reconstructed commit against the operator-signed
//! `semantic_commit`, so sidecar tamper fails closed instead of admitting stale
//! semantic state. The parsing lives in `mneme-index` to keep `mneme-verify`
//! small and to avoid duplicating the embedding sidecar format there.

use crate::SemanticIndex;
use mneme_core::{FixedPointEmbedding, MnemeError, ObjectId, decode_hex32};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct EmbeddingSidecar {
    entries: BTreeMap<String, EmbeddingSidecarEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingSidecarEntry {
    dim: u32,
    scale: i8,
    components: Vec<i16>,
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum EmbeddingJournalEntry {
    Upsert {
        id: String,
        dim: u32,
        scale: i8,
        components: Vec<i16>,
    },
    Remove {
        id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticLoadFailure {
    EmbeddingSnapshot,
    EmbeddingJournalLine,
    EmbeddingObjectIdHex,
    EmbeddingShape,
    SemanticInsert,
}

fn semantic_load_failure_to_mneme(failure: SemanticLoadFailure) -> MnemeError {
    match failure {
        SemanticLoadFailure::EmbeddingSnapshot
        | SemanticLoadFailure::EmbeddingJournalLine
        | SemanticLoadFailure::EmbeddingObjectIdHex
        | SemanticLoadFailure::EmbeddingShape => MnemeError::SchemaDrift,
        SemanticLoadFailure::SemanticInsert => MnemeError::RootInconsistent,
    }
}

struct SemanticLoadDuplicateKeyGuard;

impl<'de> serde::Deserialize<'de> for SemanticLoadDuplicateKeyGuard {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(SemanticLoadDuplicateKeyVisitor)
    }
}

struct SemanticLoadDuplicateKeyVisitor;

impl<'de> serde::de::Visitor<'de> for SemanticLoadDuplicateKeyVisitor {
    type Value = SemanticLoadDuplicateKeyGuard;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <SemanticLoadDuplicateKeyGuard as serde::Deserialize>::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while seq
            .next_element::<SemanticLoadDuplicateKeyGuard>()?
            .is_some()
        {}
        Ok(SemanticLoadDuplicateKeyGuard)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<SemanticLoadDuplicateKeyGuard>()?;
        }
        Ok(SemanticLoadDuplicateKeyGuard)
    }
}

fn semantic_load_reject_duplicate_json_object_keys(
    input: &str,
    failure: SemanticLoadFailure,
) -> Result<(), MnemeError> {
    serde_json::from_str::<SemanticLoadDuplicateKeyGuard>(input)
        .map(|_| ())
        .map_err(|_| semantic_load_failure_to_mneme(failure))
}

fn parse_semantic_load_json<T: serde::de::DeserializeOwned>(
    input: &str,
    failure: SemanticLoadFailure,
) -> Result<T, MnemeError> {
    semantic_load_reject_duplicate_json_object_keys(input, failure)?;
    serde_json::from_str(input).map_err(|_| semantic_load_failure_to_mneme(failure))
}

fn parse_semantic_load_hex32(input: &str) -> Result<[u8; 32], MnemeError> {
    decode_hex32(input)
        .map_err(|_| semantic_load_failure_to_mneme(SemanticLoadFailure::EmbeddingObjectIdHex))
}

fn parse_embedding(
    dim: u32,
    scale: i8,
    components: Vec<i16>,
) -> Result<FixedPointEmbedding, MnemeError> {
    FixedPointEmbedding::new(dim, scale, components)
        .map_err(|_| semantic_load_failure_to_mneme(SemanticLoadFailure::EmbeddingShape))
}

fn semantic_load_read_optional_to_string(path: &Path) -> Result<Option<String>, MnemeError> {
    match fs::read_to_string(path) {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(io_err(path, err)),
    }
}

fn semantic_load_journal_line_is_blank(line: &str) -> bool {
    line.trim().is_empty()
}

fn semantic_load_remove_embedding_entry(
    embeddings: &mut BTreeMap<[u8; 32], FixedPointEmbedding>,
    id: &[u8; 32],
) {
    let mut retained_embeddings = BTreeMap::new();
    for (embedding_id, embedding) in &*embeddings {
        if embedding_id != id {
            retained_embeddings.insert(*embedding_id, embedding.clone());
        }
    }
    *embeddings = retained_embeddings;
}

/// Load all semantic embeddings from a store directory (sidecar + journal replay).
pub fn load_store_embeddings(
    store: &Path,
) -> Result<BTreeMap<ObjectId, FixedPointEmbedding>, MnemeError> {
    load_embeddings(store).map(|map| {
        map.into_iter()
            .map(|(id, emb)| (ObjectId(id), emb))
            .collect()
    })
}

fn load_embeddings(store: &Path) -> Result<BTreeMap<[u8; 32], FixedPointEmbedding>, MnemeError> {
    let mut embeddings = BTreeMap::new();
    let snapshot = store.join("meta/embeddings.json");
    if let Some(data) = semantic_load_read_optional_to_string(&snapshot)? {
        let sidecar: EmbeddingSidecar =
            parse_semantic_load_json(&data, SemanticLoadFailure::EmbeddingSnapshot)?;
        for (id_hex, entry) in sidecar.entries {
            embeddings.insert(
                parse_semantic_load_hex32(&id_hex)?,
                parse_embedding(entry.dim, entry.scale, entry.components)?,
            );
        }
    }
    let journal = store.join("meta/embeddings.journal");
    if let Some(data) = semantic_load_read_optional_to_string(&journal)? {
        for line in data.lines() {
            if semantic_load_journal_line_is_blank(line) {
                continue;
            }
            match parse_semantic_load_json(line, SemanticLoadFailure::EmbeddingJournalLine)? {
                EmbeddingJournalEntry::Upsert {
                    id,
                    dim,
                    scale,
                    components,
                } => {
                    embeddings.insert(
                        parse_semantic_load_hex32(&id)?,
                        parse_embedding(dim, scale, components)?,
                    );
                }
                EmbeddingJournalEntry::Remove { id } => {
                    semantic_load_remove_embedding_entry(
                        &mut embeddings,
                        &parse_semantic_load_hex32(&id)?,
                    );
                }
            }
        }
    }
    Ok(embeddings)
}

pub fn load_semantic_commit<'a>(
    store: &Path,
    object_ids: impl IntoIterator<Item = &'a [u8; 32]>,
) -> Result<[u8; 32], MnemeError> {
    let live_objects: BTreeSet<[u8; 32]> = object_ids.into_iter().copied().collect();
    let mut semantic = SemanticIndex::new();
    for (id, embedding) in load_embeddings(store)? {
        if live_objects.contains(&id) {
            semantic
                .insert(ObjectId(id), embedding)
                .map_err(|_| semantic_load_failure_to_mneme(SemanticLoadFailure::SemanticInsert))?;
        }
    }
    Ok(semantic.semantic_commit())
}

fn io_err(path: &Path, err: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: err.kind().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEMANTIC_LOAD_TEST_DIR_ID: AtomicU64 = AtomicU64::new(0);

    struct SemanticLoadTestDir {
        path: PathBuf,
    }

    impl SemanticLoadTestDir {
        fn new(label: &str) -> Self {
            let suffix = SEMANTIC_LOAD_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mneme-semantic-load-{label}-{}-{suffix}",
                std::process::id()
            ));
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => panic!("semantic load test tempdir cleanup failed: {err}"),
            }
            fs::create_dir_all(&path).expect("semantic load test tempdir should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for SemanticLoadTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn semantic_load_production_source() -> &'static str {
        include_str!("semantic_load.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("semantic_load.rs should keep tests after production code")
    }

    fn semantic_load_test_source() -> &'static str {
        include_str!("semantic_load.rs")
            .split_once("#[cfg(test)]")
            .map(|(_production, tests)| tests)
            .expect("semantic_load.rs should keep tests after production code")
    }

    fn semantic_load_declared_test_function_names() -> BTreeSet<String> {
        crate::source_inventory::rust_function_names(semantic_load_test_source())
            .into_iter()
            .collect()
    }

    fn semantic_load_replay_source() -> &'static str {
        let production = semantic_load_production_source();
        let start = production
            .find("fn load_embeddings(")
            .expect("semantic loader replay should stay in production source");
        let end_marker = "fn io_err(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("semantic loader replay should stay before I/O adapter");
        &production[start..start + relative_end]
    }

    fn semantic_load_expect_io_failed_path(err: MnemeError, expected_path: &Path, context: &str) {
        match err {
            MnemeError::IoFailed { path, kind } => {
                assert_eq!(
                    path,
                    expected_path.display().to_string(),
                    "{context} semantic I/O fault path should match the failed optional read"
                );
                assert_ne!(
                    kind,
                    ErrorKind::NotFound.to_string(),
                    "{context} semantic I/O fault should not be classified as optional NotFound"
                );
            }
            other => panic!("{context} semantic I/O fault should stay IoFailed, got {other:?}"),
        }
    }

    fn semantic_load_embedding_entry_json(embedding: &FixedPointEmbedding) -> serde_json::Value {
        serde_json::json!({
            "dim": embedding.dim,
            "scale": embedding.scale,
            "components": embedding.components,
        })
    }

    fn semantic_load_write_embedding_snapshot(
        meta: &Path,
        entries: &[([u8; 32], &FixedPointEmbedding)],
    ) {
        let mut snapshot_entries = serde_json::Map::new();
        for &(id, embedding) in entries {
            snapshot_entries.insert(
                hex::encode(id),
                semantic_load_embedding_entry_json(embedding),
            );
        }

        semantic_load_write_embedding_snapshot_entries(meta, snapshot_entries);
    }

    fn semantic_load_write_embedding_snapshot_document(meta: &Path, document: serde_json::Value) {
        semantic_load_write_embedding_snapshot_raw(meta, &document.to_string());
    }

    fn semantic_load_write_embedding_snapshot_raw(meta: &Path, document: &str) {
        fs::write(meta.join("embeddings.json"), document)
            .expect("semantic snapshot fixture should be written");
    }

    fn semantic_load_write_embedding_snapshot_entries(
        meta: &Path,
        entries: serde_json::Map<String, serde_json::Value>,
    ) {
        semantic_load_write_embedding_snapshot_document(
            meta,
            serde_json::json!({ "entries": entries }),
        );
    }

    fn semantic_load_snapshot_with_valid_and_raw_entry(
        valid_id: [u8; 32],
        valid_components: [i16; 2],
        raw_entry_id: [u8; 32],
        raw_entry: &str,
    ) -> String {
        format!(
            "{{\"entries\":{{\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[{},{}]}},\"{}\":{}}}}}",
            hex::encode(valid_id),
            valid_components[0],
            valid_components[1],
            hex::encode(raw_entry_id),
            raw_entry,
        )
    }

    fn semantic_load_expect_snapshot_entries_value_schema_drift(
        case_name: &str,
        entries: serde_json::Value,
        context: &str,
    ) {
        let dir = SemanticLoadTestDir::new(case_name);
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-snapshot-entries meta dir should be created");

        semantic_load_write_embedding_snapshot_document(
            &meta,
            serde_json::json!({
                "entries": entries,
            }),
        );

        let err =
            load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>()).expect_err(context);

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    fn semantic_load_journal_upsert_json(
        id: [u8; 32],
        embedding: &FixedPointEmbedding,
    ) -> serde_json::Value {
        serde_json::json!({
            "op": "upsert",
            "id": hex::encode(id),
            "dim": embedding.dim,
            "scale": embedding.scale,
            "components": embedding.components,
        })
    }

    fn semantic_load_journal_remove_json(id: [u8; 32]) -> serde_json::Value {
        serde_json::json!({
            "op": "remove",
            "id": hex::encode(id),
        })
    }

    fn semantic_load_write_embedding_journal(
        meta: &Path,
        entries: impl IntoIterator<Item = serde_json::Value>,
    ) {
        semantic_load_write_embedding_journal_lines(
            meta,
            entries.into_iter().map(|entry| entry.to_string()),
        );
    }

    fn semantic_load_write_embedding_journal_lines<I, S>(meta: &Path, lines: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let journal = lines
            .into_iter()
            .map(|line| line.as_ref().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(meta.join("embeddings.journal"), format!("{journal}\n"))
            .expect("semantic journal fixture should be written");
    }

    fn semantic_load_expect_journal_upsert_id_value_schema_drift(
        case_name: &str,
        invalid_id: serde_json::Value,
        context: &str,
    ) {
        let dir = SemanticLoadTestDir::new(case_name);
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic invalid-journal-upsert-id meta dir should be created");

        let journal_id = [0xd0; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![48, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let invalid_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": invalid_id,
            "dim": 2,
            "scale": 0,
            "components": [49, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), invalid_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(context);

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    fn semantic_load_expect_journal_remove_id_value_schema_drift(
        case_name: &str,
        invalid_id: serde_json::Value,
        context: &str,
    ) {
        let dir = SemanticLoadTestDir::new(case_name);
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic invalid-journal-remove-id meta dir should be created");

        let journal_id = [0xd1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![50, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let invalid_id_remove = serde_json::json!({
            "op": "remove",
            "id": invalid_id,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), invalid_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(context);

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    fn semantic_load_expect_raw_journal_embedding_fields_schema_drift(
        case_name: &str,
        valid_id: [u8; 32],
        valid_components: [i16; 2],
        raw_entry_id: [u8; 32],
        raw_embedding_fields: &str,
        context: &str,
    ) {
        let dir = SemanticLoadTestDir::new(case_name);
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic raw-journal-fields meta dir should be created");

        let journal_embedding = FixedPointEmbedding::new(2, 0, Vec::from(valid_components))
            .expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(valid_id, &journal_embedding).to_string();
        let raw_upsert_line = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",{raw_embedding_fields}}}",
            hex::encode(raw_entry_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), raw_upsert_line.as_str()],
        );

        let live_ids = [valid_id, raw_entry_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(context);

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    fn semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
        case_name: &str,
        valid_id: [u8; 32],
        valid_components: [i16; 2],
        raw_entry_id: [u8; 32],
        raw_embedding_fields: &str,
        context: &str,
    ) {
        let dir = SemanticLoadTestDir::new(case_name);
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic raw-snapshot-fields meta dir should be created");

        let raw_entry = format!("{{{raw_embedding_fields}}}");
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            valid_components,
            raw_entry_id,
            &raw_entry,
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, raw_entry_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(context);

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_failures_are_classified_not_error_collapsed() {
        let production = semantic_load_production_source();

        for forbidden in [
            "map_err(|_| MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::RootInconsistent)",
            "return Err(MnemeError::RootInconsistent)",
            "Err(MnemeError::RootInconsistent)",
        ] {
            assert!(
                !production.contains(forbidden),
                "semantic load production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum SemanticLoadFailure",
            "fn semantic_load_failure_to_mneme(",
            "struct SemanticLoadDuplicateKeyGuard;",
            "fn semantic_load_reject_duplicate_json_object_keys(",
            "fn parse_semantic_load_json<",
            "semantic_load_reject_duplicate_json_object_keys(input, failure)?;",
            "fn parse_semantic_load_hex32(",
            "fn parse_embedding(",
            "SemanticLoadFailure::EmbeddingSnapshot",
            "SemanticLoadFailure::EmbeddingJournalLine",
            "SemanticLoadFailure::EmbeddingObjectIdHex",
            "SemanticLoadFailure::EmbeddingShape",
            "SemanticLoadFailure::SemanticInsert",
        ] {
            assert!(
                production.contains(required),
                "semantic load production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn semantic_load_hex_decoders_are_classified_not_core_propagated() {
        let replay = semantic_load_replay_source();

        assert!(
            !replay.contains("decode_hex32("),
            "semantic loader replay should route hex decoding through loader classifiers"
        );
    }

    #[test]
    fn semantic_load_replay_source_names_journal_skip_and_remove_helpers() {
        let production = semantic_load_production_source();
        let replay = semantic_load_replay_source();

        for required in [
            "fn semantic_load_journal_line_is_blank(",
            "fn semantic_load_remove_embedding_entry(",
        ] {
            assert!(
                production.contains(required),
                "semantic loader replay should name helper `{required}`"
            );
        }

        for forbidden in [".filter(", ".remove("] {
            assert!(
                !replay.contains(forbidden),
                "semantic loader replay should call named helpers instead of `{forbidden}`"
            );
        }
    }

    #[test]
    fn semantic_load_replay_source_uses_optional_read_helper() {
        let production = semantic_load_production_source();
        let replay = semantic_load_replay_source();

        assert!(
            production.contains("fn semantic_load_read_optional_to_string("),
            "semantic loader replay should centralize optional sidecar/journal reads"
        );
        assert!(
            !replay.contains(".exists()"),
            "semantic loader replay should use the optional-read helper instead of path existence probes"
        );
    }

    #[test]
    fn semantic_load_tests_cover_optional_read_filesystem_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_missing_optional_files_use_empty_commit",
            "semantic_load_snapshot_io_error_stays_io_failed",
            "semantic_load_journal_io_error_stays_io_failed",
        ] {
            assert!(
                test_function_names.contains(required),
                "semantic load tests should cover filesystem behavior `{required}`"
            );
        }
    }

    #[test]
    fn semantic_load_tests_cover_snapshot_journal_replay_order_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_snapshot_then_journal_replays_in_order",
            "semantic_load_journal_replay_skips_blank_lines",
            "semantic_load_journal_replay_removes_prior_journal_upsert",
            "semantic_load_journal_replay_uses_later_duplicate_upsert",
        ] {
            assert!(
                test_function_names.contains(required),
                "semantic load tests should cover snapshot-plus-journal replay behavior `{required}`"
            );
        }
    }

    #[test]
    fn semantic_load_tests_cover_live_object_filter_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        assert!(
            test_function_names
                .contains("semantic_load_filters_replayed_embeddings_to_live_objects"),
            "semantic load tests should cover filtering reconstructed embeddings to live objects"
        );
    }

    #[test]
    fn semantic_load_tests_cover_signed_embedding_value_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_journal_replay_accepts_signed_scale_and_components",
            "semantic_load_snapshot_accepts_signed_scale_and_components",
        ] {
            assert!(
                test_function_names.contains(required),
                "semantic load tests should cover signed embedding value behavior `{required}`"
            );
        }
    }

    #[test]
    fn semantic_load_tests_cover_journal_fail_closed_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_journal_replay_rejects_boolean_line_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_array_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_array_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_below_min_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_below_min_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_array_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_remove_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_upsert_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_upsert_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_duplicate_upsert_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_signed_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_signed_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_signed_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_negative_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_negative_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_negative_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_signed_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_signed_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_uppercase_signed_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_fraction_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_fraction_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_zero_fraction_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_exponent_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_exponent_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_exponent_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_fraction_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_fraction_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_zero_fraction_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_decimal_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_decimal_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_decimal_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_plus_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_plus_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_plus_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_zero_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_zero_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_leading_zero_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_leading_zero_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_leading_zero_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_leading_zero_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_lowercase_non_finite_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_lowercase_non_finite_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_lowercase_non_finite_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_non_finite_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_non_finite_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_non_finite_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_decimal_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_decimal_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_decimal_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_zero_fraction_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_zero_fraction_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_zero_fraction_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_zero_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_zero_fraction_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_zero_fraction_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_zero_fraction_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_fractional_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_fractional_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_fractional_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_fractional_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_fractional_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_fractional_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_fractional_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_fractional_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_plus_fractional_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_malformed_line_after_valid_upsert",
            "semantic_load_journal_replay_rejects_trailing_junk_after_valid_upsert",
            "semantic_load_journal_replay_rejects_malformed_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_malformed_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_malformed_shape_after_valid_upsert",
            "semantic_load_journal_replay_rejects_short_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_long_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_empty_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_long_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_long_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_missing_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_missing_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_missing_upsert_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_missing_upsert_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_missing_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_missing_upsert_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_multibyte_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_multibyte_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_non_hex_digit_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_non_hex_digit_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_line_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_null_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_boolean_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_string_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_line_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_non_object_line_after_valid_upsert",
            "semantic_load_journal_replay_rejects_array_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_array_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_array_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_object_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_string_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_string_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_numeric_string_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_negative_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_out_of_range_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_out_of_range_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_out_of_range_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_scalar_line_after_valid_upsert",
            "semantic_load_journal_replay_rejects_scalar_components_after_valid_upsert",
            "semantic_load_journal_replay_rejects_short_remove_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_short_upsert_id_after_valid_upsert",
            "semantic_load_journal_replay_rejects_string_component_after_valid_upsert",
            "semantic_load_journal_replay_rejects_string_dim_after_valid_upsert",
            "semantic_load_journal_replay_rejects_string_scale_after_valid_upsert",
            "semantic_load_journal_replay_rejects_unknown_op_after_valid_upsert",
            "semantic_load_journal_replay_rejects_unknown_upsert_field_after_valid_upsert",
            "semantic_load_journal_replay_rejects_unknown_remove_field_after_valid_upsert",
        ] {
            assert!(
                test_function_names.contains(required),
                "semantic load tests should cover journal fail-closed behavior `{required}`"
            );
        }
    }

    #[test]
    fn semantic_load_tests_cover_snapshot_fail_closed_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_snapshot_rejects_malformed_entry_beside_valid_entry",
            "semantic_load_snapshot_rejects_malformed_document",
            "semantic_load_snapshot_rejects_trailing_junk_after_valid_document",
            "semantic_load_snapshot_rejects_malformed_id_beside_valid_entry",
            "semantic_load_snapshot_rejects_malformed_shape_beside_valid_entry",
            "semantic_load_snapshot_rejects_short_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_long_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_empty_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_array_entry_beside_valid_entry",
            "semantic_load_snapshot_rejects_array_document",
            "semantic_load_snapshot_rejects_boolean_document",
            "semantic_load_snapshot_rejects_boolean_entry_beside_valid_entry",
            "semantic_load_snapshot_rejects_below_min_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_below_min_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_boolean_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_boolean_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_boolean_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_duplicate_entries_field",
            "semantic_load_snapshot_rejects_duplicate_entry_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_duplicate_entry_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_duplicate_entry_key_beside_valid_entry",
            "semantic_load_snapshot_rejects_duplicate_entry_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_signed_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_signed_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_signed_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_negative_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_negative_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_negative_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_signed_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_signed_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_uppercase_signed_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_fraction_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_fraction_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_zero_fraction_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_exponent_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_exponent_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_exponent_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_fraction_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_fraction_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_zero_fraction_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_decimal_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_decimal_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_decimal_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_plus_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_plus_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_plus_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_zero_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_zero_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_leading_zero_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_leading_zero_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_leading_zero_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_leading_zero_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_lowercase_non_finite_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_lowercase_non_finite_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_lowercase_non_finite_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_non_finite_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_non_finite_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_non_finite_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_trailing_decimal_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_trailing_decimal_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_trailing_decimal_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_numeric_string_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_numeric_string_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_numeric_string_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_trailing_zero_fraction_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_trailing_zero_fraction_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_trailing_zero_fraction_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_zero_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_zero_fraction_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_zero_fraction_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_zero_fraction_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_fractional_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_fractional_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_fractional_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_fractional_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_fractional_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_fractional_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_fractional_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_fractional_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_plus_fractional_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_long_id_beside_valid_entry",
            "semantic_load_snapshot_rejects_missing_entries_field",
            "semantic_load_snapshot_rejects_missing_entry_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_missing_entry_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_missing_entry_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_multibyte_id_beside_valid_entry",
            "semantic_load_snapshot_rejects_non_hex_digit_id_beside_valid_entry",
            "semantic_load_snapshot_rejects_boolean_entries_value",
            "semantic_load_snapshot_rejects_null_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_null_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_null_document",
            "semantic_load_snapshot_rejects_null_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_null_entries_value",
            "semantic_load_snapshot_rejects_null_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_boolean_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_object_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_string_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_non_object_entry_beside_valid_entry",
            "semantic_load_snapshot_rejects_non_object_entries_value",
            "semantic_load_snapshot_rejects_numeric_document",
            "semantic_load_snapshot_rejects_numeric_entry_beside_valid_entry",
            "semantic_load_snapshot_rejects_numeric_entries_value",
            "semantic_load_snapshot_rejects_array_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_array_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_array_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_object_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_object_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_object_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_negative_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_out_of_range_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_out_of_range_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_out_of_range_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_scalar_entry_beside_valid_entry",
            "semantic_load_snapshot_rejects_scalar_components_beside_valid_entry",
            "semantic_load_snapshot_rejects_scalar_document",
            "semantic_load_snapshot_rejects_short_id_beside_valid_entry",
            "semantic_load_snapshot_rejects_string_component_beside_valid_entry",
            "semantic_load_snapshot_rejects_string_dim_beside_valid_entry",
            "semantic_load_snapshot_rejects_string_entries_value",
            "semantic_load_snapshot_rejects_string_scale_beside_valid_entry",
            "semantic_load_snapshot_rejects_unknown_entry_field_beside_valid_entry",
            "semantic_load_snapshot_rejects_unknown_top_level_field",
        ] {
            assert!(
                test_function_names.contains(required),
                "semantic load tests should cover snapshot fail-closed behavior `{required}`"
            );
        }
    }

    #[test]
    fn semantic_load_tests_cover_source_invariant_behavior() {
        let test_function_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_source_invariants_share_declared_function_names_helper",
            "semantic_load_source_invariants_require_fail_closed_serde_deserializers",
            "semantic_load_source_invariants_reject_sidecar_serde_default",
            "semantic_load_source_invariants_use_shared_source_inventory_helper",
        ] {
            assert!(
                test_function_names.contains(required),
                "semantic load tests should cover source invariant `{required}`"
            );
        }
    }

    #[test]
    fn semantic_load_source_invariants_require_fail_closed_serde_deserializers() {
        let production = semantic_load_production_source();

        for required in [
            "#[derive(serde::Deserialize, Default)]\n#[serde(deny_unknown_fields)]\nstruct EmbeddingSidecar",
            "#[derive(serde::Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct EmbeddingSidecarEntry",
            "#[derive(serde::Deserialize)]\n#[serde(tag = \"op\", rename_all = \"snake_case\", deny_unknown_fields)]\nenum EmbeddingJournalEntry",
        ] {
            assert!(
                production.contains(required),
                "semantic load serde deserializer must keep fail-closed marker `{required}`"
            );
        }

        assert_eq!(
            production.matches("deny_unknown_fields").count(),
            3,
            "semantic load should keep exactly the three reviewed serde unknown-field rejections"
        );
    }

    #[test]
    fn semantic_load_source_invariants_reject_sidecar_serde_default() {
        let production = semantic_load_production_source();
        let sidecar_source = crate::source_inventory::source_between_markers(
            production,
            "#[derive(serde::Deserialize, Default)]\n#[serde(deny_unknown_fields)]\nstruct EmbeddingSidecar",
            "#[derive(serde::Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct EmbeddingSidecarEntry",
        );

        assert!(
            !sidecar_source.contains("serde(default"),
            "EmbeddingSidecar must not use serde(default); missing `entries` must fail closed"
        );
        assert!(
            !sidecar_source.contains("#[serde(default)]"),
            "EmbeddingSidecar must not gain whole-struct serde defaulting"
        );
    }

    #[test]
    fn semantic_load_source_invariants_use_shared_source_inventory_helper() {
        let tests = semantic_load_test_source();
        let crate_root = include_str!("lib.rs");

        assert!(
            crate_root.contains("#[path = \"../../../tests/support/source_inventory.rs\"]"),
            "semantic load tests should import the shared source inventory helper"
        );
        assert!(
            crate_root.contains("mod source_inventory;"),
            "semantic load tests should keep the shared source inventory module named plainly"
        );
        assert!(
            tests.contains(
                "crate::source_inventory::rust_function_names(semantic_load_test_source())"
            ),
            "semantic load declared function inventory should use shared source_inventory parsing"
        );
        crate::source_inventory::assert_no_local_source_scan_helpers("semantic_load.rs", tests);
    }

    #[test]
    fn semantic_load_source_invariants_share_declared_function_names_helper() {
        let tests = semantic_load_test_source();

        assert_eq!(
            tests
                .lines()
                .filter(|line| {
                    line.trim_start()
                        .starts_with("fn semantic_load_declared_test_function_names(")
                })
                .count(),
            1,
            "semantic load source invariants should share declared function-name parsing"
        );

        let declared_function_parser = [
            ".filter_map(|line| line.trim_start().strip_prefix(",
            "\"fn \"",
            "))",
        ]
        .concat();
        assert_eq!(
            tests.matches(&declared_function_parser).count(),
            0,
            "semantic load tests should use shared source inventory instead of local function-name parsing"
        );
    }

    #[test]
    fn semantic_load_io_failed_tests_use_named_assertion_helper() {
        let tests = semantic_load_test_source();
        let test_helper_names = semantic_load_declared_test_function_names();

        assert!(
            test_helper_names.contains("semantic_load_expect_io_failed_path"),
            "semantic load IoFailed behavior tests should share a named assertion helper"
        );

        let io_failed_pattern = ["MnemeError", "::", "IoFailed { path, kind }"].concat();
        assert_eq!(
            tests.matches(&io_failed_pattern).count(),
            1,
            "semantic load tests should destructure IoFailed only in the named helper"
        );
    }

    #[test]
    fn semantic_load_replay_fixture_tests_use_named_fixture_writers() {
        let tests = semantic_load_test_source();
        let test_helper_names = semantic_load_declared_test_function_names();

        for required in [
            "semantic_load_embedding_entry_json",
            "semantic_load_write_embedding_snapshot",
            "semantic_load_write_embedding_snapshot_raw",
            "semantic_load_write_embedding_journal",
        ] {
            assert!(
                test_helper_names.contains(required),
                "semantic load replay tests should share fixture helper `{required}`"
            );
        }

        let snapshot_fixture_path = ["meta.join(", "\"embeddings.json\"", ")"].concat();
        assert_eq!(
            tests.matches(&snapshot_fixture_path).count(),
            1,
            "semantic load tests should write snapshot fixtures through one named helper"
        );

        let journal_fixture_path = ["meta.join(", "\"embeddings.journal\"", ")"].concat();
        assert_eq!(
            tests.matches(&journal_fixture_path).count(),
            1,
            "semantic load tests should write journal fixtures through one named helper"
        );
    }

    #[test]
    fn semantic_load_missing_optional_files_use_empty_commit() {
        let dir = SemanticLoadTestDir::new("missing-optional-files");

        let commit = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect("missing optional semantic files should not reject an empty store");

        assert_eq!(commit, SemanticIndex::new().semantic_commit());
    }

    #[test]
    fn semantic_load_snapshot_then_journal_replays_in_order() {
        let dir = SemanticLoadTestDir::new("snapshot-journal-replay");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic replay meta dir should be created");

        let removed_id = [0x11; 32];
        let retained_id = [0x22; 32];
        let journal_id = [0x33; 32];
        let removed_embedding =
            FixedPointEmbedding::new(2, 0, vec![1, 0]).expect("valid removed embedding");
        let retained_embedding =
            FixedPointEmbedding::new(2, 0, vec![2, 0]).expect("valid retained embedding");
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![3, 0]).expect("valid journal embedding");

        semantic_load_write_embedding_snapshot(
            &meta,
            &[
                (removed_id, &removed_embedding),
                (retained_id, &retained_embedding),
            ],
        );
        semantic_load_write_embedding_journal(
            &meta,
            [
                semantic_load_journal_remove_json(removed_id),
                semantic_load_journal_upsert_json(journal_id, &journal_embedding),
            ],
        );

        let live_ids = [removed_id, retained_id, journal_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("snapshot plus journal semantic replay should load");

        let mut expected = SemanticIndex::new();
        expected
            .insert(ObjectId(retained_id), retained_embedding.clone())
            .expect("expected retained embedding should insert");
        expected
            .insert(ObjectId(journal_id), journal_embedding)
            .expect("expected journal embedding should insert");
        assert_eq!(loaded_commit, expected.semantic_commit());

        expected
            .insert(ObjectId(removed_id), removed_embedding)
            .expect("stale snapshot-only embedding should insert");
        assert_ne!(
            loaded_commit,
            expected.semantic_commit(),
            "journal removal should remove stale snapshot embedding before commit reconstruction"
        );
    }

    #[test]
    fn semantic_load_journal_replay_skips_blank_lines() {
        let dir = SemanticLoadTestDir::new("journal-blank-lines");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic blank-line meta dir should be created");

        let journal_id = [0x77; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![7, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            ["", "   ", upsert_line.as_str(), "\t", ""],
        );

        let live_ids = [journal_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("blank journal lines should be skipped during semantic replay");

        let mut expected = SemanticIndex::new();
        expected
            .insert(ObjectId(journal_id), journal_embedding)
            .expect("expected journal embedding should insert");
        assert_eq!(loaded_commit, expected.semantic_commit());
    }

    #[test]
    fn semantic_load_journal_replay_removes_prior_journal_upsert() {
        let dir = SemanticLoadTestDir::new("journal-upsert-then-remove");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic journal-upsert-remove meta dir should be created");

        let journal_id = [0xee; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![16, 0]).expect("valid journal embedding");
        semantic_load_write_embedding_journal(
            &meta,
            [
                semantic_load_journal_upsert_json(journal_id, &journal_embedding),
                semantic_load_journal_remove_json(journal_id),
            ],
        );

        let live_ids = [journal_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("journal remove should replay after journal upsert");

        let empty_semantic = SemanticIndex::new();
        assert_eq!(loaded_commit, empty_semantic.semantic_commit());

        let mut stale_semantic = SemanticIndex::new();
        stale_semantic
            .insert(ObjectId(journal_id), journal_embedding)
            .expect("stale journal embedding should insert");
        assert_ne!(
            loaded_commit,
            stale_semantic.semantic_commit(),
            "journal removal should remove a prior journal upsert before commit reconstruction"
        );
    }

    #[test]
    fn semantic_load_journal_replay_uses_later_duplicate_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-upsert meta dir should be created");

        let journal_id = [0xef; 32];
        let first_embedding =
            FixedPointEmbedding::new(2, 0, vec![17, 0]).expect("valid first journal embedding");
        let later_embedding =
            FixedPointEmbedding::new(2, 0, vec![18, 0]).expect("valid later journal embedding");
        semantic_load_write_embedding_journal(
            &meta,
            [
                semantic_load_journal_upsert_json(journal_id, &first_embedding),
                semantic_load_journal_upsert_json(journal_id, &later_embedding),
            ],
        );

        let live_ids = [journal_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("duplicate journal upserts should replay deterministically");

        let mut expected = SemanticIndex::new();
        expected
            .insert(ObjectId(journal_id), later_embedding)
            .expect("expected later journal embedding should insert");
        assert_eq!(loaded_commit, expected.semantic_commit());

        let mut stale_semantic = SemanticIndex::new();
        stale_semantic
            .insert(ObjectId(journal_id), first_embedding)
            .expect("stale first journal embedding should insert");
        assert_ne!(
            loaded_commit,
            stale_semantic.semantic_commit(),
            "later duplicate journal upsert should replace the first embedding before commit reconstruction"
        );
    }

    #[test]
    fn semantic_load_journal_replay_accepts_signed_scale_and_components() {
        let dir = SemanticLoadTestDir::new("journal-signed-scale-components");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-journal-values meta dir should be created");

        let journal_id = [0x3a; 32];
        let signed_embedding = FixedPointEmbedding::new(3, -4, vec![-32768, -17, 2048])
            .expect("valid signed journal embedding");
        semantic_load_write_embedding_journal(
            &meta,
            [semantic_load_journal_upsert_json(
                journal_id,
                &signed_embedding,
            )],
        );

        let live_ids = [journal_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("signed journal embedding values should replay");

        let mut expected = SemanticIndex::new();
        expected
            .insert(ObjectId(journal_id), signed_embedding.clone())
            .expect("expected signed journal embedding should insert");
        assert_eq!(loaded_commit, expected.semantic_commit());

        assert_ne!(
            loaded_commit,
            SemanticIndex::new().semantic_commit(),
            "signed journal values should affect reconstructed semantic commit"
        );

        let wrong_scale_embedding = FixedPointEmbedding::new(3, 0, vec![-32768, -17, 2048])
            .expect("valid wrong-scale journal embedding");
        let mut wrong_scale = SemanticIndex::new();
        wrong_scale
            .insert(ObjectId(journal_id), wrong_scale_embedding)
            .expect("wrong-scale journal embedding should insert");
        assert_ne!(
            loaded_commit,
            wrong_scale.semantic_commit(),
            "signed journal scale should be preserved during replay"
        );
    }

    #[test]
    fn semantic_load_snapshot_accepts_signed_scale_and_components() {
        let dir = SemanticLoadTestDir::new("snapshot-signed-scale-components");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-snapshot-values meta dir should be created");

        let snapshot_id = [0x3b; 32];
        let signed_embedding = FixedPointEmbedding::new(3, -5, vec![-1024, 0, 32767])
            .expect("valid signed snapshot embedding");
        semantic_load_write_embedding_snapshot(&meta, &[(snapshot_id, &signed_embedding)]);

        let live_ids = [snapshot_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("signed snapshot embedding values should load");

        let mut expected = SemanticIndex::new();
        expected
            .insert(ObjectId(snapshot_id), signed_embedding.clone())
            .expect("expected signed snapshot embedding should insert");
        assert_eq!(loaded_commit, expected.semantic_commit());

        assert_ne!(
            loaded_commit,
            SemanticIndex::new().semantic_commit(),
            "signed snapshot values should affect reconstructed semantic commit"
        );

        let wrong_scale_embedding = FixedPointEmbedding::new(3, 0, vec![-1024, 0, 32767])
            .expect("valid wrong-scale snapshot embedding");
        let mut wrong_scale = SemanticIndex::new();
        wrong_scale
            .insert(ObjectId(snapshot_id), wrong_scale_embedding)
            .expect("wrong-scale snapshot embedding should insert");
        assert_ne!(
            loaded_commit,
            wrong_scale.semantic_commit(),
            "signed snapshot scale should be preserved during load"
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_upsert_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-upsert-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-upsert-scale meta dir should be created");

        let journal_id = [0x38; 32];
        let duplicate_scale_id = [0x39; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![151, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"scale\":1,\"components\":[152,0]}}",
            hex::encode(duplicate_scale_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, duplicate_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal upsert scale field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_upsert_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-upsert-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-upsert-dim meta dir should be created");

        let journal_id = [0x50; 32];
        let duplicate_dim_id = [0x51; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![170, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"dim\":3,\"scale\":0,\"components\":[171,0]}}",
            hex::encode(duplicate_dim_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, duplicate_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal upsert dim field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_upsert_components_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-upsert-components-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-upsert-components meta dir should be created");

        let journal_id = [0x52; 32];
        let duplicate_components_id = [0x53; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![172, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_components_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[173,0],\"components\":[174,0]}}",
            hex::encode(duplicate_components_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_components_upsert.as_str()],
        );

        let live_ids = [journal_id, duplicate_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal upsert components field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-op meta dir should be created");

        let journal_id = [0x40; 32];
        let duplicate_op_id = [0x41; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![156, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_op_upsert = format!(
            "{{\"op\":\"upsert\",\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[157,0]}}",
            hex::encode(duplicate_op_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_op_upsert.as_str()],
        );

        let live_ids = [journal_id, duplicate_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal op field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-upsert-id meta dir should be created");

        let journal_id = [0x42; 32];
        let first_duplicate_id = [0x43; 32];
        let second_duplicate_id = [0x44; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![158, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_id_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[159,0]}}",
            hex::encode(first_duplicate_id),
            hex::encode(second_duplicate_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_id_upsert.as_str()],
        );

        let live_ids = [journal_id, first_duplicate_id, second_duplicate_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal upsert id field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-remove-id meta dir should be created");

        let journal_id = [0x45; 32];
        let first_remove_id = [0x46; 32];
        let second_remove_id = [0x47; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![160, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_id_remove = format!(
            "{{\"op\":\"remove\",\"id\":\"{}\",\"id\":\"{}\"}}",
            hex::encode(first_remove_id),
            hex::encode(second_remove_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_id_remove.as_str()],
        );

        let live_ids = [journal_id, first_remove_id, second_remove_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal remove id field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_duplicate_remove_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-duplicate-remove-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-journal-remove-op meta dir should be created");

        let journal_id = [0x54; 32];
        let remove_id = [0x55; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![175, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let duplicate_op_remove = format!(
            "{{\"op\":\"remove\",\"op\":\"remove\",\"id\":\"{}\"}}",
            hex::encode(remove_id),
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), duplicate_op_remove.as_str()],
        );

        let live_ids = [journal_id, remove_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate journal remove op field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_malformed_line_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-malformed-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic malformed-journal meta dir should be created");

        let journal_id = [0x88; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![8, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        semantic_load_write_embedding_journal_lines(&meta, [upsert_line.as_str(), "{"]);

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed journal line after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_junk_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-trailing-junk-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-junk-journal meta dir should be created");

        let journal_id = [0x90; 32];
        let trailing_id = [0x91; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![8, 0]).expect("valid journal embedding");
        let trailing_embedding =
            FixedPointEmbedding::new(2, 0, vec![9, 0]).expect("valid trailing journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let trailing_junk_line = format!(
            "{} trailing-junk",
            semantic_load_journal_upsert_json(trailing_id, &trailing_embedding)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), trailing_junk_line.as_str()],
        );

        let live_ids = [journal_id, trailing_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing junk after valid journal entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_non_object_line_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-non-object-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic non-object-journal-line meta dir should be created");

        let journal_id = [0xef; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![33, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let non_object_line = serde_json::json!(["not", "a", "journal", "entry"]).to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), non_object_line.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "non-object journal line after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_line_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-null-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-journal-line meta dir should be created");

        let journal_id = [0xe2; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![35, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let null_line = serde_json::Value::Null.to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), null_line.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("null journal line after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_line_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-journal-line meta dir should be created");

        let journal_id = [0xe3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![36, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_line = serde_json::Value::Bool(true).to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_line.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean journal line after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_line_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-numeric-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic numeric-journal-line meta dir should be created");

        let journal_id = [0xe4; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![37, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let numeric_line = serde_json::json!(42).to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), numeric_line.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "numeric journal line after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_scalar_line_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-scalar-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic scalar-journal-line meta dir should be created");

        let journal_id = [0xe1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![34, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let scalar_line = serde_json::Value::String("not-a-journal-entry".to_owned()).to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), scalar_line.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("scalar journal line after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_unknown_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-unknown-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic unknown-journal-op meta dir should be created");

        let journal_id = [0xf4; 32];
        let unknown_op_id = [0xf5; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![23, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let unknown_op_line = serde_json::json!({
            "op": "replace",
            "id": hex::encode(unknown_op_id),
            "dim": 2,
            "scale": 0,
            "components": [24, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), unknown_op_line.as_str()],
        );

        let live_ids = [journal_id, unknown_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("unknown journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic boolean-journal-op meta dir should be created");

        let journal_id = [0xb0; 32];
        let boolean_op_id = [0xb1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![38, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_op_line = serde_json::json!({
            "op": true,
            "id": hex::encode(boolean_op_id),
            "dim": 2,
            "scale": 0,
            "components": [39, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_op_line.as_str()],
        );

        let live_ids = [journal_id, boolean_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("boolean journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-numeric-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic numeric-journal-op meta dir should be created");

        let journal_id = [0xb2; 32];
        let numeric_op_id = [0xb3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![40, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let numeric_op_line = serde_json::json!({
            "op": 7,
            "id": hex::encode(numeric_op_id),
            "dim": 2,
            "scale": 0,
            "components": [41, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), numeric_op_line.as_str()],
        );

        let live_ids = [journal_id, numeric_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("numeric journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_array_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-array-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic array-journal-op meta dir should be created");

        let journal_id = [0xc0; 32];
        let array_op_id = [0xc1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![42, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let array_op_line = serde_json::json!({
            "op": ["upsert"],
            "id": hex::encode(array_op_id),
            "dim": 2,
            "scale": 0,
            "components": [43, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), array_op_line.as_str()],
        );

        let live_ids = [journal_id, array_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("array journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-null-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-journal-op meta dir should be created");

        let journal_id = [0xc2; 32];
        let null_op_id = [0xc3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![44, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let null_op_line = serde_json::json!({
            "op": null,
            "id": hex::encode(null_op_id),
            "dim": 2,
            "scale": 0,
            "components": [45, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), null_op_line.as_str()],
        );

        let live_ids = [journal_id, null_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("null journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-object-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic object-journal-op meta dir should be created");

        let journal_id = [0xc4; 32];
        let object_op_id = [0xc5; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![46, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let object_op_line = serde_json::json!({
            "op": {},
            "id": hex::encode(object_op_id),
            "dim": 2,
            "scale": 0,
            "components": [47, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), object_op_line.as_str()],
        );

        let live_ids = [journal_id, object_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("object journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_missing_op_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-missing-op-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic missing-journal-op meta dir should be created");

        let journal_id = [0xfd; 32];
        let missing_op_id = [0xfe; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![31, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let missing_op_line = serde_json::json!({
            "id": hex::encode(missing_op_id),
            "dim": 2,
            "scale": 0,
            "components": [32, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), missing_op_line.as_str()],
        );

        let live_ids = [journal_id, missing_op_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("missing journal op after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_missing_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-missing-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-journal-upsert-id meta dir should be created");

        let journal_id = [0xa1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![79, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let missing_id_upsert = serde_json::json!({
            "op": "upsert",
            "dim": 2,
            "scale": 0,
            "components": [80, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), missing_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_missing_upsert_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-missing-upsert-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-journal-upsert-dim meta dir should be created");

        let journal_id = [0xa2; 32];
        let missing_dim_id = [0xa3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![81, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let missing_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(missing_dim_id),
            "scale": 0,
            "components": [82, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), missing_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, missing_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing journal upsert dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_missing_upsert_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-missing-upsert-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-journal-upsert-scale meta dir should be created");

        let journal_id = [0xa4; 32];
        let missing_scale_id = [0xa5; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![83, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let missing_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(missing_scale_id),
            "dim": 2,
            "components": [84, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), missing_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, missing_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing journal upsert scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_missing_upsert_components_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-missing-upsert-components-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-journal-upsert-components meta dir should be created");

        let journal_id = [0xa6; 32];
        let missing_components_id = [0xa7; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![85, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let missing_components_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(missing_components_id),
            "dim": 2,
            "scale": 0,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), missing_components_upsert.as_str()],
        );

        let live_ids = [journal_id, missing_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing journal upsert components after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_missing_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-missing-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-journal-remove-id meta dir should be created");

        let journal_id = [0xa8; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![86, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let missing_id_remove = serde_json::json!({
            "op": "remove",
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), missing_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_unknown_upsert_field_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-unknown-upsert-field-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic unknown-journal-upsert-field meta dir should be created");

        let journal_id = [0xf6; 32];
        let unknown_field_id = [0xf7; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![25, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let unknown_field_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(unknown_field_id),
            "dim": 2,
            "scale": 0,
            "components": [26, 0],
            "unexpected": true,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), unknown_field_upsert.as_str()],
        );

        let live_ids = [journal_id, unknown_field_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "unknown journal upsert field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_unknown_remove_field_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-unknown-remove-field-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic unknown-journal-remove-field meta dir should be created");

        let journal_id = [0xfb; 32];
        let remove_id = [0xfc; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![30, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let unknown_field_remove = serde_json::json!({
            "op": "remove",
            "id": hex::encode(remove_id),
            "unexpected": true,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), unknown_field_remove.as_str()],
        );

        let live_ids = [journal_id, remove_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "unknown journal remove field after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_malformed_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-malformed-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-journal-id meta dir should be created");

        let journal_id = [0xcc; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![13, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let malformed_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": "not-a-hex-object-id",
            "dim": 2,
            "scale": 0,
            "components": [14, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), malformed_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed journal id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_malformed_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-malformed-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-journal-remove-id meta dir should be created");

        let journal_id = [0xdd; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![15, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let malformed_id_remove = serde_json::json!({
            "op": "remove",
            "id": "not-a-hex-object-id",
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), malformed_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_short_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-short-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic short-journal-upsert-id meta dir should be created");

        let journal_id = [0x91; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![70, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let short_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": "ab".repeat(31),
            "dim": 2,
            "scale": 0,
            "components": [71, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), short_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "short journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_long_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-long-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic long-journal-upsert-id meta dir should be created");

        let journal_id = [0x92; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![72, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let long_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": "cd".repeat(33),
            "dim": 2,
            "scale": 0,
            "components": [73, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), long_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "long journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_multibyte_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-multibyte-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic multibyte-journal-upsert-id meta dir should be created");

        let journal_id = [0x93; 32];
        let multibyte_id =
            String::from_utf8(vec![0xe2, 0x98, 0x83]).expect("valid UTF-8 multibyte id");
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![74, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let multibyte_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": multibyte_id,
            "dim": 2,
            "scale": 0,
            "components": [75, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), multibyte_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "multibyte journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_non_hex_digit_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-non-hex-digit-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic non-hex-digit-journal-upsert-id meta dir should be created");

        let journal_id = [0x97; 32];
        let non_hex_digit_id = format!("{}g", "a".repeat(63));
        assert_eq!(non_hex_digit_id.len(), 64);
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![79, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let non_hex_digit_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": non_hex_digit_id,
            "dim": 2,
            "scale": 0,
            "components": [80, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), non_hex_digit_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exact-length non-hex digit journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_short_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-short-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic short-journal-remove-id meta dir should be created");

        let journal_id = [0x94; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![76, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let short_id_remove = serde_json::json!({
            "op": "remove",
            "id": "ef".repeat(31),
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), short_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "short journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_long_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-long-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic long-journal-remove-id meta dir should be created");

        let journal_id = [0x95; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![77, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let long_id_remove = serde_json::json!({
            "op": "remove",
            "id": "01".repeat(33),
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), long_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "long journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_multibyte_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-multibyte-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic multibyte-journal-remove-id meta dir should be created");

        let journal_id = [0x96; 32];
        let multibyte_id =
            String::from_utf8(vec![0xe2, 0x98, 0x83]).expect("valid UTF-8 multibyte id");
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![78, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let multibyte_id_remove = serde_json::json!({
            "op": "remove",
            "id": multibyte_id,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), multibyte_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "multibyte journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_non_hex_digit_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-non-hex-digit-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic non-hex-digit-journal-remove-id meta dir should be created");

        let journal_id = [0x98; 32];
        let non_hex_digit_id = format!("{}g", "b".repeat(63));
        assert_eq!(non_hex_digit_id.len(), 64);
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![81, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let non_hex_digit_id_remove = serde_json::json!({
            "op": "remove",
            "id": non_hex_digit_id,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), non_hex_digit_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exact-length non-hex digit journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-journal-upsert-id meta dir should be created");

        let journal_id = [0xc1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![42, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": true,
            "dim": 2,
            "scale": 0,
            "components": [43, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_upsert_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-numeric-upsert-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic numeric-journal-upsert-id meta dir should be created");

        let journal_id = [0xc2; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![44, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let numeric_id_upsert = serde_json::json!({
            "op": "upsert",
            "id": 42,
            "dim": 2,
            "scale": 0,
            "components": [45, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), numeric_id_upsert.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "numeric journal upsert id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_array_upsert_id_after_valid_upsert() {
        semantic_load_expect_journal_upsert_id_value_schema_drift(
            "journal-array-upsert-id-after-upsert",
            serde_json::json!(["not-an-id"]),
            "array journal upsert id after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_upsert_id_after_valid_upsert() {
        semantic_load_expect_journal_upsert_id_value_schema_drift(
            "journal-null-upsert-id-after-upsert",
            serde_json::Value::Null,
            "null journal upsert id after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_upsert_id_after_valid_upsert() {
        semantic_load_expect_journal_upsert_id_value_schema_drift(
            "journal-object-upsert-id-after-upsert",
            serde_json::json!({}),
            "object journal upsert id after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-journal-remove-id meta dir should be created");

        let journal_id = [0xc3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![46, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_id_remove = serde_json::json!({
            "op": "remove",
            "id": false,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_remove_id_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-numeric-remove-id-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic numeric-journal-remove-id meta dir should be created");

        let journal_id = [0xc4; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![47, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let numeric_id_remove = serde_json::json!({
            "op": "remove",
            "id": 43,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), numeric_id_remove.as_str()],
        );

        let live_ids = [journal_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "numeric journal remove id after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_array_remove_id_after_valid_upsert() {
        semantic_load_expect_journal_remove_id_value_schema_drift(
            "journal-array-remove-id-after-upsert",
            serde_json::json!(["not-an-id"]),
            "array journal remove id after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_remove_id_after_valid_upsert() {
        semantic_load_expect_journal_remove_id_value_schema_drift(
            "journal-null-remove-id-after-upsert",
            serde_json::Value::Null,
            "null journal remove id after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_remove_id_after_valid_upsert() {
        semantic_load_expect_journal_remove_id_value_schema_drift(
            "journal-object-remove-id-after-upsert",
            serde_json::json!({}),
            "object journal remove id after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_malformed_shape_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-malformed-shape-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-journal-shape meta dir should be created");

        let journal_id = [0xf0; 32];
        let malformed_shape_id = [0xf1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![19, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let malformed_shape_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(malformed_shape_id),
            "dim": 3,
            "scale": 0,
            "components": [20, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), malformed_shape_upsert.as_str()],
        );

        let live_ids = [journal_id, malformed_shape_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed journal embedding shape after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_short_components_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-short-components-after-upsert",
            [0x41; 32],
            [19, 0],
            [0x42; 32],
            "\"dim\":2,\"scale\":0,\"components\":[20]",
            "short component vector journal replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_long_components_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-long-components-after-upsert",
            [0x43; 32],
            [19, 0],
            [0x44; 32],
            "\"dim\":2,\"scale\":0,\"components\":[20,0,1]",
            "long component vector journal replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_empty_components_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-empty-components-after-upsert",
            [0x45; 32],
            [19, 0],
            [0x46; 32],
            "\"dim\":2,\"scale\":0,\"components\":[]",
            "empty component vector journal replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic boolean-journal-dim meta dir should be created");

        let journal_id = [0xd1; 32];
        let boolean_dim_id = [0xd2; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![48, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(boolean_dim_id),
            "dim": true,
            "scale": 0,
            "components": [49, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, boolean_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("boolean journal dim after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-object-dim-after-upsert",
            [0x51; 32],
            [108, 0],
            [0x52; 32],
            "\"dim\":{},\"scale\":0,\"components\":[108,0]",
            "object-valued journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_array_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-array-dim-after-upsert",
            [0x53; 32],
            [108, 0],
            [0x54; 32],
            "\"dim\":[],\"scale\":0,\"components\":[108,0]",
            "array-valued journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_string_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-numeric-string-dim-after-upsert",
            [0x31; 32],
            [108, 0],
            [0x32; 32],
            "\"dim\":\"2\",\"scale\":0,\"components\":[108,0]",
            "numeric-string journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_string_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-string-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic string-journal-dim meta dir should be created");

        let journal_id = [0xd9; 32];
        let string_dim_id = [0xda; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![87, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let string_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(string_dim_id),
            "dim": "two",
            "scale": 0,
            "components": [88, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), string_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, string_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("string journal dim after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-null-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-journal-dim meta dir should be created");

        let journal_id = [0x48; 32];
        let null_dim_id = [0x49; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![135, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let null_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(null_dim_id),
            "dim": null,
            "scale": 0,
            "components": [136, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), null_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, null_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("null journal dim after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-journal-dim meta dir should be created");

        let journal_id = [0xef; 32];
        let negative_dim_id = [0xf4; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![123, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(negative_dim_id),
            "dim": -1,
            "scale": 0,
            "components": [124, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), negative_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, negative_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_fractional_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-fractional-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic fractional-journal-dim meta dir should be created");

        let journal_id = [0xe7; 32];
        let fractional_dim_id = [0xe8; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let fractional_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(fractional_dim_id),
            "dim": 2.5,
            "scale": 0,
            "components": [108, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), fractional_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, fractional_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "fractional journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_fractional_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-negative-fractional-dim-after-upsert",
            [0x3c; 32],
            [107, 0],
            [0x3d; 32],
            "\"dim\":-1.5,\"scale\":0,\"components\":[108,0]",
            "negative-fractional journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_fractional_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-fractional-dim-after-upsert",
            [0x48; 32],
            [107, 0],
            [0x49; 32],
            "\"dim\":+1.5,\"scale\":0,\"components\":[108,0]",
            "plus-fractional journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-negative-zero-dim-after-upsert",
            [0xb0; 32],
            [107, 0],
            [0xb1; 32],
            "\"dim\":-0,\"scale\":0,\"components\":[108,0]",
            "negative-zero journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_exponent_dim_after_valid_upsert() {
        for (case_name, token) in [("lowercase", "-0e0"), ("uppercase", "-0E0")] {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-negative-zero-exponent-dim-{case_name}-after-upsert"),
                [0x54; 32],
                [107, 0],
                [0x55; 32],
                &format!("\"dim\":{token},\"scale\":0,\"components\":[108,0]"),
                "negative-zero-exponent journal dim after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_fraction_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-negative-zero-fraction-dim-after-upsert",
            [0xb2; 32],
            [107, 0],
            [0xb3; 32],
            "\"dim\":-0.0,\"scale\":0,\"components\":[108,0]",
            "negative-zero-fraction journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_exponent_dim_after_valid_upsert() {
        for (case_name, token) in [("lowercase", "+0e0"), ("uppercase", "+0E0")] {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-plus-zero-exponent-dim-{case_name}-after-upsert"),
                [0xa0; 32],
                [107, 0],
                [0xa1; 32],
                &format!("\"dim\":{token},\"scale\":0,\"components\":[108,0]"),
                "plus-zero-exponent journal dim after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-zero-dim-after-upsert",
            [0xb8; 32],
            [107, 0],
            [0xb9; 32],
            "\"dim\":+0,\"scale\":0,\"components\":[108,0]",
            "plus-zero journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_fraction_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-zero-fraction-dim-after-upsert",
            [0x80; 32],
            [107, 0],
            [0x81; 32],
            "\"dim\":+0.0,\"scale\":0,\"components\":[108,0]",
            "plus-zero-fraction journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_zero_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-zero-dim-after-upsert",
            [0xe8; 32],
            [107, 0],
            [0xe9; 32],
            "\"dim\":0,\"scale\":0,\"components\":[]",
            "zero-dim journal embedding after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_zero_fraction_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-zero-fraction-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic zero-fraction-journal-dim meta dir should be created");

        let journal_id = [0xb6; 32];
        let zero_fraction_dim_id = [0xb7; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let zero_fraction_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2.0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(zero_fraction_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), zero_fraction_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, zero_fraction_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "zero-fraction journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_zero_fraction_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-trailing-zero-fraction-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-zero-fraction-journal-dim meta dir should be created");

        let journal_id = [0xd2; 32];
        let trailing_zero_fraction_dim_id = [0xd3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let trailing_zero_fraction_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2.00,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(trailing_zero_fraction_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                trailing_zero_fraction_dim_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, trailing_zero_fraction_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing-zero-fraction journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_lowercase_non_finite_dim_after_valid_upsert() {
        for (case_index, (case_name, token)) in [
            ("nan", "nan"),
            ("infinity", "infinity"),
            ("negative-infinity", "-infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-lowercase-non-finite-dim-after-upsert-{case_name}"),
                [0xd0 + case_index as u8; 32],
                [108, 0],
                [0xd3 + case_index as u8; 32],
                &format!("\"dim\":{token},\"scale\":0,\"components\":[108,0]"),
                "lowercase non-finite journal dim after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_non_finite_dim_after_valid_upsert() {
        for (case_index, (case_name, token)) in [
            ("nan", "NaN"),
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = SemanticLoadTestDir::new(&format!(
                "journal-non-finite-dim-after-upsert-{case_name}"
            ));
            let meta = dir.path().join("meta");
            fs::create_dir_all(&meta)
                .expect("semantic non-finite-journal-dim meta dir should be created");

            let journal_id = [0x1a + case_index as u8; 32];
            let non_finite_dim_id = [0x1d + case_index as u8; 32];
            let journal_embedding =
                FixedPointEmbedding::new(2, 0, vec![108, 0]).expect("valid journal embedding");
            let upsert_line =
                semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
            let non_finite_dim_upsert = format!(
                "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":{},\"scale\":0,\"components\":[108,0]}}",
                hex::encode(non_finite_dim_id),
                token
            );
            semantic_load_write_embedding_journal_lines(
                &meta,
                [upsert_line.as_str(), non_finite_dim_upsert.as_str()],
            );

            let live_ids = [journal_id, non_finite_dim_id];
            let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
                "non-finite journal dim after valid replay should reject whole semantic load",
            );

            assert_eq!(err, MnemeError::SchemaDrift, "{case_name}");
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_plus_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-leading-plus-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-plus-journal-dim meta dir should be created");

        let journal_id = [0x60; 32];
        let leading_plus_dim_id = [0x61; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![108, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let leading_plus_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":+2,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(leading_plus_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), leading_plus_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, leading_plus_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-plus journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_zero_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-leading-zero-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-zero-journal-dim meta dir should be created");

        let journal_id = [0x71; 32];
        let leading_zero_dim_id = [0x72; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![108, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let leading_zero_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":02,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(leading_zero_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), leading_zero_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, leading_zero_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-zero journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_leading_zero_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-leading-zero-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-leading-zero-journal-dim meta dir should be created");

        let journal_id = [0x30; 32];
        let negative_leading_zero_dim_id = [0x31; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![108, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_leading_zero_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":-02,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(negative_leading_zero_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                negative_leading_zero_dim_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, negative_leading_zero_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-leading-zero journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_decimal_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-leading-decimal-dim-after-upsert",
            [0x01; 32],
            [108, 0],
            [0x02; 32],
            "\"dim\":.5,\"scale\":0,\"components\":[108,0]",
            "leading-decimal journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_decimal_dim_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-trailing-decimal-dim-after-upsert",
            [0x03; 32],
            [108, 0],
            [0x04; 32],
            "\"dim\":2.,\"scale\":0,\"components\":[108,0]",
            "trailing-decimal journal dim after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_exponent_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-exponent-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic exponent-journal-dim meta dir should be created");

        let journal_id = [0x94; 32];
        let exponent_dim_id = [0x95; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2e0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(exponent_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exponent journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_exponent_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-uppercase-exponent-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-exponent-journal-dim meta dir should be created");

        let journal_id = [0x98; 32];
        let exponent_dim_id = [0x99; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2E0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(exponent_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase exponent journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_signed_exponent_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-uppercase-signed-exponent-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-signed-exponent-journal-dim meta dir should be created");

        let journal_id = [0xaa; 32];
        let exponent_dim_id = [0xab; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2E+0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(exponent_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase signed exponent journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_negative_exponent_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-uppercase-negative-exponent-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-negative-exponent-journal-dim meta dir should be created");

        let journal_id = [0xb0; 32];
        let exponent_dim_id = [0xb1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2E-0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(exponent_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase negative exponent journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_signed_exponent_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-signed-exponent-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-exponent-journal-dim meta dir should be created");

        let journal_id = [0x9e; 32];
        let exponent_dim_id = [0x9f; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2e+0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(exponent_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "signed exponent journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_exponent_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-exponent-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-exponent-journal-dim meta dir should be created");

        let journal_id = [0xa4; 32];
        let exponent_dim_id = [0xa5; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![107, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_dim_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2e-0,\"scale\":0,\"components\":[108,0]}}",
            hex::encode(exponent_dim_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative exponent journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_out_of_range_dim_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-out-of-range-dim-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic out-of-range-journal-dim meta dir should be created");

        let journal_id = [0xe9; 32];
        let out_of_range_dim_id = [0xea; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![109, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let out_of_range_dim_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(out_of_range_dim_id),
            "dim": 4_294_967_296_u64,
            "scale": 0,
            "components": [110, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), out_of_range_dim_upsert.as_str()],
        );

        let live_ids = [journal_id, out_of_range_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "out-of-range journal dim after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-journal-scale meta dir should be created");

        let journal_id = [0xdb; 32];
        let boolean_scale_id = [0xdc; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![89, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(boolean_scale_id),
            "dim": 2,
            "scale": false,
            "components": [90, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, boolean_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_fractional_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-fractional-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic fractional-journal-scale meta dir should be created");

        let journal_id = [0xeb; 32];
        let fractional_scale_id = [0xec; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let fractional_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(fractional_scale_id),
            "dim": 2,
            "scale": 0.5,
            "components": [112, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), fractional_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, fractional_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "fractional journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_fractional_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-negative-fractional-scale-after-upsert",
            [0x3e; 32],
            [111, 0],
            [0x3f; 32],
            "\"dim\":2,\"scale\":-1.5,\"components\":[112,0]",
            "negative-fractional journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_fractional_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-fractional-scale-after-upsert",
            [0x4a; 32],
            [111, 0],
            [0x4b; 32],
            "\"dim\":2,\"scale\":+1.5,\"components\":[112,0]",
            "plus-fractional journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_zero_fraction_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-zero-fraction-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic zero-fraction-journal-scale meta dir should be created");

        let journal_id = [0xb8; 32];
        let zero_fraction_scale_id = [0xb9; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let zero_fraction_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0.0,\"components\":[112,0]}}",
            hex::encode(zero_fraction_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), zero_fraction_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, zero_fraction_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "zero-fraction journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-zero-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-journal-scale meta dir should be created");

        let journal_id = [0xbc; 32];
        let negative_zero_scale_id = [0xbd; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_zero_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":-0,\"components\":[112,0]}}",
            hex::encode(negative_zero_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), negative_zero_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, negative_zero_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_exponent_scale_after_valid_upsert() {
        for (case_name, token) in [("lowercase", "-0e0"), ("uppercase", "-0E0")] {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-negative-zero-exponent-scale-{case_name}-after-upsert"),
                [0x56; 32],
                [111, 0],
                [0x57; 32],
                &format!("\"dim\":2,\"scale\":{token},\"components\":[112,0]"),
                "negative-zero-exponent journal scale after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_exponent_scale_after_valid_upsert() {
        for (case_name, token) in [("lowercase", "+0e0"), ("uppercase", "+0E0")] {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-plus-zero-exponent-scale-{case_name}-after-upsert"),
                [0xa2; 32],
                [111, 0],
                [0xa3; 32],
                &format!("\"dim\":2,\"scale\":{token},\"components\":[112,0]"),
                "plus-zero-exponent journal scale after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-zero-scale-after-upsert",
            [0xba; 32],
            [111, 0],
            [0xbb; 32],
            "\"dim\":2,\"scale\":+0,\"components\":[112,0]",
            "plus-zero journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_fraction_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-zero-fraction-scale-after-upsert",
            [0x82; 32],
            [111, 0],
            [0x83; 32],
            "\"dim\":2,\"scale\":+0.0,\"components\":[112,0]",
            "plus-zero-fraction journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_fraction_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-zero-fraction-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-fraction-journal-scale meta dir should be created");

        let journal_id = [0xc9; 32];
        let negative_zero_fraction_scale_id = [0xca; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_zero_fraction_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":-0.0,\"components\":[112,0]}}",
            hex::encode(negative_zero_fraction_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                negative_zero_fraction_scale_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, negative_zero_fraction_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero-fraction journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_zero_fraction_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-trailing-zero-fraction-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-zero-fraction-journal-scale meta dir should be created");

        let journal_id = [0xcb; 32];
        let trailing_zero_fraction_scale_id = [0xcd; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let trailing_zero_fraction_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0.00,\"components\":[112,0]}}",
            hex::encode(trailing_zero_fraction_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                trailing_zero_fraction_scale_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, trailing_zero_fraction_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing-zero-fraction journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_lowercase_non_finite_scale_after_valid_upsert() {
        for (case_index, (case_name, token)) in [
            ("nan", "nan"),
            ("infinity", "infinity"),
            ("negative-infinity", "-infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-lowercase-non-finite-scale-after-upsert-{case_name}"),
                [0xd6 + case_index as u8; 32],
                [111, 0],
                [0xd9 + case_index as u8; 32],
                &format!("\"dim\":2,\"scale\":{token},\"components\":[112,0]"),
                "lowercase non-finite journal scale after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_non_finite_scale_after_valid_upsert() {
        for (case_index, (case_name, token)) in [
            ("nan", "NaN"),
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = SemanticLoadTestDir::new(&format!(
                "journal-non-finite-scale-after-upsert-{case_name}"
            ));
            let meta = dir.path().join("meta");
            fs::create_dir_all(&meta)
                .expect("semantic non-finite-journal-scale meta dir should be created");

            let journal_id = [0x20 + case_index as u8; 32];
            let non_finite_scale_id = [0x23 + case_index as u8; 32];
            let journal_embedding =
                FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
            let upsert_line =
                semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
            let non_finite_scale_upsert = format!(
                "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":{},\"components\":[112,0]}}",
                hex::encode(non_finite_scale_id),
                token
            );
            semantic_load_write_embedding_journal_lines(
                &meta,
                [upsert_line.as_str(), non_finite_scale_upsert.as_str()],
            );

            let live_ids = [journal_id, non_finite_scale_id];
            let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
                "non-finite journal scale after valid replay should reject whole semantic load",
            );

            assert_eq!(err, MnemeError::SchemaDrift, "{case_name}");
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_plus_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-leading-plus-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-plus-journal-scale meta dir should be created");

        let journal_id = [0x62; 32];
        let leading_plus_scale_id = [0x63; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let leading_plus_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":+0,\"components\":[112,0]}}",
            hex::encode(leading_plus_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), leading_plus_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, leading_plus_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-plus journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_zero_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-leading-zero-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-zero-journal-scale meta dir should be created");

        let journal_id = [0x73; 32];
        let leading_zero_scale_id = [0x74; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let leading_zero_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":00,\"components\":[112,0]}}",
            hex::encode(leading_zero_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), leading_zero_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, leading_zero_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-zero journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_leading_zero_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-leading-zero-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-leading-zero-journal-scale meta dir should be created");

        let journal_id = [0x32; 32];
        let negative_leading_zero_scale_id = [0x33; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_leading_zero_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":-00,\"components\":[112,0]}}",
            hex::encode(negative_leading_zero_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                negative_leading_zero_scale_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, negative_leading_zero_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-leading-zero journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_decimal_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-leading-decimal-scale-after-upsert",
            [0x05; 32],
            [111, 0],
            [0x06; 32],
            "\"dim\":2,\"scale\":.0,\"components\":[112,0]",
            "leading-decimal journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_decimal_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-trailing-decimal-scale-after-upsert",
            [0x07; 32],
            [111, 0],
            [0x08; 32],
            "\"dim\":2,\"scale\":0.,\"components\":[112,0]",
            "trailing-decimal journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_exponent_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-exponent-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic exponent-journal-scale meta dir should be created");

        let journal_id = [0x96; 32];
        let exponent_scale_id = [0x97; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0e0,\"components\":[112,0]}}",
            hex::encode(exponent_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exponent journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_exponent_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-uppercase-exponent-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-exponent-journal-scale meta dir should be created");

        let journal_id = [0x9a; 32];
        let exponent_scale_id = [0x9b; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0E0,\"components\":[112,0]}}",
            hex::encode(exponent_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase exponent journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_signed_exponent_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-uppercase-signed-exponent-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-signed-exponent-journal-scale meta dir should be created");

        let journal_id = [0xac; 32];
        let exponent_scale_id = [0xad; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0E+0,\"components\":[112,0]}}",
            hex::encode(exponent_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase signed exponent journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_negative_exponent_scale_after_valid_upsert() {
        let dir =
            SemanticLoadTestDir::new("journal-uppercase-negative-exponent-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic uppercase-negative-exponent-journal-scale meta dir should be created",
        );

        let journal_id = [0xb2; 32];
        let exponent_scale_id = [0xb3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0E-0,\"components\":[112,0]}}",
            hex::encode(exponent_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase negative exponent journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_signed_exponent_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-signed-exponent-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-exponent-journal-scale meta dir should be created");

        let journal_id = [0xa0; 32];
        let exponent_scale_id = [0xa1; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0e+0,\"components\":[112,0]}}",
            hex::encode(exponent_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "signed exponent journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_exponent_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-exponent-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-exponent-journal-scale meta dir should be created");

        let journal_id = [0xa6; 32];
        let exponent_scale_id = [0xa7; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![111, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_scale_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0e-0,\"components\":[112,0]}}",
            hex::encode(exponent_scale_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative exponent journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_out_of_range_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-out-of-range-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic out-of-range-journal-scale meta dir should be created");

        let journal_id = [0xed; 32];
        let out_of_range_scale_id = [0xee; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![113, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let out_of_range_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(out_of_range_scale_id),
            "dim": 2,
            "scale": 128,
            "components": [114, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), out_of_range_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, out_of_range_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "out-of-range journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_below_min_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-below-min-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic below-min-journal-scale meta dir should be created");

        let journal_id = [0x40; 32];
        let below_min_scale_id = [0x41; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![127, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let below_min_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(below_min_scale_id),
            "dim": 2,
            "scale": -129,
            "components": [128, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), below_min_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, below_min_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "below-min journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-null-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-journal-scale meta dir should be created");

        let journal_id = [0x4a; 32];
        let null_scale_id = [0x4b; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![137, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let null_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(null_scale_id),
            "dim": 2,
            "scale": null,
            "components": [138, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), null_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, null_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("null journal scale after valid replay should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-object-scale-after-upsert",
            [0x55; 32],
            [111, 0],
            [0x56; 32],
            "\"dim\":2,\"scale\":{},\"components\":[112,0]",
            "object-valued journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_array_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-array-scale-after-upsert",
            [0x57; 32],
            [111, 0],
            [0x58; 32],
            "\"dim\":2,\"scale\":[],\"components\":[112,0]",
            "array-valued journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_string_scale_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-numeric-string-scale-after-upsert",
            [0x33; 32],
            [111, 0],
            [0x34; 32],
            "\"dim\":2,\"scale\":\"0\",\"components\":[112,0]",
            "numeric-string journal scale after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_string_scale_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-string-scale-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic string-journal-scale meta dir should be created");

        let journal_id = [0xd3; 32];
        let string_scale_id = [0xd4; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![50, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let string_scale_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(string_scale_id),
            "dim": 2,
            "scale": "zero",
            "components": [51, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), string_scale_upsert.as_str()],
        );

        let live_ids = [journal_id, string_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "string journal scale after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_scalar_components_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-scalar-components-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic scalar-journal-components meta dir should be created");

        let journal_id = [0xd5; 32];
        let scalar_components_id = [0xd6; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![52, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let scalar_components_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(scalar_components_id),
            "dim": 2,
            "scale": 0,
            "components": 53,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), scalar_components_upsert.as_str()],
        );

        let live_ids = [journal_id, scalar_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "scalar journal components after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_components_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-null-components-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic null-journal-components meta dir should be created");

        let journal_id = [0x4c; 32];
        let null_components_id = [0x4d; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![139, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let null_components_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(null_components_id),
            "dim": 2,
            "scale": 0,
            "components": null,
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), null_components_upsert.as_str()],
        );

        let live_ids = [journal_id, null_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "null journal components after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_components_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-boolean-components-after-upsert",
            [0x69; 32],
            [139, 0],
            [0x6a; 32],
            "\"dim\":2,\"scale\":0,\"components\":true",
            "boolean journal components field after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_string_components_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-string-components-after-upsert",
            [0x6b; 32],
            [139, 0],
            [0x6c; 32],
            "\"dim\":2,\"scale\":0,\"components\":\"[139,0]\"",
            "string journal components field after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_components_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-object-components-after-upsert",
            [0x6d; 32],
            [139, 0],
            [0x6e; 32],
            "\"dim\":2,\"scale\":0,\"components\":{}",
            "object journal components field after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_null_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-null-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic null-journal-component meta dir should be created");

        let journal_id = [0x4e; 32];
        let null_component_id = [0x4f; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![141, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let null_component_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(null_component_id),
            "dim": 2,
            "scale": 0,
            "components": [null, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), null_component_upsert.as_str()],
        );

        let live_ids = [journal_id, null_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "null journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_boolean_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-boolean-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-journal-component meta dir should be created");

        let journal_id = [0xe1; 32];
        let boolean_component_id = [0xe2; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![95, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let boolean_component_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(boolean_component_id),
            "dim": 2,
            "scale": 0,
            "components": [true, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), boolean_component_upsert.as_str()],
        );

        let live_ids = [journal_id, boolean_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_fractional_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-fractional-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic fractional-journal-component meta dir should be created");

        let journal_id = [0xe3; 32];
        let fractional_component_id = [0xe4; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let fractional_component_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(fractional_component_id),
            "dim": 2,
            "scale": 0,
            "components": [1.5, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), fractional_component_upsert.as_str()],
        );

        let live_ids = [journal_id, fractional_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "fractional journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_fractional_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-negative-fractional-component-after-upsert",
            [0x40; 32],
            [99, 0],
            [0x41; 32],
            "\"dim\":2,\"scale\":0,\"components\":[-1.5,0]",
            "negative-fractional journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_fractional_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-fractional-component-after-upsert",
            [0x4c; 32],
            [99, 0],
            [0x4d; 32],
            "\"dim\":2,\"scale\":0,\"components\":[+1.5,0]",
            "plus-fractional journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_zero_fraction_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-zero-fraction-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic zero-fraction-journal-component meta dir should be created");

        let journal_id = [0xba; 32];
        let zero_fraction_component_id = [0xbb; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let zero_fraction_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1.0,0]}}",
            hex::encode(zero_fraction_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                zero_fraction_component_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, zero_fraction_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "zero-fraction journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-zero-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-journal-component meta dir should be created");

        let journal_id = [0xbe; 32];
        let negative_zero_component_id = [0xbf; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_zero_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[99,-0]}}",
            hex::encode(negative_zero_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                negative_zero_component_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, negative_zero_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_exponent_component_after_valid_upsert() {
        for (case_name, token) in [("lowercase", "-0e0"), ("uppercase", "-0E0")] {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-negative-zero-exponent-component-{case_name}-after-upsert"),
                [0x58; 32],
                [99, 0],
                [0x59; 32],
                &format!("\"dim\":2,\"scale\":0,\"components\":[{token},0]"),
                "negative-zero-exponent journal component after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_exponent_component_after_valid_upsert() {
        for (case_name, token) in [("lowercase", "+0e0"), ("uppercase", "+0E0")] {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-plus-zero-exponent-component-{case_name}-after-upsert"),
                [0xa4; 32],
                [99, 0],
                [0xa5; 32],
                &format!("\"dim\":2,\"scale\":0,\"components\":[{token},0]"),
                "plus-zero-exponent journal component after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-zero-component-after-upsert",
            [0xbc; 32],
            [99, 0],
            [0xbd; 32],
            "\"dim\":2,\"scale\":0,\"components\":[+0,0]",
            "plus-zero journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_plus_zero_fraction_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-plus-zero-fraction-component-after-upsert",
            [0x84; 32],
            [99, 0],
            [0x85; 32],
            "\"dim\":2,\"scale\":0,\"components\":[+0.0,0]",
            "plus-zero-fraction journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_zero_fraction_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-zero-fraction-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-fraction-journal-component meta dir should be created");

        let journal_id = [0xce; 32];
        let negative_zero_fraction_component_id = [0xcf; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_zero_fraction_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[99,-0.0]}}",
            hex::encode(negative_zero_fraction_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                negative_zero_fraction_component_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, negative_zero_fraction_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero-fraction journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_zero_fraction_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-trailing-zero-fraction-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-zero-fraction-journal-component meta dir should be created");

        let journal_id = [0xd0; 32];
        let trailing_zero_fraction_component_id = [0xde; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let trailing_zero_fraction_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1.00,0]}}",
            hex::encode(trailing_zero_fraction_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                trailing_zero_fraction_component_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, trailing_zero_fraction_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing-zero-fraction journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_lowercase_non_finite_component_after_valid_upsert() {
        for (case_index, (case_name, token)) in [
            ("nan", "nan"),
            ("infinity", "infinity"),
            ("negative-infinity", "-infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            semantic_load_expect_raw_journal_embedding_fields_schema_drift(
                &format!("journal-lowercase-non-finite-component-after-upsert-{case_name}"),
                [0xdc + case_index as u8; 32],
                [99, 0],
                [0xdf + case_index as u8; 32],
                &format!("\"dim\":2,\"scale\":0,\"components\":[99,{token}]"),
                "lowercase non-finite journal component after valid replay should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_non_finite_component_after_valid_upsert() {
        for (case_index, (case_name, token)) in [
            ("nan", "NaN"),
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = SemanticLoadTestDir::new(&format!(
                "journal-non-finite-component-after-upsert-{case_name}"
            ));
            let meta = dir.path().join("meta");
            fs::create_dir_all(&meta)
                .expect("semantic non-finite-journal-component meta dir should be created");

            let journal_id = [0x26 + case_index as u8; 32];
            let non_finite_component_id = [0x29 + case_index as u8; 32];
            let journal_embedding =
                FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
            let upsert_line =
                semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
            let non_finite_component_upsert = format!(
                "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[99,{}]}}",
                hex::encode(non_finite_component_id),
                token
            );
            semantic_load_write_embedding_journal_lines(
                &meta,
                [upsert_line.as_str(), non_finite_component_upsert.as_str()],
            );

            let live_ids = [journal_id, non_finite_component_id];
            let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
                "non-finite journal component after valid replay should reject whole semantic load",
            );

            assert_eq!(err, MnemeError::SchemaDrift, "{case_name}");
        }
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_plus_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-leading-plus-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-plus-journal-component meta dir should be created");

        let journal_id = [0x64; 32];
        let leading_plus_component_id = [0x65; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let leading_plus_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[99,+1]}}",
            hex::encode(leading_plus_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), leading_plus_component_upsert.as_str()],
        );

        let live_ids = [journal_id, leading_plus_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-plus journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_zero_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-leading-zero-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-zero-journal-component meta dir should be created");

        let journal_id = [0x75; 32];
        let leading_zero_component_id = [0x76; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let leading_zero_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[99,01]}}",
            hex::encode(leading_zero_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), leading_zero_component_upsert.as_str()],
        );

        let live_ids = [journal_id, leading_zero_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-zero journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_leading_zero_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-leading-zero-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-leading-zero-journal-component meta dir should be created");

        let journal_id = [0x34; 32];
        let negative_leading_zero_component_id = [0x35; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let negative_leading_zero_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[99,-01]}}",
            hex::encode(negative_leading_zero_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [
                upsert_line.as_str(),
                negative_leading_zero_component_upsert.as_str(),
            ],
        );

        let live_ids = [journal_id, negative_leading_zero_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-leading-zero journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_leading_decimal_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-leading-decimal-component-after-upsert",
            [0x09; 32],
            [99, 0],
            [0x0a; 32],
            "\"dim\":2,\"scale\":0,\"components\":[99,.1]",
            "leading-decimal journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_trailing_decimal_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-trailing-decimal-component-after-upsert",
            [0x0b; 32],
            [99, 0],
            [0x0c; 32],
            "\"dim\":2,\"scale\":0,\"components\":[99,1.]",
            "trailing-decimal journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_exponent_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-exponent-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic exponent-journal-component meta dir should be created");

        let journal_id = [0x92; 32];
        let exponent_component_id = [0x93; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1e0,0]}}",
            hex::encode(exponent_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_component_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exponent journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_exponent_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-uppercase-exponent-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-exponent-journal-component meta dir should be created");

        let journal_id = [0x9c; 32];
        let exponent_component_id = [0x9d; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1E0,0]}}",
            hex::encode(exponent_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_component_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase exponent journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_signed_exponent_component_after_valid_upsert()
    {
        let dir =
            SemanticLoadTestDir::new("journal-uppercase-signed-exponent-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic uppercase-signed-exponent-journal-component meta dir should be created",
        );

        let journal_id = [0xae; 32];
        let exponent_component_id = [0xaf; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1E+0,0]}}",
            hex::encode(exponent_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_component_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase signed exponent journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_uppercase_negative_exponent_component_after_valid_upsert()
     {
        let dir =
            SemanticLoadTestDir::new("journal-uppercase-negative-exponent-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic uppercase-negative-exponent-journal-component meta dir should be created",
        );

        let journal_id = [0xb4; 32];
        let exponent_component_id = [0xb5; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1E-0,0]}}",
            hex::encode(exponent_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_component_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase negative exponent journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_signed_exponent_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-signed-exponent-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-exponent-journal-component meta dir should be created");

        let journal_id = [0xa2; 32];
        let exponent_component_id = [0xa3; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1e+0,0]}}",
            hex::encode(exponent_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_component_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "signed exponent journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_negative_exponent_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-negative-exponent-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-exponent-journal-component meta dir should be created");

        let journal_id = [0xa8; 32];
        let exponent_component_id = [0xa9; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![99, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let exponent_component_upsert = format!(
            "{{\"op\":\"upsert\",\"id\":\"{}\",\"dim\":2,\"scale\":0,\"components\":[1e-0,0]}}",
            hex::encode(exponent_component_id)
        );
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), exponent_component_upsert.as_str()],
        );

        let live_ids = [journal_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative exponent journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_out_of_range_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-out-of-range-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic out-of-range-journal-component meta dir should be created");

        let journal_id = [0xe5; 32];
        let out_of_range_component_id = [0xe6; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![101, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let out_of_range_component_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(out_of_range_component_id),
            "dim": 2,
            "scale": 0,
            "components": [32768, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), out_of_range_component_upsert.as_str()],
        );

        let live_ids = [journal_id, out_of_range_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "out-of-range journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_below_min_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-below-min-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic below-min-journal-component meta dir should be created");

        let journal_id = [0x42; 32];
        let below_min_component_id = [0x43; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![129, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let below_min_component_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(below_min_component_id),
            "dim": 2,
            "scale": 0,
            "components": [-32769, 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), below_min_component_upsert.as_str()],
        );

        let live_ids = [journal_id, below_min_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "below-min journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_journal_replay_rejects_object_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-object-component-after-upsert",
            [0x59; 32],
            [99, 0],
            [0x5a; 32],
            "\"dim\":2,\"scale\":0,\"components\":[{},0]",
            "object-valued journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_array_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-array-component-after-upsert",
            [0x5b; 32],
            [99, 0],
            [0x5c; 32],
            "\"dim\":2,\"scale\":0,\"components\":[[],0]",
            "array-valued journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_numeric_string_component_after_valid_upsert() {
        semantic_load_expect_raw_journal_embedding_fields_schema_drift(
            "journal-numeric-string-component-after-upsert",
            [0x35; 32],
            [99, 0],
            [0x36; 32],
            "\"dim\":2,\"scale\":0,\"components\":[\"99\",0]",
            "numeric-string journal component after valid replay should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_journal_replay_rejects_string_component_after_valid_upsert() {
        let dir = SemanticLoadTestDir::new("journal-string-component-after-upsert");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic string-journal-component meta dir should be created");

        let journal_id = [0xd7; 32];
        let string_component_id = [0xd8; 32];
        let journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![54, 0]).expect("valid journal embedding");
        let upsert_line =
            semantic_load_journal_upsert_json(journal_id, &journal_embedding).to_string();
        let string_component_upsert = serde_json::json!({
            "op": "upsert",
            "id": hex::encode(string_component_id),
            "dim": 2,
            "scale": 0,
            "components": ["55", 0],
        })
        .to_string();
        semantic_load_write_embedding_journal_lines(
            &meta,
            [upsert_line.as_str(), string_component_upsert.as_str()],
        );

        let live_ids = [journal_id, string_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "string journal component after valid replay should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_non_object_entries_value() {
        semantic_load_expect_snapshot_entries_value_schema_drift(
            "snapshot-non-object-entries",
            serde_json::json!([]),
            "non-object snapshot entries value should reject instead of loading empty state",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_entries_value() {
        semantic_load_expect_snapshot_entries_value_schema_drift(
            "snapshot-boolean-entries",
            serde_json::json!(true),
            "boolean snapshot entries value should reject instead of loading empty state",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_numeric_entries_value() {
        semantic_load_expect_snapshot_entries_value_schema_drift(
            "snapshot-numeric-entries",
            serde_json::json!(42),
            "numeric snapshot entries value should reject instead of loading empty state",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_string_entries_value() {
        semantic_load_expect_snapshot_entries_value_schema_drift(
            "snapshot-string-entries",
            serde_json::json!("not-entries"),
            "string snapshot entries value should reject instead of loading empty state",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_null_entries_value() {
        semantic_load_expect_snapshot_entries_value_schema_drift(
            "snapshot-null-entries",
            serde_json::Value::Null,
            "null snapshot entries value should reject instead of loading empty state",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_missing_entries_field() {
        let dir = SemanticLoadTestDir::new("snapshot-missing-entries");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-snapshot-entries meta dir should be created");

        semantic_load_write_embedding_snapshot_document(&meta, serde_json::json!({}));

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>()).expect_err(
            "missing snapshot entries field should reject instead of using sidecar default",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_malformed_document() {
        let dir = SemanticLoadTestDir::new("snapshot-malformed-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-snapshot-document meta dir should be created");

        semantic_load_write_embedding_snapshot_raw(&meta, "{\"entries\":{");

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("malformed snapshot document should reject instead of loading empty state");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_junk_after_valid_document() {
        let dir = SemanticLoadTestDir::new("snapshot-trailing-junk-after-valid-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-junk-snapshot-document meta dir should be created");

        let valid_id = [0x50; 32];
        let snapshot = format!(
            "{{\"entries\":{{\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[170,0]}}}}}} trailing-junk",
            hex::encode(valid_id),
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("trailing junk after valid snapshot document should reject semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_array_document() {
        let dir = SemanticLoadTestDir::new("snapshot-array-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic array-snapshot meta dir should be created");

        semantic_load_write_embedding_snapshot_document(&meta, serde_json::json!([]));

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("array snapshot document should reject instead of loading empty state");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_document() {
        let dir = SemanticLoadTestDir::new("snapshot-boolean-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic boolean-snapshot meta dir should be created");

        semantic_load_write_embedding_snapshot_document(&meta, serde_json::json!(true));

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("boolean snapshot document should reject instead of loading empty state");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_null_document() {
        let dir = SemanticLoadTestDir::new("snapshot-null-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-snapshot meta dir should be created");

        semantic_load_write_embedding_snapshot_document(&meta, serde_json::Value::Null);

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("null snapshot document should reject instead of loading empty state");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_numeric_document() {
        let dir = SemanticLoadTestDir::new("snapshot-numeric-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic numeric-snapshot meta dir should be created");

        semantic_load_write_embedding_snapshot_document(&meta, serde_json::json!(42));

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("numeric snapshot document should reject instead of loading empty state");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_scalar_document() {
        let dir = SemanticLoadTestDir::new("snapshot-scalar-document");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic scalar-snapshot meta dir should be created");

        semantic_load_write_embedding_snapshot_document(
            &meta,
            serde_json::Value::String("not-a-snapshot".to_owned()),
        );

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("scalar snapshot document should reject instead of loading empty state");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_malformed_entry_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-malformed-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic malformed-snapshot meta dir should be created");

        let valid_id = [0x99; 32];
        let malformed_id = [0xaa; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![9, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(malformed_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed snapshot entry beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_non_object_entry_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-non-object-entry-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic non-object-snapshot-entry meta dir should be created");

        let valid_id = [0xa1; 32];
        let non_object_entry_id = [0xa2; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![10, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(hex::encode(non_object_entry_id), serde_json::Value::Null);
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "non-object snapshot entry beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_array_entry_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-array-entry-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic array-snapshot-entry meta dir should be created");

        let valid_id = [0xa3; 32];
        let array_entry_id = [0xa4; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![13, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(hex::encode(array_entry_id), serde_json::json!([]));
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "array snapshot entry beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_entry_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-boolean-entry-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-snapshot-entry meta dir should be created");

        let valid_id = [0xa7; 32];
        let boolean_entry_id = [0xa8; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![15, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(hex::encode(boolean_entry_id), serde_json::json!(true));
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean snapshot entry beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_numeric_entry_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-numeric-entry-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic numeric-snapshot-entry meta dir should be created");

        let valid_id = [0xa9; 32];
        let numeric_entry_id = [0xaa; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![16, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(hex::encode(numeric_entry_id), serde_json::json!(42));
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "numeric snapshot entry beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_scalar_entry_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-scalar-entry-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic scalar-snapshot-entry meta dir should be created");

        let valid_id = [0xa5; 32];
        let scalar_entry_id = [0xa6; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![14, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(scalar_entry_id),
            serde_json::Value::String("not-an-entry".to_owned()),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "scalar snapshot entry beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_malformed_id_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-malformed-id-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-snapshot-id meta dir should be created");

        let valid_id = [0xbb; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![11, 0]).expect("valid snapshot embedding");
        let malformed_id = "not-a-hex-object-id";
        let malformed_embedding =
            FixedPointEmbedding::new(2, 0, vec![12, 0]).expect("valid malformed-id embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            malformed_id.to_string(),
            semantic_load_embedding_entry_json(&malformed_embedding),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed snapshot id beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_short_id_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-short-id-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic short-snapshot-id meta dir should be created");

        let valid_id = [0x81; 32];
        let short_id = "ab".repeat(31);
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![64, 0]).expect("valid snapshot embedding");
        let short_id_embedding =
            FixedPointEmbedding::new(2, 0, vec![65, 0]).expect("valid short-id embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            short_id,
            semantic_load_embedding_entry_json(&short_id_embedding),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("short snapshot id beside valid entry should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_long_id_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-long-id-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic long-snapshot-id meta dir should be created");

        let valid_id = [0x82; 32];
        let long_id = "cd".repeat(33);
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![66, 0]).expect("valid snapshot embedding");
        let long_id_embedding =
            FixedPointEmbedding::new(2, 0, vec![67, 0]).expect("valid long-id embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            long_id,
            semantic_load_embedding_entry_json(&long_id_embedding),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("long snapshot id beside valid entry should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_non_hex_digit_id_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-non-hex-digit-id-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic non-hex-digit-snapshot-id meta dir should be created");

        let valid_id = [0x84; 32];
        let non_hex_digit_id = format!("{}g", "a".repeat(63));
        assert_eq!(non_hex_digit_id.len(), 64);
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![70, 0]).expect("valid snapshot embedding");
        let non_hex_digit_embedding =
            FixedPointEmbedding::new(2, 0, vec![71, 0]).expect("valid non-hex-id embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            non_hex_digit_id,
            semantic_load_embedding_entry_json(&non_hex_digit_embedding),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exact-length non-hex digit snapshot id beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_multibyte_id_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-multibyte-id-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic multibyte-snapshot-id meta dir should be created");

        let valid_id = [0x83; 32];
        let multibyte_id =
            String::from_utf8(vec![0xe2, 0x98, 0x83]).expect("valid UTF-8 multibyte key");
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![68, 0]).expect("valid snapshot embedding");
        let multibyte_id_embedding =
            FixedPointEmbedding::new(2, 0, vec![69, 0]).expect("valid multibyte-id embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            multibyte_id,
            semantic_load_embedding_entry_json(&multibyte_id_embedding),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "multibyte snapshot id beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_malformed_shape_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-malformed-shape-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic malformed-snapshot-shape meta dir should be created");

        let valid_id = [0xf2; 32];
        let malformed_shape_id = [0xf3; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![21, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(malformed_shape_id),
            serde_json::json!({
                "dim": 3,
                "scale": 0,
                "components": [22, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, malformed_shape_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "malformed snapshot embedding shape beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_short_components_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-short-components-beside-valid",
            [0x47; 32],
            [21, 0],
            [0x48; 32],
            "\"dim\":2,\"scale\":0,\"components\":[22]",
            "short component vector snapshot beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_long_components_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-long-components-beside-valid",
            [0x49; 32],
            [21, 0],
            [0x4a; 32],
            "\"dim\":2,\"scale\":0,\"components\":[22,0,1]",
            "long component vector snapshot beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_empty_components_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-empty-components-beside-valid",
            [0x4b; 32],
            [21, 0],
            [0x4c; 32],
            "\"dim\":2,\"scale\":0,\"components\":[]",
            "empty component vector snapshot beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_duplicate_entry_key_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-duplicate-entry-key-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-snapshot-entry-key meta dir should be created");

        let valid_id = [0x3c; 32];
        let duplicate_entry_id = [0x3d; 32];
        let snapshot = format!(
            "{{\"entries\":{{\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[153,0]}},\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[154,0]}},\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[155,0]}}}}}}",
            hex::encode(valid_id),
            hex::encode(duplicate_entry_id),
            hex::encode(duplicate_entry_id),
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, duplicate_entry_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate snapshot entry key beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_duplicate_entries_field() {
        let dir = SemanticLoadTestDir::new("snapshot-duplicate-entries-field");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-snapshot-entries-field meta dir should be created");

        let valid_id = [0x48; 32];
        let shadow_id = [0x49; 32];
        let snapshot = format!(
            "{{\"entries\":{{\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[161,0]}}}},\"entries\":{{\"{}\":{{\"dim\":2,\"scale\":0,\"components\":[162,0]}}}}}}",
            hex::encode(valid_id),
            hex::encode(shadow_id),
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, shadow_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("duplicate snapshot entries field should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_duplicate_entry_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-duplicate-entry-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-snapshot-entry-dim meta dir should be created");

        let valid_id = [0x4a; 32];
        let duplicate_dim_id = [0x4b; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [163, 0],
            duplicate_dim_id,
            "{\"dim\":2,\"dim\":3,\"scale\":0,\"components\":[164,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, duplicate_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate snapshot entry dim field beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_duplicate_entry_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-duplicate-entry-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-snapshot-entry-scale meta dir should be created");

        let valid_id = [0x4c; 32];
        let duplicate_scale_id = [0x4d; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [165, 0],
            duplicate_scale_id,
            "{\"dim\":2,\"scale\":0,\"scale\":1,\"components\":[166,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, duplicate_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate snapshot entry scale field beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_duplicate_entry_components_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-duplicate-entry-components-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic duplicate-snapshot-entry-components meta dir should be created");

        let valid_id = [0x4e; 32];
        let duplicate_components_id = [0x4f; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [167, 0],
            duplicate_components_id,
            "{\"dim\":2,\"scale\":0,\"components\":[168,0],\"components\":[169,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, duplicate_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "duplicate snapshot entry components field beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_missing_entry_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-missing-entry-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-snapshot-entry-dim meta dir should be created");

        let valid_id = [0x79; 32];
        let missing_dim_id = [0x7a; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![70, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(missing_dim_id),
            serde_json::json!({
                "scale": 0,
                "components": [71, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, missing_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing snapshot entry dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_missing_entry_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-missing-entry-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-snapshot-entry-scale meta dir should be created");

        let valid_id = [0x7b; 32];
        let missing_scale_id = [0x7c; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![72, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(missing_scale_id),
            serde_json::json!({
                "dim": 2,
                "components": [73, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, missing_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing snapshot entry scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_missing_entry_components_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-missing-entry-components-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic missing-snapshot-entry-components meta dir should be created");

        let valid_id = [0x7d; 32];
        let missing_components_id = [0x7e; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![74, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(missing_components_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, missing_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "missing snapshot entry components beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-boolean-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-snapshot-dim meta dir should be created");

        let valid_id = [0x71; 32];
        let boolean_dim_id = [0x72; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![56, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(boolean_dim_id),
            serde_json::json!({
                "dim": true,
                "scale": 0,
                "components": [57, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, boolean_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_object_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-object-dim-beside-valid",
            [0x5d; 32],
            [116, 0],
            [0x5e; 32],
            "\"dim\":{},\"scale\":0,\"components\":[116,0]",
            "object-valued snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_array_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-array-dim-beside-valid",
            [0x5f; 32],
            [116, 0],
            [0x60; 32],
            "\"dim\":[],\"scale\":0,\"components\":[116,0]",
            "array-valued snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_numeric_string_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-numeric-string-dim-beside-valid",
            [0x37; 32],
            [116, 0],
            [0x38; 32],
            "\"dim\":\"2\",\"scale\":0,\"components\":[116,0]",
            "numeric-string snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_string_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-string-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic string-snapshot-dim meta dir should be created");

        let valid_id = [0x61; 32];
        let string_dim_id = [0x62; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![91, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(string_dim_id),
            serde_json::json!({
                "dim": "two",
                "scale": 0,
                "components": [92, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, string_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("string snapshot dim beside valid entry should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_null_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-null-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-snapshot-dim meta dir should be created");

        let valid_id = [0x30; 32];
        let null_dim_id = [0x31; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![143, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(null_dim_id),
            serde_json::json!({
                "dim": null,
                "scale": 0,
                "components": [144, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, null_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("null snapshot dim beside valid entry should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-snapshot-dim meta dir should be created");

        let valid_id = [0x59; 32];
        let negative_dim_id = [0x5a; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![125, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(negative_dim_id),
            serde_json::json!({
                "dim": -1,
                "scale": 0,
                "components": [126, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, negative_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_fractional_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-fractional-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic fractional-snapshot-dim meta dir should be created");

        let valid_id = [0x51; 32];
        let fractional_dim_id = [0x52; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![115, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(fractional_dim_id),
            serde_json::json!({
                "dim": 2.5,
                "scale": 0,
                "components": [116, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, fractional_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "fractional snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_fractional_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-negative-fractional-dim-beside-valid",
            [0x42; 32],
            [115, 0],
            [0x43; 32],
            "\"dim\":-1.5,\"scale\":0,\"components\":[116,0]",
            "negative-fractional snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_fractional_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-fractional-dim-beside-valid",
            [0x4e; 32],
            [115, 0],
            [0x4f; 32],
            "\"dim\":+1.5,\"scale\":0,\"components\":[116,0]",
            "plus-fractional snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-negative-zero-dim-beside-valid",
            [0xb4; 32],
            [115, 0],
            [0xb5; 32],
            "\"dim\":-0,\"scale\":0,\"components\":[116,0]",
            "negative-zero snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_exponent_dim_beside_valid_entry() {
        for (case_name, token) in [("lowercase", "-0e0"), ("uppercase", "-0E0")] {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-negative-zero-exponent-dim-{case_name}-beside-valid"),
                [0x5b; 32],
                [115, 0],
                [0x5c; 32],
                &format!("\"dim\":{token},\"scale\":0,\"components\":[116,0]"),
                "negative-zero-exponent snapshot dim beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_fraction_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-negative-zero-fraction-dim-beside-valid",
            [0xb6; 32],
            [115, 0],
            [0xb7; 32],
            "\"dim\":-0.0,\"scale\":0,\"components\":[116,0]",
            "negative-zero-fraction snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_exponent_dim_beside_valid_entry() {
        for (case_name, token) in [("lowercase", "+0e0"), ("uppercase", "+0E0")] {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-plus-zero-exponent-dim-{case_name}-beside-valid"),
                [0xa6; 32],
                [115, 0],
                [0xa7; 32],
                &format!("\"dim\":{token},\"scale\":0,\"components\":[116,0]"),
                "plus-zero-exponent snapshot dim beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-zero-dim-beside-valid",
            [0xbe; 32],
            [115, 0],
            [0xbf; 32],
            "\"dim\":+0,\"scale\":0,\"components\":[116,0]",
            "plus-zero snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_fraction_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-zero-fraction-dim-beside-valid",
            [0x86; 32],
            [115, 0],
            [0x87; 32],
            "\"dim\":+0.0,\"scale\":0,\"components\":[116,0]",
            "plus-zero-fraction snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_zero_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-zero-dim-beside-valid",
            [0xea; 32],
            [115, 0],
            [0xeb; 32],
            "\"dim\":0,\"scale\":0,\"components\":[]",
            "zero-dim snapshot embedding beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_zero_fraction_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-zero-fraction-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic zero-fraction-snapshot-dim meta dir should be created");

        let valid_id = [0x93; 32];
        let zero_fraction_dim_id = [0x94; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            zero_fraction_dim_id,
            "{\"dim\":2.0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, zero_fraction_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "zero-fraction snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_zero_fraction_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-trailing-zero-fraction-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-zero-fraction-snapshot-dim meta dir should be created");

        let valid_id = [0x1a; 32];
        let trailing_zero_fraction_dim_id = [0x1b; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            trailing_zero_fraction_dim_id,
            "{\"dim\":2.00,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, trailing_zero_fraction_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing-zero-fraction snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_lowercase_non_finite_dim_beside_valid_entry() {
        for (case_index, (case_name, token)) in [
            ("nan", "nan"),
            ("infinity", "infinity"),
            ("negative-infinity", "-infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-lowercase-non-finite-dim-beside-valid-{case_name}"),
                [0xe2 + case_index as u8; 32],
                [116, 0],
                [0xe5 + case_index as u8; 32],
                &format!("\"dim\":{token},\"scale\":0,\"components\":[116,0]"),
                "lowercase non-finite snapshot dim beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_non_finite_dim_beside_valid_entry() {
        for (case_index, (case_name, token)) in [
            ("nan", "NaN"),
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = SemanticLoadTestDir::new(&format!(
                "snapshot-non-finite-dim-beside-valid-{case_name}"
            ));
            let meta = dir.path().join("meta");
            fs::create_dir_all(&meta)
                .expect("semantic non-finite-snapshot-dim meta dir should be created");

            let valid_id = [0x2c + case_index as u8; 32];
            let non_finite_dim_id = [0x2f + case_index as u8; 32];
            let raw_entry = format!("{{\"dim\":{},\"scale\":0,\"components\":[116,0]}}", token);
            let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
                valid_id,
                [115, 0],
                non_finite_dim_id,
                &raw_entry,
            );
            semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

            let live_ids = [valid_id, non_finite_dim_id];
            let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
                "non-finite snapshot dim beside valid entry should reject whole semantic load",
            );

            assert_eq!(err, MnemeError::SchemaDrift, "{case_name}");
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_plus_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-leading-plus-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-plus-snapshot-dim meta dir should be created");

        let valid_id = [0x66; 32];
        let leading_plus_dim_id = [0x67; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            leading_plus_dim_id,
            "{\"dim\":+2,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, leading_plus_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-plus snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_zero_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-leading-zero-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-zero-snapshot-dim meta dir should be created");

        let valid_id = [0x77; 32];
        let leading_zero_dim_id = [0x78; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            leading_zero_dim_id,
            "{\"dim\":02,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, leading_zero_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-zero snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_leading_zero_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-leading-zero-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-leading-zero-snapshot-dim meta dir should be created");

        let valid_id = [0x36; 32];
        let negative_leading_zero_dim_id = [0x37; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            negative_leading_zero_dim_id,
            "{\"dim\":-02,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_leading_zero_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-leading-zero snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_decimal_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-leading-decimal-dim-beside-valid",
            [0x0d; 32],
            [115, 0],
            [0x0e; 32],
            "\"dim\":.5,\"scale\":0,\"components\":[116,0]",
            "leading-decimal snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_decimal_dim_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-trailing-decimal-dim-beside-valid",
            [0x0f; 32],
            [115, 0],
            [0x10; 32],
            "\"dim\":2.,\"scale\":0,\"components\":[116,0]",
            "trailing-decimal snapshot dim beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_exponent_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-exponent-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic exponent-snapshot-dim meta dir should be created");

        let valid_id = [0x6d; 32];
        let exponent_dim_id = [0x6e; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            exponent_dim_id,
            "{\"dim\":2e0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exponent snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_exponent_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-uppercase-exponent-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-exponent-snapshot-dim meta dir should be created");

        let valid_id = [0x71; 32];
        let exponent_dim_id = [0x72; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            exponent_dim_id,
            "{\"dim\":2E0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase exponent snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_signed_exponent_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-uppercase-signed-exponent-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-signed-exponent-snapshot-dim meta dir should be created");

        let valid_id = [0x87; 32];
        let exponent_dim_id = [0x88; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            exponent_dim_id,
            "{\"dim\":2E+0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase signed exponent snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_negative_exponent_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-uppercase-negative-exponent-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-negative-exponent-snapshot-dim meta dir should be created");

        let valid_id = [0x89; 32];
        let exponent_dim_id = [0x8a; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            exponent_dim_id,
            "{\"dim\":2E-0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase negative exponent snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_signed_exponent_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-signed-exponent-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-exponent-snapshot-dim meta dir should be created");

        let valid_id = [0x7b; 32];
        let exponent_dim_id = [0x7c; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            exponent_dim_id,
            "{\"dim\":2e+0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "signed exponent snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_exponent_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-exponent-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-exponent-snapshot-dim meta dir should be created");

        let valid_id = [0x81; 32];
        let exponent_dim_id = [0x82; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [115, 0],
            exponent_dim_id,
            "{\"dim\":2e-0,\"scale\":0,\"components\":[116,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative exponent snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_out_of_range_dim_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-out-of-range-dim-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic out-of-range-snapshot-dim meta dir should be created");

        let valid_id = [0x53; 32];
        let out_of_range_dim_id = [0x54; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![117, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(out_of_range_dim_id),
            serde_json::json!({
                "dim": 4_294_967_296_u64,
                "scale": 0,
                "components": [118, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, out_of_range_dim_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "out-of-range snapshot dim beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-boolean-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-snapshot-scale meta dir should be created");

        let valid_id = [0x63; 32];
        let boolean_scale_id = [0x64; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![93, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(boolean_scale_id),
            serde_json::json!({
                "dim": 2,
                "scale": true,
                "components": [94, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, boolean_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_fractional_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-fractional-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic fractional-snapshot-scale meta dir should be created");

        let valid_id = [0x55; 32];
        let fractional_scale_id = [0x56; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![119, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(fractional_scale_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0.5,
                "components": [120, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, fractional_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "fractional snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_fractional_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-negative-fractional-scale-beside-valid",
            [0x44; 32],
            [119, 0],
            [0x45; 32],
            "\"dim\":2,\"scale\":-1.5,\"components\":[120,0]",
            "negative-fractional snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_fractional_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-fractional-scale-beside-valid",
            [0x50; 32],
            [119, 0],
            [0x51; 32],
            "\"dim\":2,\"scale\":+1.5,\"components\":[120,0]",
            "plus-fractional snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_zero_fraction_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-zero-fraction-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic zero-fraction-snapshot-scale meta dir should be created");

        let valid_id = [0x95; 32];
        let zero_fraction_scale_id = [0x96; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            zero_fraction_scale_id,
            "{\"dim\":2,\"scale\":0.0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, zero_fraction_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "zero-fraction snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-zero-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-snapshot-scale meta dir should be created");

        let valid_id = [0xc5; 32];
        let negative_zero_scale_id = [0xc6; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            negative_zero_scale_id,
            "{\"dim\":2,\"scale\":-0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_zero_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_exponent_scale_beside_valid_entry() {
        for (case_name, token) in [("lowercase", "-0e0"), ("uppercase", "-0E0")] {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-negative-zero-exponent-scale-{case_name}-beside-valid"),
                [0x5d; 32],
                [119, 0],
                [0x5e; 32],
                &format!("\"dim\":2,\"scale\":{token},\"components\":[120,0]"),
                "negative-zero-exponent snapshot scale beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_exponent_scale_beside_valid_entry() {
        for (case_name, token) in [("lowercase", "+0e0"), ("uppercase", "+0E0")] {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-plus-zero-exponent-scale-{case_name}-beside-valid"),
                [0xa8; 32],
                [119, 0],
                [0xa9; 32],
                &format!("\"dim\":2,\"scale\":{token},\"components\":[120,0]"),
                "plus-zero-exponent snapshot scale beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-zero-scale-beside-valid",
            [0xc0; 32],
            [119, 0],
            [0xc1; 32],
            "\"dim\":2,\"scale\":+0,\"components\":[120,0]",
            "plus-zero snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_fraction_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-zero-fraction-scale-beside-valid",
            [0x88; 32],
            [119, 0],
            [0x89; 32],
            "\"dim\":2,\"scale\":+0.0,\"components\":[120,0]",
            "plus-zero-fraction snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_fraction_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-zero-fraction-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-fraction-snapshot-scale meta dir should be created");

        let valid_id = [0x12; 32];
        let negative_zero_fraction_scale_id = [0x13; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            negative_zero_fraction_scale_id,
            "{\"dim\":2,\"scale\":-0.0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_zero_fraction_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero-fraction snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_zero_fraction_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-trailing-zero-fraction-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic trailing-zero-fraction-snapshot-scale meta dir should be created");

        let valid_id = [0x14; 32];
        let trailing_zero_fraction_scale_id = [0x15; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            trailing_zero_fraction_scale_id,
            "{\"dim\":2,\"scale\":0.00,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, trailing_zero_fraction_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing-zero-fraction snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_lowercase_non_finite_scale_beside_valid_entry() {
        for (case_index, (case_name, token)) in [
            ("nan", "nan"),
            ("infinity", "infinity"),
            ("negative-infinity", "-infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-lowercase-non-finite-scale-beside-valid-{case_name}"),
                [0xe8 + case_index as u8; 32],
                [119, 0],
                [0xeb + case_index as u8; 32],
                &format!("\"dim\":2,\"scale\":{token},\"components\":[120,0]"),
                "lowercase non-finite snapshot scale beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_non_finite_scale_beside_valid_entry() {
        for (case_index, (case_name, token)) in [
            ("nan", "NaN"),
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = SemanticLoadTestDir::new(&format!(
                "snapshot-non-finite-scale-beside-valid-{case_name}"
            ));
            let meta = dir.path().join("meta");
            fs::create_dir_all(&meta)
                .expect("semantic non-finite-snapshot-scale meta dir should be created");

            let valid_id = [0x50 + case_index as u8; 32];
            let non_finite_scale_id = [0x53 + case_index as u8; 32];
            let raw_entry = format!("{{\"dim\":2,\"scale\":{},\"components\":[120,0]}}", token);
            let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
                valid_id,
                [119, 0],
                non_finite_scale_id,
                &raw_entry,
            );
            semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

            let live_ids = [valid_id, non_finite_scale_id];
            let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
                "non-finite snapshot scale beside valid entry should reject whole semantic load",
            );

            assert_eq!(err, MnemeError::SchemaDrift, "{case_name}");
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_plus_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-leading-plus-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-plus-snapshot-scale meta dir should be created");

        let valid_id = [0x68; 32];
        let leading_plus_scale_id = [0x69; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            leading_plus_scale_id,
            "{\"dim\":2,\"scale\":+0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, leading_plus_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-plus snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_zero_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-leading-zero-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-zero-snapshot-scale meta dir should be created");

        let valid_id = [0x7b; 32];
        let leading_zero_scale_id = [0x7c; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            leading_zero_scale_id,
            "{\"dim\":2,\"scale\":00,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, leading_zero_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-zero snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_leading_zero_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-leading-zero-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-leading-zero-snapshot-scale meta dir should be created");

        let valid_id = [0x38; 32];
        let negative_leading_zero_scale_id = [0x39; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            negative_leading_zero_scale_id,
            "{\"dim\":2,\"scale\":-00,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_leading_zero_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-leading-zero snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_decimal_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-leading-decimal-scale-beside-valid",
            [0x11; 32],
            [119, 0],
            [0x12; 32],
            "\"dim\":2,\"scale\":.0,\"components\":[120,0]",
            "leading-decimal snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_decimal_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-trailing-decimal-scale-beside-valid",
            [0x13; 32],
            [119, 0],
            [0x14; 32],
            "\"dim\":2,\"scale\":0.,\"components\":[120,0]",
            "trailing-decimal snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_exponent_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-exponent-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic exponent-snapshot-scale meta dir should be created");

        let valid_id = [0x6f; 32];
        let exponent_scale_id = [0x70; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            exponent_scale_id,
            "{\"dim\":2,\"scale\":0e0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exponent snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_exponent_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-uppercase-exponent-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-exponent-snapshot-scale meta dir should be created");

        let valid_id = [0x73; 32];
        let exponent_scale_id = [0x74; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            exponent_scale_id,
            "{\"dim\":2,\"scale\":0E0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase exponent snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_signed_exponent_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-uppercase-signed-exponent-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-signed-exponent-snapshot-scale meta dir should be created");

        let valid_id = [0x8b; 32];
        let exponent_scale_id = [0x8c; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            exponent_scale_id,
            "{\"dim\":2,\"scale\":0E+0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase signed exponent snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_negative_exponent_scale_beside_valid_entry() {
        let dir =
            SemanticLoadTestDir::new("snapshot-uppercase-negative-exponent-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic uppercase-negative-exponent-snapshot-scale meta dir should be created",
        );

        let valid_id = [0x8d; 32];
        let exponent_scale_id = [0x8e; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            exponent_scale_id,
            "{\"dim\":2,\"scale\":0E-0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase negative exponent snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_signed_exponent_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-signed-exponent-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-exponent-snapshot-scale meta dir should be created");

        let valid_id = [0x7d; 32];
        let exponent_scale_id = [0x7e; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            exponent_scale_id,
            "{\"dim\":2,\"scale\":0e+0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "signed exponent snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_exponent_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-exponent-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-exponent-snapshot-scale meta dir should be created");

        let valid_id = [0x83; 32];
        let exponent_scale_id = [0x84; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [119, 0],
            exponent_scale_id,
            "{\"dim\":2,\"scale\":0e-0,\"components\":[120,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative exponent snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_out_of_range_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-out-of-range-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic out-of-range-snapshot-scale meta dir should be created");

        let valid_id = [0x57; 32];
        let out_of_range_scale_id = [0x58; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![121, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(out_of_range_scale_id),
            serde_json::json!({
                "dim": 2,
                "scale": 128,
                "components": [122, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, out_of_range_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "out-of-range snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_below_min_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-below-min-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic below-min-snapshot-scale meta dir should be created");

        let valid_id = [0x44; 32];
        let below_min_scale_id = [0x45; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![131, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(below_min_scale_id),
            serde_json::json!({
                "dim": 2,
                "scale": -129,
                "components": [132, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, below_min_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "below-min snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_null_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-null-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic null-snapshot-scale meta dir should be created");

        let valid_id = [0x32; 32];
        let null_scale_id = [0x33; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![145, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(null_scale_id),
            serde_json::json!({
                "dim": 2,
                "scale": null,
                "components": [146, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, null_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("null snapshot scale beside valid entry should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_object_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-object-scale-beside-valid",
            [0x61; 32],
            [119, 0],
            [0x62; 32],
            "\"dim\":2,\"scale\":{},\"components\":[120,0]",
            "object-valued snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_array_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-array-scale-beside-valid",
            [0x63; 32],
            [119, 0],
            [0x64; 32],
            "\"dim\":2,\"scale\":[],\"components\":[120,0]",
            "array-valued snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_numeric_string_scale_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-numeric-string-scale-beside-valid",
            [0x39; 32],
            [119, 0],
            [0x3a; 32],
            "\"dim\":2,\"scale\":\"0\",\"components\":[120,0]",
            "numeric-string snapshot scale beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_string_scale_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-string-scale-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic string-snapshot-scale meta dir should be created");

        let valid_id = [0x73; 32];
        let string_scale_id = [0x74; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![58, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(string_scale_id),
            serde_json::json!({
                "dim": 2,
                "scale": "zero",
                "components": [59, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, string_scale_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "string snapshot scale beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_scalar_components_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-scalar-components-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic scalar-snapshot-components meta dir should be created");

        let valid_id = [0x75; 32];
        let scalar_components_id = [0x76; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![60, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(scalar_components_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": 61,
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, scalar_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "scalar snapshot components beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_null_components_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-null-components-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic null-snapshot-components meta dir should be created");

        let valid_id = [0x34; 32];
        let null_components_id = [0x35; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![147, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(null_components_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": null,
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, null_components_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "null snapshot components beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_components_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-boolean-components-beside-valid",
            [0x6f; 32],
            [147, 0],
            [0x70; 32],
            "\"dim\":2,\"scale\":0,\"components\":true",
            "boolean snapshot components field beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_string_components_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-string-components-beside-valid",
            [0x71; 32],
            [147, 0],
            [0x72; 32],
            "\"dim\":2,\"scale\":0,\"components\":\"[147,0]\"",
            "string snapshot components field beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_object_components_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-object-components-beside-valid",
            [0x73; 32],
            [147, 0],
            [0x74; 32],
            "\"dim\":2,\"scale\":0,\"components\":{}",
            "object snapshot components field beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_null_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-null-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic null-snapshot-component meta dir should be created");

        let valid_id = [0x36; 32];
        let null_component_id = [0x37; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![149, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(null_component_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": [null, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, null_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "null snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_boolean_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-boolean-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic boolean-snapshot-component meta dir should be created");

        let valid_id = [0x65; 32];
        let boolean_component_id = [0x66; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![97, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(boolean_component_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": [false, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, boolean_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "boolean snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_fractional_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-fractional-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic fractional-snapshot-component meta dir should be created");

        let valid_id = [0x67; 32];
        let fractional_component_id = [0x68; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![103, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(fractional_component_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": [1.5, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, fractional_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "fractional snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_fractional_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-negative-fractional-component-beside-valid",
            [0x46; 32],
            [103, 0],
            [0x47; 32],
            "\"dim\":2,\"scale\":0,\"components\":[-1.5,0]",
            "negative-fractional snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_fractional_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-fractional-component-beside-valid",
            [0x52; 32],
            [103, 0],
            [0x53; 32],
            "\"dim\":2,\"scale\":0,\"components\":[+1.5,0]",
            "plus-fractional snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_zero_fraction_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-zero-fraction-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic zero-fraction-snapshot-component meta dir should be created");

        let valid_id = [0x97; 32];
        let zero_fraction_component_id = [0x98; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            zero_fraction_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1.0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, zero_fraction_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "zero-fraction snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-zero-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-zero-snapshot-component meta dir should be created");

        let valid_id = [0xc7; 32];
        let negative_zero_component_id = [0xc8; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            negative_zero_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[103,-0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_zero_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_exponent_component_beside_valid_entry() {
        for (case_name, token) in [("lowercase", "-0e0"), ("uppercase", "-0E0")] {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-negative-zero-exponent-component-{case_name}-beside-valid"),
                [0x5f; 32],
                [103, 0],
                [0x60; 32],
                &format!("\"dim\":2,\"scale\":0,\"components\":[{token},0]"),
                "negative-zero-exponent snapshot component beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_exponent_component_beside_valid_entry() {
        for (case_name, token) in [("lowercase", "+0e0"), ("uppercase", "+0E0")] {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-plus-zero-exponent-component-{case_name}-beside-valid"),
                [0xaa; 32],
                [103, 0],
                [0xab; 32],
                &format!("\"dim\":2,\"scale\":0,\"components\":[{token},0]"),
                "plus-zero-exponent snapshot component beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-zero-component-beside-valid",
            [0xc2; 32],
            [103, 0],
            [0xc3; 32],
            "\"dim\":2,\"scale\":0,\"components\":[+0,0]",
            "plus-zero snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_plus_zero_fraction_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-plus-zero-fraction-component-beside-valid",
            [0x8a; 32],
            [103, 0],
            [0x8b; 32],
            "\"dim\":2,\"scale\":0,\"components\":[+0.0,0]",
            "plus-zero-fraction snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_zero_fraction_component_beside_valid_entry() {
        let dir =
            SemanticLoadTestDir::new("snapshot-negative-zero-fraction-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic negative-zero-fraction-snapshot-component meta dir should be created",
        );

        let valid_id = [0x16; 32];
        let negative_zero_fraction_component_id = [0x17; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            negative_zero_fraction_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[103,-0.0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_zero_fraction_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-zero-fraction snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_zero_fraction_component_beside_valid_entry() {
        let dir =
            SemanticLoadTestDir::new("snapshot-trailing-zero-fraction-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic trailing-zero-fraction-snapshot-component meta dir should be created",
        );

        let valid_id = [0x18; 32];
        let trailing_zero_fraction_component_id = [0x19; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            trailing_zero_fraction_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1.00,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, trailing_zero_fraction_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "trailing-zero-fraction snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_lowercase_non_finite_component_beside_valid_entry() {
        for (case_index, (case_name, token)) in [
            ("nan", "nan"),
            ("infinity", "infinity"),
            ("negative-infinity", "-infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
                &format!("snapshot-lowercase-non-finite-component-beside-valid-{case_name}"),
                [0xee + case_index as u8; 32],
                [103, 0],
                [0xf1 + case_index as u8; 32],
                &format!("\"dim\":2,\"scale\":0,\"components\":[103,{token}]"),
                "lowercase non-finite snapshot component beside valid entry should reject whole semantic load",
            );
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_non_finite_component_beside_valid_entry() {
        for (case_index, (case_name, token)) in [
            ("nan", "NaN"),
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = SemanticLoadTestDir::new(&format!(
                "snapshot-non-finite-component-beside-valid-{case_name}"
            ));
            let meta = dir.path().join("meta");
            fs::create_dir_all(&meta)
                .expect("semantic non-finite-snapshot-component meta dir should be created");

            let valid_id = [0x57 + case_index as u8; 32];
            let non_finite_component_id = [0x5a + case_index as u8; 32];
            let raw_entry = format!("{{\"dim\":2,\"scale\":0,\"components\":[103,{}]}}", token);
            let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
                valid_id,
                [103, 0],
                non_finite_component_id,
                &raw_entry,
            );
            semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

            let live_ids = [valid_id, non_finite_component_id];
            let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
                "non-finite snapshot component beside valid entry should reject whole semantic load",
            );

            assert_eq!(err, MnemeError::SchemaDrift, "{case_name}");
        }
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_plus_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-leading-plus-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-plus-snapshot-component meta dir should be created");

        let valid_id = [0x6a; 32];
        let leading_plus_component_id = [0x6b; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            leading_plus_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[103,+1]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, leading_plus_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-plus snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_zero_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-leading-zero-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic leading-zero-snapshot-component meta dir should be created");

        let valid_id = [0x7d; 32];
        let leading_zero_component_id = [0x7e; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            leading_zero_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[103,01]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, leading_zero_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "leading-zero snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_leading_zero_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-leading-zero-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-leading-zero-snapshot-component meta dir should be created");

        let valid_id = [0x3a; 32];
        let negative_leading_zero_component_id = [0x3b; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            negative_leading_zero_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[103,-01]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, negative_leading_zero_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative-leading-zero snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_leading_decimal_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-leading-decimal-component-beside-valid",
            [0x15; 32],
            [103, 0],
            [0x16; 32],
            "\"dim\":2,\"scale\":0,\"components\":[103,.1]",
            "leading-decimal snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_trailing_decimal_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-trailing-decimal-component-beside-valid",
            [0x17; 32],
            [103, 0],
            [0x18; 32],
            "\"dim\":2,\"scale\":0,\"components\":[103,1.]",
            "trailing-decimal snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_exponent_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-exponent-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic exponent-snapshot-component meta dir should be created");

        let valid_id = [0x6b; 32];
        let exponent_component_id = [0x6c; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            exponent_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1e0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "exponent snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_exponent_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-uppercase-exponent-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic uppercase-exponent-snapshot-component meta dir should be created");

        let valid_id = [0x79; 32];
        let exponent_component_id = [0x7a; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            exponent_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1E0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase exponent snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_signed_exponent_component_beside_valid_entry() {
        let dir =
            SemanticLoadTestDir::new("snapshot-uppercase-signed-exponent-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic uppercase-signed-exponent-snapshot-component meta dir should be created",
        );

        let valid_id = [0x8f; 32];
        let exponent_component_id = [0x90; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            exponent_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1E+0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase signed exponent snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_uppercase_negative_exponent_component_beside_valid_entry() {
        let dir =
            SemanticLoadTestDir::new("snapshot-uppercase-negative-exponent-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect(
            "semantic uppercase-negative-exponent-snapshot-component meta dir should be created",
        );

        let valid_id = [0x91; 32];
        let exponent_component_id = [0x92; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            exponent_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1E-0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "uppercase negative exponent snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_signed_exponent_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-signed-exponent-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic signed-exponent-snapshot-component meta dir should be created");

        let valid_id = [0x7f; 32];
        let exponent_component_id = [0x80; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            exponent_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1e+0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "signed exponent snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_negative_exponent_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-negative-exponent-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic negative-exponent-snapshot-component meta dir should be created");

        let valid_id = [0x85; 32];
        let exponent_component_id = [0x86; 32];
        let snapshot = semantic_load_snapshot_with_valid_and_raw_entry(
            valid_id,
            [103, 0],
            exponent_component_id,
            "{\"dim\":2,\"scale\":0,\"components\":[1e-0,0]}",
        );
        semantic_load_write_embedding_snapshot_raw(&meta, &snapshot);

        let live_ids = [valid_id, exponent_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "negative exponent snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_out_of_range_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-out-of-range-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic out-of-range-snapshot-component meta dir should be created");

        let valid_id = [0x69; 32];
        let out_of_range_component_id = [0x6a; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![105, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(out_of_range_component_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": [32768, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, out_of_range_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "out-of-range snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_below_min_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-below-min-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic below-min-snapshot-component meta dir should be created");

        let valid_id = [0x46; 32];
        let below_min_component_id = [0x47; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![133, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(below_min_component_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": [-32769, 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, below_min_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "below-min snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_object_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-object-component-beside-valid",
            [0x65; 32],
            [103, 0],
            [0x66; 32],
            "\"dim\":2,\"scale\":0,\"components\":[{},0]",
            "object-valued snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_array_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-array-component-beside-valid",
            [0x67; 32],
            [103, 0],
            [0x68; 32],
            "\"dim\":2,\"scale\":0,\"components\":[[],0]",
            "array-valued snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_numeric_string_component_beside_valid_entry() {
        semantic_load_expect_raw_snapshot_embedding_fields_schema_drift(
            "snapshot-numeric-string-component-beside-valid",
            [0x3b; 32],
            [103, 0],
            [0x3c; 32],
            "\"dim\":2,\"scale\":0,\"components\":[\"103\",0]",
            "numeric-string snapshot component beside valid entry should reject whole semantic load",
        );
    }

    #[test]
    fn semantic_load_snapshot_rejects_string_component_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-string-component-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic string-snapshot-component meta dir should be created");

        let valid_id = [0x77; 32];
        let string_component_id = [0x78; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![62, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(string_component_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": ["63", 0],
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, string_component_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "string snapshot component beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_unknown_entry_field_beside_valid_entry() {
        let dir = SemanticLoadTestDir::new("snapshot-unknown-entry-field-beside-valid");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic unknown-snapshot-entry-field meta dir should be created");

        let valid_id = [0xf8; 32];
        let unknown_field_id = [0xf9; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![27, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        snapshot_entries.insert(
            hex::encode(unknown_field_id),
            serde_json::json!({
                "dim": 2,
                "scale": 0,
                "components": [28, 0],
                "unexpected": true,
            }),
        );
        semantic_load_write_embedding_snapshot_entries(&meta, snapshot_entries);

        let live_ids = [valid_id, unknown_field_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter()).expect_err(
            "unknown snapshot entry field beside valid entry should reject whole semantic load",
        );

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_snapshot_rejects_unknown_top_level_field() {
        let dir = SemanticLoadTestDir::new("snapshot-unknown-top-level-field");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta)
            .expect("semantic unknown-snapshot-top-level-field meta dir should be created");

        let valid_id = [0xfa; 32];
        let valid_embedding =
            FixedPointEmbedding::new(2, 0, vec![29, 0]).expect("valid snapshot embedding");
        let mut snapshot_entries = serde_json::Map::new();
        snapshot_entries.insert(
            hex::encode(valid_id),
            semantic_load_embedding_entry_json(&valid_embedding),
        );
        semantic_load_write_embedding_snapshot_document(
            &meta,
            serde_json::json!({
                "entries": snapshot_entries,
                "unexpected": true,
            }),
        );

        let live_ids = [valid_id];
        let err = load_semantic_commit(dir.path(), live_ids.iter())
            .expect_err("unknown snapshot top-level field should reject whole semantic load");

        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn semantic_load_filters_replayed_embeddings_to_live_objects() {
        let dir = SemanticLoadTestDir::new("live-object-filter");
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).expect("semantic live-filter meta dir should be created");

        let live_id = [0x44; 32];
        let stale_snapshot_id = [0x55; 32];
        let stale_journal_id = [0x66; 32];
        let live_embedding =
            FixedPointEmbedding::new(2, 0, vec![4, 0]).expect("valid live embedding");
        let stale_snapshot_embedding =
            FixedPointEmbedding::new(2, 0, vec![5, 0]).expect("valid stale snapshot embedding");
        let stale_journal_embedding =
            FixedPointEmbedding::new(2, 0, vec![6, 0]).expect("valid stale journal embedding");

        semantic_load_write_embedding_snapshot(
            &meta,
            &[
                (live_id, &live_embedding),
                (stale_snapshot_id, &stale_snapshot_embedding),
            ],
        );
        semantic_load_write_embedding_journal(
            &meta,
            [semantic_load_journal_upsert_json(
                stale_journal_id,
                &stale_journal_embedding,
            )],
        );

        let live_ids = [live_id];
        let loaded_commit = load_semantic_commit(dir.path(), live_ids.iter())
            .expect("semantic replay should load and filter to live object ids");

        let mut expected = SemanticIndex::new();
        expected
            .insert(ObjectId(live_id), live_embedding.clone())
            .expect("expected live embedding should insert");
        assert_eq!(loaded_commit, expected.semantic_commit());

        expected
            .insert(ObjectId(stale_snapshot_id), stale_snapshot_embedding)
            .expect("stale snapshot embedding should insert");
        expected
            .insert(ObjectId(stale_journal_id), stale_journal_embedding)
            .expect("stale journal embedding should insert");
        assert_ne!(
            loaded_commit,
            expected.semantic_commit(),
            "stray semantic sidecar/journal embeddings outside live object inventory should not affect commit reconstruction"
        );
    }

    #[test]
    fn semantic_load_snapshot_io_error_stays_io_failed() {
        let dir = SemanticLoadTestDir::new("snapshot-io-error");
        let snapshot = dir.path().join("meta/embeddings.json");
        fs::create_dir_all(&snapshot).expect("snapshot path should be a directory fault");

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("non-NotFound semantic snapshot I/O should reject");

        semantic_load_expect_io_failed_path(err, &snapshot, "snapshot");
    }

    #[test]
    fn semantic_load_journal_io_error_stays_io_failed() {
        let dir = SemanticLoadTestDir::new("journal-io-error");
        let journal = dir.path().join("meta/embeddings.journal");
        fs::create_dir_all(&journal).expect("journal path should be a directory fault");

        let err = load_semantic_commit(dir.path(), std::iter::empty::<&[u8; 32]>())
            .expect_err("non-NotFound semantic journal I/O should reject");

        semantic_load_expect_io_failed_path(err, &journal, "journal");
    }

    #[test]
    fn semantic_load_failure_classifier_preserves_public_errors() {
        for failure in [
            SemanticLoadFailure::EmbeddingSnapshot,
            SemanticLoadFailure::EmbeddingJournalLine,
            SemanticLoadFailure::EmbeddingObjectIdHex,
            SemanticLoadFailure::EmbeddingShape,
        ] {
            assert_eq!(
                semantic_load_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }

        assert_eq!(
            semantic_load_failure_to_mneme(SemanticLoadFailure::SemanticInsert),
            MnemeError::RootInconsistent
        );
    }

    #[test]
    fn semantic_load_parsers_preserve_public_errors() {
        assert_eq!(
            parse_semantic_load_json::<EmbeddingSidecar>(
                "{",
                SemanticLoadFailure::EmbeddingSnapshot
            )
            .err(),
            Some(MnemeError::SchemaDrift)
        );
        assert_eq!(
            parse_semantic_load_json::<EmbeddingJournalEntry>(
                "{",
                SemanticLoadFailure::EmbeddingJournalLine
            )
            .err(),
            Some(MnemeError::SchemaDrift)
        );
        assert_eq!(
            parse_semantic_load_hex32("not-hex").err(),
            Some(MnemeError::SchemaDrift)
        );
        assert_eq!(
            parse_embedding(2, 0, vec![1]).err(),
            Some(MnemeError::SchemaDrift)
        );
    }
}
