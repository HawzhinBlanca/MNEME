use crate::{Store, atomic::durability_fsync_enabled};
use mneme_core::{
    FixedPointEmbedding, Hlc, LogicalKey, MnemeError, NodeId, decode_content_addressed_object_path,
    decode_hex32, from_bytes_strict, hash_obj,
};
use mneme_dag::DagIndex;
use mneme_index::KeyIndex;
use mneme_root::{CheckpointLog, StoredRoot};
use mneme_smt::SparseMerkleTree;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Tombstone {
    pub logical_key: mneme_core::LogicalKey,
    pub key_hash: [u8; 32],
}

pub struct LoadedState {
    pub key_index: KeyIndex,
    pub dag: DagIndex,
    pub hlc: Hlc,
    pub key_to_object: HashMap<[u8; 32], [u8; 32]>,
    pub object_keys: HashMap<[u8; 32], LogicalKey>,
    pub objects: HashMap<[u8; 32], Vec<u8>>,
    pub embeddings: HashMap<[u8; 32], FixedPointEmbedding>,
}

type LoadedKeyIndex = (HashMap<[u8; 32], [u8; 32]>, KeyIndex);

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct ObjectKeysSidecar {
    // BTreeMap (not HashMap) so the on-disk snapshot is byte-deterministic across
    // processes — the foundation gate's identity artifacts plus the full store
    // tree must reproduce bit-for-bit (§17.7). HashMap iteration order is not.
    entries: BTreeMap<String, LogicalKeySidecarEntry>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct LogicalKeySidecarEntry {
    namespace: String,
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ObjectKeysJournalEntry {
    id: String,
    namespace: String,
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
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

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct KeyIndexSidecar {
    entries: BTreeMap<String, String>,
    tombstones: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum KeyIndexJournalEntry {
    Upsert { key: String, object: String },
    Tombstone { key: String },
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct EmbeddingSidecarEntry {
    dim: u32,
    scale: i8,
    components: Vec<i16>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct EmbeddingSidecar {
    entries: BTreeMap<String, EmbeddingSidecarEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayoutParseFailure {
    ObjectKeysSidecarJson,
    ObjectKeysJournalJson,
    EmbeddingSidecarJson,
    EmbeddingShape,
    EmbeddingJournalJson,
    DuplicateObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayoutCanonicalFailure {
    PromotionEvent,
    InitialKeyIndexSidecar,
    RedactionRecord,
    KeyIndexSidecar,
    #[cfg(feature = "bitemporal_recall")]
    KeyIndexSnapshot,
    #[cfg(feature = "bitemporal_recall")]
    HistoricalKeyIndexSnapshot,
    ObjectKeysSidecar,
    ObjectKeysJournal,
    EmbeddingSidecar,
    EmbeddingJournalUpsert,
    EmbeddingJournalRemove,
    KeyIndexJournal,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PromotionEvent {
    pub from_id: String,
    pub to_id: String,
    pub from_tier: u8,
    pub to_tier: u8,
    pub writer: String,
    pub hlc: String,
    pub sequence: u64,
}

pub fn append_promotion_event(path: &Path, event: &PromotionEvent) -> Result<(), MnemeError> {
    let log = path.join("meta/promotions.log");
    let line = serde_json::to_string(event).map_err(|_| layout_promotion_event_json_error())?;
    let mut file = crate::atomic::open_append_single_link(&log)?;
    writeln!(file, "{line}").map_err(|e| io_err(&log, e))?;
    file.sync_all().map_err(|e| io_err(&log, e))?;
    Ok(())
}

pub fn init_store(path: &Path) -> Result<(), MnemeError> {
    fs::create_dir_all(path.join("objects")).map_err(|e| io_err(path, e))?;
    fs::create_dir_all(path.join("roots")).map_err(|e| io_err(path, e))?;
    fs::create_dir_all(path.join("meta")).map_err(|e| io_err(path, e))?;
    fs::create_dir_all(path.join("meta/redactions")).map_err(|e| io_err(path, e))?;
    let key_index = path.join("meta/key_index.json");
    if !crate::atomic::entry_exists(&key_index)? {
        let data = serde_json::to_string_pretty(&KeyIndexSidecar::default())
            .map_err(|_| layout_initial_key_index_sidecar_json_error())?;
        crate::atomic::atomic_write(&key_index, data.as_bytes())?;
    }
    Ok(())
}

pub fn begin_transaction(path: &Path) -> Result<(), MnemeError> {
    crate::atomic::begin_incomplete(path)
}

pub fn commit_transaction(path: &Path) -> Result<(), MnemeError> {
    crate::atomic::end_incomplete(path)
}

pub fn abort_transaction(_path: &Path) -> Result<(), MnemeError> {
    // Keep `.incomplete` on failure — fail-closed until explicit repair (INV-8).
    Ok(())
}

pub fn check_incomplete(path: &Path) -> Result<(), MnemeError> {
    crate::atomic::check_no_incomplete(path)
}

pub fn write_head(path: &Path, root: &StoredRoot) -> Result<(), MnemeError> {
    CheckpointLog::write_head(path, root)
}

pub fn read_head(path: &Path) -> Result<StoredRoot, MnemeError> {
    let head = head_path(path);
    let bytes = crate::atomic::read_no_follow(&head)?;
    StoredRoot::from_bytes(&bytes)
}

fn head_path(store: &Path) -> std::path::PathBuf {
    store.join("roots/HEAD")
}

pub fn append_checkpoint(
    path: &Path,
    operator_keys: &[[u8; 32]],
    root: &StoredRoot,
) -> Result<(), MnemeError> {
    CheckpointLog::append(path, root)?;
    mneme_root::update_root_history_peaks(path, operator_keys, root)?;
    Ok(())
}

pub fn write_redaction_record(
    path: &Path,
    record: &mneme_forget::RedactionRecord,
) -> Result<(), MnemeError> {
    let dir = path.join("meta/redactions");
    fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
    let file = dir.join(format!("{}.json", hex_encode(&record.old_object_id)));
    let data =
        serde_json::to_string_pretty(record).map_err(|_| layout_redaction_record_json_error())?;
    crate::atomic::atomic_write(&file, data.as_bytes())
}

pub fn write_object(path: &Path, id: &[u8; 32], bytes: &[u8]) -> Result<(), MnemeError> {
    let obj_path = object_path(path, id);
    crate::atomic::atomic_write(&obj_path, bytes)
}

fn object_path(store: &Path, id: &[u8; 32]) -> PathBuf {
    let hex = hex_encode(id);
    store.join(format!("objects/{}/{}.cbor", &hex[..2], hex))
}

/// §22 merge barrier: write many new object blobs with one fsync per shard directory
/// (not one `sync_parent_dir` per object — the concurrent-merge ceiling).
pub fn write_objects_batch(store: &Path, objects: &[([u8; 32], &[u8])]) -> Result<(), MnemeError> {
    if objects.is_empty() {
        return Ok(());
    }
    let mut paths = Vec::with_capacity(objects.len());
    for (id, bytes) in objects {
        let obj_path = object_path(store, id);
        crate::atomic::atomic_write_deferred(&obj_path, bytes)?;
        paths.push(obj_path);
    }
    crate::atomic::flush_parent_dirs(paths)
}

#[allow(dead_code)]
pub fn remove_object(path: &Path, id: &[u8; 32]) -> Result<(), MnemeError> {
    let hex = hex_encode(id);
    let obj_path = path.join(format!("objects/{}/{}.cbor", &hex[..2], hex));
    if obj_path.exists() {
        fs::remove_file(&obj_path).map_err(|e| io_err(&obj_path, e))?;
    }
    Ok(())
}

/// Full snapshot rewrite of `meta/key_index.json`, resetting the append-only journal
/// (the batch path: bench seed, `remember_batch`, merge, promote). Writes the whole
/// sidecar in ONE `atomic_write` (one fsync) instead of appending one fsync'd journal
/// line per key — that per-entry append was O(n) fsyncs and dominated batch ingest
/// (§22). Single-key `remember` still uses the O(1) `persist_key_index_upsert` journal
/// append. Deterministic: `BTreeMap` entries + sorted tombstones.
pub fn persist_key_index(path: &Path, store: &Store) -> Result<(), MnemeError> {
    let meta = path.join("meta");
    fs::create_dir_all(&meta).map_err(|e| io_err(&meta, e))?;
    let mut sidecar = KeyIndexSidecar::default();
    for (k, v) in store.key_to_object_ref() {
        sidecar.entries.insert(hex_encode(k), hex_encode(v));
    }
    let mut tombstones: Vec<String> = store.tombstones_ref().iter().map(hex_encode).collect();
    tombstones.sort();
    sidecar.tombstones = tombstones;
    let data = serde_json::to_string_pretty(&sidecar)
        .map_err(|_| layout_key_index_sidecar_json_error())?;
    crate::atomic::atomic_write(&meta.join("key_index.json"), data.as_bytes())?;
    truncate_journal(path, "key_index.journal")
}

/// Per-checkpoint key-index snapshot for bi-temporal `recall_verified_at` (Phase I P1-2).
#[cfg(feature = "bitemporal_recall")]
pub fn snapshot_key_index_at_seq(path: &Path, seq: u64, store: &Store) -> Result<(), MnemeError> {
    let dir = path.join("meta/snapshots").join(seq.to_string());
    fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
    let mut sidecar = KeyIndexSidecar::default();
    for (k, v) in store.key_to_object_ref() {
        sidecar.entries.insert(hex_encode(k), hex_encode(v));
    }
    let mut tombstones: Vec<String> = store.tombstones_ref().iter().map(hex_encode).collect();
    tombstones.sort();
    sidecar.tombstones = tombstones;
    let data = serde_json::to_string_pretty(&sidecar)
        .map_err(|_| layout_key_index_snapshot_json_error())?;
    crate::atomic::atomic_write(&dir.join("key_index.json"), data.as_bytes())?;
    Ok(())
}

/// Load a historical key index snapshot written at commit `seq`.
#[cfg(feature = "bitemporal_recall")]
pub fn load_key_index_at_seq(path: &Path, seq: u64) -> Result<KeyIndex, MnemeError> {
    let snap = path
        .join("meta/snapshots")
        .join(seq.to_string())
        .join("key_index.json");
    if !crate::atomic::entry_exists(&snap)? {
        return Err(MnemeError::HistoricalRecallInvalid);
    }
    let data = read_store_file(&snap)?;
    let sidecar: KeyIndexSidecar = serde_json::from_slice(&data)
        .map_err(|_| layout_historical_key_index_snapshot_json_error())?;
    let (_, key_index) = apply_sidecar(&sidecar)?;
    Ok(key_index)
}

pub fn persist_key_index_upsert(
    path: &Path,
    key_hash: &[u8; 32],
    object_id: &[u8; 32],
) -> Result<(), MnemeError> {
    append_key_index_journal_entry(
        path,
        &KeyIndexJournalEntry::Upsert {
            key: hex_encode(key_hash),
            object: hex_encode(object_id),
        },
    )
}

pub fn persist_key_index_tombstone(path: &Path, key_hash: &[u8; 32]) -> Result<(), MnemeError> {
    append_key_index_journal_entry(
        path,
        &KeyIndexJournalEntry::Tombstone {
            key: hex_encode(key_hash),
        },
    )
}

/// Full snapshot rewrite of `object_keys.json`. Resets the append-only journal so
/// the base sidecar + journal stay consistent (used by batch/rare ops: bench seed,
/// promote). The single-key `remember`/`merge` hot paths use the incremental
/// `persist_object_keys_upsert` below to avoid an O(n) rewrite per op (§22 K5).
pub fn persist_object_keys(path: &Path, store: &Store) -> Result<(), MnemeError> {
    let meta = path.join("meta");
    fs::create_dir_all(&meta).map_err(|e| io_err(&meta, e))?;
    let mut sidecar = ObjectKeysSidecar::default();
    for (id, key) in store.object_keys_ref() {
        sidecar.entries.insert(
            hex_encode(id),
            LogicalKeySidecarEntry {
                namespace: key.namespace.clone(),
                name: key.name.clone(),
            },
        );
    }
    let data = serde_json::to_string_pretty(&sidecar)
        .map_err(|_| layout_object_keys_sidecar_json_error())?;
    crate::atomic::atomic_write(&meta.join("object_keys.json"), data.as_bytes())?;
    truncate_journal(path, "object_keys.journal")
}

/// Append one object-id → logical-key mapping to `object_keys.journal` (O(1)).
pub fn persist_object_keys_upsert(
    path: &Path,
    id: &[u8; 32],
    key: &LogicalKey,
) -> Result<(), MnemeError> {
    let entry = ObjectKeysJournalEntry {
        id: hex_encode(id),
        namespace: key.namespace.clone(),
        name: key.name.clone(),
    };
    let line =
        serde_json::to_string(&entry).map_err(|_| layout_object_keys_journal_json_error())?;
    append_journal_line(path, "object_keys.journal", &line)
}

fn layout_journal_line_is_blank(line: &str) -> bool {
    line.trim().is_empty()
}

fn layout_remove_embedding_entry(
    entries: &mut HashMap<[u8; 32], FixedPointEmbedding>,
    id: &[u8; 32],
) {
    let mut retained_entries = HashMap::new();
    for (entry_id, embedding) in &*entries {
        if entry_id != id {
            retained_entries.insert(*entry_id, embedding.clone());
        }
    }
    *entries = retained_entries;
}

fn layout_remove_key_index_tombstone(tombstones: &mut Vec<String>, key: &str) {
    let mut retained_tombstones = Vec::new();
    for tombstone in &*tombstones {
        if tombstone != key {
            retained_tombstones.push(tombstone.clone());
        }
    }
    *tombstones = retained_tombstones;
}

fn layout_remove_key_index_entry(entries: &mut BTreeMap<String, String>, key: &str) {
    let mut retained_entries = BTreeMap::new();
    for (entry_key, object_id) in &*entries {
        if entry_key != key {
            retained_entries.insert(entry_key.clone(), object_id.clone());
        }
    }
    *entries = retained_entries;
}

fn layout_push_key_index_tombstone_if_absent(tombstones: &mut Vec<String>, key: String) {
    for tombstone in &*tombstones {
        if tombstone == &key {
            return;
        }
    }
    tombstones.push(key);
}

fn layout_remove_loaded_key_object(
    key_to_object: &mut HashMap<[u8; 32], [u8; 32]>,
    key_hash: &[u8; 32],
) {
    let mut retained_key_objects = HashMap::new();
    for (loaded_key_hash, object_id) in &*key_to_object {
        if loaded_key_hash != key_hash {
            retained_key_objects.insert(*loaded_key_hash, *object_id);
        }
    }
    *key_to_object = retained_key_objects;
}

fn load_object_keys(path: &Path) -> Result<HashMap<[u8; 32], LogicalKey>, MnemeError> {
    let mut out = HashMap::new();
    let p = path.join("meta/object_keys.json");
    if crate::atomic::entry_exists(&p)? {
        let data = read_store_string(&p)?;
        let sidecar: ObjectKeysSidecar =
            parse_layout_json(&data, LayoutParseFailure::ObjectKeysSidecarJson)?;
        for (id_hex, entry) in sidecar.entries {
            let id = decode_hex32(&id_hex)?;
            out.insert(
                id,
                LogicalKey {
                    namespace: entry.namespace,
                    name: entry.name,
                },
            );
        }
    }
    let journal = path.join("meta/object_keys.journal");
    if crate::atomic::entry_exists(&journal)? {
        let data = read_store_string(&journal)?;
        for line in data.lines() {
            if layout_journal_line_is_blank(line) {
                continue;
            }
            let entry: ObjectKeysJournalEntry =
                parse_layout_json(line, LayoutParseFailure::ObjectKeysJournalJson)?;
            let id = decode_hex32(&entry.id)?;
            out.insert(
                id,
                LogicalKey {
                    namespace: entry.namespace,
                    name: entry.name,
                },
            );
        }
    }
    Ok(out)
}

pub fn load_state(path: &Path) -> Result<LoadedState, MnemeError> {
    let mut dag = DagIndex::new();
    let mut max_hlc = Hlc::zero(NodeId::from_bytes([0u8; 16]));
    let mut objects = HashMap::new();

    let objects_dir = path.join("objects");
    if crate::atomic::entry_exists(&objects_dir)? {
        walk_objects(&objects_dir, &objects_dir, &mut objects)?;
    }

    let sidecar = load_key_index(path)?;
    let (key_to_object, key_index) = apply_sidecar(&sidecar)?;

    let mut dag_entries = Vec::new();
    for (id, bytes) in &objects {
        if let Ok(record) = from_bytes_strict::<mneme_core::ObjectRecord>(bytes) {
            if record.hlc.wall_ms >= max_hlc.wall_ms {
                max_hlc.wall_ms = record.hlc.wall_ms;
                max_hlc.counter = record.hlc.counter;
            }
            dag_entries.push((mneme_core::types::ObjectId(*id), record.parent_ids));
        }
    }
    dag.rebuild_from(&dag_entries)?;

    let embeddings = load_embeddings(path)?;
    let object_keys = load_object_keys(path)?;

    Ok(LoadedState {
        key_index,
        dag,
        hlc: max_hlc,
        key_to_object,
        object_keys,
        objects,
        embeddings,
    })
}

/// Full snapshot rewrite of `embeddings.json`; resets the journal (see
/// `persist_object_keys`). Hot paths use the incremental helpers below.
pub fn persist_embeddings(path: &Path, store: &Store) -> Result<(), MnemeError> {
    let meta = path.join("meta");
    fs::create_dir_all(&meta).map_err(|e| io_err(&meta, e))?;
    let mut sidecar = EmbeddingSidecar::default();
    for (id, emb) in store.embeddings_ref() {
        sidecar.entries.insert(
            hex_encode(id),
            EmbeddingSidecarEntry {
                dim: emb.dim,
                scale: emb.scale,
                components: emb.components.clone(),
            },
        );
    }
    let data = serde_json::to_string_pretty(&sidecar)
        .map_err(|_| layout_embedding_sidecar_json_error())?;
    crate::atomic::atomic_write(&meta.join("embeddings.json"), data.as_bytes())?;
    truncate_journal(path, "embeddings.journal")
}

/// Append one embedding upsert to `embeddings.journal` (O(1)).
pub fn persist_embeddings_upsert(
    path: &Path,
    id: &[u8; 32],
    emb: &FixedPointEmbedding,
) -> Result<(), MnemeError> {
    let entry = EmbeddingJournalEntry::Upsert {
        id: hex_encode(id),
        dim: emb.dim,
        scale: emb.scale,
        components: emb.components.clone(),
    };
    let line =
        serde_json::to_string(&entry).map_err(|_| layout_embedding_journal_upsert_json_error())?;
    append_journal_line(path, "embeddings.journal", &line)
}

/// Append one embedding removal (forget shred) to `embeddings.journal` (O(1)).
pub fn persist_embeddings_remove(path: &Path, id: &[u8; 32]) -> Result<(), MnemeError> {
    let entry = EmbeddingJournalEntry::Remove { id: hex_encode(id) };
    let line =
        serde_json::to_string(&entry).map_err(|_| layout_embedding_journal_remove_json_error())?;
    append_journal_line(path, "embeddings.journal", &line)
}

fn load_embeddings(path: &Path) -> Result<HashMap<[u8; 32], FixedPointEmbedding>, MnemeError> {
    let mut out = HashMap::new();
    let p = path.join("meta/embeddings.json");
    if crate::atomic::entry_exists(&p)? {
        let data = read_store_string(&p)?;
        let sidecar: EmbeddingSidecar =
            parse_layout_json(&data, LayoutParseFailure::EmbeddingSidecarJson)?;
        for (id_hex, entry) in sidecar.entries {
            let id = decode_hex32(&id_hex)?;
            let emb = FixedPointEmbedding::new(entry.dim, entry.scale, entry.components)
                .map_err(|_| layout_embedding_shape_error())?;
            out.insert(id, emb);
        }
    }
    let journal = path.join("meta/embeddings.journal");
    if crate::atomic::entry_exists(&journal)? {
        let data = read_store_string(&journal)?;
        for line in data.lines() {
            if layout_journal_line_is_blank(line) {
                continue;
            }
            let entry: EmbeddingJournalEntry =
                parse_layout_json(line, LayoutParseFailure::EmbeddingJournalJson)?;
            match entry {
                EmbeddingJournalEntry::Upsert {
                    id,
                    dim,
                    scale,
                    components,
                } => {
                    let id = decode_hex32(&id)?;
                    let emb = FixedPointEmbedding::new(dim, scale, components)
                        .map_err(|_| layout_embedding_shape_error())?;
                    out.insert(id, emb);
                }
                EmbeddingJournalEntry::Remove { id } => {
                    let id = decode_hex32(&id)?;
                    layout_remove_embedding_entry(&mut out, &id);
                }
            }
        }
    }
    Ok(out)
}

/// Overwrite object blob with non-canonical random bytes (legacy; §13.2 keeps ciphertext intact).
#[allow(dead_code)]
pub fn shred_object_file(path: &Path, id: &[u8; 32], len: usize) -> Result<(), MnemeError> {
    let mut noise = vec![0u8; len.max(1)];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut noise);
    write_object(path, id, &noise)
}

fn load_key_index(path: &Path) -> Result<KeyIndexSidecar, MnemeError> {
    let index_path = path.join("meta/key_index.json");
    let mut sidecar = if crate::atomic::entry_exists(&index_path)? {
        let data = read_store_string(&index_path)?;
        serde_json::from_str(&data).map_err(|_| layout_key_index_sidecar_json_error())?
    } else {
        KeyIndexSidecar::default()
    };
    apply_key_index_journal(path, &mut sidecar)?;
    Ok(sidecar)
}

fn append_key_index_journal_entry(
    path: &Path,
    entry: &KeyIndexJournalEntry,
) -> Result<(), MnemeError> {
    let line = serde_json::to_string(entry).map_err(|_| layout_key_index_journal_json_error())?;
    append_journal_line(path, "key_index.journal", &line)
}

/// Append one newline-terminated record to a `meta/<name>` journal, with the same
/// crash-safe fsync discipline as the key-index journal.
fn append_journal_line(path: &Path, name: &str, line: &str) -> Result<(), MnemeError> {
    let journal = path.join("meta").join(name);
    let mut file = crate::atomic::open_append_single_link(&journal)?;
    file.write_all(line.as_bytes())
        .map_err(|e| io_err(&journal, e))?;
    file.write_all(b"\n").map_err(|e| io_err(&journal, e))?;
    if durability_fsync_enabled() {
        file.sync_all().map_err(|e| io_err(&journal, e))?;
        sync_parent_dir(&journal)?;
    }
    Ok(())
}

/// Drop a `meta/<name>` journal after a full snapshot rewrite of its base sidecar,
/// keeping base + journal consistent. Replay is idempotent, so a crash between the
/// snapshot write and this removal is safe (stale upserts re-apply the same state).
fn truncate_journal(path: &Path, name: &str) -> Result<(), MnemeError> {
    let journal = path.join("meta").join(name);
    if crate::atomic::entry_exists(&journal)? {
        fs::remove_file(&journal).map_err(|e| io_err(&journal, e))?;
        if durability_fsync_enabled() {
            sync_parent_dir(&journal)?;
        }
    }
    Ok(())
}

fn apply_key_index_journal(path: &Path, sidecar: &mut KeyIndexSidecar) -> Result<(), MnemeError> {
    let journal = path.join("meta/key_index.journal");
    if !crate::atomic::entry_exists(&journal)? {
        return Ok(());
    }
    let data = read_store_string(&journal)?;
    for line in data.lines() {
        if layout_journal_line_is_blank(line) {
            continue;
        }
        let entry: KeyIndexJournalEntry =
            serde_json::from_str(line).map_err(|_| layout_key_index_journal_json_error())?;
        match entry {
            KeyIndexJournalEntry::Upsert { key, object } => {
                decode_hex32(&key)?;
                decode_hex32(&object)?;
                layout_remove_key_index_tombstone(&mut sidecar.tombstones, &key);
                sidecar.entries.insert(key, object);
            }
            KeyIndexJournalEntry::Tombstone { key } => {
                decode_hex32(&key)?;
                layout_remove_key_index_entry(&mut sidecar.entries, &key);
                layout_push_key_index_tombstone_if_absent(&mut sidecar.tombstones, key);
            }
        }
    }
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<(), MnemeError> {
    if let Some(parent) = path.parent() {
        let dir = File::open(parent).map_err(|e| io_err(parent, e))?;
        dir.sync_all().map_err(|e| io_err(parent, e))?;
    }
    Ok(())
}

fn apply_sidecar(sidecar: &KeyIndexSidecar) -> Result<LoadedKeyIndex, MnemeError> {
    let mut key_to_object = HashMap::new();
    let mut smt = SparseMerkleTree::new();
    for (k, v) in &sidecar.entries {
        let kb = decode_hex32(k)?;
        let vb = decode_hex32(v)?;
        key_to_object.insert(kb, vb);
        smt.upsert(kb, vb);
    }
    for t in &sidecar.tombstones {
        let kb = decode_hex32(t)?;
        smt.tombstone(kb);
        layout_remove_loaded_key_object(&mut key_to_object, &kb);
    }
    Ok((key_to_object, KeyIndex::from_tree(smt)))
}

fn read_store_file(path: &Path) -> Result<Vec<u8>, MnemeError> {
    crate::atomic::read_no_follow(path)
}

fn read_store_string(path: &Path) -> Result<String, MnemeError> {
    let bytes = read_store_file(path)?;
    String::from_utf8(bytes).map_err(|e| MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    })
}

fn walk_objects(
    objects_dir: &Path,
    dir: &Path,
    out: &mut HashMap<[u8; 32], Vec<u8>>,
) -> Result<(), MnemeError> {
    let dir_metadata = fs::symlink_metadata(dir).map_err(|e| io_err(dir, e))?;
    let dir_type = dir_metadata.file_type();
    if dir_type.is_symlink() {
        return Err(MnemeError::IoFailed {
            path: dir.display().to_string(),
            kind: "object directory symlink".into(),
        });
    }
    if !dir_type.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let p = entry.path();
        let file_type = entry.file_type().map_err(|e| io_err(&p, e))?;
        if file_type.is_symlink() {
            return Err(MnemeError::IoFailed {
                path: p.display().to_string(),
                kind: "object path symlink".into(),
            });
        }
        if file_type.is_dir() {
            walk_objects(objects_dir, &p, out)?;
        } else if p.extension().is_some_and(|e| e == "cbor") {
            if !file_type.is_file() {
                return Err(MnemeError::IoFailed {
                    path: p.display().to_string(),
                    kind: "object path non-regular".into(),
                });
            }
            let claimed_id = decode_content_addressed_object_path(objects_dir, &p)?;
            let bytes = read_store_file(&p)?;
            if hash_obj(&bytes) != claimed_id {
                return Err(MnemeError::ObjectTampered);
            }
            if out.insert(claimed_id, bytes).is_some() {
                return Err(layout_duplicate_object_error());
            }
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn layout_parse_failure_to_mneme(failure: LayoutParseFailure) -> MnemeError {
    match failure {
        LayoutParseFailure::ObjectKeysSidecarJson
        | LayoutParseFailure::ObjectKeysJournalJson
        | LayoutParseFailure::EmbeddingSidecarJson
        | LayoutParseFailure::EmbeddingShape
        | LayoutParseFailure::EmbeddingJournalJson
        | LayoutParseFailure::DuplicateObject => MnemeError::SchemaDrift,
    }
}

fn parse_layout_json<T: serde::de::DeserializeOwned>(
    input: &str,
    failure: LayoutParseFailure,
) -> Result<T, MnemeError> {
    serde_json::from_str(input).map_err(|_| layout_json_parse_error(failure))
}

fn layout_json_parse_error(failure: LayoutParseFailure) -> MnemeError {
    layout_parse_failure_to_mneme(failure)
}

fn layout_embedding_shape_error() -> MnemeError {
    layout_parse_failure_to_mneme(LayoutParseFailure::EmbeddingShape)
}

fn layout_duplicate_object_error() -> MnemeError {
    layout_parse_failure_to_mneme(LayoutParseFailure::DuplicateObject)
}

fn layout_canonical_failure_to_mneme(failure: LayoutCanonicalFailure) -> MnemeError {
    match failure {
        LayoutCanonicalFailure::PromotionEvent
        | LayoutCanonicalFailure::InitialKeyIndexSidecar
        | LayoutCanonicalFailure::RedactionRecord
        | LayoutCanonicalFailure::KeyIndexSidecar
        | LayoutCanonicalFailure::ObjectKeysSidecar
        | LayoutCanonicalFailure::ObjectKeysJournal
        | LayoutCanonicalFailure::EmbeddingSidecar
        | LayoutCanonicalFailure::EmbeddingJournalUpsert
        | LayoutCanonicalFailure::EmbeddingJournalRemove
        | LayoutCanonicalFailure::KeyIndexJournal => MnemeError::SerializationNonCanonical,
        #[cfg(feature = "bitemporal_recall")]
        LayoutCanonicalFailure::KeyIndexSnapshot
        | LayoutCanonicalFailure::HistoricalKeyIndexSnapshot => {
            MnemeError::SerializationNonCanonical
        }
    }
}

fn layout_promotion_event_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::PromotionEvent)
}

fn layout_initial_key_index_sidecar_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::InitialKeyIndexSidecar)
}

fn layout_redaction_record_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::RedactionRecord)
}

fn layout_key_index_sidecar_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::KeyIndexSidecar)
}

#[cfg(feature = "bitemporal_recall")]
fn layout_key_index_snapshot_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::KeyIndexSnapshot)
}

#[cfg(feature = "bitemporal_recall")]
fn layout_historical_key_index_snapshot_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::HistoricalKeyIndexSnapshot)
}

fn layout_object_keys_sidecar_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::ObjectKeysSidecar)
}

fn layout_object_keys_journal_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::ObjectKeysJournal)
}

fn layout_embedding_sidecar_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::EmbeddingSidecar)
}

fn layout_embedding_journal_upsert_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::EmbeddingJournalUpsert)
}

fn layout_embedding_journal_remove_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::EmbeddingJournalRemove)
}

fn layout_key_index_journal_json_error() -> MnemeError {
    layout_canonical_failure_to_mneme(LayoutCanonicalFailure::KeyIndexJournal)
}

fn io_err(path: &Path, e: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_production_source() -> &'static str {
        include_str!("layout.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("layout.rs should keep tests after production code")
    }

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let (_, after_start) = source
            .split_once(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let (section, _) = after_start
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        section
    }

    #[test]
    fn layout_parse_failure_classifier_preserves_schema_failures() {
        for failure in [
            LayoutParseFailure::ObjectKeysSidecarJson,
            LayoutParseFailure::ObjectKeysJournalJson,
            LayoutParseFailure::EmbeddingSidecarJson,
            LayoutParseFailure::EmbeddingShape,
            LayoutParseFailure::EmbeddingJournalJson,
            LayoutParseFailure::DuplicateObject,
        ] {
            assert_eq!(
                layout_parse_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn layout_canonical_failures_are_classified_not_serialization_collapsed() {
        let source = include_str!("layout.rs");
        let sections = [
            source_between_markers(
                source,
                "pub fn append_promotion_event(",
                "pub fn init_store(",
                "append_promotion_event",
            ),
            source_between_markers(
                source,
                "pub fn init_store(",
                "pub fn begin_transaction(",
                "init_store",
            ),
            source_between_markers(
                source,
                "pub fn write_redaction_record(",
                "pub fn write_object(",
                "write_redaction_record",
            ),
            source_between_markers(
                source,
                "pub fn persist_key_index(",
                "/// Per-checkpoint key-index snapshot",
                "persist_key_index",
            ),
            source_between_markers(
                source,
                "pub fn snapshot_key_index_at_seq(",
                "/// Load a historical key index snapshot",
                "snapshot_key_index_at_seq",
            ),
            source_between_markers(
                source,
                "pub fn load_key_index_at_seq(",
                "pub fn persist_key_index_upsert(",
                "load_key_index_at_seq",
            ),
            source_between_markers(
                source,
                "pub fn persist_object_keys(",
                "/// Append one object-id",
                "persist_object_keys",
            ),
            source_between_markers(
                source,
                "pub fn persist_object_keys_upsert(",
                "fn load_object_keys(",
                "persist_object_keys_upsert",
            ),
            source_between_markers(
                source,
                "pub fn persist_embeddings(",
                "/// Append one embedding upsert",
                "persist_embeddings",
            ),
            source_between_markers(
                source,
                "pub fn persist_embeddings_upsert(",
                "/// Append one embedding removal",
                "persist_embeddings_upsert",
            ),
            source_between_markers(
                source,
                "pub fn persist_embeddings_remove(",
                "fn load_embeddings(",
                "persist_embeddings_remove",
            ),
            source_between_markers(
                source,
                "fn append_key_index_journal_entry(",
                "/// Append one newline-terminated record",
                "append_key_index_journal_entry",
            ),
        ];

        for section in sections {
            for forbidden in [
                "map_err(|_| MnemeError::SerializationNonCanonical)",
                "Err(MnemeError::SerializationNonCanonical)",
                "return Err(MnemeError::SerializationNonCanonical)",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "layout canonicality path should route `{forbidden}` through named classifiers"
                );
            }
        }

        for required in [
            "enum LayoutCanonicalFailure",
            "fn layout_canonical_failure_to_mneme(",
            "fn layout_promotion_event_json_error(",
            "fn layout_initial_key_index_sidecar_json_error(",
            "fn layout_redaction_record_json_error(",
            "fn layout_key_index_sidecar_json_error(",
            "fn layout_key_index_snapshot_json_error(",
            "fn layout_historical_key_index_snapshot_json_error(",
            "fn layout_object_keys_sidecar_json_error(",
            "fn layout_object_keys_journal_json_error(",
            "fn layout_embedding_sidecar_json_error(",
            "fn layout_embedding_journal_upsert_json_error(",
            "fn layout_embedding_journal_remove_json_error(",
            "fn layout_key_index_journal_json_error(",
            "LayoutCanonicalFailure::PromotionEvent",
            "LayoutCanonicalFailure::InitialKeyIndexSidecar",
            "LayoutCanonicalFailure::RedactionRecord",
            "LayoutCanonicalFailure::KeyIndexSidecar",
            "LayoutCanonicalFailure::KeyIndexSnapshot",
            "LayoutCanonicalFailure::HistoricalKeyIndexSnapshot",
            "LayoutCanonicalFailure::ObjectKeysSidecar",
            "LayoutCanonicalFailure::ObjectKeysJournal",
            "LayoutCanonicalFailure::EmbeddingSidecar",
            "LayoutCanonicalFailure::EmbeddingJournalUpsert",
            "LayoutCanonicalFailure::EmbeddingJournalRemove",
            "LayoutCanonicalFailure::KeyIndexJournal",
        ] {
            assert!(
                source.contains(required),
                "layout canonical failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn layout_canonical_failure_classifier_preserves_public_error() {
        for failure in [
            LayoutCanonicalFailure::PromotionEvent,
            LayoutCanonicalFailure::InitialKeyIndexSidecar,
            LayoutCanonicalFailure::RedactionRecord,
            LayoutCanonicalFailure::KeyIndexSidecar,
            #[cfg(feature = "bitemporal_recall")]
            LayoutCanonicalFailure::KeyIndexSnapshot,
            #[cfg(feature = "bitemporal_recall")]
            LayoutCanonicalFailure::HistoricalKeyIndexSnapshot,
            LayoutCanonicalFailure::ObjectKeysSidecar,
            LayoutCanonicalFailure::ObjectKeysJournal,
            LayoutCanonicalFailure::EmbeddingSidecar,
            LayoutCanonicalFailure::EmbeddingJournalUpsert,
            LayoutCanonicalFailure::EmbeddingJournalRemove,
            LayoutCanonicalFailure::KeyIndexJournal,
        ] {
            assert_eq!(
                layout_canonical_failure_to_mneme(failure),
                MnemeError::SerializationNonCanonical
            );
        }

        for error in [
            layout_promotion_event_json_error(),
            layout_initial_key_index_sidecar_json_error(),
            layout_redaction_record_json_error(),
            layout_key_index_sidecar_json_error(),
            #[cfg(feature = "bitemporal_recall")]
            layout_key_index_snapshot_json_error(),
            #[cfg(feature = "bitemporal_recall")]
            layout_historical_key_index_snapshot_json_error(),
            layout_object_keys_sidecar_json_error(),
            layout_object_keys_journal_json_error(),
            layout_embedding_sidecar_json_error(),
            layout_embedding_journal_upsert_json_error(),
            layout_embedding_journal_remove_json_error(),
            layout_key_index_journal_json_error(),
        ] {
            assert_eq!(error, MnemeError::SerializationNonCanonical);
        }
    }

    #[test]
    fn layout_journal_replay_source_names_blank_line_checks() {
        let source = layout_production_source();
        let sections = [
            source_between_markers(
                source,
                "fn load_object_keys(",
                "pub fn load_state(",
                "load_object_keys",
            ),
            source_between_markers(
                source,
                "fn load_embeddings(",
                "/// Overwrite object blob",
                "load_embeddings",
            ),
            source_between_markers(
                source,
                "fn apply_key_index_journal(",
                "fn sync_parent_dir(",
                "apply_key_index_journal",
            ),
        ];

        assert!(
            source.contains("fn layout_journal_line_is_blank("),
            "layout journal replay code should name its blank-line predicate"
        );
        let forbidden = [".trim()", ".is_empty()"].concat();
        for section in sections {
            assert!(
                !section.contains(&forbidden),
                "layout journal replay loops should call the named blank-line predicate"
            );
        }
    }

    #[test]
    fn layout_journal_replay_source_names_mutation_shortcuts() {
        let source = layout_production_source();
        let embeddings_replay = source_between_markers(
            source,
            "fn load_embeddings(",
            "/// Overwrite object blob",
            "load_embeddings",
        );
        let key_index_replay = source_between_markers(
            source,
            "fn apply_key_index_journal(",
            "fn sync_parent_dir(",
            "apply_key_index_journal",
        );

        for required in [
            "fn layout_remove_embedding_entry(",
            "fn layout_remove_key_index_tombstone(",
            "fn layout_remove_key_index_entry(",
            "fn layout_push_key_index_tombstone_if_absent(",
        ] {
            assert!(
                source.contains(required),
                "layout journal replay code should name collection mutation helper `{required}`"
            );
        }

        let embedding_remove_shortcut = ".remove(";
        assert!(
            !embeddings_replay.contains(embedding_remove_shortcut),
            "embedding journal replay should call the named removal helper instead of `{embedding_remove_shortcut}`"
        );

        for forbidden in [".retain(", ".remove(", ".any("] {
            assert!(
                !key_index_replay.contains(forbidden),
                "key-index journal replay should call named mutation helpers instead of `{forbidden}`"
            );
        }
    }

    #[test]
    fn layout_apply_sidecar_source_names_tombstone_removal() {
        let source = layout_production_source();
        let apply_sidecar_source = source_between_markers(
            source,
            "fn apply_sidecar(",
            "fn walk_objects(",
            "apply_sidecar",
        );

        assert!(
            source.contains("fn layout_remove_loaded_key_object("),
            "layout sidecar reconstruction should name loaded key/object tombstone removal"
        );
        assert!(
            !apply_sidecar_source.contains(".remove("),
            "layout sidecar reconstruction should call the named tombstone removal helper"
        );
    }
}
