use crate::Store;
use mneme_core::{
    FixedPointEmbedding, Hlc, LogicalKey, MnemeError, NodeId, from_bytes_strict, hash_obj,
};
use mneme_dag::DagIndex;
use mneme_index::KeyIndex;
use mneme_root::{CheckpointLog, StoredRoot};
use mneme_smt::SparseMerkleTree;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
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
    let line = serde_json::to_string(event).map_err(|_| MnemeError::SerializationNonCanonical)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .map_err(|e| io_err(&log, e))?;
    writeln!(file, "{line}").map_err(|e| io_err(&log, e))?;
    file.sync_all().map_err(|e| io_err(&log, e))?;
    Ok(())
}

pub fn init_store(path: &Path) -> Result<(), MnemeError> {
    fs::create_dir_all(path.join("objects")).map_err(|e| io_err(path, e))?;
    fs::create_dir_all(path.join("roots")).map_err(|e| io_err(path, e))?;
    fs::create_dir_all(path.join("meta")).map_err(|e| io_err(path, e))?;
    #[cfg(feature = "experimental_redaction")]
    fs::create_dir_all(path.join("meta/redactions")).map_err(|e| io_err(path, e))?;
    let key_index = path.join("meta/key_index.json");
    if !key_index.exists() {
        let data = serde_json::to_string_pretty(&KeyIndexSidecar::default())
            .map_err(|_| MnemeError::SerializationNonCanonical)?;
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

pub fn append_checkpoint(path: &Path, root: &StoredRoot) -> Result<(), MnemeError> {
    CheckpointLog::append(path, root)
}

#[cfg(feature = "experimental_redaction")]
pub fn write_redaction_record(
    path: &Path,
    record: &mneme_forget::RedactionRecord,
) -> Result<(), MnemeError> {
    let dir = path.join("meta/redactions");
    fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
    let file = dir.join(format!("{}.json", hex_encode(&record.old_object_id)));
    let data =
        serde_json::to_string_pretty(record).map_err(|_| MnemeError::SerializationNonCanonical)?;
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
#[cfg(feature = "experimental_sync_crdt")]
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
        .map_err(|_| MnemeError::SerializationNonCanonical)?;
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
        .map_err(|_| MnemeError::SerializationNonCanonical)?;
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
    if !snap.exists() {
        return Err(MnemeError::HistoricalRecallInvalid);
    }
    let data = fs::read(&snap).map_err(|e| io_err(&snap, e))?;
    let sidecar: KeyIndexSidecar =
        serde_json::from_slice(&data).map_err(|_| MnemeError::SerializationNonCanonical)?;
    let (_, key_index) = apply_sidecar(&sidecar);
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
        .map_err(|_| MnemeError::SerializationNonCanonical)?;
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
    let line = serde_json::to_string(&entry).map_err(|_| MnemeError::SerializationNonCanonical)?;
    append_journal_line(path, "object_keys.journal", &line)
}

fn load_object_keys(path: &Path) -> Result<HashMap<[u8; 32], LogicalKey>, MnemeError> {
    let mut out = HashMap::new();
    let p = path.join("meta/object_keys.json");
    if p.exists() {
        let data = fs::read_to_string(&p).map_err(|e| io_err(&p, e))?;
        let sidecar: ObjectKeysSidecar =
            serde_json::from_str(&data).map_err(|_| MnemeError::SchemaDrift)?;
        for (id_hex, entry) in sidecar.entries {
            let id = parse_hex32(&id_hex)?;
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
    if journal.exists() {
        let data = fs::read_to_string(&journal).map_err(|e| io_err(&journal, e))?;
        for line in data.lines().filter(|l| !l.trim().is_empty()) {
            let entry: ObjectKeysJournalEntry =
                serde_json::from_str(line).map_err(|_| MnemeError::SchemaDrift)?;
            let id = parse_hex32(&entry.id)?;
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
    if objects_dir.exists() {
        walk_objects(&objects_dir, &mut objects)?;
    }

    let sidecar = load_key_index(path)?;
    let (key_to_object, key_index) = apply_sidecar(&sidecar);

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
        .map_err(|_| MnemeError::SerializationNonCanonical)?;
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
    let line = serde_json::to_string(&entry).map_err(|_| MnemeError::SerializationNonCanonical)?;
    append_journal_line(path, "embeddings.journal", &line)
}

/// Append one embedding removal (forget shred) to `embeddings.journal` (O(1)).
pub fn persist_embeddings_remove(path: &Path, id: &[u8; 32]) -> Result<(), MnemeError> {
    let entry = EmbeddingJournalEntry::Remove { id: hex_encode(id) };
    let line = serde_json::to_string(&entry).map_err(|_| MnemeError::SerializationNonCanonical)?;
    append_journal_line(path, "embeddings.journal", &line)
}

fn load_embeddings(path: &Path) -> Result<HashMap<[u8; 32], FixedPointEmbedding>, MnemeError> {
    let mut out = HashMap::new();
    let p = path.join("meta/embeddings.json");
    if p.exists() {
        let data = fs::read_to_string(&p).map_err(|e| io_err(&p, e))?;
        let sidecar: EmbeddingSidecar =
            serde_json::from_str(&data).map_err(|_| MnemeError::SchemaDrift)?;
        for (id_hex, entry) in sidecar.entries {
            let id = parse_hex32(&id_hex)?;
            let emb = FixedPointEmbedding::new(entry.dim, entry.scale, entry.components)
                .map_err(|_| MnemeError::SchemaDrift)?;
            out.insert(id, emb);
        }
    }
    let journal = path.join("meta/embeddings.journal");
    if journal.exists() {
        let data = fs::read_to_string(&journal).map_err(|e| io_err(&journal, e))?;
        for line in data.lines().filter(|l| !l.trim().is_empty()) {
            let entry: EmbeddingJournalEntry =
                serde_json::from_str(line).map_err(|_| MnemeError::SchemaDrift)?;
            match entry {
                EmbeddingJournalEntry::Upsert {
                    id,
                    dim,
                    scale,
                    components,
                } => {
                    let id = parse_hex32(&id)?;
                    let emb = FixedPointEmbedding::new(dim, scale, components)
                        .map_err(|_| MnemeError::SchemaDrift)?;
                    out.insert(id, emb);
                }
                EmbeddingJournalEntry::Remove { id } => {
                    let id = parse_hex32(&id)?;
                    out.remove(&id);
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
    let mut sidecar = if index_path.exists() {
        let data = fs::read_to_string(&index_path).map_err(|e| io_err(&index_path, e))?;
        serde_json::from_str(&data).map_err(|_| MnemeError::SchemaDrift)?
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
    let line = serde_json::to_string(entry).map_err(|_| MnemeError::SerializationNonCanonical)?;
    append_journal_line(path, "key_index.journal", &line)
}

/// Append one newline-terminated record to a `meta/<name>` journal, with the same
/// crash-safe fsync discipline as the key-index journal.
fn append_journal_line(path: &Path, name: &str, line: &str) -> Result<(), MnemeError> {
    let journal = path.join("meta").join(name);
    if let Some(parent) = journal.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(&journal, e))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&journal)
        .map_err(|e| io_err(&journal, e))?;
    file.write_all(line.as_bytes())
        .map_err(|e| io_err(&journal, e))?;
    file.write_all(b"\n").map_err(|e| io_err(&journal, e))?;
    if std::env::var("MNEME_NO_FSYNC").is_err() {
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
    if journal.exists() {
        fs::remove_file(&journal).map_err(|e| io_err(&journal, e))?;
        if std::env::var("MNEME_NO_FSYNC").is_err() {
            sync_parent_dir(&journal)?;
        }
    }
    Ok(())
}

/// On-open journal compaction floor. A journal below this is cheap to replay, so
/// skip the O(N) base rewrite; above it (and once the journal outgrows its base
/// snapshot) compaction bounds disk + cold-open replay cost.
const JOURNAL_COMPACT_FLOOR_BYTES: u64 = 256 * 1024;

/// Compaction floor in bytes; overridable via `MNEME_JOURNAL_COMPACT_FLOOR_BYTES`
/// (operators can tune it; tests set 0 to force compaction at any size).
fn journal_compact_floor() -> u64 {
    std::env::var("MNEME_JOURNAL_COMPACT_FLOOR_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(JOURNAL_COMPACT_FLOOR_BYTES)
}

fn journal_outgrew_base(meta: &Path, base_name: &str, journal_name: &str) -> bool {
    let jsize = fs::metadata(meta.join(journal_name))
        .map(|m| m.len())
        .unwrap_or(0);
    if jsize < journal_compact_floor() {
        return false;
    }
    let bsize = fs::metadata(meta.join(base_name))
        .map(|m| m.len())
        .unwrap_or(0);
    jsize > bsize
}

/// One-time, threshold-gated sidecar compaction, run on store open. Single-entry
/// `remember`/`forget` append to per-sidecar journals (key_index / object_keys /
/// embeddings) that are only folded back into their base snapshot by a full
/// persist (batch / rekey). Without this, a long-lived single-write store grows
/// those journals O(total writes) and replays the whole journal on every open.
/// Fold any oversized journal back into its base via the crash-safe `persist_*`
/// path (atomic base write then journal drop; replay is idempotent, so a crash
/// in between re-applies the same state). Digest-neutral: the signed root derives
/// from the in-memory index roots, not the sidecar file bytes.
pub fn compact_oversized_sidecars(path: &Path, store: &Store) -> Result<(), MnemeError> {
    let meta = path.join("meta");
    if journal_outgrew_base(&meta, "key_index.json", "key_index.journal") {
        persist_key_index(path, store)?;
    }
    if journal_outgrew_base(&meta, "object_keys.json", "object_keys.journal") {
        persist_object_keys(path, store)?;
    }
    if journal_outgrew_base(&meta, "embeddings.json", "embeddings.journal") {
        persist_embeddings(path, store)?;
    }
    Ok(())
}

fn apply_key_index_journal(path: &Path, sidecar: &mut KeyIndexSidecar) -> Result<(), MnemeError> {
    let journal = path.join("meta/key_index.journal");
    if !journal.exists() {
        return Ok(());
    }
    let data = fs::read_to_string(&journal).map_err(|e| io_err(&journal, e))?;
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: KeyIndexJournalEntry =
            serde_json::from_str(line).map_err(|_| MnemeError::SchemaDrift)?;
        match entry {
            KeyIndexJournalEntry::Upsert { key, object } => {
                parse_hex32(&key)?;
                parse_hex32(&object)?;
                sidecar.tombstones.retain(|t| t != &key);
                sidecar.entries.insert(key, object);
            }
            KeyIndexJournalEntry::Tombstone { key } => {
                parse_hex32(&key)?;
                sidecar.entries.remove(&key);
                if !sidecar.tombstones.iter().any(|t| t == &key) {
                    sidecar.tombstones.push(key);
                }
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

fn apply_sidecar(sidecar: &KeyIndexSidecar) -> (HashMap<[u8; 32], [u8; 32]>, KeyIndex) {
    let mut key_to_object = HashMap::new();
    let mut smt = SparseMerkleTree::new();
    for (k, v) in &sidecar.entries {
        if let (Ok(kb), Ok(vb)) = (parse_hex32(k), parse_hex32(v)) {
            key_to_object.insert(kb, vb);
            smt.upsert(kb, vb);
        }
    }
    for t in &sidecar.tombstones {
        if let Ok(kb) = parse_hex32(t) {
            smt.tombstone(kb);
            key_to_object.remove(&kb);
        }
    }
    (key_to_object, KeyIndex::from_tree(smt))
}

fn walk_objects(dir: &Path, out: &mut HashMap<[u8; 32], Vec<u8>>) -> Result<(), MnemeError> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let p = entry.path();
        if p.is_dir() {
            walk_objects(&p, out)?;
        } else if p.extension().is_some_and(|e| e == "cbor") {
            let bytes = fs::read(&p).map_err(|e| io_err(&p, e))?;
            let id = hash_obj(&bytes);
            out.insert(id, bytes);
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Result<[u8; 32], MnemeError> {
    // Delegate to the canonical byte-safe decoder. The earlier local impl sliced
    // `&str` by byte range after only a byte-length check, which PANICS when a
    // corrupted/tampered sidecar packs 64 bytes of multibyte UTF-8 at a
    // non-char boundary (e.g. "€"+61 ASCII == 64 bytes). Sidecars are untrusted
    // on-disk data — fail closed, never panic (INV fail-closed default).
    mneme_core::decode_hex32(s)
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

    #[test]
    fn parse_hex32_rejects_multibyte_utf8_without_panic() {
        // 3-byte '€' + 61 ASCII == 64 bytes but not 64 chars. The previous
        // byte-range `&str` slice panicked on this corrupted-sidecar shape; the
        // canonical decoder must fail closed with a typed error instead.
        let s = format!("\u{20AC}{}", "a".repeat(61));
        assert_eq!(s.len(), 64);
        assert_eq!(parse_hex32(&s).unwrap_err(), MnemeError::SchemaDrift);
    }

    #[test]
    fn parse_hex32_roundtrips_canonical_lowercase() {
        let id = [0xABu8; 32];
        assert_eq!(parse_hex32(&hex_encode(&id)).unwrap(), id);
    }

    #[test]
    fn parse_hex32_rejects_wrong_length() {
        assert_eq!(parse_hex32("dead").unwrap_err(), MnemeError::SchemaDrift);
    }

    #[test]
    fn journal_outgrew_base_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let meta = dir.path().join("meta");
        fs::create_dir_all(&meta).unwrap();
        // No journal -> not oversized.
        assert!(!journal_outgrew_base(&meta, "k.json", "k.journal"));
        // Journal below the floor -> not oversized regardless of base.
        fs::write(meta.join("k.journal"), vec![0u8; 1024]).unwrap();
        assert!(!journal_outgrew_base(&meta, "k.json", "k.journal"));
        // Above floor and larger than base -> oversized (compact).
        fs::write(meta.join("k.journal"), vec![0u8; 300 * 1024]).unwrap();
        fs::write(meta.join("k.json"), vec![0u8; 1024]).unwrap();
        assert!(journal_outgrew_base(&meta, "k.json", "k.journal"));
        // Above floor but base is larger -> not oversized (no churn).
        fs::write(meta.join("k.json"), vec![0u8; 400 * 1024]).unwrap();
        assert!(!journal_outgrew_base(&meta, "k.json", "k.journal"));
    }
}
