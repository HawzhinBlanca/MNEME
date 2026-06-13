//! Chronicle-style atomic I/O: temp + fsync + rename + `.incomplete` marker (§5.8, INV-8).

use mneme_core::MnemeError;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt},
    io::AsRawFd,
};

pub(crate) fn durability_fsync_enabled() -> bool {
    !debug_no_fsync_requested()
}

#[cfg(debug_assertions)]
fn debug_no_fsync_requested() -> bool {
    std::env::var_os("MNEME_NO_FSYNC").is_some()
}

#[cfg(not(debug_assertions))]
fn debug_no_fsync_requested() -> bool {
    false
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    atomic_write_inner(path, data, true)
}

/// Like [`atomic_write`] but defers directory fsync until [`flush_parent_dirs`].
pub fn atomic_write_deferred(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    atomic_write_inner(path, data, false)
}

fn atomic_write_inner(path: &Path, data: &[u8], sync_dir: bool) -> Result<(), MnemeError> {
    if let Some(parent) = path.parent() {
        ensure_atomic_parent_dir(parent, "atomic write parent")?;
    }
    let (tmp, mut f) = create_atomic_tmp_file(path)?;
    {
        f.write_all(data).map_err(|e| io_err(path, e))?;
        if durability_fsync_enabled() {
            f.sync_all().map_err(|e| io_err(path, e))?;
        }
    }
    fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    if sync_dir && durability_fsync_enabled() {
        sync_parent_dir(path)?;
    }
    Ok(())
}

fn create_atomic_tmp_file(path: &Path) -> Result<(PathBuf, File), MnemeError> {
    create_atomic_tmp_file_from_nonces(path, rand::random::<u64>)
}

fn create_atomic_tmp_file_from_nonces(
    path: &Path,
    mut next_nonce: impl FnMut() -> u64,
) -> Result<(PathBuf, File), MnemeError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: "missing file name".into(),
    })?;
    for _ in 0..16 {
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".{}.{}.tmp", std::process::id(), next_nonce()));
        let tmp = parent.join(tmp_name);
        match OpenOptions::new().create_new(true).write(true).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(io_err(&tmp, err)),
        }
    }
    Err(MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: "temporary path collisions exhausted".into(),
    })
}

/// Fsync each parent directory once after a batch of [`atomic_write_deferred`] calls.
pub fn flush_parent_dirs(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
) -> Result<(), MnemeError> {
    if !durability_fsync_enabled() {
        return Ok(());
    }
    let mut seen = HashSet::new();
    for path in paths {
        if let Some(parent) = path.as_ref().parent() {
            if parent.as_os_str().is_empty() {
                continue;
            }
            let key = parent.to_path_buf();
            if seen.insert(key.clone()) {
                sync_dir(&key, "atomic sync parent")?;
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn create_new(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    reject_existing_entry(path)?;
    atomic_write(path, data)
}

fn reject_existing_entry(path: &Path) -> Result<(), MnemeError> {
    if entry_exists(path)? {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "exists".into(),
        });
    }
    Ok(())
}

pub(crate) fn entry_exists(path: &Path) -> Result<bool, MnemeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_err(path, err)),
    }
}

pub(crate) fn reject_store_root_alias(store: &Path) -> Result<(), MnemeError> {
    reject_store_parent_alias(store)?;
    match fs::symlink_metadata(store) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(MnemeError::IoFailed {
                    path: store.display().to_string(),
                    kind: "store directory symlink".into(),
                });
            }
            if !file_type.is_dir() {
                return Err(MnemeError::IoFailed {
                    path: store.display().to_string(),
                    kind: "store path non-directory".into(),
                });
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_err(store, err)),
    }
}

fn reject_store_parent_alias(store: &Path) -> Result<(), MnemeError> {
    if let Some(parent) = store.parent() {
        if !parent.as_os_str().is_empty() {
            reject_atomic_dir_alias(parent, "store parent")?;
            // Limit the alias scan to the mutable store-boundary suffix; scanning
            // every absolute ancestor would reject platform aliases like macOS /var.
            if let Some(ancestor) = parent.parent() {
                if !ancestor.as_os_str().is_empty() {
                    reject_atomic_dir_alias(ancestor, "store parent ancestor")?;
                }
            }
        }
    }
    Ok(())
}

/// Read a file without following symlinks (§15.1 no-follow-open on Unix).
pub fn read_no_follow(path: &Path) -> Result<Vec<u8>, MnemeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| io_err(path, e))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| io_err(path, e))?;
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        fs::read(path).map_err(|e| io_err(path, e))
    }
}

pub(crate) fn open_append_single_link(path: &Path) -> Result<File, MnemeError> {
    if let Some(parent) = path.parent() {
        ensure_atomic_parent_dir(parent, "append parent")?;
    }
    #[cfg(unix)]
    {
        let mut create = OpenOptions::new();
        create
            .create_new(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW);
        match create.open(path) {
            Ok(file) => {
                validate_open_append_file(path, &file)?;
                return Ok(file);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(io_err(path, err)),
        }

        validate_append_path(path)?;
        let mut open = OpenOptions::new();
        open.append(true).custom_flags(libc::O_NOFOLLOW);
        let file = open.open(path).map_err(|e| io_err(path, e))?;
        validate_open_append_file(path, &file)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| io_err(path, e))
    }
}

#[cfg(unix)]
fn validate_append_path(path: &Path) -> Result<fs::Metadata, MnemeError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_err(path, e))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "append target symlink".into(),
        });
    }
    if !file_type.is_file() {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "append target non-regular".into(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "append target hard-linked".into(),
        });
    }
    Ok(metadata)
}

#[cfg(unix)]
fn validate_open_append_file(path: &Path, file: &File) -> Result<(), MnemeError> {
    let path_metadata = validate_append_path(path)?;
    let file_metadata = file.metadata().map_err(|e| io_err(path, e))?;
    if !file_metadata.file_type().is_file() || file_metadata.nlink() != 1 {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "opened append target is not a regular single-link file".into(),
        });
    }
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "append target changed during open".into(),
        });
    }
    Ok(())
}

/// Fsync the parent directory so a preceding `rename` is durable across a crash.
///
/// This is a **Unix** durability primitive: after `rename(2)`, the directory entry
/// must be fsync'd for the rename to survive power loss. Windows has no equivalent —
/// a directory handle cannot be flushed via `sync_all` (it fails with "Access is
/// denied"), and NTFS does not require it: the temp file's own `sync_all`
/// (`FlushFileBuffers`, see `atomic_write`) plus the transactional `MoveFileEx`
/// rename provide the durability barrier. So directory fsync is performed on Unix and
/// is a correct no-op elsewhere — Windows keeps full *file*-level durability (we never
/// disable `sync_all`), only the dir-entry fsync that the platform neither supports
/// nor needs is skipped. This makes Windows a first-class store host with the same
/// crash-safety contract, without the crash-unsafe `MNEME_NO_FSYNC` escape hatch.
fn sync_parent_dir(path: &Path) -> Result<(), MnemeError> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(());
            }
            sync_dir(parent, "atomic sync parent")?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path, label: &str) -> Result<(), MnemeError> {
    reject_atomic_dir_alias(dir, label)?;
    let dir_file = File::open(dir).map_err(|e| io_err(dir, e))?;
    dir_file.sync_all().map_err(|e| io_err(dir, e))
}

#[cfg(not(unix))]
fn sync_dir(dir: &Path, label: &str) -> Result<(), MnemeError> {
    let _ = (dir, label);
    Ok(())
}

fn ensure_atomic_parent_dir(parent: &Path, label: &str) -> Result<(), MnemeError> {
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    reject_atomic_dir_alias(parent, label)?;
    fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    reject_atomic_dir_alias(parent, label)
}

fn reject_atomic_dir_alias(dir: &Path, label: &str) -> Result<(), MnemeError> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => validate_atomic_dir_metadata(dir, label, metadata).map(|_| ()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_err(dir, err)),
    }
}

fn validate_atomic_dir_metadata(
    dir: &Path,
    label: &str,
    metadata: fs::Metadata,
) -> Result<fs::Metadata, MnemeError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(MnemeError::IoFailed {
            path: dir.display().to_string(),
            kind: format!("{label} directory symlink"),
        });
    }
    if !file_type.is_dir() {
        return Err(MnemeError::IoFailed {
            path: dir.display().to_string(),
            kind: format!("{label} path non-directory"),
        });
    }
    Ok(metadata)
}

fn io_err(path: &Path, e: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    }
}

pub fn incomplete_marker(store: &Path) -> PathBuf {
    store.join(".incomplete")
}

pub fn begin_incomplete(store: &Path) -> Result<(), MnemeError> {
    let marker = incomplete_marker(store);
    atomic_write(&marker, b"1")
}

pub fn end_incomplete(store: &Path) -> Result<(), MnemeError> {
    let marker = incomplete_marker(store);
    if entry_exists(&marker)? {
        fs::remove_file(&marker).map_err(|e| io_err(&marker, e))?;
        if durability_fsync_enabled() {
            sync_parent_dir(&marker)?;
        }
    }
    Ok(())
}

pub fn check_no_incomplete(store: &Path) -> Result<(), MnemeError> {
    if entry_exists(&incomplete_marker(store))? {
        return Err(MnemeError::IncompleteTransaction);
    }
    Ok(())
}

/// Advisory exclusive lock for single-writer store access (L2 deployment invariant).
pub fn open_store_lock(store: &Path) -> Result<File, MnemeError> {
    reject_store_parent_alias(store)?;
    if let Some(parent) = store.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
            reject_store_parent_alias(store)?;
        }
    }
    reject_store_root_alias(store)?;
    fs::create_dir_all(store).map_err(|e| io_err(store, e))?;
    reject_store_root_alias(store)?;
    let lock = store.join(".mneme.lock");
    let file = open_store_lock_file(&lock)?;
    #[cfg(unix)]
    {
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Err(MnemeError::LockHeld);
            }
            return Err(io_err(&lock, err));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &file;
        return Err(MnemeError::IoFailed {
            path: lock.display().to_string(),
            kind: "advisory flock requires unix".into(),
        });
    }
    Ok(file)
}

#[cfg(unix)]
fn open_store_lock_file(lock: &Path) -> Result<File, MnemeError> {
    let mut create = OpenOptions::new();
    create
        .create_new(true)
        .write(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW);
    match create.open(lock) {
        Ok(file) => {
            validate_open_lock_file(lock, &file)?;
            return Ok(file);
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(io_err(lock, err)),
    }

    validate_lock_path(lock)?;
    let mut open = OpenOptions::new();
    open.write(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW);
    let file = open.open(lock).map_err(|e| io_err(lock, e))?;
    validate_open_lock_file(lock, &file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_store_lock_file(lock: &Path) -> Result<File, MnemeError> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lock)
        .map_err(|e| io_err(lock, e))
}

#[cfg(unix)]
fn validate_lock_path(lock: &Path) -> Result<fs::Metadata, MnemeError> {
    let metadata = fs::symlink_metadata(lock).map_err(|e| io_err(lock, e))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(MnemeError::IoFailed {
            path: lock.display().to_string(),
            kind: "lockfile symlink".into(),
        });
    }
    if !file_type.is_file() {
        return Err(MnemeError::IoFailed {
            path: lock.display().to_string(),
            kind: "lockfile non-regular".into(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(MnemeError::IoFailed {
            path: lock.display().to_string(),
            kind: "lockfile hard-linked".into(),
        });
    }
    Ok(metadata)
}

#[cfg(unix)]
fn validate_open_lock_file(lock: &Path, file: &File) -> Result<(), MnemeError> {
    let path_metadata = validate_lock_path(lock)?;
    let file_metadata = file.metadata().map_err(|e| io_err(lock, e))?;
    if !file_metadata.file_type().is_file() || file_metadata.nlink() != 1 {
        return Err(MnemeError::IoFailed {
            path: lock.display().to_string(),
            kind: "opened lockfile is not a regular single-link file".into(),
        });
    }
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(MnemeError::IoFailed {
            path: lock.display().to_string(),
            kind: "lockfile changed during open".into(),
        });
    }
    Ok(())
}

const DURABILITY_DISABLED_META: &str = "meta/durability_disabled.json";

/// One-time durability audit at store open (WO-11).
pub fn audit_durability_at_open(store: &Path) -> Result<(), MnemeError> {
    let flag_path = store.join(DURABILITY_DISABLED_META);
    if flag_path.exists() {
        eprintln!(
            "mneme-store: WARNING — prior session wrote meta/durability_disabled.json; \
             crash-unsafe durability was enabled in a debug/test run"
        );
    }
    if !durability_fsync_enabled() {
        eprintln!(
            "mneme-store: WARNING — MNEME_NO_FSYNC is set; all fsync barriers are disabled \
             (debug/test only, crash-unsafe)"
        );
        fs::create_dir_all(store.join("meta")).map_err(|e| io_err(store, e))?;
        let payload = serde_json::json!({
            "reason": "MNEME_NO_FSYNC",
            "fsync_enabled": false,
        });
        let data = serde_json::to_string_pretty(&payload)
            .map_err(|_| MnemeError::SerializationNonCanonical)?;
        atomic_write(&flag_path, data.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_source(source: &str) -> &str {
        source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _tests)| production)
    }

    #[cfg(unix)]
    #[test]
    fn atomic_tmp_file_skips_preexisting_symlink_without_truncating_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("HEAD");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"victim").expect("victim fixture");

        let first_tmp = dir
            .path()
            .join(format!(".HEAD.{}.{}.tmp", std::process::id(), 11_u64));
        std::os::unix::fs::symlink(&victim, &first_tmp).expect("tmp symlink fixture");

        let mut calls = 0_u8;
        let (second_tmp, file) = create_atomic_tmp_file_from_nonces(&target, || {
            calls += 1;
            if calls == 1 { 11 } else { 12 }
        })
        .expect("second nonce creates tmp file");
        drop(file);

        assert_ne!(second_tmp, first_tmp);
        assert!(second_tmp.exists());
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"victim");
        assert!(
            std::fs::symlink_metadata(&first_tmp)
                .expect("first tmp symlink")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn atomic_tmp_file_fails_closed_after_collision_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("HEAD");
        for nonce in 0..16_u64 {
            let tmp = dir
                .path()
                .join(format!(".HEAD.{}.{}.tmp", std::process::id(), nonce));
            std::fs::write(tmp, b"occupied").expect("occupied tmp fixture");
        }

        let mut nonce = 0_u64;
        let err = create_atomic_tmp_file_from_nonces(&target, || {
            let current = nonce;
            nonce += 1;
            current
        })
        .expect_err("collisions should fail closed");
        assert!(
            err.to_string()
                .contains("temporary path collisions exhausted")
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_rejects_symlinked_parent_without_writing_external_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let external = dir.path().join("external-parent");
        let parent = dir.path().join("linked-parent");
        std::fs::create_dir(&external).expect("external parent target");
        std::os::unix::fs::symlink(&external, &parent).expect("parent symlink");

        let err = atomic_write(&parent.join("HEAD"), b"root")
            .expect_err("atomic write should reject a symlinked parent");

        assert!(
            err.to_string().contains("symlink"),
            "parent alias rejection should mention symlink, got {err}"
        );
        assert!(
            std::fs::read_dir(&external)
                .expect("external parent read")
                .next()
                .is_none(),
            "atomic write must not create temp or target files through a symlinked parent"
        );
        assert!(
            std::fs::symlink_metadata(&parent)
                .expect("parent symlink metadata")
                .file_type()
                .is_symlink(),
            "failed atomic write must leave the symlinked parent for explicit repair"
        );
    }

    #[cfg(unix)]
    #[test]
    fn flush_parent_dirs_rejects_symlinked_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let external = dir.path().join("external-sync-parent");
        let parent = dir.path().join("linked-sync-parent");
        std::fs::create_dir(&external).expect("external sync parent target");
        std::os::unix::fs::symlink(&external, &parent).expect("sync parent symlink");

        let err = flush_parent_dirs([parent.join("HEAD")])
            .expect_err("parent flush should reject a symlinked parent");

        assert!(
            err.to_string().contains("symlink"),
            "sync parent alias rejection should mention symlink, got {err}"
        );
        assert!(
            std::fs::symlink_metadata(&parent)
                .expect("sync parent symlink metadata")
                .file_type()
                .is_symlink(),
            "failed parent flush must leave the symlinked parent for explicit repair"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_new_rejects_broken_symlink_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("new-entry");
        let missing = dir.path().join("missing-target");
        std::os::unix::fs::symlink(&missing, &target).expect("broken symlink fixture");
        assert!(!target.exists(), "fixture should be a dangling symlink");

        let err = create_new(&target, b"new").expect_err("broken symlink counts as existing");

        assert!(matches!(err, MnemeError::IoFailed { kind, .. } if kind == "exists"));
        assert!(
            std::fs::symlink_metadata(&target)
                .expect("target symlink remains")
                .file_type()
                .is_symlink()
        );
        assert!(
            !missing.exists(),
            "create_new must not follow or materialize the symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn incomplete_marker_checks_count_dangling_symlink_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing-incomplete-marker");
        let marker = incomplete_marker(dir.path());
        std::os::unix::fs::symlink(&missing, &marker).expect("dangling marker symlink");
        assert!(!marker.exists(), "fixture should be a dangling symlink");

        let err = check_no_incomplete(dir.path()).expect_err("dangling marker must fail closed");
        assert_eq!(err, MnemeError::IncompleteTransaction);

        end_incomplete(dir.path()).expect("remove dangling marker entry");
        assert!(
            std::fs::symlink_metadata(&marker).is_err(),
            "end_incomplete should remove the symlink entry"
        );
        assert!(
            !missing.exists(),
            "marker cleanup must not materialize a dangling target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_store_lock_creates_regular_single_link_lockfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("store");

        let file = open_store_lock(&store).expect("lock open");
        let lock = store.join(".mneme.lock");
        let path_metadata = std::fs::symlink_metadata(&lock).expect("lock metadata");
        let file_metadata = file.metadata().expect("open lock metadata");

        assert!(path_metadata.file_type().is_file());
        assert_eq!(path_metadata.nlink(), 1);
        assert_eq!(path_metadata.dev(), file_metadata.dev());
        assert_eq!(path_metadata.ino(), file_metadata.ino());
    }

    #[cfg(unix)]
    #[test]
    fn open_store_lock_rejects_symlink_lockfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("store dir");
        let target = dir.path().join("external.lock");
        std::fs::write(&target, b"external").expect("external lock fixture");
        std::os::unix::fs::symlink(&target, store.join(".mneme.lock"))
            .expect("lock symlink fixture");

        let err = open_store_lock(&store).expect_err("symlink lockfile rejected");

        assert!(err.to_string().contains("lockfile symlink"));
        assert_eq!(
            std::fs::read(&target).expect("external lock target"),
            b"external"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_store_lock_rejects_hard_linked_lockfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("store dir");
        let target = dir.path().join("external.lock");
        std::fs::write(&target, b"external").expect("external lock fixture");
        std::fs::hard_link(&target, store.join(".mneme.lock")).expect("lock hard-link fixture");

        let err = open_store_lock(&store).expect_err("hard-linked lockfile rejected");

        assert!(err.to_string().contains("lockfile hard-linked"));
        assert_eq!(
            std::fs::read(&target).expect("external lock target"),
            b"external"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_store_lock_rejects_non_regular_lockfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("store");
        std::fs::create_dir_all(store.join(".mneme.lock")).expect("directory lock fixture");

        let err = open_store_lock(&store).expect_err("directory lockfile rejected");

        assert!(err.to_string().contains("lockfile non-regular"));
    }

    #[test]
    fn no_fsync_escape_hatch_is_debug_only_and_centralized() {
        let atomic = production_source(include_str!("atomic.rs"));
        let layout = production_source(include_str!("layout.rs"));
        let combined = [atomic, layout].join("\n");

        assert!(
            atomic.contains("fn durability_fsync_enabled("),
            "store fsync decisions must route through a named helper"
        );
        assert!(
            atomic.contains("#[cfg(debug_assertions)]"),
            "MNEME_NO_FSYNC may only be read in debug builds"
        );
        assert!(
            atomic.contains("#[cfg(not(debug_assertions))]"),
            "release builds must compile an env-independent fsync path"
        );
        assert_eq!(
            combined
                .matches("std::env::var(\"MNEME_NO_FSYNC\")")
                .count(),
            0,
            "store write paths must not read MNEME_NO_FSYNC directly"
        );
        assert_eq!(
            combined
                .matches("std::env::var_os(\"MNEME_NO_FSYNC\")")
                .count(),
            1,
            "only the debug-only helper may inspect MNEME_NO_FSYNC"
        );
    }
}
