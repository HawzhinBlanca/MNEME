//! Chronicle-style atomic I/O: temp + fsync + rename + `.incomplete` marker (§5.8, INV-8).

use mneme_core::MnemeError;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

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
        fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
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
                sync_parent_dir(&key)?;
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn create_new(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    if path.exists() {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "exists".into(),
        });
    }
    atomic_write(path, data)
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
            let dir = File::open(parent).map_err(|e| io_err(parent, e))?;
            dir.sync_all().map_err(|e| io_err(parent, e))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
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
    if marker.exists() {
        fs::remove_file(&marker).map_err(|e| io_err(&marker, e))?;
        if durability_fsync_enabled() {
            sync_parent_dir(&marker)?;
        }
    }
    Ok(())
}

pub fn check_no_incomplete(store: &Path) -> Result<(), MnemeError> {
    if incomplete_marker(store).exists() {
        return Err(MnemeError::IncompleteTransaction);
    }
    Ok(())
}

/// Advisory exclusive lock for single-writer store access (L2 deployment invariant).
pub fn open_store_lock(store: &Path) -> Result<File, MnemeError> {
    if let Some(parent) = store.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
    }
    fs::create_dir_all(store).map_err(|e| io_err(store, e))?;
    let lock = store.join(".mneme.lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock)
        .map_err(|e| io_err(&lock, e))?;
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
