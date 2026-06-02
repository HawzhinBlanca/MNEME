//! Chronicle-style atomic I/O: temp + fsync + rename + `.incomplete` marker (§5.8, INV-8).

use mneme_core::MnemeError;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| io_err(path, e))?;
        f.write_all(data).map_err(|e| io_err(path, e))?;
        if std::env::var("MNEME_NO_FSYNC").is_err() {
            f.sync_all().map_err(|e| io_err(path, e))?;
        }
    }
    fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    if sync_dir && std::env::var("MNEME_NO_FSYNC").is_err() {
        sync_parent_dir(path)?;
    }
    Ok(())
}

/// Fsync each parent directory once after a batch of [`atomic_write_deferred`] calls.
pub fn flush_parent_dirs(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
) -> Result<(), MnemeError> {
    if std::env::var("MNEME_NO_FSYNC").is_ok() {
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
    }
    Ok(())
}

pub fn check_no_incomplete(store: &Path) -> Result<(), MnemeError> {
    if incomplete_marker(store).exists() {
        return Err(MnemeError::IncompleteTransaction);
    }
    Ok(())
}

#[allow(dead_code)]
pub fn open_store_lock(store: &Path) -> Result<File, MnemeError> {
    let lock = store.join(".mneme.lock");
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock)
        .map_err(|e| io_err(&lock, e))
}
