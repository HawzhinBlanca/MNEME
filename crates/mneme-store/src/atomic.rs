//! Chronicle-style atomic I/O: temp + fsync + rename + `.incomplete` marker (§5.8, INV-8).

use mneme_core::MnemeError;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
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
    if std::env::var("MNEME_NO_FSYNC").is_err() {
        sync_parent_dir(path)?;
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

fn sync_parent_dir(path: &Path) -> Result<(), MnemeError> {
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        let dir = File::open(parent).map_err(|e| io_err(parent, e))?;
        dir.sync_all().map_err(|e| io_err(parent, e))?;
    }
    Ok(())
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
