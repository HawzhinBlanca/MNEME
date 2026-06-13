//! Atomic rename writes for checkpoint log and HEAD (§5.8, §15.1).

use mneme_core::MnemeError;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
    }
    let (tmp, mut f) = create_atomic_tmp_file(path)?;
    {
        f.write_all(data).map_err(|e| io_err(path, e))?;
        f.sync_all().map_err(|e| io_err(path, e))?;
    }
    fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    sync_parent_dir(path)?;
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

/// Create-new checkpoint entry; fails closed if the sequence file already exists.
pub fn create_new(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    reject_existing_entry(path)?;
    atomic_write(path, data)
}

fn reject_existing_entry(path: &Path) -> Result<(), MnemeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "exists".into(),
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_err(path, err)),
    }
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
}
