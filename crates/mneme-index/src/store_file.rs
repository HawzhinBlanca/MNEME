//! Store sidecar file reads for verifier-side index reconstruction.
//!
//! These readers keep filesystem custody checks in `mneme-index`, where the
//! sidecar formats live, instead of growing the `mneme-verify` TCB.

use mneme_core::MnemeError;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;

pub(crate) fn read_optional_to_string(path: &Path) -> Result<Option<String>, MnemeError> {
    if !entry_exists(path)? {
        return Ok(None);
    }
    let bytes = read_single_link_file(path)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| store_file_error_kind_failure_to_mneme(path, ErrorKind::InvalidData))
}

fn entry_exists(path: &Path) -> Result<bool, MnemeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(store_file_io_failure_to_mneme(path, err)),
    }
}

#[cfg(unix)]
fn read_single_link_file(path: &Path) -> Result<Vec<u8>, MnemeError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let path_metadata = validate_single_link_path(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| store_file_io_failure_to_mneme(path, e))?;
    validate_open_file_matches_path(path, &path_metadata, &file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| store_file_io_failure_to_mneme(path, e))?;
    Ok(bytes)
}

#[cfg(unix)]
fn validate_single_link_path(path: &Path) -> Result<fs::Metadata, MnemeError> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::symlink_metadata(path).map_err(|e| store_file_io_failure_to_mneme(path, e))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(store_file_failure_to_mneme(path, StoreFileFailure::Symlink));
    }
    if !file_type.is_file() {
        return Err(store_file_failure_to_mneme(
            path,
            StoreFileFailure::NonRegular,
        ));
    }
    if metadata.nlink() != 1 {
        return Err(store_file_failure_to_mneme(
            path,
            StoreFileFailure::HardLinked,
        ));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn validate_open_file_matches_path(
    path: &Path,
    path_metadata: &fs::Metadata,
    file: &fs::File,
) -> Result<(), MnemeError> {
    use std::os::unix::fs::MetadataExt;

    let file_metadata = file
        .metadata()
        .map_err(|e| store_file_io_failure_to_mneme(path, e))?;
    if !file_metadata.file_type().is_file() || file_metadata.nlink() != 1 {
        return Err(store_file_failure_to_mneme(
            path,
            StoreFileFailure::OpenedNotSingleLink,
        ));
    }
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(store_file_failure_to_mneme(
            path,
            StoreFileFailure::ChangedDuringOpen,
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_single_link_file(path: &Path) -> Result<Vec<u8>, MnemeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| store_file_io_failure_to_mneme(path, e))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(store_file_failure_to_mneme(path, StoreFileFailure::Symlink));
    }
    if !file_type.is_file() {
        return Err(store_file_failure_to_mneme(
            path,
            StoreFileFailure::NonRegular,
        ));
    }
    fs::read(path).map_err(|e| store_file_io_failure_to_mneme(path, e))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreFileFailure {
    Symlink,
    NonRegular,
    HardLinked,
    OpenedNotSingleLink,
    ChangedDuringOpen,
}

fn store_file_failure_to_mneme(path: &Path, failure: StoreFileFailure) -> MnemeError {
    let kind = match failure {
        StoreFileFailure::Symlink => "index sidecar symlink",
        StoreFileFailure::NonRegular => "index sidecar non-regular",
        StoreFileFailure::HardLinked => "index sidecar hard-linked",
        StoreFileFailure::OpenedNotSingleLink => {
            "opened index sidecar is not a regular single-link file"
        }
        StoreFileFailure::ChangedDuringOpen => "index sidecar changed during open",
    };
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: kind.into(),
    }
}

fn store_file_io_failure_to_mneme(path: &Path, err: std::io::Error) -> MnemeError {
    store_file_error_kind_failure_to_mneme(path, err.kind())
}

fn store_file_error_kind_failure_to_mneme(path: &Path, kind: ErrorKind) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn optional_missing_sidecar_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            read_optional_to_string(&dir.path().join("missing.json")).expect("optional read"),
            None
        );
    }

    #[test]
    fn optional_invalid_utf8_stays_io_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.json");
        fs::write(&path, [0xff]).expect("fixture");

        let err = read_optional_to_string(&path).expect_err("invalid UTF-8 rejected");

        assert_eq!(
            err,
            MnemeError::IoFailed {
                path: path.display().to_string(),
                kind: ErrorKind::InvalidData.to_string(),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn optional_symlink_sidecar_is_rejected_without_following_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("external.json");
        let link = dir.path().join("sidecar.json");
        fs::write(&target, "{}").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = read_optional_to_string(&link).expect_err("symlink rejected");

        assert_eq!(
            err,
            MnemeError::IoFailed {
                path: link.display().to_string(),
                kind: "index sidecar symlink".into(),
            }
        );
        assert_eq!(fs::read_to_string(&target).expect("target"), "{}");
    }

    #[cfg(unix)]
    #[test]
    fn optional_hardlinked_sidecar_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("external.json");
        let hardlink = dir.path().join("sidecar.json");
        fs::write(&target, "{}").expect("target");
        fs::hard_link(&target, &hardlink).expect("hardlink");

        let err = read_optional_to_string(&hardlink).expect_err("hardlink rejected");

        assert_eq!(
            err,
            MnemeError::IoFailed {
                path: hardlink.display().to_string(),
                kind: "index sidecar hard-linked".into(),
            }
        );
    }
}
