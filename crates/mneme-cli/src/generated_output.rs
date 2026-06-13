use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum GeneratedOutputError {
    Io(io::Error),
    Symlink,
    NotRegularFile,
    HardLinked,
}

impl fmt::Display for GeneratedOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Symlink => write!(
                f,
                "output path must reference a regular file, not a symlink"
            ),
            Self::NotRegularFile => write!(f, "output path must reference a regular file"),
            Self::HardLinked => write!(f, "output path must not be hard-linked"),
        }
    }
}

impl std::error::Error for GeneratedOutputError {}

impl From<io::Error> for GeneratedOutputError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

pub fn validate_path(path: &Path) -> Result<(), GeneratedOutputError> {
    if let Some(metadata) = existing_metadata(path)? {
        reject_alias_metadata(&metadata)?;
    }
    Ok(())
}

fn existing_metadata(path: &Path) -> Result<Option<fs::Metadata>, GeneratedOutputError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn reject_alias_metadata(metadata: &fs::Metadata) -> Result<(), GeneratedOutputError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(GeneratedOutputError::Symlink);
    }
    if !file_type.is_file() {
        return Err(GeneratedOutputError::NotRegularFile);
    }
    reject_hard_linked(metadata)
}

#[cfg(unix)]
fn reject_hard_linked(metadata: &fs::Metadata) -> Result<(), GeneratedOutputError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() != 1 {
        return Err(GeneratedOutputError::HardLinked);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hard_linked(_metadata: &fs::Metadata) -> Result<(), GeneratedOutputError> {
    Ok(())
}

pub fn write_file(path: &Path, data: &[u8]) -> Result<(), GeneratedOutputError> {
    write_file_from_nonces(path, data, rand::random::<u64>)
}

fn write_file_from_nonces(
    path: &Path,
    data: &[u8],
    next_nonce: impl FnMut() -> u64,
) -> Result<(), GeneratedOutputError> {
    reject_parent_alias(path)?;
    validate_path(path)?;
    let (tmp_path, mut file) = create_tmp_file_from_nonces(path, next_nonce)?;
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        reject_alias_metadata(&file.metadata()?)?;
        fs::rename(&tmp_path, path)?;
        sync_parent_dir(path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn create_tmp_file_from_nonces(
    path: &Path,
    mut next_nonce: impl FnMut() -> u64,
) -> Result<(PathBuf, File), GeneratedOutputError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "output path missing file name")
    })?;
    for _ in 0..16 {
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".{}.{}.tmp", std::process::id(), next_nonce()));
        let tmp_path = parent.join(tmp_name);
        let mut open = fs::OpenOptions::new();
        open.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW);
        }
        match open.open(&tmp_path) {
            Ok(file) => {
                reject_alias_metadata(&file.metadata()?)?;
                return Ok((tmp_path, file));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary output path collisions exhausted",
    )
    .into())
}

fn sync_parent_dir(path: &Path) -> Result<(), GeneratedOutputError> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(());
            }
            reject_dir_alias(parent)?;
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn reject_parent_alias(path: &Path) -> Result<(), GeneratedOutputError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            reject_dir_alias(parent)?;
        }
    }
    Ok(())
}

fn reject_dir_alias(dir: &Path) -> Result<(), GeneratedOutputError> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(GeneratedOutputError::Symlink);
            }
            if !file_type.is_dir() {
                return Err(GeneratedOutputError::NotRegularFile);
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_file_replaces_existing_output_with_new_inode() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("proof.cbor");
        fs::write(&output, b"old valid proof").expect("existing output");
        let old_metadata = fs::metadata(&output).expect("old output metadata");

        write_file(&output, b"new valid proof").expect("atomic generated output write");

        let new_metadata = fs::metadata(&output).expect("new output metadata");
        assert_eq!(
            fs::read(&output).expect("new output bytes"),
            b"new valid proof"
        );
        assert_ne!(
            (old_metadata.dev(), old_metadata.ino()),
            (new_metadata.dev(), new_metadata.ino()),
            "generated output replacement must publish a new file instead of truncating the old output in place"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_file_skips_preexisting_tmp_symlink_without_truncating_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("proof.cbor");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"victim").expect("victim fixture");
        let first_tmp =
            dir.path()
                .join(format!(".proof.cbor.{}.{}.tmp", std::process::id(), 7_u64));
        std::os::unix::fs::symlink(&victim, &first_tmp).expect("tmp symlink fixture");

        let mut calls = 0_u8;
        write_file_from_nonces(&output, b"new proof", || {
            calls += 1;
            if calls == 1 { 7 } else { 8 }
        })
        .expect("second tmp nonce should publish output");

        assert_eq!(fs::read(&output).expect("output bytes"), b"new proof");
        assert_eq!(fs::read(&victim).expect("victim bytes"), b"victim");
        assert!(
            fs::symlink_metadata(&first_tmp)
                .expect("first tmp symlink remains")
                .file_type()
                .is_symlink(),
            "failed tmp collision must leave the preexisting symlink untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_file_rejects_symlinked_parent_without_writing_external_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let external = dir.path().join("external-output-parent");
        let parent = dir.path().join("linked-output-parent");
        fs::create_dir(&external).expect("external output parent target");
        std::os::unix::fs::symlink(&external, &parent).expect("output parent symlink");

        let err = write_file(&parent.join("proof.cbor"), b"proof")
            .expect_err("generated output writer should reject a symlinked parent");

        assert!(
            err.to_string().contains("symlink"),
            "parent alias rejection should mention symlink, got {err}"
        );
        assert!(
            fs::read_dir(&external)
                .expect("external parent read")
                .next()
                .is_none(),
            "generated output writer must not create temp or output files through a symlinked parent"
        );
        assert!(
            fs::symlink_metadata(&parent)
                .expect("parent symlink metadata")
                .file_type()
                .is_symlink(),
            "failed generated output write must leave the symlinked parent for explicit repair"
        );
    }
}
