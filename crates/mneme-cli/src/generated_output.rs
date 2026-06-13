use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

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
    validate_path(path)?;
    let mut open = fs::OpenOptions::new();
    open.create(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = open.open(path)?;
    reject_alias_metadata(&file.metadata()?)?;
    file.set_len(0)?;
    file.write_all(data)?;
    Ok(())
}
