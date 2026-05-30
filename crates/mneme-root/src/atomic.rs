//! Atomic rename writes for checkpoint log and HEAD (§5.8, §15.1).

use mneme_core::MnemeError;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| io_err(path, e))?;
        f.write_all(data).map_err(|e| io_err(path, e))?;
        f.sync_all().map_err(|e| io_err(path, e))?;
    }
    fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    Ok(())
}

/// Create-new checkpoint entry; fails closed if the sequence file already exists.
pub fn create_new(path: &Path, data: &[u8]) -> Result<(), MnemeError> {
    if path.exists() {
        return Err(MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: "exists".into(),
        });
    }
    atomic_write(path, data)
}

fn io_err(path: &Path, e: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    }
}
