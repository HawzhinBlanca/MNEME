//! Canonical content-addressed object path parsing for store and verifier loaders.

use std::path::{Component, Path};

use crate::{MnemeError, decode_hex32};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectPathFailure {
    OutsideObjectsDir,
    MissingShard,
    MissingFile,
    NonUtf8Shard,
    NonUtf8File,
    ExtraComponent,
    MissingCborSuffix,
    ShardLength,
    IdLength,
    ShardMismatch,
}

/// Parse `objects/<first-two-hex>/<64-hex-id>.cbor` and return the claimed id.
pub fn decode_content_addressed_object_path(
    objects_dir: &Path,
    path: &Path,
) -> Result<[u8; 32], MnemeError> {
    let relative = path
        .strip_prefix(objects_dir)
        .map_err(|_| object_path_outside_objects_dir_error())?;
    let mut components = relative.components();
    let shard = match components.next() {
        Some(Component::Normal(shard)) => shard
            .to_str()
            .ok_or_else(object_path_non_utf8_shard_error)?,
        _ => return Err(object_path_missing_shard_error()),
    };
    let file = match components.next() {
        Some(Component::Normal(file)) => {
            file.to_str().ok_or_else(object_path_non_utf8_file_error)?
        }
        _ => return Err(object_path_missing_file_error()),
    };
    if components.next().is_some() {
        return Err(object_path_extra_component_error());
    }
    let claimed_hex = file
        .strip_suffix(".cbor")
        .ok_or_else(object_path_missing_cbor_suffix_error)?;
    let shard_bytes = shard.as_bytes();
    let claimed_bytes = claimed_hex.as_bytes();
    if shard_bytes.len() != 2 {
        return Err(object_path_shard_length_error());
    }
    if claimed_bytes.len() != 64 {
        return Err(object_path_id_length_error());
    }
    if !shard_bytes.eq_ignore_ascii_case(&claimed_bytes[..2]) {
        return Err(object_path_shard_mismatch_error());
    }
    decode_hex32(claimed_hex)
}

fn object_path_failure_to_mneme(failure: ObjectPathFailure) -> MnemeError {
    match failure {
        ObjectPathFailure::OutsideObjectsDir
        | ObjectPathFailure::MissingShard
        | ObjectPathFailure::MissingFile
        | ObjectPathFailure::NonUtf8Shard
        | ObjectPathFailure::NonUtf8File
        | ObjectPathFailure::ExtraComponent
        | ObjectPathFailure::MissingCborSuffix
        | ObjectPathFailure::ShardLength
        | ObjectPathFailure::IdLength
        | ObjectPathFailure::ShardMismatch => MnemeError::SchemaDrift,
    }
}

fn object_path_outside_objects_dir_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::OutsideObjectsDir)
}

fn object_path_missing_shard_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::MissingShard)
}

fn object_path_missing_file_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::MissingFile)
}

fn object_path_non_utf8_shard_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::NonUtf8Shard)
}

fn object_path_non_utf8_file_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::NonUtf8File)
}

fn object_path_extra_component_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::ExtraComponent)
}

fn object_path_missing_cbor_suffix_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::MissingCborSuffix)
}

fn object_path_shard_length_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::ShardLength)
}

fn object_path_id_length_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::IdLength)
}

fn object_path_shard_mismatch_error() -> MnemeError {
    object_path_failure_to_mneme(ObjectPathFailure::ShardMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_path_failures_are_schema_drift() {
        for failure in [
            ObjectPathFailure::OutsideObjectsDir,
            ObjectPathFailure::MissingShard,
            ObjectPathFailure::MissingFile,
            ObjectPathFailure::NonUtf8Shard,
            ObjectPathFailure::NonUtf8File,
            ObjectPathFailure::ExtraComponent,
            ObjectPathFailure::MissingCborSuffix,
            ObjectPathFailure::ShardLength,
            ObjectPathFailure::IdLength,
            ObjectPathFailure::ShardMismatch,
        ] {
            assert_eq!(
                object_path_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }
}
