//! Fail-closed wire fuzz hooks for index + receipt paths (§17.4, CRDT-less).

use crate::commit::SemanticMerkleTree;
use mneme_core::MnemeError;
use mneme_smt::{fuzz_parse_and_verify, parse_proof_blob};

const TAG_RECEIPT_BUNDLE: u8 = 0x03;
const TAG_SEM_PATH: u8 = 0x04;
const MAX_SEM_PATH_LEN: usize = 64;

type SemPathWire = (usize, [u8; 32], Vec<[u8; 32]>, [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexWireFailure {
    ReadOverflow,
    ReadTruncated,
    SemPathTooLong,
    SemPathReserve,
    SemPathTrailing,
    ReceiptMissingProofTail,
}

fn index_wire_failure_to_mneme(failure: IndexWireFailure) -> MnemeError {
    match failure {
        IndexWireFailure::ReadOverflow
        | IndexWireFailure::ReadTruncated
        | IndexWireFailure::SemPathTooLong
        | IndexWireFailure::SemPathReserve
        | IndexWireFailure::SemPathTrailing
        | IndexWireFailure::ReceiptMissingProofTail => MnemeError::SchemaDrift,
    }
}

fn index_read_overflow_error() -> MnemeError {
    index_wire_failure_to_mneme(IndexWireFailure::ReadOverflow)
}

fn index_read_truncated_error() -> MnemeError {
    index_wire_failure_to_mneme(IndexWireFailure::ReadTruncated)
}

fn index_sem_path_too_long_error() -> MnemeError {
    index_wire_failure_to_mneme(IndexWireFailure::SemPathTooLong)
}

fn index_sem_path_reserve_error() -> MnemeError {
    index_wire_failure_to_mneme(IndexWireFailure::SemPathReserve)
}

fn index_sem_path_trailing_error() -> MnemeError {
    index_wire_failure_to_mneme(IndexWireFailure::SemPathTrailing)
}

fn index_receipt_missing_proof_tail_error() -> MnemeError {
    index_wire_failure_to_mneme(IndexWireFailure::ReceiptMissingProofTail)
}

fn read_exact<const N: usize>(input: &[u8], pos: &mut usize) -> Result<[u8; N], MnemeError> {
    let end = pos.checked_add(N).ok_or_else(index_read_overflow_error)?;
    if end > input.len() {
        return Err(index_read_truncated_error());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[*pos..end]);
    *pos = end;
    Ok(out)
}

fn read_u16(input: &[u8], pos: &mut usize) -> Result<u16, MnemeError> {
    let bytes = read_exact::<2>(input, pos)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, MnemeError> {
    let bytes = read_exact::<4>(input, pos)?;
    Ok(u32::from_be_bytes(bytes))
}

fn parse_sem_path_wire(input: &[u8]) -> Result<SemPathWire, MnemeError> {
    let mut pos = 0;
    let leaf_index = read_u32(input, &mut pos)? as usize;
    let commit = read_exact::<32>(input, &mut pos)?;
    let path_len = read_u16(input, &mut pos)? as usize;
    if path_len > MAX_SEM_PATH_LEN {
        return Err(index_sem_path_too_long_error());
    }
    let mut path = Vec::new();
    path.try_reserve_exact(path_len)
        .map_err(|_| index_sem_path_reserve_error())?;
    for _ in 0..path_len {
        path.push(read_exact::<32>(input, &mut pos)?);
    }
    let root = read_exact::<32>(input, &mut pos)?;
    if pos != input.len() {
        return Err(index_sem_path_trailing_error());
    }
    Ok((leaf_index, commit, path, root))
}

/// Fuzz entry: semantic index Merkle path wire; never panics.
pub fn fuzz_index_path_wire(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if bytes[0] != TAG_SEM_PATH {
        return;
    }
    let Ok((index, commit, path, root)) = parse_sem_path_wire(&bytes[1..]) else {
        return;
    };
    let _ = SemanticMerkleTree::verify_path_with_index(index, &commit, &path, &root);
}

/// Fuzz entry: receipt bundle (header + SMT proof tail); never panics.
pub fn fuzz_receipt_wire(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    match bytes[0] {
        TAG_RECEIPT_BUNDLE => {
            let Ok(tail) = parse_receipt_tail(&bytes[1..]) else {
                return;
            };
            let _ = parse_proof_blob(tail);
        }
        _ => fuzz_parse_and_verify(bytes),
    }
}

fn parse_receipt_tail(input: &[u8]) -> Result<&[u8], MnemeError> {
    let mut pos = 0;
    let _root_bound = read_exact::<32>(input, &mut pos)?;
    let _logical_key = read_exact::<32>(input, &mut pos)?;
    let _object_id = read_exact::<32>(input, &mut pos)?;
    if pos >= input.len() {
        return Err(index_receipt_missing_proof_tail_error());
    }
    Ok(&input[pos..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn index_wire_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("wire.rs");
        let parser =
            source_between_markers(source, "fn read_exact", "#[cfg(test)]", "index wire parser");

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !parser.contains(forbidden),
                "index wire parser should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum IndexWireFailure",
            "fn index_wire_failure_to_mneme(",
            "fn index_read_overflow_error(",
            "fn index_read_truncated_error(",
            "fn index_sem_path_too_long_error(",
            "fn index_sem_path_reserve_error(",
            "fn index_sem_path_trailing_error(",
            "fn index_receipt_missing_proof_tail_error(",
            "IndexWireFailure::ReadOverflow",
            "IndexWireFailure::ReadTruncated",
            "IndexWireFailure::SemPathTooLong",
            "IndexWireFailure::SemPathReserve",
            "IndexWireFailure::SemPathTrailing",
            "IndexWireFailure::ReceiptMissingProofTail",
        ] {
            assert!(
                source.contains(required),
                "index wire failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn index_wire_failure_classifier_preserves_public_error() {
        for failure in [
            IndexWireFailure::ReadOverflow,
            IndexWireFailure::ReadTruncated,
            IndexWireFailure::SemPathTooLong,
            IndexWireFailure::SemPathReserve,
            IndexWireFailure::SemPathTrailing,
            IndexWireFailure::ReceiptMissingProofTail,
        ] {
            assert_eq!(
                index_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn index_wire_oversize_semantic_path_fails_closed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&((MAX_SEM_PATH_LEN as u16) + 1).to_be_bytes());

        assert!(matches!(
            parse_sem_path_wire(&bytes),
            Err(MnemeError::SchemaDrift)
        ));
    }

    #[test]
    fn index_wire_receipt_without_proof_tail_fails_closed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&[0x33; 32]);

        assert_eq!(parse_receipt_tail(&bytes), Err(MnemeError::SchemaDrift));
    }
}
