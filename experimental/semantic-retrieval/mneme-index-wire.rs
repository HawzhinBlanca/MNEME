//! Fail-closed wire fuzz hooks for index + receipt paths (§17.4, CRDT-less).

use crate::commit::SemanticMerkleTree;
use mneme_core::MnemeError;
use mneme_smt::{fuzz_parse_and_verify, parse_proof_blob};

const TAG_RECEIPT_BUNDLE: u8 = 0x03;
const TAG_SEM_PATH: u8 = 0x04;
const MAX_SEM_PATH_LEN: usize = 64;

type SemPathWire = (usize, [u8; 32], Vec<[u8; 32]>, [u8; 32]);

fn read_exact<const N: usize>(input: &[u8], pos: &mut usize) -> Result<[u8; N], MnemeError> {
    let end = pos.checked_add(N).ok_or(MnemeError::SchemaDrift)?;
    if end > input.len() {
        return Err(MnemeError::SchemaDrift);
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
        return Err(MnemeError::SchemaDrift);
    }
    let mut path = Vec::new();
    path.try_reserve_exact(path_len)
        .map_err(|_| MnemeError::SchemaDrift)?;
    for _ in 0..path_len {
        path.push(read_exact::<32>(input, &mut pos)?);
    }
    let root = read_exact::<32>(input, &mut pos)?;
    if pos != input.len() {
        return Err(MnemeError::SchemaDrift);
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
        return Err(MnemeError::SchemaDrift);
    }
    Ok(&input[pos..])
}
