//! Fail-closed wire parsing for SMT proofs (§17.4 fuzz target).

use crate::defaults::TREE_DEPTH;
use crate::proof::{MembershipProof, NonMembershipProof};
use crate::tree::SparseMerkleTree;
use mneme_core::MnemeError;

const TAG_MEMBERSHIP: u8 = 0x01;
const TAG_NON_MEMBERSHIP: u8 = 0x02;
const MAX_PATH_LEN: usize = TREE_DEPTH;

#[derive(Clone, Debug)]
pub enum ParsedProof {
    Membership(MembershipProof),
    NonMembership(NonMembershipProof),
}

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

fn read_path(input: &[u8], pos: &mut usize) -> Result<Vec<[u8; 32]>, MnemeError> {
    let len = read_u16(input, pos)? as usize;
    if len > MAX_PATH_LEN {
        return Err(MnemeError::SchemaDrift);
    }
    let mut path = Vec::new();
    path.try_reserve_exact(len)
        .map_err(|_| MnemeError::SchemaDrift)?;
    for _ in 0..len {
        path.push(read_exact::<32>(input, pos)?);
    }
    Ok(path)
}

fn parse_membership_wire(input: &[u8]) -> Result<MembershipProof, MnemeError> {
    let mut pos = 0;
    let key = read_exact::<32>(input, &mut pos)?;
    let value = read_exact::<32>(input, &mut pos)?;
    let path = read_path(input, &mut pos)?;
    let root = read_exact::<32>(input, &mut pos)?;
    let leaf_index = read_u32(input, &mut pos)? as usize;
    if pos != input.len() {
        return Err(MnemeError::SchemaDrift);
    }
    Ok(MembershipProof {
        key,
        value,
        path,
        root,
        leaf_index,
    })
}

fn parse_non_membership_wire(input: &[u8]) -> Result<NonMembershipProof, MnemeError> {
    let mut pos = 0;
    let key = read_exact::<32>(input, &mut pos)?;
    let path = read_path(input, &mut pos)?;
    let root = read_exact::<32>(input, &mut pos)?;
    let has_conflict = read_exact::<1>(input, &mut pos)?[0];
    let conflicting_leaf = match has_conflict {
        0 => None,
        1 => {
            let ck = read_exact::<32>(input, &mut pos)?;
            let cv = read_exact::<32>(input, &mut pos)?;
            Some((ck, cv))
        }
        _ => return Err(MnemeError::SchemaDrift),
    };
    if pos != input.len() {
        return Err(MnemeError::SchemaDrift);
    }
    Ok(NonMembershipProof {
        key,
        path,
        root,
        conflicting_leaf,
    })
}

/// Parse a tagged proof blob; rejects trailing bytes and oversize paths.
pub fn parse_proof_blob(bytes: &[u8]) -> Result<ParsedProof, MnemeError> {
    if bytes.is_empty() {
        return Err(MnemeError::SchemaDrift);
    }
    match bytes[0] {
        TAG_MEMBERSHIP => parse_membership_wire(&bytes[1..]).map(ParsedProof::Membership),
        TAG_NON_MEMBERSHIP => {
            parse_non_membership_wire(&bytes[1..]).map(ParsedProof::NonMembership)
        }
        _ => Err(MnemeError::SchemaDrift),
    }
}

/// Fuzz entry: parse then verify; never panics.
pub fn fuzz_parse_and_verify(bytes: &[u8]) {
    let Ok(parsed) = parse_proof_blob(bytes) else {
        return;
    };
    match parsed {
        ParsedProof::Membership(p) => {
            let _ = SparseMerkleTree::verify_membership(&p);
        }
        ParsedProof::NonMembership(p) => {
            let _ = SparseMerkleTree::verify_non_membership(&p);
        }
    }
}

pub fn encode_membership_wire(proof: &MembershipProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 2 + proof.path.len() * 32 + 32 + 4);
    out.push(TAG_MEMBERSHIP);
    out.extend_from_slice(&proof.key);
    out.extend_from_slice(&proof.value);
    out.extend_from_slice(&(proof.path.len() as u16).to_be_bytes());
    for node in &proof.path {
        out.extend_from_slice(node);
    }
    out.extend_from_slice(&proof.root);
    out.extend_from_slice(&(proof.leaf_index as u32).to_be_bytes());
    out
}

pub fn encode_non_membership_wire(proof: &NonMembershipProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 2 + proof.path.len() * 32 + 32 + 1 + 64);
    out.push(TAG_NON_MEMBERSHIP);
    out.extend_from_slice(&proof.key);
    out.extend_from_slice(&(proof.path.len() as u16).to_be_bytes());
    for node in &proof.path {
        out.extend_from_slice(node);
    }
    out.extend_from_slice(&proof.root);
    match proof.conflicting_leaf {
        None => out.push(0),
        Some((k, v)) => {
            out.push(1);
            out.extend_from_slice(&k);
            out.extend_from_slice(&v);
        }
    }
    out
}
