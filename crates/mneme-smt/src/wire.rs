//! Fail-closed wire parsing for SMT proofs (§17.4 fuzz target).

use crate::defaults::TREE_DEPTH;
use crate::proof::{MembershipProof, NonMembershipProof};
use crate::tree::SparseMerkleTree;
use mneme_core::MnemeError;

const TAG_MEMBERSHIP: u8 = 0x01;
const TAG_NON_MEMBERSHIP: u8 = 0x02;
const MAX_PATH_LEN: usize = TREE_DEPTH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmtWireFailure {
    ReadOverflow,
    ReadTruncated,
    PathTooLong,
    PathReserve,
    MembershipTrailing,
    NonMembershipConflictTag,
    NonMembershipTrailing,
    EmptyBlob,
    UnknownTag,
}

fn smt_wire_failure_to_mneme(failure: SmtWireFailure) -> MnemeError {
    match failure {
        SmtWireFailure::ReadOverflow
        | SmtWireFailure::ReadTruncated
        | SmtWireFailure::PathTooLong
        | SmtWireFailure::PathReserve
        | SmtWireFailure::MembershipTrailing
        | SmtWireFailure::NonMembershipConflictTag
        | SmtWireFailure::NonMembershipTrailing
        | SmtWireFailure::EmptyBlob
        | SmtWireFailure::UnknownTag => MnemeError::SchemaDrift,
    }
}

fn smt_read_overflow_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::ReadOverflow)
}

fn smt_read_truncated_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::ReadTruncated)
}

fn smt_path_too_long_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::PathTooLong)
}

fn smt_path_reserve_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::PathReserve)
}

fn smt_membership_trailing_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::MembershipTrailing)
}

fn smt_non_membership_conflict_tag_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::NonMembershipConflictTag)
}

fn smt_non_membership_trailing_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::NonMembershipTrailing)
}

fn smt_empty_blob_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::EmptyBlob)
}

fn smt_unknown_tag_error() -> MnemeError {
    smt_wire_failure_to_mneme(SmtWireFailure::UnknownTag)
}

#[derive(Clone, Debug)]
pub enum ParsedProof {
    Membership(MembershipProof),
    NonMembership(NonMembershipProof),
}

fn read_exact<const N: usize>(input: &[u8], pos: &mut usize) -> Result<[u8; N], MnemeError> {
    let end = pos.checked_add(N).ok_or_else(smt_read_overflow_error)?;
    if end > input.len() {
        return Err(smt_read_truncated_error());
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
        return Err(smt_path_too_long_error());
    }
    let mut path = Vec::new();
    path.try_reserve_exact(len)
        .map_err(|_| smt_path_reserve_error())?;
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
        return Err(smt_membership_trailing_error());
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
        _ => return Err(smt_non_membership_conflict_tag_error()),
    };
    if pos != input.len() {
        return Err(smt_non_membership_trailing_error());
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
        return Err(smt_empty_blob_error());
    }
    match bytes[0] {
        TAG_MEMBERSHIP => parse_membership_wire(&bytes[1..]).map(ParsedProof::Membership),
        TAG_NON_MEMBERSHIP => {
            parse_non_membership_wire(&bytes[1..]).map(ParsedProof::NonMembership)
        }
        _ => Err(smt_unknown_tag_error()),
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
    fn smt_wire_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("wire.rs");
        let parser = source_between_markers(
            source,
            "fn read_exact",
            "pub fn encode_membership_wire",
            "SMT proof wire parser",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
            "_ => Err(MnemeError::SchemaDrift)",
            "_ => return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !parser.contains(forbidden),
                "SMT proof wire parser should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum SmtWireFailure",
            "fn smt_wire_failure_to_mneme(",
            "fn smt_read_overflow_error(",
            "fn smt_read_truncated_error(",
            "fn smt_path_too_long_error(",
            "fn smt_path_reserve_error(",
            "fn smt_membership_trailing_error(",
            "fn smt_non_membership_conflict_tag_error(",
            "fn smt_non_membership_trailing_error(",
            "fn smt_empty_blob_error(",
            "fn smt_unknown_tag_error(",
            "SmtWireFailure::ReadOverflow",
            "SmtWireFailure::ReadTruncated",
            "SmtWireFailure::PathTooLong",
            "SmtWireFailure::PathReserve",
            "SmtWireFailure::MembershipTrailing",
            "SmtWireFailure::NonMembershipConflictTag",
            "SmtWireFailure::NonMembershipTrailing",
            "SmtWireFailure::EmptyBlob",
            "SmtWireFailure::UnknownTag",
        ] {
            assert!(
                source.contains(required),
                "SMT proof wire failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn smt_wire_failure_classifier_preserves_public_error() {
        for failure in [
            SmtWireFailure::ReadOverflow,
            SmtWireFailure::ReadTruncated,
            SmtWireFailure::PathTooLong,
            SmtWireFailure::PathReserve,
            SmtWireFailure::MembershipTrailing,
            SmtWireFailure::NonMembershipConflictTag,
            SmtWireFailure::NonMembershipTrailing,
            SmtWireFailure::EmptyBlob,
            SmtWireFailure::UnknownTag,
        ] {
            assert_eq!(smt_wire_failure_to_mneme(failure), MnemeError::SchemaDrift);
        }
    }

    #[test]
    fn smt_wire_oversize_path_fails_closed() {
        let mut bytes = Vec::new();
        bytes.push(TAG_MEMBERSHIP);
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&((MAX_PATH_LEN as u16) + 1).to_be_bytes());

        assert!(matches!(
            parse_proof_blob(&bytes),
            Err(MnemeError::SchemaDrift)
        ));
    }
}
