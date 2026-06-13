//! ForgetProof wire decode and verification (reference path).

use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;
use crate::smt::{NonMembershipProof, SparseMerkleTree, TOMBSTONE};

pub const FORGET_PROOF_VERSION: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgetMode {
    Shred,
    Redact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredForgetProof {
    pub version: u16,
    pub target_commit: [u8; 32],
    pub mode: ForgetMode,
    pub shred_commit: [u8; 32],
    pub absence_path: Vec<[u8; 32]>,
    pub root_bound: [u8; 32],
    pub cognition_cert_commit: Option<[u8; 32]>,
}

impl StoredForgetProof {
    pub fn decode(bytes: &[u8]) -> Result<Self, CrossrefError> {
        let mut dec = Decoder::new(bytes);
        let map = dec.decode_map()?;
        dec.ensure_consumed()?;

        let mut version = None;
        let mut target_commit = None;
        let mut mode = None;
        let mut shred_commit = None;
        let mut absence_path = None;
        let mut root_bound = None;
        let mut cognition_cert_commit = None;

        for (key, value) in map {
            let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
            match field {
                1 => version = Some(parse_u16(&value)?),
                2 => target_commit = Some(parse_fixed32(&value)?),
                3 => mode = Some(parse_mode(&value)?),
                4 => shred_commit = Some(parse_fixed32(&value)?),
                5 => absence_path = Some(parse_absence_path(&value)?),
                6 => root_bound = Some(parse_fixed32(&value)?),
                7 => cognition_cert_commit = Some(parse_optional_commit(&value)?),
                _ => return Err(CrossrefError::SchemaDrift),
            }
        }

        Ok(Self {
            version: version.ok_or(CrossrefError::SchemaDrift)?,
            target_commit: target_commit.ok_or(CrossrefError::SchemaDrift)?,
            mode: mode.ok_or(CrossrefError::SchemaDrift)?,
            shred_commit: shred_commit.ok_or(CrossrefError::SchemaDrift)?,
            absence_path: absence_path.ok_or(CrossrefError::SchemaDrift)?,
            root_bound: root_bound.ok_or(CrossrefError::SchemaDrift)?,
            cognition_cert_commit: cognition_cert_commit.ok_or(CrossrefError::SchemaDrift)?,
        })
    }

    pub fn verify(&self, key_index_root: &[u8; 32]) -> Result<(), CrossrefError> {
        if self.version != FORGET_PROOF_VERSION {
            return Err(CrossrefError::SchemaDrift);
        }
        if self.mode != ForgetMode::Shred {
            return Err(CrossrefError::SchemaDrift);
        }
        if self.shred_commit == [0u8; 32] {
            return Err(CrossrefError::SchemaDrift);
        }
        let absence = NonMembershipProof {
            key: self.target_commit,
            path: self.absence_path.clone(),
            root: *key_index_root,
            conflicting_leaf: Some((self.target_commit, TOMBSTONE)),
        };
        SparseMerkleTree::verify_non_membership(&absence)?;
        Ok(())
    }
}

fn parse_u16(v: &CborValue) -> Result<u16, CrossrefError> {
    let n = v.as_u64().ok_or(CrossrefError::SchemaDrift)?;
    u16::try_from(n).map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let b = v.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    b.try_into().map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_mode(v: &CborValue) -> Result<ForgetMode, CrossrefError> {
    let tag = v.as_u64().ok_or(CrossrefError::SchemaDrift)?;
    match tag {
        0 => Ok(ForgetMode::Shred),
        1 => Ok(ForgetMode::Redact),
        _ => Err(CrossrefError::SchemaDrift),
    }
}

fn parse_absence_path(v: &CborValue) -> Result<Vec<[u8; 32]>, CrossrefError> {
    let arr = v.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(parse_fixed32(item)?);
    }
    Ok(out)
}

fn parse_optional_commit(v: &CborValue) -> Result<Option<[u8; 32]>, CrossrefError> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(parse_fixed32(v)?))
    }
}
