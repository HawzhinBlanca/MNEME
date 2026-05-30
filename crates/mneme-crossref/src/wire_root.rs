//! StoredRoot wire decode + preimage recompute (reference path).

use crate::dcbor::{CborValue, Decoder};
use crate::domain::hash_root_preimage;
use crate::error::CrossrefError;
use ed25519_dalek::{Signature, VerifyingKey};

const ROOT_VERSION: u16 = 1;
const F_VERSION: u64 = 1;
const F_DAG_HEAD_ROOT: u64 = 2;
const F_KEY_INDEX_ROOT: u64 = 3;
const F_SEMANTIC_COMMIT: u64 = 4;
const F_HLC_MAX: u64 = 5;
const F_PREV_ROOT: u64 = 6;
const F_PREIMAGE_HASH: u64 = 7;
const F_SIGNATURE: u64 = 8;
const F_SEQUENCE: u64 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRoot {
    pub version: u16,
    pub dag_head_root: [u8; 32],
    pub key_index_root: [u8; 32],
    pub semantic_commit: [u8; 32],
    pub hlc_max: [u8; 14],
    pub prev_root: [u8; 32],
    pub preimage_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub sequence: u64,
}

impl StoredRoot {
    pub fn decode(bytes: &[u8]) -> Result<Self, CrossrefError> {
        let mut dec = Decoder::new(bytes);
        let map = dec.decode_map()?;
        dec.ensure_consumed()?;

        let mut version = None;
        let mut dag_head_root = None;
        let mut key_index_root = None;
        let mut semantic_commit = None;
        let mut hlc_max = None;
        let mut prev_root = None;
        let mut preimage_hash = None;
        let mut signature = None;
        let mut sequence = None;

        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_VERSION => version = Some(parse_u16(&value)?),
                F_DAG_HEAD_ROOT => dag_head_root = Some(parse_fixed32(&value)?),
                F_KEY_INDEX_ROOT => key_index_root = Some(parse_fixed32(&value)?),
                F_SEMANTIC_COMMIT => semantic_commit = Some(parse_fixed32(&value)?),
                F_HLC_MAX => hlc_max = Some(parse_fixed14(&value)?),
                F_PREV_ROOT => prev_root = Some(parse_fixed32(&value)?),
                F_PREIMAGE_HASH => preimage_hash = Some(parse_fixed32(&value)?),
                F_SIGNATURE => signature = Some(parse_bytes(&value)?),
                F_SEQUENCE => sequence = Some(parse_u64(&value)?),
                _ => return Err(CrossrefError::SchemaDrift),
            }
        }

        Ok(Self {
            version: version.ok_or(CrossrefError::SchemaDrift)?,
            dag_head_root: dag_head_root.ok_or(CrossrefError::SchemaDrift)?,
            key_index_root: key_index_root.ok_or(CrossrefError::SchemaDrift)?,
            semantic_commit: semantic_commit.ok_or(CrossrefError::SchemaDrift)?,
            hlc_max: hlc_max.ok_or(CrossrefError::SchemaDrift)?,
            prev_root: prev_root.ok_or(CrossrefError::SchemaDrift)?,
            preimage_hash: preimage_hash.ok_or(CrossrefError::SchemaDrift)?,
            signature: signature.ok_or(CrossrefError::SchemaDrift)?,
            sequence: sequence.ok_or(CrossrefError::SchemaDrift)?,
        })
    }

    pub fn recompute_preimage_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(2 + 32 * 4 + 14);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.dag_head_root);
        buf.extend_from_slice(&self.key_index_root);
        buf.extend_from_slice(&self.semantic_commit);
        buf.extend_from_slice(&self.hlc_max);
        buf.extend_from_slice(&self.prev_root);
        hash_root_preimage(&buf)
    }

    pub fn verify_signature(&self, operator_pubkey: &[u8; 32]) -> Result<(), CrossrefError> {
        if self.signature.len() != 64 {
            return Err(CrossrefError::SigInvalid);
        }
        let vk =
            VerifyingKey::from_bytes(operator_pubkey).map_err(|_| CrossrefError::SigInvalid)?;
        let sig = Signature::from_bytes(
            self.signature
                .as_slice()
                .try_into()
                .map_err(|_| CrossrefError::SigInvalid)?,
        );
        vk.verify_strict(&self.preimage_hash, &sig)
            .map_err(|_| CrossrefError::SigInvalid)
    }
}

pub fn verify_committed_signed_root(
    bytes: &[u8],
    operator_pubkey: &[u8; 32],
    expected_preimage_hex: &str,
) -> Result<(), CrossrefError> {
    let root = StoredRoot::decode(bytes)?;
    if root.version != ROOT_VERSION {
        return Err(CrossrefError::SchemaDrift);
    }
    let recomputed = root.recompute_preimage_hash();
    if recomputed != root.preimage_hash {
        return Err(CrossrefError::SchemaDrift);
    }
    let expected = hex32(expected_preimage_hex)?;
    if recomputed != expected {
        return Err(CrossrefError::SchemaDrift);
    }
    root.verify_signature(operator_pubkey)?;
    Ok(())
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, CrossrefError> {
    key.as_u64().ok_or(CrossrefError::SchemaDrift)
}

fn parse_u16(v: &CborValue) -> Result<u16, CrossrefError> {
    let n = v.as_u64().ok_or(CrossrefError::SchemaDrift)?;
    u16::try_from(n).map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_u64(v: &CborValue) -> Result<u64, CrossrefError> {
    v.as_u64().ok_or(CrossrefError::SchemaDrift)
}

fn parse_bytes(v: &CborValue) -> Result<Vec<u8>, CrossrefError> {
    v.as_bytes()
        .map(|b| b.to_vec())
        .ok_or(CrossrefError::SchemaDrift)
}

fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let b = v.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    b.try_into().map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_fixed14(v: &CborValue) -> Result<[u8; 14], CrossrefError> {
    let b = v.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    b.try_into().map_err(|_| CrossrefError::SchemaDrift)
}

pub fn hex32(s: &str) -> Result<[u8; 32], CrossrefError> {
    let bytes = hex::decode(s).map_err(|_| CrossrefError::SchemaDrift)?;
    bytes.try_into().map_err(|_| CrossrefError::SchemaDrift)
}
