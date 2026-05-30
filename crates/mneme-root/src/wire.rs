//! MNEME-dCBOR wire format for persisted root checkpoints.

use crate::ROOT_VERSION;
use crate::StoredRoot;
use mneme_core::{CborValue, DcborDecode, DcborEncode, Decoder, Encoder, MnemeError};
use mneme_crypto::ED25519_SIG_LEN;

const F_VERSION: u64 = 1;
const F_DAG_HEAD_ROOT: u64 = 2;
const F_KEY_INDEX_ROOT: u64 = 3;
const F_SEMANTIC_COMMIT: u64 = 4;
const F_HLC_MAX: u64 = 5;
const F_PREV_ROOT: u64 = 6;
const F_PREIMAGE_HASH: u64 = 7;
const F_SIGNATURE: u64 = 8;
const F_SEQUENCE: u64 = 9;

const HLC_MAX_LEN: usize = 14;

impl DcborEncode for StoredRoot {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        self.validate_invariants()?;
        enc.begin_map(9)?;
        enc.encode_unsigned(F_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_DAG_HEAD_ROOT)?;
        enc.encode_bytes(&self.dag_head_root)?;
        enc.encode_unsigned(F_KEY_INDEX_ROOT)?;
        enc.encode_bytes(&self.key_index_root)?;
        enc.encode_unsigned(F_SEMANTIC_COMMIT)?;
        enc.encode_bytes(&self.semantic_commit)?;
        enc.encode_unsigned(F_HLC_MAX)?;
        enc.encode_bytes(&self.hlc_max)?;
        enc.encode_unsigned(F_PREV_ROOT)?;
        enc.encode_bytes(&self.prev_root)?;
        enc.encode_unsigned(F_PREIMAGE_HASH)?;
        enc.encode_bytes(&self.preimage_hash)?;
        enc.encode_unsigned(F_SIGNATURE)?;
        enc.encode_bytes(&self.signature)?;
        enc.encode_unsigned(F_SEQUENCE)?;
        enc.encode_unsigned(self.sequence)?;
        Ok(())
    }
}

impl DcborDecode for StoredRoot {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
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
                F_HLC_MAX => hlc_max = Some(parse_fixed_slice::<HLC_MAX_LEN>(&value)?),
                F_PREV_ROOT => prev_root = Some(parse_fixed32(&value)?),
                F_PREIMAGE_HASH => preimage_hash = Some(parse_fixed32(&value)?),
                F_SIGNATURE => signature = Some(parse_signature(&value)?),
                F_SEQUENCE => sequence = Some(parse_u64(&value)?),
                _ => {
                    let field_id = match u16::try_from(field) {
                        Ok(v) => v,
                        Err(_) => u16::MAX,
                    };
                    return Err(MnemeError::UnknownField { field: field_id });
                }
            }
        }

        let stored = Self {
            version: version.ok_or(MnemeError::SchemaDrift)?,
            dag_head_root: dag_head_root.ok_or(MnemeError::SchemaDrift)?,
            key_index_root: key_index_root.ok_or(MnemeError::SchemaDrift)?,
            semantic_commit: semantic_commit.ok_or(MnemeError::SchemaDrift)?,
            hlc_max: hlc_max.ok_or(MnemeError::SchemaDrift)?,
            prev_root: prev_root.ok_or(MnemeError::SchemaDrift)?,
            preimage_hash: preimage_hash.ok_or(MnemeError::SchemaDrift)?,
            signature: signature.ok_or(MnemeError::SchemaDrift)?,
            sequence: sequence.ok_or(MnemeError::SchemaDrift)?,
        };
        stored.validate_invariants()?;
        Ok(stored)
    }
}

impl StoredRoot {
    pub(crate) fn validate_invariants(&self) -> Result<(), MnemeError> {
        if self.version != ROOT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: self.version });
        }
        if self.signature.len() != ED25519_SIG_LEN {
            return Err(MnemeError::RootSigInvalid);
        }
        if self.hlc_max.len() != HLC_MAX_LEN {
            return Err(MnemeError::HlcMalformed);
        }
        Ok(())
    }
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let raw = value.as_u64().ok_or(MnemeError::SchemaDrift)?;
    u16::try_from(raw).map_err(|_| MnemeError::SchemaDrift)
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != 32 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fixed_slice<const N: usize>(value: &CborValue) -> Result<[u8; N], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != N {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_signature(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != ED25519_SIG_LEN {
        return Err(MnemeError::RootSigInvalid);
    }
    Ok(bytes.to_vec())
}
