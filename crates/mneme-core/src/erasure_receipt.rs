//! Core erasure receipt wire for `ForgetProof`.
//!
//! A [`ForgetProof`] proves *crypto-shred witness + proof-of-absence under a
//! signed root* (deleted, and not served from trusted memory afterward). It does
//! **not** prove that no out-of-band copy ever existed elsewhere.

use crate::interface::ForgetMode;
use crate::{CborValue, Decoder, Encoder, MnemeError};
use std::convert::TryFrom;

/// Core forget-proof wire version. Distinct from `OBJECT_VERSION` and the root
/// version; this is the deletion receipt seam consumed by store/MCP verify.
pub const FORGET_PROOF_VERSION: u16 = 3;

/// Proof that a target was forgotten: crypto-shred witness plus proof-of-absence
/// under a signed root.
///
/// The receipt-enabled store path populates `shred_commit` from the completed
/// key-destruction witness and `absence_path` from the post-erase SMT
/// non-membership proof, then verifies both against `root_bound` before
/// returning the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgetProof {
    /// Wire version; equals [`FORGET_PROOF_VERSION`].
    pub version: u16,
    /// Commit of what was forgotten (logical-key hash or object id).
    pub target_commit: [u8; 32],
    /// Forget mode applied: crypto-shred in the v1 public erasure surface.
    pub mode: ForgetMode,
    /// Crypto-shred witness commit (destruction of the wrapping key).
    pub shred_commit: [u8; 32],
    /// Proof-of-absence: SMT non-membership path against `root_bound`'s key
    /// index.
    pub absence_path: Vec<[u8; 32]>,
    /// Signed root the absence proof is bound to (A-REPLAY safe at the gate).
    pub root_bound: [u8; 32],
    /// OPTIONAL cognition-certificate ("cert v2") commit witnessing
    /// not-used-after. `None` until cert v2 is finalized; never fabricated.
    pub cognition_cert_commit: Option<[u8; 32]>,
}

impl ForgetProof {
    /// 1-byte mode tag: `Shred -> 0`, `Redact -> 1`.
    pub fn mode_tag(&self) -> u8 {
        match self.mode {
            ForgetMode::Shred => 0,
            ForgetMode::Redact => 1,
        }
    }

    /// Canonical payload: `version || target_commit || mode_tag(1) ||
    /// shred_commit || root_bound || absence_len(4 LE) || absence_path* ||
    /// cert_present(1) || [cert_commit]`.
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(2 + 32 + 1 + 32 + 32 + 4 + self.absence_path.len() * 32 + 1);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.target_commit);
        buf.push(self.mode_tag());
        buf.extend_from_slice(&self.shred_commit);
        buf.extend_from_slice(&self.root_bound);
        buf.extend_from_slice(&(self.absence_path.len() as u32).to_le_bytes());
        for node in &self.absence_path {
            buf.extend_from_slice(node);
        }
        match self.cognition_cert_commit {
            Some(commit) => {
                buf.push(1);
                buf.extend_from_slice(&commit);
            }
            None => buf.push(0),
        }
        buf
    }
}

/// Canonical dCBOR wire for [`ForgetProof`]. Version-gated: refuses to emit
/// anything but the current [`FORGET_PROOF_VERSION`].
///
/// Field map (ascending numeric keys):
/// 1 -> version (`u16`), 2 -> target_commit (32-byte), 3 -> mode (tagged `u8`),
/// 4 -> shred_commit (32-byte), 5 -> absence_path (array of 32-byte nodes),
/// 6 -> root_bound (32-byte), 7 -> cognition_cert_commit (32-byte, `null` if
/// absent).
pub fn encode_forget_proof(proof: &ForgetProof) -> Result<Vec<u8>, MnemeError> {
    if proof.version != FORGET_PROOF_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: proof.version });
    }

    let mut enc = Encoder::new();
    enc.begin_map(7)?;

    enc.encode_unsigned(1)?;
    enc.encode_unsigned(u64::from(proof.version))?;

    enc.encode_unsigned(2)?;
    enc.encode_bytes(&proof.target_commit)?;

    enc.encode_unsigned(3)?;
    enc.encode_unsigned(u64::from(proof.mode_tag()))?;

    enc.encode_unsigned(4)?;
    enc.encode_bytes(&proof.shred_commit)?;

    enc.encode_unsigned(5)?;
    enc.begin_array(proof.absence_path.len() as u64)?;
    for node in &proof.absence_path {
        enc.encode_bytes(node)?;
    }

    enc.encode_unsigned(6)?;
    enc.encode_bytes(&proof.root_bound)?;

    enc.encode_unsigned(7)?;
    match proof.cognition_cert_commit {
        Some(commit) => enc.encode_bytes(&commit)?,
        None => enc.encode_null()?,
    }

    Ok(enc.finish())
}

/// Parse a canonical [`ForgetProof`] wire. Fails closed on version mismatch or
/// malformed fields.
pub fn decode_forget_proof(bytes: &[u8]) -> Result<ForgetProof, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;

    let mut version = None;
    let mut target_commit = None;
    let mut mode = None;
    let mut shred_commit = None;
    let mut absence_path = None;
    let mut root_bound = None;
    let mut cognition_cert_commit = None;

    for (key, value) in map {
        let field = parse_field_key(&key)?;
        match field {
            1 => {
                if version.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                version = Some(parse_u16(&value)?);
            }
            2 => {
                if target_commit.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                target_commit = Some(parse_fixed32(&value)?);
            }
            3 => {
                if mode.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                mode = Some(parse_mode(&value)?);
            }
            4 => {
                if shred_commit.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                shred_commit = Some(parse_fixed32(&value)?);
            }
            5 => {
                if absence_path.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                absence_path = Some(parse_absence_path(&value)?);
            }
            6 => {
                if root_bound.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                root_bound = Some(parse_fixed32(&value)?);
            }
            7 => {
                if cognition_cert_commit.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                cognition_cert_commit = Some(parse_optional_commit(&value)?);
            }
            _ => return Err(MnemeError::UnknownField { field }),
        }
    }

    let version = version.ok_or(MnemeError::SchemaDrift)?;
    if version != FORGET_PROOF_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: version });
    }

    Ok(ForgetProof {
        version,
        target_commit: target_commit.ok_or(MnemeError::SchemaDrift)?,
        mode: mode.ok_or(MnemeError::SchemaDrift)?,
        shred_commit: shred_commit.ok_or(MnemeError::SchemaDrift)?,
        absence_path: absence_path.ok_or(MnemeError::SchemaDrift)?,
        root_bound: root_bound.ok_or(MnemeError::SchemaDrift)?,
        cognition_cert_commit: cognition_cert_commit.ok_or(MnemeError::SchemaDrift)?,
    })
}

fn parse_field_key(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(MnemeError::SchemaDrift),
    }
}

fn parse_optional_commit(value: &CborValue) -> Result<Option<[u8; 32]>, MnemeError> {
    match value {
        CborValue::Null => Ok(None),
        _ => Ok(Some(parse_fixed32(value)?)),
    }
}

fn parse_mode(value: &CborValue) -> Result<ForgetMode, MnemeError> {
    let tag = value
        .as_u64()
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(MnemeError::SchemaDrift)?;
    match tag {
        0 => Ok(ForgetMode::Shred),
        1 => Ok(ForgetMode::Redact),
        _ => Err(MnemeError::SchemaDrift),
    }
}

fn parse_absence_path(value: &CborValue) -> Result<Vec<[u8; 32]>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for node in arr {
        out.push(parse_fixed32(node)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn sample_proof(cert: Option<[u8; 32]>) -> ForgetProof {
        ForgetProof {
            version: FORGET_PROOF_VERSION,
            target_commit: [0x21; 32],
            mode: ForgetMode::Redact,
            shred_commit: [0x22; 32],
            absence_path: vec![[0x23; 32], [0x24; 32]],
            root_bound: [0x25; 32],
            cognition_cert_commit: cert,
        }
    }

    #[test]
    fn forget_proof_wire_version_is_three() {
        assert_eq!(FORGET_PROOF_VERSION, 3);
    }

    #[test]
    fn forget_proof_payload_is_deterministic_and_mode_tagged() {
        let proof = ForgetProof {
            version: FORGET_PROOF_VERSION,
            target_commit: [0x01; 32],
            mode: ForgetMode::Shred,
            shred_commit: [0x02; 32],
            absence_path: vec![[0x03; 32], [0x04; 32]],
            root_bound: [0x05; 32],
            cognition_cert_commit: None,
        };
        assert_eq!(proof.mode_tag(), 0);
        assert_eq!(
            hex::encode(proof.encode_payload()),
            concat!(
                "0300",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "00",
                "0202020202020202020202020202020202020202020202020202020202020202",
                "0505050505050505050505050505050505050505050505050505050505050505",
                "02000000",
                "0303030303030303030303030303030303030303030303030303030303030303",
                "0404040404040404040404040404040404040404040404040404040404040404",
                "00"
            )
        );

        let redact = ForgetProof {
            mode: ForgetMode::Redact,
            ..proof.clone()
        };
        assert_eq!(redact.mode_tag(), 1);
        assert_ne!(proof.encode_payload(), redact.encode_payload());
    }

    #[test]
    fn forget_proof_wire_roundtrips() {
        let proof = sample_proof(None);
        let bytes_a = encode_forget_proof(&proof).unwrap();
        let bytes_b = encode_forget_proof(&proof).unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded = decode_forget_proof(&bytes_a).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn forget_proof_wire_hex_is_frozen() {
        let proof = sample_proof(Some([0xAA; 32]));
        let bytes = encode_forget_proof(&proof).unwrap();
        assert_eq!(
            hex::encode(bytes),
            "a70103025820212121212121212121212121212121212121212121212121212121212121212103010458202222222222222222222222222222222222222222222222222222222222222222058258202323232323232323232323232323232323232323232323232323232323232323582024242424242424242424242424242424242424242424242424242424242424240658202525252525252525252525252525252525252525252525252525252525252525075820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn forget_proof_wire_rejects_wrong_version_encode_and_decode() {
        let mut proof = sample_proof(None);
        proof.version = FORGET_PROOF_VERSION + 1;
        let err = encode_forget_proof(&proof).unwrap_err();
        assert_eq!(
            err,
            MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION + 1
            }
        );

        let valid = encode_forget_proof(&sample_proof(None)).unwrap();
        let mut dec = Decoder::new(&valid);
        let map = dec.decode_map().unwrap();
        let mut enc = Encoder::new();
        enc.begin_map(map.len() as u64).unwrap();
        for (k, v) in map {
            let field = k.as_u64().unwrap();
            enc.encode_unsigned(field).unwrap();
            match field {
                1 => enc
                    .encode_unsigned(u64::from(FORGET_PROOF_VERSION + 1))
                    .unwrap(),
                _ => encode_value(&mut enc, &v).unwrap(),
            }
        }
        let bad = enc.finish();
        let err = decode_forget_proof(&bad).unwrap_err();
        assert_eq!(
            err,
            MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION + 1
            }
        );
    }

    #[test]
    fn forget_proof_wire_rejects_missing_or_malformed_fields() {
        let mut bytes = encode_forget_proof(&sample_proof(None)).unwrap();
        bytes.truncate(bytes.len().saturating_sub(34));
        assert_eq!(
            decode_forget_proof(&bytes).unwrap_err(),
            MnemeError::SchemaDrift
        );

        let mut enc = Encoder::new();
        enc.begin_map(1).unwrap();
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(9).unwrap();
        let err = decode_forget_proof(&enc.finish()).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }

    fn encode_value(enc: &mut Encoder, value: &CborValue) -> Result<(), MnemeError> {
        match value {
            CborValue::Unsigned(v) => enc.encode_unsigned(*v)?,
            CborValue::Bytes(bytes) => enc.encode_bytes(bytes)?,
            CborValue::Null => enc.encode_null()?,
            CborValue::Array(items) => {
                enc.begin_array(items.len() as u64)?;
                for item in items {
                    encode_value(enc, item)?;
                }
            }
            _ => return Err(MnemeError::SchemaDrift),
        }
        Ok(())
    }
}
