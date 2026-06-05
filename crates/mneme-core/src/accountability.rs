//! Phase III action-accountability wire skeletons (ROADMAP Phase III, P3-1).
//!
//! **STATUS:** [`ActionReceipt`] wire + domain-separated signable preimage are
//! **frozen at v3** (`DomainTag::ActionReceipt`, `MNEME-action-rcpt-v3`). Ed25519
//! covers the BLAKE3 digest from [`crate::domain::hash_action_receipt_preimage`],
//! not the raw payload bytes.
//!
//! **Honesty boundary (CLAUDE.md §honesty, carried into Phase III):**
//! - An [`ActionReceipt`] binds an external action to the capability that
//!   authorized it and the human identity that sanctioned it. It proves
//!   *authorization + non-repudiation* — never that the action was wise, nor
//!   that its premises were true.
//! - The link to the Phase II cognition certificate ("cert v2") is an
//!   **optional** field: cert v2's layout is not yet finalized, so we bind only
//!   an opaque 32-byte commit when one is available and `None` otherwise. We
//!   never fabricate a commit to imply a cognition proof that was not produced.

use crate::{CborValue, Decoder, Encoder, MnemeError};
use std::convert::TryFrom;

/// Phase III action-receipt wire version. Distinct from `OBJECT_VERSION` and the
/// root version; the value `3` marks the Phase III seam and is provisional until
/// the seam is frozen. Used by `mneme-account::bind_action` as the
/// `UnsupportedVersion { got }` payload while the gate is closed.
pub const ACTION_RECEIPT_VERSION: u16 = 3;

/// Non-repudiation receipt binding an external action to its authorizing
/// capability and sanctioning human identity (Phase III P3-1).
///
/// Detached Ed25519 signature covers [`ActionReceipt::signable_preimage`] (32-byte digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionReceipt {
    /// Wire version; equals [`ACTION_RECEIPT_VERSION`] for receipts minted by
    /// this build.
    pub version: u16,
    /// BLAKE3 commit over the external action payload (e.g. the tool call /
    /// effect descriptor). Provisional; the action-encoding is frozen at the gate.
    pub action_commit: [u8; 32],
    /// Commit of the capability token body that authorized the action
    /// (`hash_cap` domain). Empty-of-meaning until the gate binds it.
    pub capability_commit: [u8; 32],
    /// Sanctioning human identity — an Ed25519 public key (NIST non-repudiation).
    pub sanctioner: [u8; 32],
    /// Signed root the action was bound against (chain-of-custody anchor).
    pub root_bound: [u8; 32],
    /// HLC at binding time, 14-byte wire form (matches `Root::hlc_max`).
    pub hlc: [u8; 14],
    /// OPTIONAL commit to the Phase II cognition certificate ("cert v2") the
    /// action consumed. `None` until cert v2 is finalized — never fabricated.
    pub cognition_cert_commit: Option<[u8; 32]>,
    /// Detached Ed25519 signature over [`ActionReceipt::signable_preimage`].
    pub signature: Vec<u8>,
}

impl ActionReceipt {
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 * 4 + 14 + 1 + 32);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.action_commit);
        buf.extend_from_slice(&self.capability_commit);
        buf.extend_from_slice(&self.sanctioner);
        buf.extend_from_slice(&self.root_bound);
        buf.extend_from_slice(&self.hlc);
        match self.cognition_cert_commit {
            Some(c) => {
                buf.push(1);
                buf.extend_from_slice(&c);
            }
            None => buf.push(0),
        }
        buf
    }
    pub fn signable_preimage(&self) -> [u8; 32] {
        crate::domain::hash_action_receipt_preimage(&self.encode_payload())
    }
}

/// Canonical dCBOR wire for [`ActionReceipt`]. Version-gated: refuses to emit
/// anything but the current [`ACTION_RECEIPT_VERSION`].
///
/// Field map (ascending numeric keys):
/// 1 → version (`u16`), 2 → action_commit (32-byte), 3 → capability_commit
/// (32-byte), 4 → sanctioner (32-byte), 5 → root_bound (32-byte),
/// 6 → hlc (14-byte), 7 → cognition_cert_commit (32-byte, `null` if absent),
/// 8 → signature (opaque bytes).
pub fn encode_action_receipt(receipt: &ActionReceipt) -> Result<Vec<u8>, MnemeError> {
    if receipt.version != ACTION_RECEIPT_VERSION {
        return Err(MnemeError::UnsupportedVersion {
            got: receipt.version,
        });
    }

    let mut enc = Encoder::new();
    enc.begin_map(8)?;

    enc.encode_unsigned(1)?;
    enc.encode_unsigned(u64::from(receipt.version))?;

    enc.encode_unsigned(2)?;
    enc.encode_bytes(&receipt.action_commit)?;

    enc.encode_unsigned(3)?;
    enc.encode_bytes(&receipt.capability_commit)?;

    enc.encode_unsigned(4)?;
    enc.encode_bytes(&receipt.sanctioner)?;

    enc.encode_unsigned(5)?;
    enc.encode_bytes(&receipt.root_bound)?;

    enc.encode_unsigned(6)?;
    enc.encode_bytes(&receipt.hlc)?;

    enc.encode_unsigned(7)?;
    match receipt.cognition_cert_commit {
        Some(commit) => enc.encode_bytes(&commit)?,
        None => enc.encode_null()?,
    }

    enc.encode_unsigned(8)?;
    enc.encode_bytes(&receipt.signature)?;

    Ok(enc.finish())
}

/// Parse a canonical [`ActionReceipt`] wire. Fails closed on version mismatch or
/// malformed fields.
pub fn decode_action_receipt(bytes: &[u8]) -> Result<ActionReceipt, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;

    let mut version = None;
    let mut action_commit = None;
    let mut capability_commit = None;
    let mut sanctioner = None;
    let mut root_bound = None;
    let mut hlc = None;
    let mut cognition_cert_commit = None;
    let mut signature = None;

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
                if action_commit.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                action_commit = Some(parse_fixed32(&value)?);
            }
            3 => {
                if capability_commit.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                capability_commit = Some(parse_fixed32(&value)?);
            }
            4 => {
                if sanctioner.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                sanctioner = Some(parse_fixed32(&value)?);
            }
            5 => {
                if root_bound.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                root_bound = Some(parse_fixed32(&value)?);
            }
            6 => {
                if hlc.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                hlc = Some(parse_fixed14(&value)?);
            }
            7 => {
                if cognition_cert_commit.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                cognition_cert_commit = Some(parse_optional_commit(&value)?);
            }
            8 => {
                if signature.is_some() {
                    return Err(MnemeError::SchemaDrift);
                }
                signature = Some(parse_bytes(&value)?);
            }
            _ => return Err(MnemeError::UnknownField { field }),
        }
    }

    let version = version.ok_or(MnemeError::SchemaDrift)?;
    if version != ACTION_RECEIPT_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: version });
    }

    Ok(ActionReceipt {
        version,
        action_commit: action_commit.ok_or(MnemeError::SchemaDrift)?,
        capability_commit: capability_commit.ok_or(MnemeError::SchemaDrift)?,
        sanctioner: sanctioner.ok_or(MnemeError::SchemaDrift)?,
        root_bound: root_bound.ok_or(MnemeError::SchemaDrift)?,
        hlc: hlc.ok_or(MnemeError::SchemaDrift)?,
        cognition_cert_commit: cognition_cert_commit.ok_or(MnemeError::SchemaDrift)?,
        signature: signature.ok_or(MnemeError::SchemaDrift)?,
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

fn parse_fixed14(value: &CborValue) -> Result<[u8; 14], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 14 => {
            let mut out = [0u8; 14];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(MnemeError::SchemaDrift),
    }
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

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or(MnemeError::SchemaDrift)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn action_receipt_wire_version_is_three() {
        assert_eq!(ACTION_RECEIPT_VERSION, 3);
    }

    fn sample_action(cert: Option<[u8; 32]>) -> ActionReceipt {
        ActionReceipt {
            version: ACTION_RECEIPT_VERSION,
            action_commit: [0x11; 32],
            capability_commit: [0x22; 32],
            sanctioner: [0x33; 32],
            root_bound: [0x44; 32],
            hlc: [0x55; 14],
            cognition_cert_commit: cert,
            signature: Vec::new(),
        }
    }

    #[test]
    fn action_signable_preimage_excludes_signature_and_is_deterministic() {
        let mut a = sample_action(None);
        let p1 = a.signable_preimage();
        a.signature = vec![0xAB; 64];
        assert_eq!(p1, a.signable_preimage());
    }
    #[test]
    fn action_optional_cert_changes_signable_digest() {
        assert_ne!(
            sample_action(None).signable_preimage(),
            sample_action(Some([0x99; 32])).signable_preimage()
        );
    }
    #[test]
    fn action_encode_payload_hex_is_frozen() {
        assert_eq!(
            hex::encode(sample_action(None).encode_payload()),
            "03001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555500"
        );
    }
    #[test]
    fn action_signable_preimage_hex_is_frozen() {
        assert_eq!(
            hex::encode(sample_action(None).signable_preimage()),
            "568df55727a6b84c311baf90349f0a3ab3e98902e4a08dfb717e5d14a8002c2b"
        );
    }

    fn sample_action_with_signature(cert: Option<[u8; 32]>) -> ActionReceipt {
        let mut receipt = sample_action(cert);
        receipt.signature = vec![0xEE; 8];
        receipt
    }

    #[test]
    fn action_receipt_wire_roundtrips() {
        let receipt = sample_action_with_signature(Some([0x99; 32]));
        let bytes_a = encode_action_receipt(&receipt).unwrap();
        let bytes_b = encode_action_receipt(&receipt).unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded = decode_action_receipt(&bytes_a).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn action_receipt_wire_hex_is_frozen() {
        let receipt = sample_action_with_signature(None);
        let bytes = encode_action_receipt(&receipt).unwrap();
        assert_eq!(
            hex::encode(bytes),
            "a801030258201111111111111111111111111111111111111111111111111111111111111111035820222222222222222222222222222222222222222222222222222222222222222204582033333333333333333333333333333333333333333333333333333333333333330558204444444444444444444444444444444444444444444444444444444444444444064e555555555555555555555555555507f60848eeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn action_receipt_wire_rejects_wrong_version_encode_and_decode() {
        let mut receipt = sample_action_with_signature(None);
        receipt.version = ACTION_RECEIPT_VERSION + 1;
        let err = encode_action_receipt(&receipt).unwrap_err();
        assert_eq!(
            err,
            MnemeError::UnsupportedVersion {
                got: ACTION_RECEIPT_VERSION + 1
            }
        );

        // Flip encoded version to 4.
        let valid = encode_action_receipt(&sample_action_with_signature(None)).unwrap();
        let mut dec = Decoder::new(&valid);
        let map = dec.decode_map().unwrap();
        let mut enc = Encoder::new();
        enc.begin_map(map.len() as u64).unwrap();
        for (k, v) in map {
            let field = k.as_u64().unwrap();
            enc.encode_unsigned(field).unwrap();
            match field {
                1 => enc
                    .encode_unsigned(u64::from(ACTION_RECEIPT_VERSION + 1))
                    .unwrap(),
                _ => encode_value(&mut enc, &v).unwrap(),
            }
        }
        let bad = enc.finish();
        let err = decode_action_receipt(&bad).unwrap_err();
        assert_eq!(
            err,
            MnemeError::UnsupportedVersion {
                got: ACTION_RECEIPT_VERSION + 1
            }
        );
    }

    #[test]
    fn action_receipt_wire_rejects_missing_or_malformed_fields() {
        let mut bytes = encode_action_receipt(&sample_action_with_signature(None)).unwrap();
        bytes.truncate(bytes.len().saturating_sub(10));
        assert_eq!(
            decode_action_receipt(&bytes).unwrap_err(),
            MnemeError::SchemaDrift
        );

        // Unknown field should fail.
        let mut enc = Encoder::new();
        enc.begin_map(1).unwrap();
        enc.encode_unsigned(99).unwrap();
        enc.encode_unsigned(1).unwrap();
        let err = decode_action_receipt(&enc.finish()).unwrap_err();
        assert_eq!(err, MnemeError::UnknownField { field: 99 });
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
