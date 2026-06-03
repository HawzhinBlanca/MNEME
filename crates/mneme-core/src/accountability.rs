//! Phase III accountability wire skeletons (ROADMAP Phase III, P3-1 / P3-2).
//!
//! **STATUS: wire skeleton only — not a frozen interface seam, not implemented.**
//! These types declare the *shape* of the Phase III certificate extensions
//! (authorized action + honored forgetting). No proving, signing, hashing-to-a
//! -domain-tag, or verification logic exists yet: the Phase III gate is closed
//! and the `mneme-account` crate fails closed (`MnemeError::UnsupportedVersion`).
//! Unlike [`crate::interface`], this module is **not** under the §20.3 interface
//! freeze; layouts here are provisional until the Phase III seam is reviewed and
//! frozen (at which point `*_VERSION` and any domain tags are pinned).
//!
//! **Honesty boundary (CLAUDE.md §honesty, carried into Phase III):**
//! - An [`ActionReceipt`] binds an external action to the capability that
//!   authorized it and the human identity that sanctioned it. It proves
//!   *authorization + non-repudiation* — never that the action was wise, nor
//!   that its premises were true.
//! - A [`ForgetProof`] proves *crypto-shred witness + proof-of-absence under a
//!   signed root* (deleted, and not served from trusted memory afterward). It
//!   does **not** prove that no out-of-band copy ever existed elsewhere.
//! - The link to the Phase II cognition certificate ("cert v2") is an
//!   **optional** field: cert v2's layout is not yet finalized, so we bind only
//!   an opaque 32-byte commit when one is available and `None` otherwise. We
//!   never fabricate a commit to imply a cognition proof that was not produced.

use crate::interface::ForgetMode;
use crate::{CborValue, Decoder, Encoder, MnemeError};
use std::convert::TryFrom;

/// Phase III action-receipt wire version. Distinct from `OBJECT_VERSION` and the
/// root version; the value `3` marks the Phase III seam and is provisional until
/// the seam is frozen. Used by `mneme-account::bind_action` as the
/// `UnsupportedVersion { got }` payload while the gate is closed.
pub const ACTION_RECEIPT_VERSION: u16 = 3;

/// Phase III forget-proof wire version (see [`ACTION_RECEIPT_VERSION`]).
pub const FORGET_PROOF_VERSION: u16 = 3;

/// Non-repudiation receipt binding an external action to its authorizing
/// capability and sanctioning human identity (Phase III P3-1).
///
/// **Skeleton:** the `signature` is empty and no field is hash-bound yet;
/// [`ActionReceipt::signable_preimage`] returns the provisional byte layout that
/// a future signer will cover, but nothing signs it today.
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
    /// Detached signature over [`ActionReceipt::signable_preimage`]. Empty in
    /// the skeleton (no signer wired yet).
    pub signature: Vec<u8>,
}

impl ActionReceipt {
    /// Provisional signable preimage: `version ‖ action_commit ‖
    /// capability_commit ‖ sanctioner ‖ root_bound ‖ hlc ‖ cert_present(1) ‖
    /// [cert_commit]`. Excludes `signature` (signed-over content), mirroring
    /// [`crate::interface::RootPreimage`]. **No domain tag is applied yet** —
    /// that is pinned when the Phase III seam is frozen.
    pub fn signable_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 * 4 + 14 + 1 + 32);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.action_commit);
        buf.extend_from_slice(&self.capability_commit);
        buf.extend_from_slice(&self.sanctioner);
        buf.extend_from_slice(&self.root_bound);
        buf.extend_from_slice(&self.hlc);
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

/// Proof that a target was forgotten: crypto-shred witness plus proof-of-absence
/// under a signed root (Phase III P3-2, verifiable forgetting).
///
/// **Skeleton:** `shred_commit` and `absence_path` are placeholders for the real
/// key-destruction witness and SMT non-membership path; nothing populates or
/// verifies them yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgetProof {
    /// Wire version; equals [`FORGET_PROOF_VERSION`].
    pub version: u16,
    /// Commit of what was forgotten (logical-key hash or object id).
    pub target_commit: [u8; 32],
    /// Forget mode applied — shred vs accountable chameleon redaction (§13.3).
    pub mode: ForgetMode,
    /// Crypto-shred witness commit (destruction of the wrapping key). Deferred.
    pub shred_commit: [u8; 32],
    /// Proof-of-absence: SMT non-membership path against `root_bound`'s key
    /// index. Empty in the skeleton.
    pub absence_path: Vec<[u8; 32]>,
    /// Signed root the absence proof is bound to (A-REPLAY safe at the gate).
    pub root_bound: [u8; 32],
    /// OPTIONAL cognition-certificate ("cert v2") commit witnessing
    /// not-used-after. `None` until cert v2 is finalized — never fabricated.
    pub cognition_cert_commit: Option<[u8; 32]>,
}

impl ForgetProof {
    /// 1-byte mode tag: `Shred → 0`, `Redact → 1`.
    pub fn mode_tag(&self) -> u8 {
        match self.mode {
            ForgetMode::Shred => 0,
            ForgetMode::Redact => 1,
        }
    }

    /// Provisional canonical payload: `version ‖ target_commit ‖ mode_tag(1) ‖
    /// shred_commit ‖ root_bound ‖ absence_len(4 LE) ‖ absence_path* ‖
    /// cert_present(1) ‖ [cert_commit]`. **No domain tag yet** (pinned at freeze).
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

/// Canonical dCBOR wire for [`ForgetProof`]. Version-gated: refuses to emit
/// anything but the current [`FORGET_PROOF_VERSION`].
///
/// Field map (ascending numeric keys):
/// 1 → version (`u16`), 2 → target_commit (32-byte), 3 → mode (tagged `u8`),
/// 4 → shred_commit (32-byte), 5 → absence_path (array of 32-byte nodes),
/// 6 → root_bound (32-byte), 7 → cognition_cert_commit (32-byte, `null` if
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

    #[test]
    fn phase_iii_wire_versions_are_provisionally_three() {
        assert_eq!(ACTION_RECEIPT_VERSION, 3);
        assert_eq!(FORGET_PROOF_VERSION, 3);
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
    fn action_preimage_excludes_signature_and_is_deterministic() {
        let mut a = sample_action(None);
        let p1 = a.signable_preimage();
        // Signature is signed-over content, never part of its own preimage.
        a.signature = vec![0xAB; 64];
        let p2 = a.signable_preimage();
        assert_eq!(p1, p2);
    }

    #[test]
    fn action_optional_cert_changes_preimage_without_fabrication() {
        let without = sample_action(None).signable_preimage();
        let with = sample_action(Some([0x99; 32])).signable_preimage();
        // Presence flag + commit must be observable; absence is one byte `0`.
        assert_eq!(*without.last().unwrap(), 0u8);
        assert_eq!(with.len(), without.len() + 32);
        assert_ne!(without, with);
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
        assert_eq!(proof.encode_payload(), proof.encode_payload());

        let redact = ForgetProof {
            mode: ForgetMode::Redact,
            ..proof.clone()
        };
        assert_eq!(redact.mode_tag(), 1);
        assert_ne!(proof.encode_payload(), redact.encode_payload());
    }

    fn sample_action_with_signature(cert: Option<[u8; 32]>) -> ActionReceipt {
        let mut receipt = sample_action(cert);
        receipt.signature = vec![0xEE; 8];
        receipt
    }

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
    fn action_receipt_wire_roundtrips() {
        let receipt = sample_action_with_signature(Some([0x99; 32]));
        let bytes_a = encode_action_receipt(&receipt).unwrap();
        let bytes_b = encode_action_receipt(&receipt).unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded = decode_action_receipt(&bytes_a).unwrap();
        assert_eq!(decoded, receipt);
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
    fn action_receipt_wire_hex_is_frozen() {
        let receipt = sample_action_with_signature(None);
        let bytes = encode_action_receipt(&receipt).unwrap();
        assert_eq!(
            hex::encode(bytes),
            "a801030258201111111111111111111111111111111111111111111111111111111111111111035820222222222222222222222222222222222222222222222222222222222222222204582033333333333333333333333333333333333333333333333333333333333333330558204444444444444444444444444444444444444444444444444444444444444444064e555555555555555555555555555507f60848eeeeeeeeeeeeeeee"
        );
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

    #[test]
    fn forget_proof_wire_rejects_missing_or_malformed_fields() {
        // Missing root_bound by truncation.
        let mut bytes = encode_forget_proof(&sample_proof(None)).unwrap();
        bytes.truncate(bytes.len().saturating_sub(34));
        assert_eq!(
            decode_forget_proof(&bytes).unwrap_err(),
            MnemeError::SchemaDrift
        );

        // Bad mode tag.
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
