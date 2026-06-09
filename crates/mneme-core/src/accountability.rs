//! Phase III accountability wire skeletons (ROADMAP Phase III, P3-1 / P3-2).
//!
//! **STATUS:** [`ActionReceipt`] wire + domain-separated signable preimage are
//! **frozen at v3** (`DomainTag::ActionReceipt`, `MNEME-action-rcpt-v3`). Ed25519
//! covers the BLAKE3 digest from [`crate::domain::hash_action_receipt_preimage`],
//! not the raw payload bytes. [`ForgetProof`] remains a provisional wire skeleton.
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

/// Proof that a target was forgotten: crypto-shred witness plus proof-of-absence
/// under a signed root (Phase III P3-2, verifiable forgetting).
///
/// `shred_commit` and `absence_path` are populated by `mneme-account` forget minting
/// (`forget.rs`) and verified offline (`verify.rs`) for shred-mode proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgetProof {
    /// Wire version; equals [`FORGET_PROOF_VERSION`].
    pub version: u16,
    /// Commit of what was forgotten (logical-key hash or object id).
    pub target_commit: [u8; 32],
    /// Forget mode applied — shred vs accountable chameleon redaction (§13.3).
    pub mode: ForgetMode,
    /// Crypto-shred witness commit (destruction of the wrapping key).
    pub shred_commit: [u8; 32],
    /// Proof-of-absence: SMT non-membership path against `root_bound`'s key index.
    pub absence_path: Vec<[u8; 32]>,
    /// Signed root the absence proof is bound to (A-REPLAY safe at the gate).
    pub root_bound: [u8; 32],
    /// OPTIONAL cognition-certificate ("cert v2") commit witnessing
    /// not-used-after. `None` until cert v2 is finalized — never fabricated.
    pub cognition_cert_commit: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActionReceiptWireFailure {
    EncodeUnsupportedVersion { got: u16 },
    DuplicateVersion,
    DuplicateActionCommit,
    DuplicateCapabilityCommit,
    DuplicateSanctioner,
    DuplicateRootBound,
    DuplicateHlc,
    DuplicateCognitionCertCommit,
    DuplicateSignature,
    UnknownField { field: u16 },
    MissingVersion,
    DecodeUnsupportedVersion { got: u16 },
    MissingActionCommit,
    MissingCapabilityCommit,
    MissingSanctioner,
    MissingRootBound,
    MissingHlc,
    MissingCognitionCertCommit,
    MissingSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForgetProofWireFailure {
    EncodeUnsupportedVersion { got: u16 },
    DuplicateVersion,
    DuplicateTargetCommit,
    DuplicateMode,
    DuplicateShredCommit,
    DuplicateAbsencePath,
    DuplicateRootBound,
    DuplicateCognitionCertCommit,
    UnknownField { field: u16 },
    MissingVersion,
    DecodeUnsupportedVersion { got: u16 },
    MissingTargetCommit,
    MissingMode,
    MissingShredCommit,
    MissingAbsencePath,
    MissingRootBound,
    MissingCognitionCertCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountabilityParseFailure {
    FieldKey,
    U16Value,
    Fixed14,
    Fixed32,
    Bytes,
    ModeTag,
    UnknownModeTag,
    AbsencePathArray,
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

fn action_receipt_wire_failure_to_mneme(failure: ActionReceiptWireFailure) -> MnemeError {
    match failure {
        ActionReceiptWireFailure::EncodeUnsupportedVersion { got }
        | ActionReceiptWireFailure::DecodeUnsupportedVersion { got } => {
            MnemeError::UnsupportedVersion { got }
        }
        ActionReceiptWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        ActionReceiptWireFailure::DuplicateVersion
        | ActionReceiptWireFailure::DuplicateActionCommit
        | ActionReceiptWireFailure::DuplicateCapabilityCommit
        | ActionReceiptWireFailure::DuplicateSanctioner
        | ActionReceiptWireFailure::DuplicateRootBound
        | ActionReceiptWireFailure::DuplicateHlc
        | ActionReceiptWireFailure::DuplicateCognitionCertCommit
        | ActionReceiptWireFailure::DuplicateSignature
        | ActionReceiptWireFailure::MissingVersion
        | ActionReceiptWireFailure::MissingActionCommit
        | ActionReceiptWireFailure::MissingCapabilityCommit
        | ActionReceiptWireFailure::MissingSanctioner
        | ActionReceiptWireFailure::MissingRootBound
        | ActionReceiptWireFailure::MissingHlc
        | ActionReceiptWireFailure::MissingCognitionCertCommit
        | ActionReceiptWireFailure::MissingSignature => MnemeError::SchemaDrift,
    }
}

fn action_receipt_encode_unsupported_version_error(got: u16) -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::EncodeUnsupportedVersion { got })
}

fn action_receipt_decode_unsupported_version_error(got: u16) -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DecodeUnsupportedVersion { got })
}

fn action_receipt_unknown_field_error(field: u16) -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::UnknownField { field })
}

fn duplicate_action_receipt_version_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateVersion)
}

fn duplicate_action_receipt_action_commit_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateActionCommit)
}

fn duplicate_action_receipt_capability_commit_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateCapabilityCommit)
}

fn duplicate_action_receipt_sanctioner_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateSanctioner)
}

fn duplicate_action_receipt_root_bound_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateRootBound)
}

fn duplicate_action_receipt_hlc_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateHlc)
}

fn duplicate_action_receipt_cognition_cert_commit_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateCognitionCertCommit)
}

fn duplicate_action_receipt_signature_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::DuplicateSignature)
}

fn missing_action_receipt_version_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingVersion)
}

fn missing_action_receipt_action_commit_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingActionCommit)
}

fn missing_action_receipt_capability_commit_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingCapabilityCommit)
}

fn missing_action_receipt_sanctioner_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingSanctioner)
}

fn missing_action_receipt_root_bound_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingRootBound)
}

fn missing_action_receipt_hlc_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingHlc)
}

fn missing_action_receipt_cognition_cert_commit_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingCognitionCertCommit)
}

fn missing_action_receipt_signature_error() -> MnemeError {
    action_receipt_wire_failure_to_mneme(ActionReceiptWireFailure::MissingSignature)
}

fn forget_proof_wire_failure_to_mneme(failure: ForgetProofWireFailure) -> MnemeError {
    match failure {
        ForgetProofWireFailure::EncodeUnsupportedVersion { got }
        | ForgetProofWireFailure::DecodeUnsupportedVersion { got } => {
            MnemeError::UnsupportedVersion { got }
        }
        ForgetProofWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        ForgetProofWireFailure::DuplicateVersion
        | ForgetProofWireFailure::DuplicateTargetCommit
        | ForgetProofWireFailure::DuplicateMode
        | ForgetProofWireFailure::DuplicateShredCommit
        | ForgetProofWireFailure::DuplicateAbsencePath
        | ForgetProofWireFailure::DuplicateRootBound
        | ForgetProofWireFailure::DuplicateCognitionCertCommit
        | ForgetProofWireFailure::MissingVersion
        | ForgetProofWireFailure::MissingTargetCommit
        | ForgetProofWireFailure::MissingMode
        | ForgetProofWireFailure::MissingShredCommit
        | ForgetProofWireFailure::MissingAbsencePath
        | ForgetProofWireFailure::MissingRootBound
        | ForgetProofWireFailure::MissingCognitionCertCommit => MnemeError::SchemaDrift,
    }
}

fn forget_proof_encode_unsupported_version_error(got: u16) -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::EncodeUnsupportedVersion { got })
}

fn forget_proof_decode_unsupported_version_error(got: u16) -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DecodeUnsupportedVersion { got })
}

fn forget_proof_unknown_field_error(field: u16) -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::UnknownField { field })
}

fn duplicate_forget_proof_version_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateVersion)
}

fn duplicate_forget_proof_target_commit_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateTargetCommit)
}

fn duplicate_forget_proof_mode_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateMode)
}

fn duplicate_forget_proof_shred_commit_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateShredCommit)
}

fn duplicate_forget_proof_absence_path_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateAbsencePath)
}

fn duplicate_forget_proof_root_bound_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateRootBound)
}

fn duplicate_forget_proof_cognition_cert_commit_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::DuplicateCognitionCertCommit)
}

fn missing_forget_proof_version_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingVersion)
}

fn missing_forget_proof_target_commit_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingTargetCommit)
}

fn missing_forget_proof_mode_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingMode)
}

fn missing_forget_proof_shred_commit_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingShredCommit)
}

fn missing_forget_proof_absence_path_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingAbsencePath)
}

fn missing_forget_proof_root_bound_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingRootBound)
}

fn missing_forget_proof_cognition_cert_commit_error() -> MnemeError {
    forget_proof_wire_failure_to_mneme(ForgetProofWireFailure::MissingCognitionCertCommit)
}

fn accountability_parse_failure_to_mneme(failure: AccountabilityParseFailure) -> MnemeError {
    match failure {
        AccountabilityParseFailure::FieldKey
        | AccountabilityParseFailure::U16Value
        | AccountabilityParseFailure::Fixed14
        | AccountabilityParseFailure::Fixed32
        | AccountabilityParseFailure::Bytes
        | AccountabilityParseFailure::ModeTag
        | AccountabilityParseFailure::UnknownModeTag
        | AccountabilityParseFailure::AbsencePathArray => MnemeError::SchemaDrift,
    }
}

fn field_key_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::FieldKey)
}

fn u16_value_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::U16Value)
}

fn fixed14_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::Fixed14)
}

fn fixed32_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::Fixed32)
}

fn bytes_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::Bytes)
}

fn mode_tag_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::ModeTag)
}

fn unknown_mode_tag_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::UnknownModeTag)
}

fn absence_path_array_error() -> MnemeError {
    accountability_parse_failure_to_mneme(AccountabilityParseFailure::AbsencePathArray)
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
        return Err(action_receipt_encode_unsupported_version_error(
            receipt.version,
        ));
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
                    return Err(duplicate_action_receipt_version_error());
                }
                version = Some(parse_u16(&value)?);
            }
            2 => {
                if action_commit.is_some() {
                    return Err(duplicate_action_receipt_action_commit_error());
                }
                action_commit = Some(parse_fixed32(&value)?);
            }
            3 => {
                if capability_commit.is_some() {
                    return Err(duplicate_action_receipt_capability_commit_error());
                }
                capability_commit = Some(parse_fixed32(&value)?);
            }
            4 => {
                if sanctioner.is_some() {
                    return Err(duplicate_action_receipt_sanctioner_error());
                }
                sanctioner = Some(parse_fixed32(&value)?);
            }
            5 => {
                if root_bound.is_some() {
                    return Err(duplicate_action_receipt_root_bound_error());
                }
                root_bound = Some(parse_fixed32(&value)?);
            }
            6 => {
                if hlc.is_some() {
                    return Err(duplicate_action_receipt_hlc_error());
                }
                hlc = Some(parse_fixed14(&value)?);
            }
            7 => {
                if cognition_cert_commit.is_some() {
                    return Err(duplicate_action_receipt_cognition_cert_commit_error());
                }
                cognition_cert_commit = Some(parse_optional_commit(&value)?);
            }
            8 => {
                if signature.is_some() {
                    return Err(duplicate_action_receipt_signature_error());
                }
                signature = Some(parse_bytes(&value)?);
            }
            _ => return Err(action_receipt_unknown_field_error(field)),
        }
    }

    let version = version.ok_or_else(missing_action_receipt_version_error)?;
    if version != ACTION_RECEIPT_VERSION {
        return Err(action_receipt_decode_unsupported_version_error(version));
    }

    Ok(ActionReceipt {
        version,
        action_commit: action_commit.ok_or_else(missing_action_receipt_action_commit_error)?,
        capability_commit: capability_commit
            .ok_or_else(missing_action_receipt_capability_commit_error)?,
        sanctioner: sanctioner.ok_or_else(missing_action_receipt_sanctioner_error)?,
        root_bound: root_bound.ok_or_else(missing_action_receipt_root_bound_error)?,
        hlc: hlc.ok_or_else(missing_action_receipt_hlc_error)?,
        cognition_cert_commit: cognition_cert_commit
            .ok_or_else(missing_action_receipt_cognition_cert_commit_error)?,
        signature: signature.ok_or_else(missing_action_receipt_signature_error)?,
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
        return Err(forget_proof_encode_unsupported_version_error(proof.version));
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
                    return Err(duplicate_forget_proof_version_error());
                }
                version = Some(parse_u16(&value)?);
            }
            2 => {
                if target_commit.is_some() {
                    return Err(duplicate_forget_proof_target_commit_error());
                }
                target_commit = Some(parse_fixed32(&value)?);
            }
            3 => {
                if mode.is_some() {
                    return Err(duplicate_forget_proof_mode_error());
                }
                mode = Some(parse_mode(&value)?);
            }
            4 => {
                if shred_commit.is_some() {
                    return Err(duplicate_forget_proof_shred_commit_error());
                }
                shred_commit = Some(parse_fixed32(&value)?);
            }
            5 => {
                if absence_path.is_some() {
                    return Err(duplicate_forget_proof_absence_path_error());
                }
                absence_path = Some(parse_absence_path(&value)?);
            }
            6 => {
                if root_bound.is_some() {
                    return Err(duplicate_forget_proof_root_bound_error());
                }
                root_bound = Some(parse_fixed32(&value)?);
            }
            7 => {
                if cognition_cert_commit.is_some() {
                    return Err(duplicate_forget_proof_cognition_cert_commit_error());
                }
                cognition_cert_commit = Some(parse_optional_commit(&value)?);
            }
            _ => return Err(forget_proof_unknown_field_error(field)),
        }
    }

    let version = version.ok_or_else(missing_forget_proof_version_error)?;
    if version != FORGET_PROOF_VERSION {
        return Err(forget_proof_decode_unsupported_version_error(version));
    }

    Ok(ForgetProof {
        version,
        target_commit: target_commit.ok_or_else(missing_forget_proof_target_commit_error)?,
        mode: mode.ok_or_else(missing_forget_proof_mode_error)?,
        shred_commit: shred_commit.ok_or_else(missing_forget_proof_shred_commit_error)?,
        absence_path: absence_path.ok_or_else(missing_forget_proof_absence_path_error)?,
        root_bound: root_bound.ok_or_else(missing_forget_proof_root_bound_error)?,
        cognition_cert_commit: cognition_cert_commit
            .ok_or_else(missing_forget_proof_cognition_cert_commit_error)?,
    })
}

fn parse_field_key(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(field_key_error)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(u16_value_error)
}

fn parse_fixed14(value: &CborValue) -> Result<[u8; 14], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 14 => {
            let mut out = [0u8; 14];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(fixed14_error()),
    }
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(fixed32_error()),
    }
}

fn parse_optional_commit(value: &CborValue) -> Result<Option<[u8; 32]>, MnemeError> {
    match value {
        CborValue::Null => Ok(None),
        _ => Ok(Some(parse_fixed32(value)?)),
    }
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value.as_bytes().map(|b| b.to_vec()).ok_or_else(bytes_error)
}

fn parse_mode(value: &CborValue) -> Result<ForgetMode, MnemeError> {
    let tag = value
        .as_u64()
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(mode_tag_error)?;
    match tag {
        0 => Ok(ForgetMode::Shred),
        1 => Ok(ForgetMode::Redact),
        _ => Err(unknown_mode_tag_error()),
    }
}

fn parse_absence_path(value: &CborValue) -> Result<Vec<[u8; 32]>, MnemeError> {
    let arr = value.as_array().ok_or_else(absence_path_array_error)?;
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

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let (_, after_start) = source
            .split_once(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let (section, _) = after_start
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        section
    }

    #[test]
    fn action_receipt_wire_errors_are_classified_not_directly_returned() {
        let source = include_str!("accountability.rs");
        let sections = [
            source_between_markers(
                source,
                "pub fn encode_action_receipt",
                "/// Parse a canonical [`ActionReceipt`] wire",
                "ActionReceipt encode",
            ),
            source_between_markers(
                source,
                "pub fn decode_action_receipt",
                "/// Canonical dCBOR wire for [`ForgetProof`]",
                "ActionReceipt decode",
            ),
        ];

        for section in sections {
            for forbidden in [
                "return Err(MnemeError::SchemaDrift)",
                "ok_or(MnemeError::SchemaDrift)",
                "return Err(MnemeError::UnknownField",
                "return Err(MnemeError::UnsupportedVersion",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "ActionReceipt wire paths should route `{forbidden}` through named classifiers"
                );
            }
        }

        for required in [
            "enum ActionReceiptWireFailure",
            "fn action_receipt_wire_failure_to_mneme(",
            "fn action_receipt_encode_unsupported_version_error(",
            "fn duplicate_action_receipt_version_error(",
            "fn action_receipt_unknown_field_error(",
            "fn missing_action_receipt_version_error(",
            "fn action_receipt_decode_unsupported_version_error(",
            "fn missing_action_receipt_signature_error(",
            "ActionReceiptWireFailure::EncodeUnsupportedVersion",
            "ActionReceiptWireFailure::DuplicateVersion",
            "ActionReceiptWireFailure::UnknownField",
            "ActionReceiptWireFailure::MissingVersion",
            "ActionReceiptWireFailure::DecodeUnsupportedVersion",
            "ActionReceiptWireFailure::MissingSignature",
        ] {
            assert!(
                source.contains(required),
                "ActionReceipt wire classification should include `{required}`"
            );
        }
    }

    #[test]
    fn action_receipt_wire_classifier_preserves_public_errors() {
        assert_eq!(
            action_receipt_encode_unsupported_version_error(9),
            MnemeError::UnsupportedVersion { got: 9 }
        );
        assert_eq!(
            action_receipt_decode_unsupported_version_error(10),
            MnemeError::UnsupportedVersion { got: 10 }
        );
        assert_eq!(
            action_receipt_unknown_field_error(99),
            MnemeError::UnknownField { field: 99 }
        );

        for failure in [
            ActionReceiptWireFailure::DuplicateVersion,
            ActionReceiptWireFailure::DuplicateActionCommit,
            ActionReceiptWireFailure::DuplicateCapabilityCommit,
            ActionReceiptWireFailure::DuplicateSanctioner,
            ActionReceiptWireFailure::DuplicateRootBound,
            ActionReceiptWireFailure::DuplicateHlc,
            ActionReceiptWireFailure::DuplicateCognitionCertCommit,
            ActionReceiptWireFailure::DuplicateSignature,
            ActionReceiptWireFailure::MissingVersion,
            ActionReceiptWireFailure::MissingActionCommit,
            ActionReceiptWireFailure::MissingCapabilityCommit,
            ActionReceiptWireFailure::MissingSanctioner,
            ActionReceiptWireFailure::MissingRootBound,
            ActionReceiptWireFailure::MissingHlc,
            ActionReceiptWireFailure::MissingCognitionCertCommit,
            ActionReceiptWireFailure::MissingSignature,
        ] {
            assert_eq!(
                action_receipt_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn forget_proof_wire_errors_are_classified_not_directly_returned() {
        let source = include_str!("accountability.rs");
        let sections = [
            source_between_markers(
                source,
                "pub fn encode_forget_proof",
                "/// Parse a canonical [`ForgetProof`] wire",
                "ForgetProof encode",
            ),
            source_between_markers(
                source,
                "pub fn decode_forget_proof",
                "fn parse_field_key",
                "ForgetProof decode",
            ),
        ];

        for section in sections {
            for forbidden in [
                "return Err(MnemeError::SchemaDrift)",
                "ok_or(MnemeError::SchemaDrift)",
                "return Err(MnemeError::UnknownField",
                "return Err(MnemeError::UnsupportedVersion",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "ForgetProof wire paths should route `{forbidden}` through named classifiers"
                );
            }
        }

        for required in [
            "enum ForgetProofWireFailure",
            "fn forget_proof_wire_failure_to_mneme(",
            "fn forget_proof_encode_unsupported_version_error(",
            "fn duplicate_forget_proof_version_error(",
            "fn forget_proof_unknown_field_error(",
            "fn missing_forget_proof_version_error(",
            "fn forget_proof_decode_unsupported_version_error(",
            "fn missing_forget_proof_cognition_cert_commit_error(",
            "ForgetProofWireFailure::EncodeUnsupportedVersion",
            "ForgetProofWireFailure::DuplicateVersion",
            "ForgetProofWireFailure::UnknownField",
            "ForgetProofWireFailure::MissingVersion",
            "ForgetProofWireFailure::DecodeUnsupportedVersion",
            "ForgetProofWireFailure::MissingCognitionCertCommit",
        ] {
            assert!(
                source.contains(required),
                "ForgetProof wire classification should include `{required}`"
            );
        }
    }

    #[test]
    fn forget_proof_wire_classifier_preserves_public_errors() {
        assert_eq!(
            forget_proof_encode_unsupported_version_error(11),
            MnemeError::UnsupportedVersion { got: 11 }
        );
        assert_eq!(
            forget_proof_decode_unsupported_version_error(12),
            MnemeError::UnsupportedVersion { got: 12 }
        );
        assert_eq!(
            forget_proof_unknown_field_error(98),
            MnemeError::UnknownField { field: 98 }
        );

        for failure in [
            ForgetProofWireFailure::DuplicateVersion,
            ForgetProofWireFailure::DuplicateTargetCommit,
            ForgetProofWireFailure::DuplicateMode,
            ForgetProofWireFailure::DuplicateShredCommit,
            ForgetProofWireFailure::DuplicateAbsencePath,
            ForgetProofWireFailure::DuplicateRootBound,
            ForgetProofWireFailure::DuplicateCognitionCertCommit,
            ForgetProofWireFailure::MissingVersion,
            ForgetProofWireFailure::MissingTargetCommit,
            ForgetProofWireFailure::MissingMode,
            ForgetProofWireFailure::MissingShredCommit,
            ForgetProofWireFailure::MissingAbsencePath,
            ForgetProofWireFailure::MissingRootBound,
            ForgetProofWireFailure::MissingCognitionCertCommit,
        ] {
            assert_eq!(
                forget_proof_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn accountability_parse_helpers_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("accountability.rs");
        let section = source_between_markers(
            source,
            "fn parse_field_key",
            "#[cfg(test)]",
            "accountability parse helpers",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "accountability parse helpers should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum AccountabilityParseFailure",
            "fn accountability_parse_failure_to_mneme(",
            "fn field_key_error(",
            "fn u16_value_error(",
            "fn fixed14_error(",
            "fn fixed32_error(",
            "fn bytes_error(",
            "fn mode_tag_error(",
            "fn unknown_mode_tag_error(",
            "fn absence_path_array_error(",
            "AccountabilityParseFailure::FieldKey",
            "AccountabilityParseFailure::U16Value",
            "AccountabilityParseFailure::Fixed14",
            "AccountabilityParseFailure::Fixed32",
            "AccountabilityParseFailure::Bytes",
            "AccountabilityParseFailure::ModeTag",
            "AccountabilityParseFailure::UnknownModeTag",
            "AccountabilityParseFailure::AbsencePathArray",
        ] {
            assert!(
                source.contains(required),
                "accountability parse helper classification should include `{required}`"
            );
        }
    }

    #[test]
    fn accountability_parse_failure_classifier_preserves_schema_drift() {
        for failure in [
            AccountabilityParseFailure::FieldKey,
            AccountabilityParseFailure::U16Value,
            AccountabilityParseFailure::Fixed14,
            AccountabilityParseFailure::Fixed32,
            AccountabilityParseFailure::Bytes,
            AccountabilityParseFailure::ModeTag,
            AccountabilityParseFailure::UnknownModeTag,
            AccountabilityParseFailure::AbsencePathArray,
        ] {
            assert_eq!(
                accountability_parse_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

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
