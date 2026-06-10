//! Cognition Certificate v1 — offline-verifiable bundle (Phase I P1-4).
//!
//! Optional field 7 (`audit_beacon`) carries a drand v2 beacon binding for Trick #1
//! probabilistically-checkable retrieval (see `beacon_spot_check`).

#[cfg(feature = "context_gate")]
use crate::context_gate::{CONTEXT_GATE_STRICT_STATUS, apply_context_gate_strict};
use crate::beacon_spot_check::{
    AuditBeacon, SpotCheckContext, verify_beacon_spot_check, DEFAULT_AUDIT_RATE_PPM,
};
use crate::receipt::SemanticRecallReceipt;
use crate::verify::verify_semantic_receipt_vo_zkann;
#[cfg(feature = "context_gate")]
use mneme_core::COGNITION_CERT_VERSION_V2_DRAFT;
use mneme_core::{
    AsOf, COGNITION_CERT_VERSION, CborValue, DcborDecode, DcborEncode, Decoder, Encoder,
    MnemeError, RetrievalProofLevel, Root, from_bytes_strict, to_bytes_canonical,
};
#[cfg(feature = "context_gate")]
use mneme_core::{
    ContextConsumptionAttestation, Entry, OutputBinding, decode_context_consumption_attestation,
    decode_output_binding,
};
use mneme_core::{ObjectId, Procedure, RootPreimage};
use mneme_crypto::{TrustConfig, public_key_from_bytes, verify_signature_bytes};
use mneme_root::StoredRoot;
use std::collections::HashSet;

type VoNodes = Vec<([u8; 32], Vec<[u8; 32]>)>;
type VoCandidates = Vec<(ObjectId, [u8; 32], i64)>;

const F_CERT_VERSION: u64 = 1;
const F_LEVEL: u64 = 2;
const F_AS_OF_SEQ: u64 = 3;
const F_STORED_ROOT: u64 = 4;
const F_SEMANTIC_RECEIPT: u64 = 5;
#[cfg(feature = "context_gate")]
const F_CONTEXT_ATTESTATION: u64 = 6;
const F_AUDIT_BEACON: u64 = 7;
#[cfg(feature = "context_gate")]
const F_CCA: u64 = 4;
#[cfg(feature = "context_gate")]
const F_OUTPUT_BINDING: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CognitionCertFailure {
    UnsupportedV1Version {
        version: u16,
    },
    V1WireDecode,
    V1ReceiptRootBoundMismatch,
    V1ReceiptSemanticCommitMismatch,
    V1AsOfSequenceMismatch,
    V1ZkannLevelMismatch,
    V1ZkannMissingForLevel,
    #[cfg(feature = "context_gate")]
    UnsupportedV2DraftVersion {
        version: u16,
    },
    #[cfg(feature = "context_gate")]
    V2DraftWireDecode,
    #[cfg(feature = "context_gate")]
    V2DraftWireVersionMissing,
    #[cfg(feature = "context_gate")]
    V2DraftWireLevelMissing,
    #[cfg(feature = "context_gate")]
    V2DraftWireStoredRootMissing,
    #[cfg(feature = "context_gate")]
    V2DraftWireReceiptMissing,
    #[cfg(feature = "context_gate")]
    V2DraftWireAttestationMissing,
    #[cfg(feature = "context_gate")]
    V2DraftReceiptRootBoundMismatch,
    #[cfg(feature = "context_gate")]
    V2DraftReceiptSemanticCommitMismatch,
    #[cfg(feature = "context_gate")]
    V2DraftAsOfSequenceMismatch,
    #[cfg(feature = "context_gate")]
    V2DraftZkannLevelMismatch,
    #[cfg(feature = "context_gate")]
    V2DraftZkannMissingForLevel,
    #[cfg(feature = "context_gate")]
    V2DraftStatusMismatch,
    #[cfg(feature = "context_gate")]
    V2DraftStrictAttestationPresent,
    #[cfg(feature = "context_gate")]
    UnsupportedV2StrictVersion {
        version: u16,
    },
    #[cfg(feature = "context_gate")]
    V2StrictWireDecode,
    #[cfg(feature = "context_gate")]
    V2StrictReceiptRootBoundMismatch,
    #[cfg(feature = "context_gate")]
    V2StrictReceiptSemanticCommitMismatch,
    #[cfg(feature = "context_gate")]
    V2StrictAsOfSequenceMismatch,
    #[cfg(feature = "context_gate")]
    V2StrictZkannLevelMismatch,
    #[cfg(feature = "context_gate")]
    V2StrictZkannMissingForLevel,
    #[cfg(feature = "context_gate")]
    V2StrictStatusMismatch,
    #[cfg(feature = "context_gate")]
    V2StrictAttestationMissing,
    #[cfg(feature = "context_gate")]
    V2StrictContextDigestMismatch,
    RootPreimageMismatch,
    RootSignatureInvalid,
    V1WireVersionMissing,
    V1WireLevelMissing,
    V1WireStoredRootMissing,
    V1WireReceiptMissing,
    WireUnknownField {
        field: u16,
    },
    #[cfg(feature = "context_gate")]
    V2WireUnknownField {
        field: u16,
    },
    #[cfg(feature = "context_gate")]
    ContextAttestationUnknownField,
    #[cfg(feature = "context_gate")]
    ContextAttestationStatusMissing,
    #[cfg(feature = "context_gate")]
    ContextAttestationDigestMissing,
    SemanticReceiptVoBodyMissing,
    SemanticReceiptRootBoundMissing,
    SemanticReceiptCommitMissing,
    SemanticReceiptProcedureMissing,
    SemanticReceiptQueryMissing,
    SemanticReceiptResultsMissing,
    SemanticReceiptUnknownField {
        field: u16,
    },
    VerificationObjectBodyMapInvalid,
    VerificationObjectNodesMissing,
    VerificationObjectCandidatesMissing,
    VerificationObjectLeafIndicesMissing,
    VerificationObjectLeafIndexLengthMismatch,
    ParseLevelUnknownTag,
    ParseFieldKeyInvalid,
    ParseU16OutOfRange,
    ParseU64Invalid,
    ParseBytesInvalid,
    ParseFixed32LengthInvalid,
    #[cfg(feature = "context_gate")]
    ParseTextInvalid,
    ResultIdsArrayInvalid,
    VerificationObjectNodesArrayInvalid,
    VerificationObjectNodePairInvalid,
    VerificationObjectNodePairLengthInvalid,
    VerificationObjectNodePathInvalid,
    LeafIndexEncodeOutOfRange,
    LeafIndicesArrayInvalid,
    LeafIndexOutOfRange,
    CandidateRowsArrayInvalid,
    CandidateRowInvalid,
    CandidateRowLengthInvalid,
    CandidateDistanceInvalid,
    ZkannMapInvalid,
    ZkannLevelMissing,
    ZkannVisitedMissing,
    ZkannVisitedEmpty,
    ZkannVisitedDuplicate,
    VerificationObjectUnknownField,
    ZkannUnknownField,
    V1AuditBeaconSpotCheckFailed,
    #[cfg(feature = "context_gate")]
    V2DraftAuditBeaconSpotCheckFailed,
    #[cfg(feature = "context_gate")]
    V2StrictAuditBeaconSpotCheckFailed,
}

fn cognition_cert_failure_to_mneme(failure: CognitionCertFailure) -> MnemeError {
    match failure {
        CognitionCertFailure::UnsupportedV1Version { version } => {
            MnemeError::UnsupportedVersion { got: version }
        }
        CognitionCertFailure::V1ReceiptRootBoundMismatch
        | CognitionCertFailure::V1ReceiptSemanticCommitMismatch => MnemeError::ReceiptRootMismatch,
        CognitionCertFailure::V1WireDecode
        | CognitionCertFailure::V1AsOfSequenceMismatch
        | CognitionCertFailure::V1ZkannLevelMismatch
        | CognitionCertFailure::V1ZkannMissingForLevel => MnemeError::CertificateInvalid,
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::UnsupportedV2DraftVersion { version } => {
            MnemeError::UnsupportedVersion { got: version }
        }
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::V2DraftReceiptRootBoundMismatch
        | CognitionCertFailure::V2DraftReceiptSemanticCommitMismatch => {
            MnemeError::ReceiptRootMismatch
        }
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::V2DraftWireDecode
        | CognitionCertFailure::V2DraftWireVersionMissing
        | CognitionCertFailure::V2DraftWireLevelMissing
        | CognitionCertFailure::V2DraftWireStoredRootMissing
        | CognitionCertFailure::V2DraftWireReceiptMissing
        | CognitionCertFailure::V2DraftWireAttestationMissing
        | CognitionCertFailure::V2DraftAsOfSequenceMismatch
        | CognitionCertFailure::V2DraftZkannLevelMismatch
        | CognitionCertFailure::V2DraftZkannMissingForLevel
        | CognitionCertFailure::V2DraftStatusMismatch
        | CognitionCertFailure::V2DraftStrictAttestationPresent => MnemeError::CertificateInvalid,
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::UnsupportedV2StrictVersion { version } => {
            MnemeError::UnsupportedVersion { got: version }
        }
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::V2StrictReceiptRootBoundMismatch
        | CognitionCertFailure::V2StrictReceiptSemanticCommitMismatch => {
            MnemeError::ReceiptRootMismatch
        }
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::V2StrictWireDecode
        | CognitionCertFailure::V2StrictAsOfSequenceMismatch
        | CognitionCertFailure::V2StrictZkannLevelMismatch
        | CognitionCertFailure::V2StrictZkannMissingForLevel
        | CognitionCertFailure::V2StrictStatusMismatch
        | CognitionCertFailure::V2StrictAttestationMissing
        | CognitionCertFailure::V2StrictContextDigestMismatch => MnemeError::CertificateInvalid,
        CognitionCertFailure::RootPreimageMismatch | CognitionCertFailure::RootSignatureInvalid => {
            MnemeError::RootSigInvalid
        }
        CognitionCertFailure::V1WireVersionMissing
        | CognitionCertFailure::V1WireLevelMissing
        | CognitionCertFailure::V1WireStoredRootMissing
        | CognitionCertFailure::V1WireReceiptMissing => MnemeError::CertificateInvalid,
        CognitionCertFailure::WireUnknownField { field }
        | CognitionCertFailure::SemanticReceiptUnknownField { field } => {
            MnemeError::UnknownField { field }
        }
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::V2WireUnknownField { field } => MnemeError::UnknownField { field },
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::ContextAttestationUnknownField => {
            MnemeError::UnknownField { field: 0 }
        }
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::ContextAttestationStatusMissing
        | CognitionCertFailure::ContextAttestationDigestMissing => MnemeError::CertificateInvalid,
        CognitionCertFailure::SemanticReceiptVoBodyMissing
        | CognitionCertFailure::SemanticReceiptRootBoundMissing
        | CognitionCertFailure::SemanticReceiptCommitMissing
        | CognitionCertFailure::SemanticReceiptProcedureMissing
        | CognitionCertFailure::SemanticReceiptQueryMissing
        | CognitionCertFailure::SemanticReceiptResultsMissing
        | CognitionCertFailure::VerificationObjectBodyMapInvalid
        | CognitionCertFailure::VerificationObjectNodesMissing
        | CognitionCertFailure::VerificationObjectCandidatesMissing
        | CognitionCertFailure::VerificationObjectLeafIndicesMissing
        | CognitionCertFailure::VerificationObjectLeafIndexLengthMismatch
        | CognitionCertFailure::ParseLevelUnknownTag
        | CognitionCertFailure::ParseFieldKeyInvalid
        | CognitionCertFailure::ParseU16OutOfRange
        | CognitionCertFailure::ParseU64Invalid
        | CognitionCertFailure::ParseBytesInvalid
        | CognitionCertFailure::ParseFixed32LengthInvalid
        | CognitionCertFailure::ResultIdsArrayInvalid
        | CognitionCertFailure::VerificationObjectNodesArrayInvalid
        | CognitionCertFailure::VerificationObjectNodePairInvalid
        | CognitionCertFailure::VerificationObjectNodePairLengthInvalid
        | CognitionCertFailure::VerificationObjectNodePathInvalid
        | CognitionCertFailure::LeafIndexEncodeOutOfRange
        | CognitionCertFailure::LeafIndicesArrayInvalid
        | CognitionCertFailure::LeafIndexOutOfRange
        | CognitionCertFailure::CandidateRowsArrayInvalid
        | CognitionCertFailure::CandidateRowInvalid
        | CognitionCertFailure::CandidateRowLengthInvalid
        | CognitionCertFailure::CandidateDistanceInvalid
        | CognitionCertFailure::ZkannMapInvalid
        | CognitionCertFailure::ZkannLevelMissing
        | CognitionCertFailure::ZkannVisitedMissing
        | CognitionCertFailure::ZkannVisitedEmpty
        | CognitionCertFailure::ZkannVisitedDuplicate => MnemeError::CertificateInvalid,
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::ParseTextInvalid => MnemeError::CertificateInvalid,
        CognitionCertFailure::VerificationObjectUnknownField
        | CognitionCertFailure::ZkannUnknownField => MnemeError::UnknownField { field: 0 },
        CognitionCertFailure::V1AuditBeaconSpotCheckFailed => MnemeError::CertificateInvalid,
        #[cfg(feature = "context_gate")]
        CognitionCertFailure::V2DraftAuditBeaconSpotCheckFailed
        | CognitionCertFailure::V2StrictAuditBeaconSpotCheckFailed => {
            MnemeError::CertificateInvalid
        }
    }
}

fn cognition_cert_error(failure: CognitionCertFailure) -> MnemeError {
    cognition_cert_failure_to_mneme(failure)
}

fn unsupported_cognition_cert_v1_version_error(version: u16) -> MnemeError {
    cognition_cert_error(CognitionCertFailure::UnsupportedV1Version { version })
}

#[cfg(feature = "context_gate")]
fn unsupported_cognition_cert_v2_draft_version_error(version: u16) -> MnemeError {
    cognition_cert_error(CognitionCertFailure::UnsupportedV2DraftVersion { version })
}

#[cfg(feature = "context_gate")]
fn unsupported_cognition_cert_v2_strict_version_error(version: u16) -> MnemeError {
    cognition_cert_error(CognitionCertFailure::UnsupportedV2StrictVersion { version })
}

fn cognition_cert_wire_unknown_field_error(field: u16) -> MnemeError {
    cognition_cert_error(CognitionCertFailure::WireUnknownField { field })
}

#[cfg(feature = "context_gate")]
fn cognition_cert_v2_wire_unknown_field_error(field: u16) -> MnemeError {
    cognition_cert_error(CognitionCertFailure::V2WireUnknownField { field })
}

#[cfg(feature = "context_gate")]
fn cognition_context_attestation_unknown_field_error() -> MnemeError {
    cognition_cert_error(CognitionCertFailure::ContextAttestationUnknownField)
}

fn cognition_receipt_unknown_field_error(field: u16) -> MnemeError {
    cognition_cert_error(CognitionCertFailure::SemanticReceiptUnknownField { field })
}

fn cognition_vo_body_unknown_field_error() -> MnemeError {
    cognition_cert_error(CognitionCertFailure::VerificationObjectUnknownField)
}

fn cognition_zkann_unknown_field_error() -> MnemeError {
    cognition_cert_error(CognitionCertFailure::ZkannUnknownField)
}

#[cfg(feature = "context_gate")]
pub const CONTEXT_GATE_DRAFT_STATUS: &str = "unverified_until_phase_ii_gate";

#[cfg(feature = "context_gate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextAttestationDraft {
    /// Digest of the deterministically assembled context (placeholder until enclave binding).
    pub context_digest: [u8; 32],
    /// Optional output digest hook for Phase II step 4 (unverified in this draft).
    pub output_digest: Option<[u8; 32]>,
    /// Honest label carried on-wire so verifiers fail-closed if an attestor claims more.
    pub status: String,
    pub consumption_attestation: Option<ContextConsumptionAttestation>,
    pub output_binding: Option<OutputBinding>,
}

#[cfg(feature = "context_gate")]
impl ContextAttestationDraft {
    pub fn placeholder(context_digest: [u8; 32]) -> Self {
        Self {
            context_digest,
            output_digest: None,
            status: CONTEXT_GATE_DRAFT_STATUS.to_string(),
            consumption_attestation: None,
            output_binding: None,
        }
    }

    pub fn strict(
        attestation: ContextConsumptionAttestation,
        output_binding: Option<OutputBinding>,
    ) -> Self {
        Self {
            context_digest: attestation.context_hash,
            output_digest: output_binding.as_ref().map(|b| b.output_hash),
            status: CONTEXT_GATE_STRICT_STATUS.to_string(),
            consumption_attestation: Some(attestation),
            output_binding,
        }
    }
}

/// Assemble Certificate v1 bytes from a signed head and semantic recall receipt.
pub fn assemble_cognition_certificate_v1(
    stored_root: &StoredRoot,
    receipt: &SemanticRecallReceipt,
    as_of: Option<AsOf>,
) -> Result<Vec<u8>, MnemeError> {
    assemble_cognition_certificate_v1_with_beacon(stored_root, receipt, as_of, None)
}

/// Assemble Certificate v1 with optional drand `audit_beacon` (field 7).
pub fn assemble_cognition_certificate_v1_with_beacon(
    stored_root: &StoredRoot,
    receipt: &SemanticRecallReceipt,
    as_of: Option<AsOf>,
    audit_beacon: Option<AuditBeacon>,
) -> Result<Vec<u8>, MnemeError> {
    let wire = CognitionCertWire {
        version: COGNITION_CERT_VERSION,
        level: receipt
            .zkann
            .as_ref()
            .map(|z| z.level)
            .unwrap_or(RetrievalProofLevel::ExactDominance),
        as_of_seq: match as_of {
            Some(AsOf::RootSeq(s)) => Some(s),
            Some(AsOf::ValidTime(_)) => None,
            None => None,
        },
        stored_root: stored_root.clone(),
        receipt: receipt.clone(),
        audit_beacon,
    };
    to_bytes_canonical(&wire)
}

/// Assemble Certificate v2 draft (Phase II seam) behind `context_gate`.
///
/// Carries all v1 fields plus a placeholder context-attestation field that is **not**
/// enclave-backed. The attestation is labeled `CONTEXT_GATE_DRAFT_STATUS` so verifiers can
/// fail-closed until the Phase II gate lands.
#[cfg(feature = "context_gate")]
pub fn assemble_cognition_certificate_v2_draft(
    stored_root: &StoredRoot,
    receipt: &SemanticRecallReceipt,
    as_of: Option<AsOf>,
    attestation: ContextAttestationDraft,
) -> Result<Vec<u8>, MnemeError> {
    assemble_cognition_certificate_v2_draft_with_beacon(
        stored_root,
        receipt,
        as_of,
        attestation,
        None,
    )
}

/// Assemble Certificate v2 draft with optional drand `audit_beacon` (field 7).
#[cfg(feature = "context_gate")]
pub fn assemble_cognition_certificate_v2_draft_with_beacon(
    stored_root: &StoredRoot,
    receipt: &SemanticRecallReceipt,
    as_of: Option<AsOf>,
    attestation: ContextAttestationDraft,
    audit_beacon: Option<AuditBeacon>,
) -> Result<Vec<u8>, MnemeError> {
    let wire = CognitionCertWireV2Draft {
        version: COGNITION_CERT_VERSION_V2_DRAFT,
        level: receipt
            .zkann
            .as_ref()
            .map(|z| z.level)
            .unwrap_or(RetrievalProofLevel::ExactDominance),
        as_of_seq: match as_of {
            Some(AsOf::RootSeq(s)) => Some(s),
            Some(AsOf::ValidTime(_)) => None,
            None => None,
        },
        stored_root: stored_root.clone(),
        receipt: receipt.clone(),
        attestation,
        audit_beacon,
    };
    to_bytes_canonical(&wire)
}

/// Offline fail-closed verification (no store access beyond embedded root + receipt).
pub fn verify_cognition_certificate_v1(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<Root, MnemeError> {
    verify_cognition_certificate_v1_with_spot_check(bytes, trust, proc, None)
}

/// Certificate v1 verification with optional embedding-backed beacon spot-check context.
pub fn verify_cognition_certificate_v1_with_spot_check(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
    spot_check: Option<&SpotCheckContext<'_>>,
) -> Result<Root, MnemeError> {
    let wire: CognitionCertWire = from_bytes_strict(bytes)
        .map_err(|_| cognition_cert_error(CognitionCertFailure::V1WireDecode))?;
    if wire.version != COGNITION_CERT_VERSION {
        return Err(unsupported_cognition_cert_v1_version_error(wire.version));
    }

    let root = stored_root_to_root(&wire.stored_root)?;
    verify_root_offline(&root, trust)?;
    if wire.receipt.root_bound != root.preimage_hash {
        return Err(cognition_cert_error(
            CognitionCertFailure::V1ReceiptRootBoundMismatch,
        ));
    }
    if !wire.receipt.binds_to_semantic_commit(&root.semantic_commit) {
        return Err(cognition_cert_error(
            CognitionCertFailure::V1ReceiptSemanticCommitMismatch,
        ));
    }
    if let Some(seq) = wire.as_of_seq {
        if root.sequence != seq {
            return Err(cognition_cert_error(
                CognitionCertFailure::V1AsOfSequenceMismatch,
            ));
        }
    }
    match &wire.receipt.zkann {
        Some(z) if z.level != wire.level => {
            return Err(cognition_cert_error(
                CognitionCertFailure::V1ZkannLevelMismatch,
            ));
        }
        None if wire.level != RetrievalProofLevel::ExactDominance => {
            return Err(cognition_cert_error(
                CognitionCertFailure::V1ZkannMissingForLevel,
            ));
        }
        _ => {}
    }
    let committed_leaf_count = wire.receipt.verification_object.candidates.len();
    verify_semantic_receipt_vo_zkann(&wire.receipt, proc, committed_leaf_count)?;
    if let Some(beacon) = &wire.audit_beacon {
        verify_beacon_spot_check(
            beacon,
            &wire.receipt,
            wire.level,
            proc,
            DEFAULT_AUDIT_RATE_PPM,
            spot_check,
        )
        .map_err(|_| cognition_cert_error(CognitionCertFailure::V1AuditBeaconSpotCheckFailed))?;
    }
    Ok(root)
}

/// Offline verification for the Phase II draft certificate.
///
/// Checks the v1 fields plus the presence of an explicitly unverified context-attestation
/// marker. Fails closed if the attestation is absent or the label is elevated.
#[cfg(feature = "context_gate")]
pub fn verify_cognition_certificate_v2_draft(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<Root, MnemeError> {
    let wire: CognitionCertWireV2Draft = from_bytes_strict(bytes)
        .map_err(|_| cognition_cert_error(CognitionCertFailure::V2DraftWireDecode))?;
    if wire.version != COGNITION_CERT_VERSION_V2_DRAFT {
        return Err(unsupported_cognition_cert_v2_draft_version_error(
            wire.version,
        ));
    }

    let root = stored_root_to_root(&wire.stored_root)?;
    verify_root_offline(&root, trust)?;
    if wire.receipt.root_bound != root.preimage_hash {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2DraftReceiptRootBoundMismatch,
        ));
    }
    if !wire.receipt.binds_to_semantic_commit(&root.semantic_commit) {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2DraftReceiptSemanticCommitMismatch,
        ));
    }
    if let Some(seq) = wire.as_of_seq {
        if root.sequence != seq {
            return Err(cognition_cert_error(
                CognitionCertFailure::V2DraftAsOfSequenceMismatch,
            ));
        }
    }
    match &wire.receipt.zkann {
        Some(z) if z.level != wire.level => {
            return Err(cognition_cert_error(
                CognitionCertFailure::V2DraftZkannLevelMismatch,
            ));
        }
        None if wire.level != RetrievalProofLevel::ExactDominance => {
            return Err(cognition_cert_error(
                CognitionCertFailure::V2DraftZkannMissingForLevel,
            ));
        }
        _ => {}
    }
    if wire.attestation.status != CONTEXT_GATE_DRAFT_STATUS {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2DraftStatusMismatch,
        ));
    }
    if wire.attestation.consumption_attestation.is_some()
        || wire.attestation.output_binding.is_some()
    {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2DraftStrictAttestationPresent,
        ));
    }
    let committed_leaf_count = wire.receipt.verification_object.candidates.len();
    verify_semantic_receipt_vo_zkann(&wire.receipt, proc, committed_leaf_count)?;
    if let Some(beacon) = &wire.audit_beacon {
        verify_beacon_spot_check(
            beacon,
            &wire.receipt,
            wire.level,
            proc,
            DEFAULT_AUDIT_RATE_PPM,
            None,
        )
        .map_err(|_| {
            cognition_cert_error(CognitionCertFailure::V2DraftAuditBeaconSpotCheckFailed)
        })?;
    }
    Ok(root)
}

/// Offline verification for Phase II strict context gate (gate open + `context_gate` feature).
#[cfg(feature = "context_gate")]
pub fn verify_cognition_certificate_v2_draft_strict(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
    entries: &[Entry],
    model_output: Option<&[u8]>,
    model_identity: Option<&[u8; 32]>,
) -> Result<Root, MnemeError> {
    let wire: CognitionCertWireV2Draft = from_bytes_strict(bytes)
        .map_err(|_| cognition_cert_error(CognitionCertFailure::V2StrictWireDecode))?;
    if wire.version != COGNITION_CERT_VERSION_V2_DRAFT {
        return Err(unsupported_cognition_cert_v2_strict_version_error(
            wire.version,
        ));
    }
    let root = stored_root_to_root(&wire.stored_root)?;
    verify_root_offline(&root, trust)?;
    if wire.receipt.root_bound != root.preimage_hash {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2StrictReceiptRootBoundMismatch,
        ));
    }
    if !wire.receipt.binds_to_semantic_commit(&root.semantic_commit) {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2StrictReceiptSemanticCommitMismatch,
        ));
    }
    if let Some(seq) = wire.as_of_seq {
        if root.sequence != seq {
            return Err(cognition_cert_error(
                CognitionCertFailure::V2StrictAsOfSequenceMismatch,
            ));
        }
    }
    match &wire.receipt.zkann {
        Some(z) if z.level != wire.level => {
            return Err(cognition_cert_error(
                CognitionCertFailure::V2StrictZkannLevelMismatch,
            ));
        }
        None if wire.level != RetrievalProofLevel::ExactDominance => {
            return Err(cognition_cert_error(
                CognitionCertFailure::V2StrictZkannMissingForLevel,
            ));
        }
        _ => {}
    }
    if wire.attestation.status != CONTEXT_GATE_STRICT_STATUS {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2StrictStatusMismatch,
        ));
    }
    let att = wire
        .attestation
        .consumption_attestation
        .as_ref()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::V2StrictAttestationMissing))?;
    if att.context_hash != wire.attestation.context_digest {
        return Err(cognition_cert_error(
            CognitionCertFailure::V2StrictContextDigestMismatch,
        ));
    }
    let committed_leaf_count = wire.receipt.verification_object.candidates.len();
    verify_semantic_receipt_vo_zkann(&wire.receipt, proc, committed_leaf_count)?;
    apply_context_gate_strict(
        &wire.receipt.verification_object.result_ids,
        entries,
        att,
        wire.attestation.output_binding.as_ref(),
        model_output,
        model_identity,
    )?;
    if let Some(beacon) = &wire.audit_beacon {
        verify_beacon_spot_check(
            beacon,
            &wire.receipt,
            wire.level,
            proc,
            DEFAULT_AUDIT_RATE_PPM,
            None,
        )
        .map_err(|_| {
            cognition_cert_error(CognitionCertFailure::V2StrictAuditBeaconSpotCheckFailed)
        })?;
    }
    Ok(root)
}

fn verify_root_offline(root: &Root, trust: &TrustConfig) -> Result<(), MnemeError> {
    let bound = RootPreimage {
        version: root.version,
        dag_head_root: root.dag_head_root,
        key_index_root: root.key_index_root,
        semantic_commit: root.semantic_commit,
        hlc_max: root.hlc_max,
        prev_root: root.prev_root,
    };
    if bound.hash() != root.preimage_hash {
        return Err(cognition_cert_error(
            CognitionCertFailure::RootPreimageMismatch,
        ));
    }
    let mut verified = false;
    for pk_bytes in &trust.operator_keys {
        let pk = public_key_from_bytes(pk_bytes)?;
        if verify_signature_bytes(&pk, &root.preimage_hash, &root.signature).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(cognition_cert_error(
            CognitionCertFailure::RootSignatureInvalid,
        ));
    }
    Ok(())
}

fn stored_root_to_root(stored: &StoredRoot) -> Result<Root, MnemeError> {
    Ok(Root {
        version: stored.version,
        preimage_hash: stored.preimage_hash,
        dag_head_root: stored.dag_head_root,
        key_index_root: stored.key_index_root,
        semantic_commit: stored.semantic_commit,
        hlc_max: stored.hlc_max,
        prev_root: stored.prev_root,
        signature: stored.signature.clone(),
        sequence: stored.sequence,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CognitionCertWire {
    version: u16,
    level: RetrievalProofLevel,
    as_of_seq: Option<u64>,
    stored_root: StoredRoot,
    receipt: SemanticRecallReceipt,
    audit_beacon: Option<AuditBeacon>,
}

#[cfg(feature = "context_gate")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CognitionCertWireV2Draft {
    version: u16,
    level: RetrievalProofLevel,
    as_of_seq: Option<u64>,
    stored_root: StoredRoot,
    receipt: SemanticRecallReceipt,
    attestation: ContextAttestationDraft,
    audit_beacon: Option<AuditBeacon>,
}

impl DcborEncode for CognitionCertWire {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let receipt_bytes = encode_semantic_receipt(&self.receipt)?;
        let root_bytes = to_bytes_canonical(&self.stored_root)?;
        let mut n = 4u64;
        if self.as_of_seq.is_some() {
            n += 1;
        }
        if self.audit_beacon.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(F_CERT_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_LEVEL)?;
        enc.encode_unsigned(level_tag(self.level))?;
        if let Some(seq) = self.as_of_seq {
            enc.encode_unsigned(F_AS_OF_SEQ)?;
            enc.encode_unsigned(seq)?;
        }
        enc.encode_unsigned(F_STORED_ROOT)?;
        enc.encode_bytes(&root_bytes)?;
        enc.encode_unsigned(F_SEMANTIC_RECEIPT)?;
        enc.encode_bytes(&receipt_bytes)?;
        if let Some(beacon) = &self.audit_beacon {
            enc.encode_unsigned(F_AUDIT_BEACON)?;
            enc.encode_bytes(&crate::beacon_spot_check::encode_audit_beacon(beacon)?)?;
        }
        Ok(())
    }
}

impl DcborDecode for CognitionCertWire {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut level = None;
        let mut as_of_seq = None;
        let mut stored_root = None;
        let mut receipt = None;
        let mut audit_beacon = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_CERT_VERSION => version = Some(parse_u16(&value)?),
                F_LEVEL => level = Some(parse_level(&value)?),
                F_AS_OF_SEQ => as_of_seq = Some(parse_u64(&value)?),
                F_STORED_ROOT => {
                    let bytes = parse_bytes(&value)?;
                    stored_root = Some(from_bytes_strict(&bytes)?);
                }
                F_SEMANTIC_RECEIPT => {
                    let bytes = parse_bytes(&value)?;
                    receipt = Some(decode_semantic_receipt(&bytes)?);
                }
                F_AUDIT_BEACON => {
                    let bytes = parse_bytes(&value)?;
                    audit_beacon = Some(crate::beacon_spot_check::decode_audit_beacon(&bytes)?);
                }
                _ => {
                    let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                    return Err(cognition_cert_wire_unknown_field_error(field_id));
                }
            }
        }
        Ok(Self {
            version: version
                .ok_or_else(|| cognition_cert_error(CognitionCertFailure::V1WireVersionMissing))?,
            level: level
                .ok_or_else(|| cognition_cert_error(CognitionCertFailure::V1WireLevelMissing))?,
            as_of_seq,
            stored_root: stored_root.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::V1WireStoredRootMissing)
            })?,
            receipt: receipt
                .ok_or_else(|| cognition_cert_error(CognitionCertFailure::V1WireReceiptMissing))?,
            audit_beacon,
        })
    }
}

#[cfg(feature = "context_gate")]
impl DcborEncode for CognitionCertWireV2Draft {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let receipt_bytes = encode_semantic_receipt(&self.receipt)?;
        let root_bytes = to_bytes_canonical(&self.stored_root)?;
        let att_bytes = to_bytes_canonical(&self.attestation)?;
        let mut n = 5u64;
        if self.as_of_seq.is_some() {
            n += 1;
        }
        if self.audit_beacon.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(F_CERT_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_LEVEL)?;
        enc.encode_unsigned(level_tag(self.level))?;
        if let Some(seq) = self.as_of_seq {
            enc.encode_unsigned(F_AS_OF_SEQ)?;
            enc.encode_unsigned(seq)?;
        }
        enc.encode_unsigned(F_STORED_ROOT)?;
        enc.encode_bytes(&root_bytes)?;
        enc.encode_unsigned(F_SEMANTIC_RECEIPT)?;
        enc.encode_bytes(&receipt_bytes)?;
        enc.encode_unsigned(F_CONTEXT_ATTESTATION)?;
        enc.encode_bytes(&att_bytes)?;
        if let Some(beacon) = &self.audit_beacon {
            enc.encode_unsigned(F_AUDIT_BEACON)?;
            enc.encode_bytes(&crate::beacon_spot_check::encode_audit_beacon(beacon)?)?;
        }
        Ok(())
    }
}

#[cfg(feature = "context_gate")]
impl DcborDecode for CognitionCertWireV2Draft {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut level = None;
        let mut as_of_seq = None;
        let mut stored_root = None;
        let mut receipt = None;
        let mut attestation = None;
        let mut audit_beacon = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_CERT_VERSION => version = Some(parse_u16(&value)?),
                F_LEVEL => level = Some(parse_level(&value)?),
                F_AS_OF_SEQ => as_of_seq = Some(parse_u64(&value)?),
                F_STORED_ROOT => {
                    let bytes = parse_bytes(&value)?;
                    stored_root = Some(from_bytes_strict(&bytes)?);
                }
                F_SEMANTIC_RECEIPT => {
                    let bytes = parse_bytes(&value)?;
                    receipt = Some(decode_semantic_receipt(&bytes)?);
                }
                F_CONTEXT_ATTESTATION => {
                    let bytes = parse_bytes(&value)?;
                    attestation = Some(from_bytes_strict(&bytes)?);
                }
                F_AUDIT_BEACON => {
                    let bytes = parse_bytes(&value)?;
                    audit_beacon = Some(crate::beacon_spot_check::decode_audit_beacon(&bytes)?);
                }
                _ => {
                    let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                    return Err(cognition_cert_v2_wire_unknown_field_error(field_id));
                }
            }
        }
        Ok(Self {
            version: version.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::V2DraftWireVersionMissing)
            })?,
            level: level.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::V2DraftWireLevelMissing)
            })?,
            as_of_seq,
            stored_root: stored_root.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::V2DraftWireStoredRootMissing)
            })?,
            receipt: receipt.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::V2DraftWireReceiptMissing)
            })?,
            attestation: attestation.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::V2DraftWireAttestationMissing)
            })?,
            audit_beacon,
        })
    }
}

#[cfg(feature = "context_gate")]
impl DcborEncode for ContextAttestationDraft {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let mut n = 2u64;
        if self.output_digest.is_some() {
            n += 1;
        }
        if self.consumption_attestation.is_some() {
            n += 1;
        }
        if self.output_binding.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(1)?;
        enc.encode_text(&self.status)?;
        enc.encode_unsigned(2)?;
        enc.encode_bytes(&self.context_digest)?;
        if let Some(digest) = self.output_digest {
            enc.encode_unsigned(3)?;
            enc.encode_bytes(&digest)?;
        }
        if let Some(att) = &self.consumption_attestation {
            enc.encode_unsigned(F_CCA)?;
            enc.encode_bytes(&mneme_core::encode_context_consumption_attestation(att)?)?;
        }
        if let Some(binding) = &self.output_binding {
            enc.encode_unsigned(F_OUTPUT_BINDING)?;
            enc.encode_bytes(&mneme_core::encode_output_binding(binding)?)?;
        }
        Ok(())
    }
}

#[cfg(feature = "context_gate")]
impl DcborDecode for ContextAttestationDraft {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut status = None;
        let mut context_digest = None;
        let mut output_digest = None;
        let mut consumption_attestation = None;
        let mut output_binding = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                1 => status = Some(parse_text(&value)?),
                2 => context_digest = Some(parse_fixed32(&value)?),
                3 => output_digest = Some(parse_fixed32(&value)?),
                f if f == F_CCA => {
                    consumption_attestation = Some(decode_context_consumption_attestation(
                        &parse_bytes(&value)?,
                    )?);
                }
                f if f == F_OUTPUT_BINDING => {
                    output_binding = Some(decode_output_binding(&parse_bytes(&value)?)?);
                }
                _ => return Err(cognition_context_attestation_unknown_field_error()),
            }
        }
        Ok(Self {
            status: status.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::ContextAttestationStatusMissing)
            })?,
            context_digest: context_digest.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::ContextAttestationDigestMissing)
            })?,
            output_digest,
            consumption_attestation,
            output_binding,
        })
    }
}

fn encode_semantic_receipt(receipt: &SemanticRecallReceipt) -> Result<Vec<u8>, MnemeError> {
    let vo = &receipt.verification_object;
    let mut enc = Encoder::new();
    let map_len = if receipt.zkann.is_some() { 7 } else { 6 };
    enc.begin_map(map_len)?;
    enc.encode_unsigned(1)?;
    enc.encode_bytes(&receipt.root_bound)?;
    enc.encode_unsigned(2)?;
    enc.encode_bytes(&receipt.semantic_commit)?;
    enc.encode_unsigned(3)?;
    enc.encode_bytes(&vo.procedure_id)?;
    enc.encode_unsigned(4)?;
    enc.encode_bytes(&vo.query_commit)?;
    enc.encode_unsigned(5)?;
    encode_result_ids(&mut enc, &vo.result_ids)?;
    enc.encode_unsigned(6)?;
    encode_vo_body(&mut enc, vo)?;
    if let Some(z) = &receipt.zkann {
        enc.encode_unsigned(7)?;
        enc.begin_map(2)?;
        enc.encode_unsigned(1)?;
        enc.encode_unsigned(level_tag(z.level))?;
        enc.encode_unsigned(2)?;
        encode_object_id_list(&mut enc, &z.visited_order)?;
    }
    Ok(enc.finish())
}

fn decode_semantic_receipt(bytes: &[u8]) -> Result<SemanticRecallReceipt, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut root_bound = None;
    let mut semantic_commit = None;
    let mut procedure_id = None;
    let mut query_commit = None;
    let mut result_ids = None;
    let mut vo_body = None;
    let mut zkann = None;
    for (key, value) in map {
        let field = parse_u64_field_key(&key)?;
        match field {
            1 => root_bound = Some(parse_fixed32(&value)?),
            2 => semantic_commit = Some(parse_fixed32(&value)?),
            3 => procedure_id = Some(parse_fixed32(&value)?),
            4 => query_commit = Some(parse_fixed32(&value)?),
            5 => result_ids = Some(decode_result_ids(&value)?),
            6 => vo_body = Some(decode_vo_body(&value)?),
            7 => zkann = Some(decode_zkann(&value)?),
            _ => {
                let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                return Err(cognition_receipt_unknown_field_error(field_id));
            }
        }
    }
    let (nodes, candidates, leaf_indices) = vo_body
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::SemanticReceiptVoBodyMissing))?;
    Ok(SemanticRecallReceipt {
        root_bound: root_bound.ok_or_else(|| {
            cognition_cert_error(CognitionCertFailure::SemanticReceiptRootBoundMissing)
        })?,
        semantic_commit: semantic_commit.ok_or_else(|| {
            cognition_cert_error(CognitionCertFailure::SemanticReceiptCommitMissing)
        })?,
        verification_object: mneme_core::VerificationObject {
            nodes,
            candidates,
            leaf_indices,
            procedure_id: procedure_id.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::SemanticReceiptProcedureMissing)
            })?,
            query_commit: query_commit.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::SemanticReceiptQueryMissing)
            })?,
            result_ids: result_ids.ok_or_else(|| {
                cognition_cert_error(CognitionCertFailure::SemanticReceiptResultsMissing)
            })?,
        },
        zk_retrieval: None,
        zkann,
        provenance: None,
    })
}

fn encode_vo_body(
    enc: &mut Encoder,
    vo: &mneme_core::VerificationObject,
) -> Result<(), MnemeError> {
    enc.begin_map(3)?;
    enc.encode_unsigned(1)?;
    encode_vo_nodes(enc, &vo.nodes)?;
    enc.encode_unsigned(2)?;
    encode_candidates(enc, &vo.candidates)?;
    enc.encode_unsigned(3)?;
    encode_leaf_indices(enc, &vo.leaf_indices)?;
    Ok(())
}

fn decode_vo_body(value: &CborValue) -> Result<(VoNodes, VoCandidates, Vec<usize>), MnemeError> {
    let map = value.as_map().ok_or_else(|| {
        cognition_cert_error(CognitionCertFailure::VerificationObjectBodyMapInvalid)
    })?;
    let mut nodes = None;
    let mut candidates = None;
    let mut leaf_indices = None;
    for (k, v) in map {
        match parse_u64_field_key(k)? {
            1 => nodes = Some(decode_vo_nodes(v)?),
            2 => candidates = Some(decode_candidates(v)?),
            3 => leaf_indices = Some(decode_leaf_indices(v)?),
            _ => return Err(cognition_vo_body_unknown_field_error()),
        }
    }
    let nodes = nodes.ok_or_else(|| {
        cognition_cert_error(CognitionCertFailure::VerificationObjectNodesMissing)
    })?;
    let candidates = candidates.ok_or_else(|| {
        cognition_cert_error(CognitionCertFailure::VerificationObjectCandidatesMissing)
    })?;
    let leaf_indices = leaf_indices.ok_or_else(|| {
        cognition_cert_error(CognitionCertFailure::VerificationObjectLeafIndicesMissing)
    })?;
    if leaf_indices.len() != nodes.len() || leaf_indices.len() != candidates.len() {
        return Err(cognition_cert_error(
            CognitionCertFailure::VerificationObjectLeafIndexLengthMismatch,
        ));
    }
    Ok((nodes, candidates, leaf_indices))
}

fn level_tag(level: RetrievalProofLevel) -> u64 {
    match level {
        RetrievalProofLevel::ExactDominance => 0,
        RetrievalProofLevel::HnswAuditOnDemand => 1,
    }
}

fn parse_level(value: &CborValue) -> Result<RetrievalProofLevel, MnemeError> {
    let n = parse_u64(value)?;
    match n {
        0 => Ok(RetrievalProofLevel::ExactDominance),
        1 => Ok(RetrievalProofLevel::HnswAuditOnDemand),
        _ => Err(cognition_cert_error(
            CognitionCertFailure::ParseLevelUnknownTag,
        )),
    }
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::ParseFieldKeyInvalid))
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let n = parse_u64(value)?;
    u16::try_from(n).map_err(|_| cognition_cert_error(CognitionCertFailure::ParseU16OutOfRange))
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value
        .as_u64()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::ParseU64Invalid))
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::ParseBytesInvalid))
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(value)?;
    b.try_into()
        .map_err(|_| cognition_cert_error(CognitionCertFailure::ParseFixed32LengthInvalid))
}

#[cfg(feature = "context_gate")]
fn parse_text(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(|s| s.to_string())
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::ParseTextInvalid))
}

fn encode_result_ids(enc: &mut Encoder, ids: &[ObjectId]) -> Result<(), MnemeError> {
    enc.begin_array(ids.len() as u64)?;
    for id in ids {
        enc.encode_bytes(id.as_bytes())?;
    }
    Ok(())
}

fn decode_result_ids(value: &CborValue) -> Result<Vec<ObjectId>, MnemeError> {
    let arr = value
        .as_array()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::ResultIdsArrayInvalid))?;
    arr.iter().map(|v| parse_fixed32(v).map(ObjectId)).collect()
}

fn encode_object_id_list(enc: &mut Encoder, ids: &[ObjectId]) -> Result<(), MnemeError> {
    encode_result_ids(enc, ids)
}

fn encode_vo_nodes(
    enc: &mut Encoder,
    nodes: &[([u8; 32], Vec<[u8; 32]>)],
) -> Result<(), MnemeError> {
    enc.begin_array(nodes.len() as u64)?;
    for (commit, path) in nodes {
        enc.begin_array(2)?;
        enc.encode_bytes(commit)?;
        enc.begin_array(path.len() as u64)?;
        for sib in path {
            enc.encode_bytes(sib)?;
        }
    }
    Ok(())
}

fn decode_vo_nodes(value: &CborValue) -> Result<VoNodes, MnemeError> {
    let outer = value.as_array().ok_or_else(|| {
        cognition_cert_error(CognitionCertFailure::VerificationObjectNodesArrayInvalid)
    })?;
    let mut out = Vec::with_capacity(outer.len());
    for item in outer {
        let pair = item.as_array().ok_or_else(|| {
            cognition_cert_error(CognitionCertFailure::VerificationObjectNodePairInvalid)
        })?;
        if pair.len() != 2 {
            return Err(cognition_cert_error(
                CognitionCertFailure::VerificationObjectNodePairLengthInvalid,
            ));
        }
        let commit = parse_fixed32(&pair[0])?;
        let path_arr = pair[1].as_array().ok_or_else(|| {
            cognition_cert_error(CognitionCertFailure::VerificationObjectNodePathInvalid)
        })?;
        let path: Result<Vec<_>, _> = path_arr.iter().map(parse_fixed32).collect();
        out.push((commit, path?));
    }
    Ok(out)
}

fn encode_leaf_indices(enc: &mut Encoder, leaves: &[usize]) -> Result<(), MnemeError> {
    enc.begin_array(leaves.len() as u64)?;
    for idx in leaves {
        enc.encode_unsigned(
            u64::try_from(*idx).map_err(|_| {
                cognition_cert_error(CognitionCertFailure::LeafIndexEncodeOutOfRange)
            })?,
        )?;
    }
    Ok(())
}

fn decode_leaf_indices(value: &CborValue) -> Result<Vec<usize>, MnemeError> {
    let arr = value
        .as_array()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::LeafIndicesArrayInvalid))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let n = parse_u64(v)?;
        out.push(
            usize::try_from(n)
                .map_err(|_| cognition_cert_error(CognitionCertFailure::LeafIndexOutOfRange))?,
        );
    }
    Ok(out)
}

fn encode_candidates(
    enc: &mut Encoder,
    rows: &[(ObjectId, [u8; 32], i64)],
) -> Result<(), MnemeError> {
    enc.begin_array(rows.len() as u64)?;
    for (id, emb, dist) in rows {
        enc.begin_array(3)?;
        enc.encode_bytes(id.as_bytes())?;
        enc.encode_bytes(emb)?;
        enc.encode_signed(*dist)?;
    }
    Ok(())
}

fn decode_candidates(value: &CborValue) -> Result<VoCandidates, MnemeError> {
    let outer = value
        .as_array()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::CandidateRowsArrayInvalid))?;
    let mut out = Vec::with_capacity(outer.len());
    for item in outer {
        let row = item
            .as_array()
            .ok_or_else(|| cognition_cert_error(CognitionCertFailure::CandidateRowInvalid))?;
        if row.len() != 3 {
            return Err(cognition_cert_error(
                CognitionCertFailure::CandidateRowLengthInvalid,
            ));
        }
        let id = ObjectId(parse_fixed32(&row[0])?);
        let emb = parse_fixed32(&row[1])?;
        let dist = row[2]
            .as_i64()
            .ok_or_else(|| cognition_cert_error(CognitionCertFailure::CandidateDistanceInvalid))?;
        out.push((id, emb, dist));
    }
    Ok(out)
}

/// Fuzz entry: decode Certificate v1 wire only; must not panic (§17.4).
pub fn fuzz_cognition_cert_wire(bytes: &[u8]) {
    let _ = from_bytes_strict::<CognitionCertWire>(bytes);
}

fn decode_zkann(value: &CborValue) -> Result<crate::receipt::ZkannAttachment, MnemeError> {
    let map = value
        .as_map()
        .ok_or_else(|| cognition_cert_error(CognitionCertFailure::ZkannMapInvalid))?;
    let mut level = None;
    let mut visited = None;
    for (k, v) in map {
        match parse_u64_field_key(k)? {
            1 => level = Some(parse_level(v)?),
            2 => visited = Some(decode_result_ids(v)?),
            _ => return Err(cognition_zkann_unknown_field_error()),
        }
    }
    let level =
        level.ok_or_else(|| cognition_cert_error(CognitionCertFailure::ZkannLevelMissing))?;
    let visited_order =
        visited.ok_or_else(|| cognition_cert_error(CognitionCertFailure::ZkannVisitedMissing))?;
    if level == RetrievalProofLevel::HnswAuditOnDemand && visited_order.is_empty() {
        return Err(cognition_cert_error(
            CognitionCertFailure::ZkannVisitedEmpty,
        ));
    }
    let mut seen = HashSet::with_capacity(visited_order.len());
    for id in &visited_order {
        if !seen.insert(*id) {
            return Err(cognition_cert_error(
                CognitionCertFailure::ZkannVisitedDuplicate,
            ));
        }
    }
    Ok(crate::receipt::ZkannAttachment {
        level,
        visited_order,
    })
}

#[derive(Clone, Debug)]
pub struct ParsedCognitionCert {
    pub version: u16,
    pub level: RetrievalProofLevel,
    pub as_of_seq: Option<u64>,
    pub stored_root: StoredRoot,
    pub receipt: SemanticRecallReceipt,
    pub audit_beacon: Option<AuditBeacon>,
    #[cfg(feature = "context_gate")]
    pub attestation: Option<ContextAttestationDraft>,
}

pub fn parse_cognition_certificate(bytes: &[u8]) -> Result<ParsedCognitionCert, MnemeError> {
    #[cfg(feature = "context_gate")]
    {
        if let Ok(wire) = from_bytes_strict::<CognitionCertWireV2Draft>(bytes) {
            return Ok(ParsedCognitionCert {
                version: wire.version,
                level: wire.level,
                as_of_seq: wire.as_of_seq,
                stored_root: wire.stored_root,
                receipt: wire.receipt,
                audit_beacon: wire.audit_beacon,
                attestation: Some(wire.attestation),
            });
        }
    }
    let wire: CognitionCertWire = from_bytes_strict(bytes)?;
    Ok(ParsedCognitionCert {
        version: wire.version,
        level: wire.level,
        as_of_seq: wire.as_of_seq,
        stored_root: wire.stored_root,
        receipt: wire.receipt,
        audit_beacon: wire.audit_beacon,
        #[cfg(feature = "context_gate")]
        attestation: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::SemanticIndex;
    use mneme_core::{DistanceMetric, FixedPointEmbedding, ProcedureAlgo};
    use mneme_crypto::KeyPair;

    fn cognition_cert_production_source() -> &'static str {
        include_str!("cognition_cert.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("cognition_cert.rs should keep tests after production code")
    }

    fn cognition_cert_v1_verifier_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "pub fn verify_cognition_certificate_v1(";
        let start = production
            .find(marker)
            .expect("cognition cert v1 verifier should stay in production source");
        let end_marker = "/// Offline verification for the Phase II draft certificate.";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("v1 verifier should stay before v2 draft verifier");
        &production[start..start + relative_end]
    }

    fn cognition_cert_v2_draft_verifier_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "pub fn verify_cognition_certificate_v2_draft(";
        let start = production
            .find(marker)
            .expect("cognition cert v2 draft verifier should stay in production source");
        let end_marker = "/// Offline verification for Phase II strict context gate (gate open + `context_gate` feature).";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("v2 draft verifier should stay before strict verifier");
        &production[start..start + relative_end]
    }

    fn cognition_cert_v2_strict_verifier_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "pub fn verify_cognition_certificate_v2_draft_strict(";
        let start = production
            .find(marker)
            .expect("cognition cert v2 strict verifier should stay in production source");
        let end_marker = "fn verify_root_offline(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("v2 strict verifier should stay before root verifier");
        &production[start..start + relative_end]
    }

    fn cognition_cert_root_verifier_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "fn verify_root_offline(";
        let start = production
            .find(marker)
            .expect("cognition cert root verifier should stay in production source");
        let end_marker = "fn stored_root_to_root(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("root verifier should stay before stored-root adapter");
        &production[start..start + relative_end]
    }

    fn cognition_cert_v1_wire_decoder_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "impl DcborDecode for CognitionCertWire {";
        let start = production
            .find(marker)
            .expect("cognition cert v1 wire decoder should stay in production source");
        let end_marker =
            "#[cfg(feature = \"context_gate\")]\nimpl DcborEncode for CognitionCertWireV2Draft";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("v1 wire decoder should stay before v2 draft encoder");
        &production[start..start + relative_end]
    }

    fn cognition_cert_v2_draft_wire_decoder_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "impl DcborDecode for CognitionCertWireV2Draft {";
        let start = production
            .find(marker)
            .expect("cognition cert v2 draft wire decoder should stay in production source");
        let end_marker =
            "#[cfg(feature = \"context_gate\")]\nimpl DcborEncode for ContextAttestationDraft";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("v2 draft wire decoder should stay before context attestation encoder");
        &production[start..start + relative_end]
    }

    fn cognition_context_attestation_decoder_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "impl DcborDecode for ContextAttestationDraft {";
        let start = production
            .find(marker)
            .expect("context attestation decoder should stay in production source");
        let end_marker = "fn encode_semantic_receipt(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("context attestation decoder should stay before receipt encoder");
        &production[start..start + relative_end]
    }

    fn cognition_semantic_receipt_decoder_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "fn decode_semantic_receipt(";
        let start = production
            .find(marker)
            .expect("semantic receipt decoder should stay in production source");
        let end_marker = "fn encode_vo_body(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("semantic receipt decoder should stay before VO body encoder");
        &production[start..start + relative_end]
    }

    fn cognition_vo_body_decoder_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "fn decode_vo_body(";
        let start = production
            .find(marker)
            .expect("VO body decoder should stay in production source");
        let end_marker = "fn level_tag(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("VO body decoder should stay before proof-level tag encoder");
        &production[start..start + relative_end]
    }

    fn cognition_parse_helpers_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "fn parse_level(";
        let start = production
            .find(marker)
            .expect("cognition parse helpers should stay in production source");
        let end_marker = "fn encode_result_ids(";
        let relative_end = production[start..]
            .find(end_marker)
            .expect("parse helpers should stay before result-id encoder");
        &production[start..start + relative_end]
    }

    fn cognition_list_vector_helpers_source() -> &'static str {
        let production = cognition_cert_production_source();
        let marker = "fn decode_result_ids(";
        let start = production
            .find(marker)
            .expect("list/vector helpers should stay in production source");
        &production[start..]
    }

    #[test]
    fn cognition_cert_failures_are_classified_not_error_collapsed() {
        let production = cognition_cert_production_source();

        for forbidden in [
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
            "return Err(MnemeError::UnknownField",
            "Err(MnemeError::UnknownField",
        ] {
            assert!(
                !production.contains(forbidden),
                "cognition cert production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum CognitionCertFailure",
            "fn cognition_cert_failure_to_mneme(",
            "fn unsupported_cognition_cert_v1_version_error(",
            "fn cognition_cert_wire_unknown_field_error(",
            "fn cognition_receipt_unknown_field_error(",
            "fn cognition_vo_body_unknown_field_error(",
            "fn cognition_zkann_unknown_field_error(",
            "CognitionCertFailure::UnsupportedV1Version",
            "CognitionCertFailure::WireUnknownField",
            "CognitionCertFailure::SemanticReceiptUnknownField",
            "CognitionCertFailure::VerificationObjectUnknownField",
            "CognitionCertFailure::ZkannUnknownField",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_v1_verifier_failures_are_classified_not_error_collapsed() {
        let production = cognition_cert_production_source();
        let v1_verifier = cognition_cert_v1_verifier_source();

        for forbidden in [
            "from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid",
            "return Err(MnemeError::ReceiptRootMismatch",
            "return Err(MnemeError::CertificateInvalid",
            "Err(MnemeError::ReceiptRootMismatch",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !v1_verifier.contains(forbidden),
                "cognition cert v1 verifier still collapses directly through {forbidden}"
            );
        }

        for required in [
            "fn cognition_cert_error(",
            "CognitionCertFailure::V1WireDecode",
            "CognitionCertFailure::V1ReceiptRootBoundMismatch",
            "CognitionCertFailure::V1ReceiptSemanticCommitMismatch",
            "CognitionCertFailure::V1AsOfSequenceMismatch",
            "CognitionCertFailure::V1ZkannLevelMismatch",
            "CognitionCertFailure::V1ZkannMissingForLevel",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing v1 verifier classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_v2_draft_verifier_failures_are_classified_not_error_collapsed() {
        let production = cognition_cert_production_source();
        let v2_draft_verifier = cognition_cert_v2_draft_verifier_source();

        for forbidden in [
            "from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid",
            "return Err(MnemeError::ReceiptRootMismatch",
            "return Err(MnemeError::CertificateInvalid",
            "Err(MnemeError::ReceiptRootMismatch",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !v2_draft_verifier.contains(forbidden),
                "cognition cert v2 draft verifier still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::V2DraftWireDecode",
            "CognitionCertFailure::V2DraftReceiptRootBoundMismatch",
            "CognitionCertFailure::V2DraftReceiptSemanticCommitMismatch",
            "CognitionCertFailure::V2DraftAsOfSequenceMismatch",
            "CognitionCertFailure::V2DraftZkannLevelMismatch",
            "CognitionCertFailure::V2DraftZkannMissingForLevel",
            "CognitionCertFailure::V2DraftStatusMismatch",
            "CognitionCertFailure::V2DraftStrictAttestationPresent",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing v2 draft verifier classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_v2_strict_verifier_failures_are_classified_not_error_collapsed() {
        let production = cognition_cert_production_source();
        let v2_strict_verifier = cognition_cert_v2_strict_verifier_source();

        for forbidden in [
            "from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid",
            "return Err(MnemeError::ReceiptRootMismatch",
            "return Err(MnemeError::CertificateInvalid",
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::ReceiptRootMismatch",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !v2_strict_verifier.contains(forbidden),
                "cognition cert v2 strict verifier still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::V2StrictWireDecode",
            "CognitionCertFailure::V2StrictReceiptRootBoundMismatch",
            "CognitionCertFailure::V2StrictReceiptSemanticCommitMismatch",
            "CognitionCertFailure::V2StrictAsOfSequenceMismatch",
            "CognitionCertFailure::V2StrictZkannLevelMismatch",
            "CognitionCertFailure::V2StrictZkannMissingForLevel",
            "CognitionCertFailure::V2StrictStatusMismatch",
            "CognitionCertFailure::V2StrictAttestationMissing",
            "CognitionCertFailure::V2StrictContextDigestMismatch",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing v2 strict verifier classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_root_verifier_failures_are_classified_not_root_sig_collapsed() {
        let production = cognition_cert_production_source();
        let root_verifier = cognition_cert_root_verifier_source();

        for forbidden in [
            "return Err(MnemeError::RootSigInvalid",
            "Err(MnemeError::RootSigInvalid",
        ] {
            assert!(
                !root_verifier.contains(forbidden),
                "cognition cert root verifier still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::RootPreimageMismatch",
            "CognitionCertFailure::RootSignatureInvalid",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing root verifier classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_v1_wire_required_fields_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let v1_wire_decoder = cognition_cert_v1_wire_decoder_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !v1_wire_decoder.contains(forbidden),
                "cognition cert v1 wire decoder still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::V1WireVersionMissing",
            "CognitionCertFailure::V1WireLevelMissing",
            "CognitionCertFailure::V1WireStoredRootMissing",
            "CognitionCertFailure::V1WireReceiptMissing",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing v1 wire decoder classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_v2_draft_wire_required_fields_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let v2_draft_wire_decoder = cognition_cert_v2_draft_wire_decoder_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !v2_draft_wire_decoder.contains(forbidden),
                "cognition cert v2 draft wire decoder still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::V2DraftWireVersionMissing",
            "CognitionCertFailure::V2DraftWireLevelMissing",
            "CognitionCertFailure::V2DraftWireStoredRootMissing",
            "CognitionCertFailure::V2DraftWireReceiptMissing",
            "CognitionCertFailure::V2DraftWireAttestationMissing",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing v2 draft wire decoder classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_context_attestation_required_fields_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let context_attestation_decoder = cognition_context_attestation_decoder_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !context_attestation_decoder.contains(forbidden),
                "cognition context attestation decoder still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::ContextAttestationStatusMissing",
            "CognitionCertFailure::ContextAttestationDigestMissing",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing context attestation decoder classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_semantic_receipt_required_fields_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let semantic_receipt_decoder = cognition_semantic_receipt_decoder_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !semantic_receipt_decoder.contains(forbidden),
                "cognition semantic receipt decoder still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::SemanticReceiptVoBodyMissing",
            "CognitionCertFailure::SemanticReceiptRootBoundMissing",
            "CognitionCertFailure::SemanticReceiptCommitMissing",
            "CognitionCertFailure::SemanticReceiptProcedureMissing",
            "CognitionCertFailure::SemanticReceiptQueryMissing",
            "CognitionCertFailure::SemanticReceiptResultsMissing",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing semantic receipt decoder classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_vo_body_decoder_failures_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let vo_body_decoder = cognition_vo_body_decoder_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
        ] {
            assert!(
                !vo_body_decoder.contains(forbidden),
                "cognition VO body decoder still collapses directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::VerificationObjectBodyMapInvalid",
            "CognitionCertFailure::VerificationObjectNodesMissing",
            "CognitionCertFailure::VerificationObjectCandidatesMissing",
            "CognitionCertFailure::VerificationObjectLeafIndexLengthMismatch",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing VO body decoder classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_parse_helper_failures_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let parse_helpers = cognition_parse_helpers_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
            "map_err(|_| MnemeError::CertificateInvalid",
        ] {
            assert!(
                !parse_helpers.contains(forbidden),
                "cognition parse helpers still collapse directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::ParseLevelUnknownTag",
            "CognitionCertFailure::ParseFieldKeyInvalid",
            "CognitionCertFailure::ParseU16OutOfRange",
            "CognitionCertFailure::ParseU64Invalid",
            "CognitionCertFailure::ParseBytesInvalid",
            "CognitionCertFailure::ParseFixed32LengthInvalid",
            "CognitionCertFailure::ParseTextInvalid",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing parse helper classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_list_vector_helper_failures_are_classified_not_certificate_collapsed() {
        let production = cognition_cert_production_source();
        let list_vector_helpers = cognition_list_vector_helpers_source();

        for forbidden in [
            ".ok_or(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
            "map_err(|_| MnemeError::CertificateInvalid",
        ] {
            assert!(
                !list_vector_helpers.contains(forbidden),
                "cognition list/vector helpers still collapse directly through {forbidden}"
            );
        }

        for required in [
            "CognitionCertFailure::ResultIdsArrayInvalid",
            "CognitionCertFailure::VerificationObjectNodesArrayInvalid",
            "CognitionCertFailure::VerificationObjectNodePairInvalid",
            "CognitionCertFailure::VerificationObjectNodePairLengthInvalid",
            "CognitionCertFailure::VerificationObjectNodePathInvalid",
            "CognitionCertFailure::LeafIndexEncodeOutOfRange",
            "CognitionCertFailure::LeafIndicesArrayInvalid",
            "CognitionCertFailure::LeafIndexOutOfRange",
            "CognitionCertFailure::CandidateRowsArrayInvalid",
            "CognitionCertFailure::CandidateRowInvalid",
            "CognitionCertFailure::CandidateRowLengthInvalid",
            "CognitionCertFailure::CandidateDistanceInvalid",
            "CognitionCertFailure::ZkannMapInvalid",
            "CognitionCertFailure::ZkannLevelMissing",
            "CognitionCertFailure::ZkannVisitedMissing",
        ] {
            assert!(
                production.contains(required),
                "cognition cert production code is missing list/vector helper classifier marker {required}"
            );
        }
    }

    #[test]
    fn cognition_cert_failure_classifier_preserves_public_errors() {
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::UnsupportedV1Version {
                version: 99
            }),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            unsupported_cognition_cert_v1_version_error(99),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1WireDecode),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_error(CognitionCertFailure::V1WireDecode),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1ReceiptRootBoundMismatch),
            MnemeError::ReceiptRootMismatch
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1ReceiptSemanticCommitMismatch),
            MnemeError::ReceiptRootMismatch
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1AsOfSequenceMismatch),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1ZkannLevelMismatch),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1ZkannMissingForLevel),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::RootPreimageMismatch),
            MnemeError::RootSigInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::RootSignatureInvalid),
            MnemeError::RootSigInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1WireVersionMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1WireLevelMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1WireStoredRootMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::V1WireReceiptMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptVoBodyMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptRootBoundMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptCommitMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptProcedureMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptQueryMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptResultsMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::VerificationObjectBodyMapInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::VerificationObjectNodesMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(
                CognitionCertFailure::VerificationObjectCandidatesMissing
            ),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(
                CognitionCertFailure::VerificationObjectLeafIndexLengthMismatch
            ),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ParseLevelUnknownTag),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ParseFieldKeyInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ParseU16OutOfRange),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ParseU64Invalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ParseBytesInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ParseFixed32LengthInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ResultIdsArrayInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(
                CognitionCertFailure::VerificationObjectNodesArrayInvalid
            ),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(
                CognitionCertFailure::VerificationObjectNodePairInvalid
            ),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(
                CognitionCertFailure::VerificationObjectNodePairLengthInvalid
            ),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(
                CognitionCertFailure::VerificationObjectNodePathInvalid
            ),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::LeafIndexEncodeOutOfRange),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::LeafIndicesArrayInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::LeafIndexOutOfRange),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::CandidateRowsArrayInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::CandidateRowInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::CandidateRowLengthInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::CandidateDistanceInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ZkannMapInvalid),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ZkannLevelMissing),
            MnemeError::CertificateInvalid
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ZkannVisitedMissing),
            MnemeError::CertificateInvalid
        );
        #[cfg(feature = "context_gate")]
        {
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::ParseTextInvalid),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftWireDecode),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftWireVersionMissing),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftWireLevelMissing),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftWireStoredRootMissing),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftWireReceiptMissing),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2DraftWireAttestationMissing
                ),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2DraftReceiptRootBoundMismatch
                ),
                MnemeError::ReceiptRootMismatch
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2DraftReceiptSemanticCommitMismatch
                ),
                MnemeError::ReceiptRootMismatch
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftAsOfSequenceMismatch),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftZkannLevelMismatch),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftZkannMissingForLevel),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2DraftStatusMismatch),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2DraftStrictAttestationPresent
                ),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2StrictWireDecode),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2StrictReceiptRootBoundMismatch
                ),
                MnemeError::ReceiptRootMismatch
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2StrictReceiptSemanticCommitMismatch
                ),
                MnemeError::ReceiptRootMismatch
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2StrictAsOfSequenceMismatch),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2StrictZkannLevelMismatch),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2StrictZkannMissingForLevel),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2StrictStatusMismatch),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(CognitionCertFailure::V2StrictAttestationMissing),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::V2StrictContextDigestMismatch
                ),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::ContextAttestationStatusMissing
                ),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                cognition_cert_failure_to_mneme(
                    CognitionCertFailure::ContextAttestationDigestMissing
                ),
                MnemeError::CertificateInvalid
            );
        }
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::WireUnknownField { field: 42 }),
            MnemeError::UnknownField { field: 42 }
        );
        assert_eq!(
            cognition_cert_wire_unknown_field_error(42),
            MnemeError::UnknownField { field: 42 }
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::SemanticReceiptUnknownField {
                field: 7
            }),
            MnemeError::UnknownField { field: 7 }
        );
        assert_eq!(
            cognition_receipt_unknown_field_error(7),
            MnemeError::UnknownField { field: 7 }
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::VerificationObjectUnknownField),
            MnemeError::UnknownField { field: 0 }
        );
        assert_eq!(
            cognition_vo_body_unknown_field_error(),
            MnemeError::UnknownField { field: 0 }
        );
        assert_eq!(
            cognition_cert_failure_to_mneme(CognitionCertFailure::ZkannUnknownField),
            MnemeError::UnknownField { field: 0 }
        );
        assert_eq!(
            cognition_zkann_unknown_field_error(),
            MnemeError::UnknownField { field: 0 }
        );
    }

    #[test]
    fn cognition_cert_v1_rejects_hnsw_wire_level_without_receipt_zkann() {
        let operator = KeyPair::from_seed([0x42; 32]);
        let mut index = SemanticIndex::new();
        index
            .insert(
                ObjectId::from_bytes([0x01; 32]),
                FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap(),
            )
            .unwrap();
        let stored = StoredRoot::assemble(
            [0x10; 32],
            [0x11; 32],
            index.semantic_commit(),
            [0x12; 14],
            [0x00; 32],
            1,
            &operator,
        )
        .unwrap();
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 1,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let mut receipt = index
            .recall_receipt_zkann(
                &proc,
                &query,
                stored.preimage_hash,
                RetrievalProofLevel::HnswAuditOnDemand,
            )
            .unwrap();
        assert!(receipt.zkann.is_some());
        receipt.zkann = None;

        let wire = CognitionCertWire {
            version: COGNITION_CERT_VERSION,
            level: RetrievalProofLevel::HnswAuditOnDemand,
            as_of_seq: None,
            stored_root: stored,
            receipt,
            audit_beacon: None,
        };
        let bytes = to_bytes_canonical(&wire).unwrap();
        let trust = TrustConfig::new(operator.public_key_bytes());

        assert_eq!(
            verify_cognition_certificate_v1(&bytes, &trust, &proc),
            Err(MnemeError::CertificateInvalid)
        );
    }

    #[test]
    fn cognition_vo_body_decoder_rejects_missing_leaf_indices() {
        let value = CborValue::Map(vec![
            (
                CborValue::Unsigned(1),
                CborValue::Array(vec![CborValue::Array(vec![
                    CborValue::Bytes([0x11; 32].to_vec()),
                    CborValue::Array(Vec::new()),
                ])]),
            ),
            (
                CborValue::Unsigned(2),
                CborValue::Array(vec![CborValue::Array(vec![
                    CborValue::Bytes([0x01; 32].to_vec()),
                    CborValue::Bytes([0x22; 32].to_vec()),
                    CborValue::Unsigned(1),
                ])]),
            ),
        ]);

        assert_eq!(decode_vo_body(&value), Err(MnemeError::CertificateInvalid));
    }

    #[test]
    fn cognition_zkann_decoder_rejects_hnsw_empty_visited_order() {
        let value = CborValue::Map(vec![
            (CborValue::Unsigned(1), CborValue::Unsigned(1)),
            (CborValue::Unsigned(2), CborValue::Array(Vec::new())),
        ]);

        assert_eq!(decode_zkann(&value), Err(MnemeError::CertificateInvalid));
    }

    #[test]
    fn cognition_zkann_decoder_rejects_duplicate_visited_order_member() {
        let duplicated = CborValue::Bytes([0x01; 32].to_vec());
        let value = CborValue::Map(vec![
            (CborValue::Unsigned(1), CborValue::Unsigned(1)),
            (
                CborValue::Unsigned(2),
                CborValue::Array(vec![duplicated.clone(), duplicated]),
            ),
        ]);

        assert_eq!(decode_zkann(&value), Err(MnemeError::CertificateInvalid));
    }
}
