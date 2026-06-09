//! Federated cognition certificate wire sketch — **Phase IV P4-2 (research only)**.
//!
//! Cross-org / multi-agent certificate format draft: dCBOR wire types and
//! fail-closed decode only. No federation verifier, no CRDT merge proof, and no
//! trust-surface enforcement beyond parsing and an explicit draft status label.
//!
//! See `docs/PHASE_IV_TASK_SPEC.md` P4-2 and `docs/phase-program/INTEROP_SDK_STUB.md`.

use blake3::Hasher;
use mneme_core::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, MnemeError, from_bytes_strict,
};

/// Draft wire version for federated cognition certificates (not shipped).
pub const FEDERATION_COGNITION_CERT_VERSION: u16 = 1;

/// Carried on-wire so verifiers reject elevated claims until the Phase IV gate opens.
pub const FEDERATION_CERT_DRAFT_STATUS: &str = "unverified_until_phase_iv_federation_gate";

/// Phase IV federation gate. Remains `false` until cross-org verification exists.
pub const PHASE_IV_FEDERATION_GATE_OPEN: bool = false;

/// Sketch-only bound on embedded cognition cert bytes (DoS guard; not a trust claim).
pub const FEDERATION_MAX_COGNITION_CERT_BYTES: usize = 4 * 1024 * 1024;

const F_VERSION: u64 = 1;
const F_STATUS: u64 = 2;
const F_ISSUER_ORG: u64 = 3;
const F_COGNITION_CERT: u64 = 4;
const F_MERGE_HEAD: u64 = 5;

const FED_MERGE_HEAD_DOMAIN: &[u8] = b"MNEME-FED-MERGE-HEAD-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FederationCertFailure {
    PhaseGateClosed { version: u16 },
    UnsupportedWireVersion { version: u16 },
    UnknownWireField { field: u16 },
    MalformedWire,
    MergeHeadDigestMismatch,
    UnexpectedDraftStatus,
    EmbeddedCognitionCertEmpty,
    EmbeddedCognitionCertOversized,
    IssuerOrgAllZero,
    MergeHeadDigestAllZero,
    MissingVersion,
    MissingStatus,
    MissingIssuerOrg,
    MissingCognitionCertBytes,
    MissingMergeHeadDigest,
    FieldKeyType,
    U16OutOfRange,
    UnsignedValueType,
    TextValueType,
    BytesValueType,
    Fixed32Length,
}

fn federation_cert_failure_to_mneme(failure: FederationCertFailure) -> MnemeError {
    match failure {
        FederationCertFailure::PhaseGateClosed { version }
        | FederationCertFailure::UnsupportedWireVersion { version } => {
            MnemeError::UnsupportedVersion { got: version }
        }
        FederationCertFailure::UnknownWireField { field } => MnemeError::UnknownField { field },
        FederationCertFailure::MalformedWire
        | FederationCertFailure::MergeHeadDigestMismatch
        | FederationCertFailure::UnexpectedDraftStatus
        | FederationCertFailure::EmbeddedCognitionCertEmpty
        | FederationCertFailure::EmbeddedCognitionCertOversized
        | FederationCertFailure::IssuerOrgAllZero
        | FederationCertFailure::MergeHeadDigestAllZero
        | FederationCertFailure::MissingVersion
        | FederationCertFailure::MissingStatus
        | FederationCertFailure::MissingIssuerOrg
        | FederationCertFailure::MissingCognitionCertBytes
        | FederationCertFailure::MissingMergeHeadDigest
        | FederationCertFailure::FieldKeyType
        | FederationCertFailure::U16OutOfRange
        | FederationCertFailure::UnsignedValueType
        | FederationCertFailure::TextValueType
        | FederationCertFailure::BytesValueType
        | FederationCertFailure::Fixed32Length => MnemeError::CertificateInvalid,
    }
}

fn federation_cert_gate_closed_error(version: u16) -> MnemeError {
    federation_cert_failure_to_mneme(FederationCertFailure::PhaseGateClosed { version })
}

fn unsupported_federation_cert_wire_version_error(version: u16) -> MnemeError {
    federation_cert_failure_to_mneme(FederationCertFailure::UnsupportedWireVersion { version })
}

fn unknown_federation_cert_field_error(field: u16) -> MnemeError {
    federation_cert_failure_to_mneme(FederationCertFailure::UnknownWireField { field })
}

fn federation_cert_invalid_error(failure: FederationCertFailure) -> MnemeError {
    federation_cert_failure_to_mneme(failure)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FederationMergeHeadSketch {
    pub key_index_root: [u8; 32],
    pub dag_root: [u8; 32],
    pub sequence: u64,
}

pub fn digest_federation_merge_head_sketch(sketch: &FederationMergeHeadSketch) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(FED_MERGE_HEAD_DOMAIN);
    h.update(&sketch.key_index_root);
    h.update(&sketch.dag_root);
    h.update(&sketch.sequence.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Federated cognition certificate wire (decode-only sketch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationCognitionCertWire {
    pub version: u16,
    pub status: String,
    /// Issuing organization identifier (opaque 32-byte label).
    pub issuer_org_id: [u8; 32],
    /// Embedded local Cognition Certificate v1 bytes (opaque at this layer).
    pub cognition_cert_bytes: Vec<u8>,
    /// Digest binding to the verified CRDT merge head (sketch; not verified here).
    pub merge_head_digest: [u8; 32],
}

/// Fail-closed decode of federated certificate bytes (malformed → `CertificateInvalid`).
pub fn decode_federation_cognition_cert_wire(
    bytes: &[u8],
) -> Result<FederationCognitionCertWire, MnemeError> {
    from_bytes_strict(bytes)
        .map_err(|_| federation_cert_invalid_error(FederationCertFailure::MalformedWire))
}

pub fn verify_federation_cognition_cert_wire(bytes: &[u8]) -> Result<(), MnemeError> {
    verify_federation_cognition_cert_wire_with_merge_head(bytes, None)
}

pub fn verify_federation_cognition_cert_wire_with_merge_head(
    bytes: &[u8],
    expected_merge_head: Option<&FederationMergeHeadSketch>,
) -> Result<(), MnemeError> {
    let wire = verify_federation_cognition_cert_structural(bytes)?;
    if let Some(sketch) = expected_merge_head {
        if wire.merge_head_digest != digest_federation_merge_head_sketch(sketch) {
            return Err(federation_cert_invalid_error(
                FederationCertFailure::MergeHeadDigestMismatch,
            ));
        }
    }
    if !PHASE_IV_FEDERATION_GATE_OPEN {
        return Err(federation_cert_gate_closed_error(wire.version));
    }
    Ok(())
}

fn verify_federation_cognition_cert_structural(
    bytes: &[u8],
) -> Result<FederationCognitionCertWire, MnemeError> {
    let wire = decode_federation_cognition_cert_wire(bytes)?;
    if wire.version != FEDERATION_COGNITION_CERT_VERSION {
        return Err(unsupported_federation_cert_wire_version_error(wire.version));
    }
    if wire.status != FEDERATION_CERT_DRAFT_STATUS {
        return Err(federation_cert_invalid_error(
            FederationCertFailure::UnexpectedDraftStatus,
        ));
    }
    if wire.cognition_cert_bytes.is_empty() {
        return Err(federation_cert_invalid_error(
            FederationCertFailure::EmbeddedCognitionCertEmpty,
        ));
    }
    if wire.cognition_cert_bytes.len() > FEDERATION_MAX_COGNITION_CERT_BYTES {
        return Err(federation_cert_invalid_error(
            FederationCertFailure::EmbeddedCognitionCertOversized,
        ));
    }
    if wire.issuer_org_id == [0u8; 32] {
        return Err(federation_cert_invalid_error(
            FederationCertFailure::IssuerOrgAllZero,
        ));
    }
    if wire.merge_head_digest == [0u8; 32] {
        return Err(federation_cert_invalid_error(
            FederationCertFailure::MergeHeadDigestAllZero,
        ));
    }
    Ok(wire)
}

/// Fuzz entry: decode federated certificate wire only; must not panic.
pub fn fuzz_federation_cert_wire(bytes: &[u8]) {
    let _ = decode_federation_cognition_cert_wire(bytes);
}

/// Fuzz entry: decode + offline verify sketch; must not panic (gate stays closed).
pub fn fuzz_federation_cert_verify(bytes: &[u8]) {
    let _ = verify_federation_cognition_cert_wire(bytes);
}

impl DcborEncode for FederationCognitionCertWire {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        enc.begin_map(5)?;
        enc.encode_unsigned(F_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_STATUS)?;
        enc.encode_text(&self.status)?;
        enc.encode_unsigned(F_ISSUER_ORG)?;
        enc.encode_bytes(&self.issuer_org_id)?;
        enc.encode_unsigned(F_COGNITION_CERT)?;
        enc.encode_bytes(&self.cognition_cert_bytes)?;
        enc.encode_unsigned(F_MERGE_HEAD)?;
        enc.encode_bytes(&self.merge_head_digest)?;
        Ok(())
    }
}

impl DcborDecode for FederationCognitionCertWire {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut status = None;
        let mut issuer_org_id = None;
        let mut cognition_cert_bytes = None;
        let mut merge_head_digest = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_VERSION => version = Some(parse_u16(&value)?),
                F_STATUS => status = Some(parse_text(&value)?),
                F_ISSUER_ORG => issuer_org_id = Some(parse_fixed32(&value)?),
                F_COGNITION_CERT => cognition_cert_bytes = Some(parse_bytes(&value)?),
                F_MERGE_HEAD => merge_head_digest = Some(parse_fixed32(&value)?),
                _ => {
                    let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                    return Err(unknown_federation_cert_field_error(field_id));
                }
            }
        }
        Ok(Self {
            version: version.ok_or_else(|| {
                federation_cert_invalid_error(FederationCertFailure::MissingVersion)
            })?,
            status: status.ok_or_else(|| {
                federation_cert_invalid_error(FederationCertFailure::MissingStatus)
            })?,
            issuer_org_id: issuer_org_id.ok_or_else(|| {
                federation_cert_invalid_error(FederationCertFailure::MissingIssuerOrg)
            })?,
            cognition_cert_bytes: cognition_cert_bytes.ok_or_else(|| {
                federation_cert_invalid_error(FederationCertFailure::MissingCognitionCertBytes)
            })?,
            merge_head_digest: merge_head_digest.ok_or_else(|| {
                federation_cert_invalid_error(FederationCertFailure::MissingMergeHeadDigest)
            })?,
        })
    }
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64()
        .ok_or_else(|| federation_cert_invalid_error(FederationCertFailure::FieldKeyType))
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let n = parse_u64(value)?;
    u16::try_from(n)
        .map_err(|_| federation_cert_invalid_error(FederationCertFailure::U16OutOfRange))
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value
        .as_u64()
        .ok_or_else(|| federation_cert_invalid_error(FederationCertFailure::UnsignedValueType))
}

fn parse_text(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(str::to_owned)
        .ok_or_else(|| federation_cert_invalid_error(FederationCertFailure::TextValueType))
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(|| federation_cert_invalid_error(FederationCertFailure::BytesValueType))
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(value)?;
    b.try_into()
        .map_err(|_| federation_cert_invalid_error(FederationCertFailure::Fixed32Length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::to_bytes_canonical;

    fn federation_cert_production_source() -> &'static str {
        include_str!("federation_cert.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("federation_cert.rs should keep tests after production code")
    }

    #[test]
    fn federation_cert_failures_are_classified_not_error_collapsed() {
        let production = federation_cert_production_source();

        for forbidden in [
            "return Err(MnemeError::CertificateInvalid",
            "Err(MnemeError::CertificateInvalid",
            ".ok_or(MnemeError::CertificateInvalid",
            "map_err(|_| MnemeError::CertificateInvalid",
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
            "return Err(MnemeError::UnknownField",
            "Err(MnemeError::UnknownField",
        ] {
            assert!(
                !production.contains(forbidden),
                "federation cert production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum FederationCertFailure",
            "fn federation_cert_failure_to_mneme(",
            "fn federation_cert_gate_closed_error(",
            "fn unsupported_federation_cert_wire_version_error(",
            "fn unknown_federation_cert_field_error(",
            "fn federation_cert_invalid_error(",
            "FederationCertFailure::PhaseGateClosed",
            "FederationCertFailure::UnsupportedWireVersion",
            "FederationCertFailure::UnknownWireField",
            "FederationCertFailure::MalformedWire",
            "FederationCertFailure::MergeHeadDigestMismatch",
            "FederationCertFailure::UnexpectedDraftStatus",
            "FederationCertFailure::EmbeddedCognitionCertEmpty",
            "FederationCertFailure::EmbeddedCognitionCertOversized",
            "FederationCertFailure::IssuerOrgAllZero",
            "FederationCertFailure::MergeHeadDigestAllZero",
            "FederationCertFailure::MissingVersion",
            "FederationCertFailure::MissingStatus",
            "FederationCertFailure::MissingIssuerOrg",
            "FederationCertFailure::MissingCognitionCertBytes",
            "FederationCertFailure::MissingMergeHeadDigest",
            "FederationCertFailure::FieldKeyType",
            "FederationCertFailure::U16OutOfRange",
            "FederationCertFailure::UnsignedValueType",
            "FederationCertFailure::TextValueType",
            "FederationCertFailure::BytesValueType",
            "FederationCertFailure::Fixed32Length",
        ] {
            assert!(
                production.contains(required),
                "federation cert production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn federation_cert_failure_classifier_preserves_public_errors() {
        assert_eq!(
            federation_cert_failure_to_mneme(FederationCertFailure::PhaseGateClosed {
                version: FEDERATION_COGNITION_CERT_VERSION
            }),
            MnemeError::UnsupportedVersion {
                got: FEDERATION_COGNITION_CERT_VERSION
            }
        );
        assert_eq!(
            federation_cert_gate_closed_error(FEDERATION_COGNITION_CERT_VERSION),
            MnemeError::UnsupportedVersion {
                got: FEDERATION_COGNITION_CERT_VERSION
            }
        );
        assert_eq!(
            federation_cert_failure_to_mneme(FederationCertFailure::UnsupportedWireVersion {
                version: 99
            }),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            unsupported_federation_cert_wire_version_error(99),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            federation_cert_failure_to_mneme(FederationCertFailure::UnknownWireField { field: 42 }),
            MnemeError::UnknownField { field: 42 }
        );
        assert_eq!(
            unknown_federation_cert_field_error(42),
            MnemeError::UnknownField { field: 42 }
        );

        for failure in [
            FederationCertFailure::MalformedWire,
            FederationCertFailure::MergeHeadDigestMismatch,
            FederationCertFailure::UnexpectedDraftStatus,
            FederationCertFailure::EmbeddedCognitionCertEmpty,
            FederationCertFailure::EmbeddedCognitionCertOversized,
            FederationCertFailure::IssuerOrgAllZero,
            FederationCertFailure::MergeHeadDigestAllZero,
            FederationCertFailure::MissingVersion,
            FederationCertFailure::MissingStatus,
            FederationCertFailure::MissingIssuerOrg,
            FederationCertFailure::MissingCognitionCertBytes,
            FederationCertFailure::MissingMergeHeadDigest,
            FederationCertFailure::FieldKeyType,
            FederationCertFailure::U16OutOfRange,
            FederationCertFailure::UnsignedValueType,
            FederationCertFailure::TextValueType,
            FederationCertFailure::BytesValueType,
            FederationCertFailure::Fixed32Length,
        ] {
            assert_eq!(
                federation_cert_failure_to_mneme(failure),
                MnemeError::CertificateInvalid
            );
            assert_eq!(
                federation_cert_invalid_error(failure),
                MnemeError::CertificateInvalid
            );
        }
    }

    #[test]
    fn roundtrip_wire_decode() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0xab; 32],
            cognition_cert_bytes: vec![0x01, 0x02, 0x03],
            merge_head_digest: [0xcd; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        let decoded = decode_federation_cognition_cert_wire(&bytes).expect("decode");
        assert_eq!(decoded, wire);
    }

    #[test]
    fn verify_fails_closed_while_gate_closed() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0x99],
            merge_head_digest: [0x02; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::UnsupportedVersion {
                got: FEDERATION_COGNITION_CERT_VERSION
            })
        );
    }

    #[test]
    fn wrong_status_rejects() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: "verified".to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0x99],
            merge_head_digest: [0x02; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::CertificateInvalid)
        );
    }

    #[test]
    fn unknown_field_rejects() {
        let mut enc = Encoder::new();
        enc.begin_map(1).unwrap();
        enc.encode_unsigned(99).unwrap();
        enc.encode_unsigned(1).unwrap();
        let bytes = enc.finish();
        assert!(decode_federation_cognition_cert_wire(&bytes).is_err());
    }

    fn sample_wire_bytes() -> Vec<u8> {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0x99, 0xAA, 0xBB],
            merge_head_digest: [0x02; 32],
        };
        to_bytes_canonical(&wire).expect("encode")
    }

    /// Replay: resubmitting identical wire must stay fail-closed (no accept on replay).
    #[test]
    fn forgery_replayed_wire_stays_fail_closed() {
        let bytes = sample_wire_bytes();
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::UnsupportedVersion {
                got: FEDERATION_COGNITION_CERT_VERSION
            })
        );
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::UnsupportedVersion {
                got: FEDERATION_COGNITION_CERT_VERSION
            })
        );
    }

    /// Bad merge head: tampered digest decodes but verify rejects (gate closed).
    #[test]
    fn forgery_bad_merge_head_rejects() {
        let mut bytes = sample_wire_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        if decode_federation_cognition_cert_wire(&bytes).is_ok() {
            assert_eq!(
                verify_federation_cognition_cert_wire(&bytes),
                Err(MnemeError::UnsupportedVersion {
                    got: FEDERATION_COGNITION_CERT_VERSION
                })
            );
        } else {
            assert_eq!(
                verify_federation_cognition_cert_wire(&bytes),
                Err(MnemeError::CertificateInvalid)
            );
        }
    }

    /// Wire tamper: truncate federated cert bytes.
    #[test]
    fn forgery_truncated_wire_rejects() {
        let bytes = sample_wire_bytes();
        for trim in 1..=12 {
            let tampered = &bytes[..bytes.len().saturating_sub(trim)];
            assert!(verify_federation_cognition_cert_wire(tampered).is_err());
        }
    }

    /// Oversized embedded cognition cert (DoS sketch guard).
    #[test]
    fn forgery_oversized_cognition_cert_embed_rejects() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0u8; FEDERATION_MAX_COGNITION_CERT_BYTES + 1],
            merge_head_digest: [0x02; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::CertificateInvalid)
        );
    }

    /// Wire tamper: flip cognition_cert payload byte after decode.
    #[test]
    fn forgery_tampered_cognition_cert_payload_rejects() {
        let mut bytes = sample_wire_bytes();
        if let Some(pos) = bytes.iter().position(|&b| b == 0x99) {
            bytes[pos] ^= 0x01;
        }
        assert!(verify_federation_cognition_cert_wire(&bytes).is_err());
    }

    #[test]
    fn wrong_version_rejects_before_gate() {
        let wire = FederationCognitionCertWire {
            version: 99,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0x99],
            merge_head_digest: [0x02; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::UnsupportedVersion { got: 99 })
        );
    }

    #[test]
    fn zero_issuer_org_rejects() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0u8; 32],
            cognition_cert_bytes: vec![0x99],
            merge_head_digest: [0x02; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::CertificateInvalid)
        );
    }

    #[test]
    fn zero_merge_head_rejects() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0x99],
            merge_head_digest: [0u8; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::CertificateInvalid)
        );
    }

    #[test]
    fn malformed_bytes_reject_without_panic() {
        for garbage in [b"".as_slice(), b"\x00", b"\xff\xd9\x00", b"not-cbor"] {
            assert!(verify_federation_cognition_cert_wire(garbage).is_err());
        }
    }

    fn sample_merge_head() -> FederationMergeHeadSketch {
        FederationMergeHeadSketch {
            key_index_root: [0x11; 32],
            dag_root: [0x22; 32],
            sequence: 42,
        }
    }
    fn sample_wire_with_merge_head(sketch: &FederationMergeHeadSketch) -> Vec<u8> {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![0x99, 0xAA, 0xBB],
            merge_head_digest: digest_federation_merge_head_sketch(sketch),
        };
        to_bytes_canonical(&wire).expect("encode")
    }
    #[test]
    fn forgery_merge_head_mismatch_rejects() {
        let sketch = sample_merge_head();
        let bytes = sample_wire_with_merge_head(&sketch);
        let stale = FederationMergeHeadSketch {
            sequence: sketch.sequence + 1,
            ..sketch
        };
        assert_eq!(
            verify_federation_cognition_cert_wire_with_merge_head(&bytes, Some(&stale)),
            Err(MnemeError::CertificateInvalid)
        );
    }
    #[test]
    fn merge_head_binding_ok_still_gate_closed() {
        let sketch = sample_merge_head();
        let bytes = sample_wire_with_merge_head(&sketch);
        assert_eq!(
            verify_federation_cognition_cert_wire_with_merge_head(&bytes, Some(&sketch)),
            Err(MnemeError::UnsupportedVersion {
                got: FEDERATION_COGNITION_CERT_VERSION
            })
        );
    }
    /// Wire tamper: empty cognition cert rejected before gate check.
    #[test]
    fn forgery_empty_cognition_cert_rejects() {
        let wire = FederationCognitionCertWire {
            version: FEDERATION_COGNITION_CERT_VERSION,
            status: FEDERATION_CERT_DRAFT_STATUS.to_string(),
            issuer_org_id: [0x01; 32],
            cognition_cert_bytes: vec![],
            merge_head_digest: [0x02; 32],
        };
        let bytes = to_bytes_canonical(&wire).expect("encode");
        assert_eq!(
            verify_federation_cognition_cert_wire(&bytes),
            Err(MnemeError::CertificateInvalid)
        );
    }
}
