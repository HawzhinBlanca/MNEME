//! Federated cognition certificate wire sketch — **Phase IV P4-2 (research only)**.
//!
//! Cross-org / multi-agent certificate format draft: dCBOR wire types and
//! fail-closed decode only. No federation verifier, no CRDT merge proof, and no
//! trust-surface enforcement beyond parsing and an explicit draft status label.
//!
//! See `docs/PHASE_IV_TASK_SPEC.md` P4-2 and `docs/phase-program/INTEROP_SDK_STUB.md`.

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
    from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid)
}

/// Offline verification hook — **gate closed**: parses then rejects with
/// [`MnemeError::UnsupportedVersion`] so malformed wires still surface parse errors.
pub fn verify_federation_cognition_cert_wire(bytes: &[u8]) -> Result<(), MnemeError> {
    let wire = decode_federation_cognition_cert_wire(bytes)?;
    if wire.version != FEDERATION_COGNITION_CERT_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: wire.version });
    }
    if wire.status != FEDERATION_CERT_DRAFT_STATUS {
        return Err(MnemeError::CertificateInvalid);
    }
    if wire.cognition_cert_bytes.is_empty()
        || wire.cognition_cert_bytes.len() > FEDERATION_MAX_COGNITION_CERT_BYTES
    {
        return Err(MnemeError::CertificateInvalid);
    }
    if wire.issuer_org_id == [0u8; 32] {
        return Err(MnemeError::CertificateInvalid);
    }
    if wire.merge_head_digest == [0u8; 32] {
        return Err(MnemeError::CertificateInvalid);
    }
    if !PHASE_IV_FEDERATION_GATE_OPEN {
        return Err(MnemeError::UnsupportedVersion { got: wire.version });
    }
    Ok(())
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
                    return Err(MnemeError::UnknownField { field: field_id });
                }
            }
        }
        Ok(Self {
            version: version.ok_or(MnemeError::CertificateInvalid)?,
            status: status.ok_or(MnemeError::CertificateInvalid)?,
            issuer_org_id: issuer_org_id.ok_or(MnemeError::CertificateInvalid)?,
            cognition_cert_bytes: cognition_cert_bytes.ok_or(MnemeError::CertificateInvalid)?,
            merge_head_digest: merge_head_digest.ok_or(MnemeError::CertificateInvalid)?,
        })
    }
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or(MnemeError::CertificateInvalid)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let n = parse_u64(value)?;
    u16::try_from(n).map_err(|_| MnemeError::CertificateInvalid)
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::CertificateInvalid)
}

fn parse_text(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(str::to_owned)
        .ok_or(MnemeError::CertificateInvalid)
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or(MnemeError::CertificateInvalid)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(value)?;
    b.try_into().map_err(|_| MnemeError::CertificateInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::to_bytes_canonical;

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
