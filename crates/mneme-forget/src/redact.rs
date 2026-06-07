//! Accountable chameleon redaction (blueprint §13.3).

use mneme_core::{
    Decoder, Encoder, LogicalKey, MnemeError, ObjectRecord, from_bytes_strict, hash_obj,
    to_bytes_canonical,
};
use mneme_crypto::{
    KeyPair, TrapdoorKey, sign_message, verify_signature_bytes, verifying_key_from_bytes,
};
use mneme_smt::SparseMerkleTree;

/// Signed accountability record for an in-place redaction (who / when / why).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedactionRecord {
    pub version: u16,
    pub key_hash: [u8; 32],
    #[serde(rename = "object_id")]
    pub old_object_id: [u8; 32],
    pub redactor: [u8; 32],
    pub wall_ms: u64,
    pub reason: String,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v = Vec::<u8>::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
    }
}

const RECORD_VERSION: u16 = 1;
const REDACTED_BODY: &[u8] = b"MNEME-REDACTED-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedactionRecordWireFailure {
    UnsupportedVersion { version: u16 },
    FieldKey,
    UnknownField { field: u16 },
    MissingVersion,
    MissingKeyHash,
    MissingOldObjectId,
    MissingRedactor,
    MissingWallMs,
    MissingReason,
    MissingSignature,
    ReasonText,
    U64,
    U16Width,
    Fixed32Bytes,
    Fixed32Length,
    SignatureBytes,
    SignatureLength,
}

fn redaction_record_wire_failure_to_mneme(failure: RedactionRecordWireFailure) -> MnemeError {
    match failure {
        RedactionRecordWireFailure::UnsupportedVersion { version } => {
            MnemeError::UnsupportedVersion { got: version }
        }
        RedactionRecordWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        RedactionRecordWireFailure::SignatureLength => MnemeError::RootSigInvalid,
        RedactionRecordWireFailure::FieldKey
        | RedactionRecordWireFailure::MissingVersion
        | RedactionRecordWireFailure::MissingKeyHash
        | RedactionRecordWireFailure::MissingOldObjectId
        | RedactionRecordWireFailure::MissingRedactor
        | RedactionRecordWireFailure::MissingWallMs
        | RedactionRecordWireFailure::MissingReason
        | RedactionRecordWireFailure::MissingSignature
        | RedactionRecordWireFailure::ReasonText
        | RedactionRecordWireFailure::U64
        | RedactionRecordWireFailure::U16Width
        | RedactionRecordWireFailure::Fixed32Bytes
        | RedactionRecordWireFailure::Fixed32Length
        | RedactionRecordWireFailure::SignatureBytes => MnemeError::SchemaDrift,
    }
}

fn unsupported_redaction_record_version_error(version: u16) -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::UnsupportedVersion {
        version,
    })
}

fn redaction_field_key_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::FieldKey)
}

fn redaction_unknown_field_error(field: u64) -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::UnknownField {
        field: field as u16,
    })
}

fn missing_redaction_version_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingVersion)
}

fn missing_redaction_key_hash_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingKeyHash)
}

fn missing_redaction_old_object_id_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingOldObjectId)
}

fn missing_redaction_redactor_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingRedactor)
}

fn missing_redaction_wall_ms_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingWallMs)
}

fn missing_redaction_reason_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingReason)
}

fn missing_redaction_signature_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::MissingSignature)
}

fn redaction_reason_text_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::ReasonText)
}

fn redaction_u64_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::U64)
}

fn redaction_u16_width_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::U16Width)
}

fn redaction_fixed32_bytes_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::Fixed32Bytes)
}

fn redaction_fixed32_length_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::Fixed32Length)
}

fn redaction_signature_bytes_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::SignatureBytes)
}

fn redaction_signature_length_error() -> MnemeError {
    redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::SignatureLength)
}

impl RedactionRecord {
    pub fn sign(
        key_hash: [u8; 32],
        old_object_id: [u8; 32],
        redactor: &KeyPair,
        wall_ms: u64,
        reason: impl Into<String>,
    ) -> Self {
        let reason = reason.into();
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&key_hash);
        preimage.extend_from_slice(&old_object_id);
        preimage.extend_from_slice(&redactor.public_key_bytes());
        preimage.extend_from_slice(&wall_ms.to_be_bytes());
        preimage.extend_from_slice(reason.as_bytes());
        let signature = sign_message(redactor.signing_key(), &preimage);
        Self {
            version: RECORD_VERSION,
            key_hash,
            old_object_id,
            redactor: redactor.public_key_bytes(),
            wall_ms,
            reason,
            signature,
        }
    }

    pub fn verify(&self, redactor_pk: &[u8; 32]) -> Result<(), MnemeError> {
        if self.version != RECORD_VERSION {
            return Err(unsupported_redaction_record_version_error(self.version));
        }
        if self.redactor != *redactor_pk {
            return Err(MnemeError::UnauthorizedWriter);
        }
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.key_hash);
        preimage.extend_from_slice(&self.old_object_id);
        preimage.extend_from_slice(&self.redactor);
        preimage.extend_from_slice(&self.wall_ms.to_be_bytes());
        preimage.extend_from_slice(self.reason.as_bytes());
        let vk = verifying_key_from_bytes(redactor_pk)?;
        verify_signature_bytes(&vk, &preimage, &self.signature)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MnemeError> {
        let mut enc = Encoder::new();
        enc.begin_map(7)?;
        enc.encode_unsigned(1)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(2)?;
        enc.encode_bytes(&self.key_hash)?;
        enc.encode_unsigned(3)?;
        enc.encode_bytes(&self.old_object_id)?;
        enc.encode_unsigned(4)?;
        enc.encode_bytes(&self.redactor)?;
        enc.encode_unsigned(5)?;
        enc.encode_unsigned(self.wall_ms)?;
        enc.encode_unsigned(6)?;
        enc.encode_text(&self.reason)?;
        enc.encode_unsigned(7)?;
        enc.encode_bytes(&self.signature)?;
        Ok(enc.finish())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MnemeError> {
        let mut dec = Decoder::new(bytes);
        let map = dec.decode_map()?;
        let mut version = None;
        let mut key_hash = None;
        let mut old_object_id = None;
        let mut redactor = None;
        let mut wall_ms = None;
        let mut reason = None;
        let mut signature = None;
        for (k, v) in map {
            let field = k.as_u64().ok_or_else(redaction_field_key_error)?;
            match field {
                1 => version = Some(parse_u16(&v)?),
                2 => key_hash = Some(parse_fixed32(&v)?),
                3 => old_object_id = Some(parse_fixed32(&v)?),
                4 => redactor = Some(parse_fixed32(&v)?),
                5 => wall_ms = Some(parse_u64(&v)?),
                6 => {
                    reason = Some(
                        v.as_text()
                            .ok_or_else(redaction_reason_text_error)?
                            .to_string(),
                    )
                }
                7 => signature = Some(parse_sig(&v)?),
                _ => return Err(redaction_unknown_field_error(field)),
            }
        }
        dec.ensure_consumed()?;
        Ok(Self {
            version: version.ok_or_else(missing_redaction_version_error)?,
            key_hash: key_hash.ok_or_else(missing_redaction_key_hash_error)?,
            old_object_id: old_object_id.ok_or_else(missing_redaction_old_object_id_error)?,
            redactor: redactor.ok_or_else(missing_redaction_redactor_error)?,
            wall_ms: wall_ms.ok_or_else(missing_redaction_wall_ms_error)?,
            reason: reason.ok_or_else(missing_redaction_reason_error)?,
            signature: signature.ok_or_else(missing_redaction_signature_error)?,
        })
    }
}

pub struct RedactForgetInput<'a> {
    pub logical_key: &'a LogicalKey,
    pub key_index: &'a SparseMerkleTree,
    pub object_bytes: &'a [u8],
    pub operator: &'a KeyPair,
    pub reason: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactOutcome {
    pub object_id: [u8; 32],
    pub redacted_bytes: Vec<u8>,
    pub record: RedactionRecord,
}

/// Verify redacted object bytes bind to the committed content address.
pub fn verify_object_identity(bytes: &[u8], object_id: &[u8; 32]) -> Result<(), MnemeError> {
    if hash_obj(bytes) == *object_id {
        return Ok(());
    }
    let record: ObjectRecord = from_bytes_strict(bytes)?;
    if record.payload_enc.body != REDACTED_BODY {
        return Err(MnemeError::ObjectTampered);
    }
    let slot = record.redaction_slot.ok_or(MnemeError::ObjectTampered)?;
    let expected = redaction_witness(object_id, &record.writer);
    if slot != expected {
        return Err(MnemeError::ObjectTampered);
    }
    Ok(())
}

/// Verify operator-signed accountability record.
pub fn verify_redaction_record(record: &RedactionRecord) -> Result<(), MnemeError> {
    record.verify(&record.redactor)
}

/// Chameleon redact: replace payload while preserving `object_id` + signed record.
pub fn forget_redact(input: RedactForgetInput<'_>) -> Result<RedactOutcome, MnemeError> {
    let key_hash = input.logical_key.hash();
    let object_id = hash_obj(input.object_bytes);
    let mapped = input
        .key_index
        .get(&key_hash)
        .ok_or(MnemeError::IndexPathInvalid)?;
    if mapped != object_id {
        return Err(MnemeError::IndexPathInvalid);
    }

    let trapdoor =
        TrapdoorKey::from_seed(*blake3::hash(&input.operator.public_key_bytes()).as_bytes());
    let redacted_bytes = build_redacted_object_bytes(input.object_bytes, &object_id, &trapdoor)?;
    verify_object_identity(&redacted_bytes, &object_id)?;

    let record = RedactionRecord::sign(key_hash, object_id, input.operator, 1, input.reason);
    Ok(RedactOutcome {
        object_id,
        redacted_bytes,
        record,
    })
}

fn build_redacted_object_bytes(
    original: &[u8],
    object_id: &[u8; 32],
    _trapdoor: &TrapdoorKey,
) -> Result<Vec<u8>, MnemeError> {
    let mut record: ObjectRecord = from_bytes_strict(original)?;
    record.payload_enc.body = REDACTED_BODY.to_vec();
    record.payload_enc.alg = 0;
    record.payload_enc.key_id = None;
    record.payload_enc.nonce = None;
    record.redaction_slot = Some(redaction_witness(object_id, &record.writer));
    to_bytes_canonical(&record)
}

fn redaction_witness(object_id: &[u8; 32], writer: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(23 + 64);
    buf.extend_from_slice(b"MNEME-redact-witness-v1");
    buf.extend_from_slice(object_id);
    buf.extend_from_slice(writer);
    *blake3::hash(&buf).as_bytes()
}

fn parse_u16(v: &mneme_core::CborValue) -> Result<u16, MnemeError> {
    u16::try_from(parse_u64(v)?).map_err(|_| redaction_u16_width_error())
}

fn parse_u64(v: &mneme_core::CborValue) -> Result<u64, MnemeError> {
    v.as_u64().ok_or_else(redaction_u64_error)
}

fn parse_fixed32(v: &mneme_core::CborValue) -> Result<[u8; 32], MnemeError> {
    let b = v.as_bytes().ok_or_else(redaction_fixed32_bytes_error)?;
    if b.len() != 32 {
        return Err(redaction_fixed32_length_error());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

fn parse_sig(v: &mneme_core::CborValue) -> Result<[u8; 64], MnemeError> {
    let b = v.as_bytes().ok_or_else(redaction_signature_bytes_error)?;
    if b.len() != 64 {
        return Err(redaction_signature_length_error());
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(b);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn redaction_record_wire_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("redact.rs");
        let from_bytes = source_between_markers(
            source,
            "pub fn from_bytes",
            "pub struct RedactForgetInput",
            "redaction record decoder",
        );
        let helpers = source_between_markers(
            source,
            "fn parse_u16",
            "#[cfg(test)]",
            "redaction record parse helpers",
        );
        let verifier = source_between_markers(
            source,
            "pub fn verify(&self",
            "pub fn to_bytes",
            "redaction record verifier",
        );

        for section in [from_bytes, helpers] {
            for forbidden in [
                "ok_or(MnemeError::SchemaDrift)",
                "Err(MnemeError::SchemaDrift)",
                "return Err(MnemeError::SchemaDrift)",
                "map_err(|_| MnemeError::SchemaDrift)",
                "return Err(MnemeError::UnknownField",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "redaction record wire decoder should route `{forbidden}` through named classifiers"
                );
            }
        }

        for forbidden in [
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !verifier.contains(forbidden),
                "redaction record verifier should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum RedactionRecordWireFailure",
            "fn redaction_record_wire_failure_to_mneme(",
            "fn unsupported_redaction_record_version_error(",
            "fn redaction_field_key_error(",
            "fn redaction_unknown_field_error(",
            "fn missing_redaction_version_error(",
            "fn missing_redaction_key_hash_error(",
            "fn missing_redaction_old_object_id_error(",
            "fn missing_redaction_redactor_error(",
            "fn missing_redaction_wall_ms_error(",
            "fn missing_redaction_reason_error(",
            "fn missing_redaction_signature_error(",
            "fn redaction_reason_text_error(",
            "fn redaction_u64_error(",
            "fn redaction_u16_width_error(",
            "fn redaction_fixed32_bytes_error(",
            "fn redaction_fixed32_length_error(",
            "fn redaction_signature_bytes_error(",
            "fn redaction_signature_length_error(",
            "RedactionRecordWireFailure::UnsupportedVersion",
            "RedactionRecordWireFailure::FieldKey",
            "RedactionRecordWireFailure::UnknownField",
            "RedactionRecordWireFailure::MissingVersion",
            "RedactionRecordWireFailure::MissingKeyHash",
            "RedactionRecordWireFailure::MissingOldObjectId",
            "RedactionRecordWireFailure::MissingRedactor",
            "RedactionRecordWireFailure::MissingWallMs",
            "RedactionRecordWireFailure::MissingReason",
            "RedactionRecordWireFailure::MissingSignature",
            "RedactionRecordWireFailure::ReasonText",
            "RedactionRecordWireFailure::U64",
            "RedactionRecordWireFailure::U16Width",
            "RedactionRecordWireFailure::Fixed32Bytes",
            "RedactionRecordWireFailure::Fixed32Length",
            "RedactionRecordWireFailure::SignatureBytes",
            "RedactionRecordWireFailure::SignatureLength",
        ] {
            assert!(
                source.contains(required),
                "redaction record wire failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn redaction_record_wire_failure_classifier_preserves_public_errors() {
        assert_eq!(
            redaction_record_wire_failure_to_mneme(
                RedactionRecordWireFailure::UnsupportedVersion { version: 99 }
            ),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            unsupported_redaction_record_version_error(99),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::UnknownField {
                field: 9
            }),
            MnemeError::UnknownField { field: 9 }
        );
        assert_eq!(
            redaction_record_wire_failure_to_mneme(RedactionRecordWireFailure::SignatureLength),
            MnemeError::RootSigInvalid
        );

        for failure in [
            RedactionRecordWireFailure::FieldKey,
            RedactionRecordWireFailure::MissingVersion,
            RedactionRecordWireFailure::MissingKeyHash,
            RedactionRecordWireFailure::MissingOldObjectId,
            RedactionRecordWireFailure::MissingRedactor,
            RedactionRecordWireFailure::MissingWallMs,
            RedactionRecordWireFailure::MissingReason,
            RedactionRecordWireFailure::MissingSignature,
            RedactionRecordWireFailure::ReasonText,
            RedactionRecordWireFailure::U64,
            RedactionRecordWireFailure::U16Width,
            RedactionRecordWireFailure::Fixed32Bytes,
            RedactionRecordWireFailure::Fixed32Length,
            RedactionRecordWireFailure::SignatureBytes,
        ] {
            assert_eq!(
                redaction_record_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn redaction_record_wire_version_width_overflow_fails_closed() {
        let mut enc = Encoder::new();
        enc.begin_map(7).expect("begin map");
        enc.encode_unsigned(1).expect("version key");
        enc.encode_unsigned(u64::from(u16::MAX) + 1)
            .expect("too-wide version");
        enc.encode_unsigned(2).expect("key_hash key");
        enc.encode_bytes(&[0x11; 32]).expect("key_hash");
        enc.encode_unsigned(3).expect("old_object_id key");
        enc.encode_bytes(&[0x22; 32]).expect("old_object_id");
        enc.encode_unsigned(4).expect("redactor key");
        enc.encode_bytes(&[0x33; 32]).expect("redactor");
        enc.encode_unsigned(5).expect("wall_ms key");
        enc.encode_unsigned(1).expect("wall_ms");
        enc.encode_unsigned(6).expect("reason key");
        enc.encode_text("compliance").expect("reason");
        enc.encode_unsigned(7).expect("signature key");
        enc.encode_bytes(&[0x44; 64]).expect("signature");
        let bytes = enc.finish();

        assert_eq!(
            RedactionRecord::from_bytes(&bytes),
            Err(MnemeError::SchemaDrift)
        );
    }
}
