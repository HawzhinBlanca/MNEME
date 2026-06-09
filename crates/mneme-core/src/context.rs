//! Context-consumption attestation wire (Phase II software slice).
//!
//! **Honesty:** no enclave claim; the gate is closed. The wire only proves hash
//! equality between the assembled prompt and the certified memory set.

use crate::{
    AssemblyProfile, CborValue, ContextConsumptionAttestation, Decoder, Encoder, MnemeError,
};
use std::convert::TryFrom;

/// Versioned CCA wire (dCBOR, canonical).
pub const CONTEXT_ATTESTATION_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextAttestationWireFailure {
    UnknownField { field: u16 },
    DecodeUnsupportedVersion { got: u16 },
    MissingVersion,
    MissingAssemblyProfile,
    MissingContextHash,
    MissingCertifiedMemorySetHash,
    FieldKey,
    U16Value,
    Fixed32,
}

/// Encode a context-consumption attestation into the canonical wire format.
///
/// Map fields:
/// 1 → version (`u16`), 2 → assembly_profile.id (32-byte), 3 → context_hash
/// (32-byte), 4 → certified_memory_set_hash (32-byte).
pub fn encode_context_consumption_attestation(
    attestation: &ContextConsumptionAttestation,
) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    enc.begin_map(4)?;
    enc.encode_unsigned(1)?;
    enc.encode_unsigned(u64::from(CONTEXT_ATTESTATION_VERSION))?;
    enc.encode_unsigned(2)?;
    enc.encode_bytes(&attestation.assembly_profile.id)?;
    enc.encode_unsigned(3)?;
    enc.encode_bytes(&attestation.context_hash)?;
    enc.encode_unsigned(4)?;
    enc.encode_bytes(&attestation.certified_memory_set_hash)?;
    Ok(enc.finish())
}

fn context_attestation_wire_failure_to_mneme(failure: ContextAttestationWireFailure) -> MnemeError {
    match failure {
        ContextAttestationWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        ContextAttestationWireFailure::DecodeUnsupportedVersion { got } => {
            MnemeError::UnsupportedVersion { got }
        }
        ContextAttestationWireFailure::MissingVersion
        | ContextAttestationWireFailure::MissingAssemblyProfile
        | ContextAttestationWireFailure::MissingContextHash
        | ContextAttestationWireFailure::MissingCertifiedMemorySetHash
        | ContextAttestationWireFailure::FieldKey
        | ContextAttestationWireFailure::U16Value
        | ContextAttestationWireFailure::Fixed32 => MnemeError::SchemaDrift,
    }
}

fn unknown_context_attestation_field_error(field: u16) -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::UnknownField { field })
}

fn unsupported_context_attestation_version_error(got: u16) -> MnemeError {
    context_attestation_wire_failure_to_mneme(
        ContextAttestationWireFailure::DecodeUnsupportedVersion { got },
    )
}

fn missing_context_attestation_version_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::MissingVersion)
}

fn missing_context_attestation_profile_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::MissingAssemblyProfile)
}

fn missing_context_attestation_context_hash_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::MissingContextHash)
}

fn missing_context_attestation_certified_hash_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(
        ContextAttestationWireFailure::MissingCertifiedMemorySetHash,
    )
}

fn context_attestation_field_key_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::FieldKey)
}

fn context_attestation_u16_value_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::U16Value)
}

fn context_attestation_fixed32_error() -> MnemeError {
    context_attestation_wire_failure_to_mneme(ContextAttestationWireFailure::Fixed32)
}

/// Decode a canonical CCA wire into its structured form.
pub fn decode_context_consumption_attestation(
    bytes: &[u8],
) -> Result<ContextConsumptionAttestation, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut version = None;
    let mut profile = None;
    let mut context_hash = None;
    let mut certified_hash = None;
    for (key, value) in map {
        let field = parse_field_key(&key)?;
        match field {
            1 => version = Some(parse_u16(&value)?),
            2 => profile = Some(parse_fixed32(&value)?),
            3 => context_hash = Some(parse_fixed32(&value)?),
            4 => certified_hash = Some(parse_fixed32(&value)?),
            _ => return Err(unknown_context_attestation_field_error(field)),
        }
    }
    let version = version.ok_or_else(missing_context_attestation_version_error)?;
    if version != CONTEXT_ATTESTATION_VERSION {
        return Err(unsupported_context_attestation_version_error(version));
    }
    Ok(ContextConsumptionAttestation {
        assembly_profile: AssemblyProfile {
            id: profile.ok_or_else(missing_context_attestation_profile_error)?,
        },
        context_hash: context_hash.ok_or_else(missing_context_attestation_context_hash_error)?,
        certified_memory_set_hash: certified_hash
            .ok_or_else(missing_context_attestation_certified_hash_error)?,
    })
}

fn parse_field_key(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(context_attestation_field_key_error)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(context_attestation_u16_value_error)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(context_attestation_fixed32_error()),
    }
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

    fn sample_attestation(byte: u8) -> ContextConsumptionAttestation {
        ContextConsumptionAttestation {
            assembly_profile: AssemblyProfile { id: [byte; 32] },
            context_hash: [byte.wrapping_add(1); 32],
            certified_memory_set_hash: [byte.wrapping_add(2); 32],
        }
    }

    #[test]
    fn context_attestation_decoder_failures_are_classified_not_collapsed() {
        let source = include_str!("context.rs");
        let section = source_between_markers(
            source,
            "pub fn decode_context_consumption_attestation",
            "#[cfg(test)]",
            "context attestation decoder",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::UnknownField",
            "return Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !section.contains(forbidden),
                "context attestation decoder should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ContextAttestationWireFailure",
            "fn context_attestation_wire_failure_to_mneme(",
            "fn unknown_context_attestation_field_error(",
            "fn unsupported_context_attestation_version_error(",
            "fn missing_context_attestation_version_error(",
            "fn missing_context_attestation_profile_error(",
            "fn missing_context_attestation_context_hash_error(",
            "fn missing_context_attestation_certified_hash_error(",
            "fn context_attestation_field_key_error(",
            "fn context_attestation_u16_value_error(",
            "fn context_attestation_fixed32_error(",
            "ContextAttestationWireFailure::UnknownField",
            "ContextAttestationWireFailure::DecodeUnsupportedVersion",
            "ContextAttestationWireFailure::MissingVersion",
            "ContextAttestationWireFailure::MissingAssemblyProfile",
            "ContextAttestationWireFailure::MissingContextHash",
            "ContextAttestationWireFailure::MissingCertifiedMemorySetHash",
            "ContextAttestationWireFailure::FieldKey",
            "ContextAttestationWireFailure::U16Value",
            "ContextAttestationWireFailure::Fixed32",
        ] {
            assert!(
                source.contains(required),
                "context attestation classification should include `{required}`"
            );
        }
    }

    #[test]
    fn context_attestation_wire_failure_classifier_preserves_public_errors() {
        assert_eq!(
            context_attestation_wire_failure_to_mneme(
                ContextAttestationWireFailure::DecodeUnsupportedVersion { got: 9 }
            ),
            MnemeError::UnsupportedVersion { got: 9 }
        );
        assert_eq!(
            context_attestation_wire_failure_to_mneme(
                ContextAttestationWireFailure::UnknownField { field: 99 }
            ),
            MnemeError::UnknownField { field: 99 }
        );
        for failure in [
            ContextAttestationWireFailure::MissingVersion,
            ContextAttestationWireFailure::MissingAssemblyProfile,
            ContextAttestationWireFailure::MissingContextHash,
            ContextAttestationWireFailure::MissingCertifiedMemorySetHash,
            ContextAttestationWireFailure::FieldKey,
            ContextAttestationWireFailure::U16Value,
            ContextAttestationWireFailure::Fixed32,
        ] {
            assert_eq!(
                context_attestation_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn cca_wire_is_deterministic_and_roundtrips() {
        let att = sample_attestation(0x11);
        let bytes_a = encode_context_consumption_attestation(&att).unwrap();
        let bytes_b = encode_context_consumption_attestation(&att).unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded = decode_context_consumption_attestation(&bytes_a).unwrap();
        assert_eq!(decoded, att);
    }

    #[test]
    fn cca_wire_hex_is_frozen() {
        let att = sample_attestation(0x01);
        let bytes = encode_context_consumption_attestation(&att).unwrap();
        assert_eq!(
            hex::encode(bytes),
            "a40101025820010101010101010101010101010101010101010101010101010101010101010103582002020202020202020202020202020202020202020202020202020202020202020458200303030303030303030303030303030303030303030303030303030303030303"
        );
    }

    #[test]
    fn cca_wire_rejects_wrong_version() {
        let att = sample_attestation(0x05);
        let good_bytes = encode_context_consumption_attestation(&att).unwrap();
        // Re-encode with version bumped to 2.
        let mut dec = Decoder::new(&good_bytes);
        let map = dec.decode_map().unwrap();
        let mut enc = Encoder::new();
        enc.begin_map(map.len() as u64).unwrap();
        for (k, v) in map {
            let field = k.as_u64().unwrap();
            enc.encode_unsigned(field).unwrap();
            match field {
                1 => enc.encode_unsigned(2).unwrap(),
                _ => encode_value(&mut enc, &v).unwrap(),
            }
        }
        let bad_bytes = enc.finish();
        let err = decode_context_consumption_attestation(&bad_bytes).unwrap_err();
        assert_eq!(err, MnemeError::UnsupportedVersion { got: 2 });
    }

    #[test]
    fn cca_wire_rejects_missing_fields() {
        let att = sample_attestation(0x07);
        let mut bytes = encode_context_consumption_attestation(&att).unwrap();
        // Drop the final field by truncating the map payload.
        bytes.truncate(bytes.len().saturating_sub(34));
        let err = decode_context_consumption_attestation(&bytes).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn cca_wire_rejects_garbage_bytes() {
        let garbage_inputs: &[&[u8]] = &[b"", b"\xff", b"not-cbor", b"\xa1\x00\x00"];
        for garbage in garbage_inputs {
            assert!(
                decode_context_consumption_attestation(garbage).is_err(),
                "malformed CCA wire must fail closed"
            );
        }
    }

    #[test]
    fn cca_wire_rejects_unknown_field() {
        let att = sample_attestation(0x09);
        let good = encode_context_consumption_attestation(&att).unwrap();
        let mut dec = Decoder::new(&good);
        let map = dec.decode_map().unwrap();
        let mut enc = Encoder::new();
        enc.begin_map(map.len() as u64 + 1).unwrap();
        for (k, v) in map {
            let field = k.as_u64().unwrap();
            enc.encode_unsigned(field).unwrap();
            encode_value(&mut enc, &v).unwrap();
        }
        enc.encode_unsigned(99).unwrap();
        enc.encode_bytes(&[0u8; 32]).unwrap();
        let bad = enc.finish();
        let err = decode_context_consumption_attestation(&bad).unwrap_err();
        assert_eq!(err, MnemeError::UnknownField { field: 99 });
    }

    #[test]
    fn cca_wire_rejects_non_32_byte_hashes() {
        let att = sample_attestation(0x0a);
        let good = encode_context_consumption_attestation(&att).unwrap();
        let mut dec = Decoder::new(&good);
        let map = dec.decode_map().unwrap();
        let mut enc = Encoder::new();
        enc.begin_map(map.len() as u64).unwrap();
        for (k, v) in map {
            let field = k.as_u64().unwrap();
            enc.encode_unsigned(field).unwrap();
            match field {
                3 | 4 => enc.encode_bytes(&[0u8; 31]).unwrap(),
                _ => encode_value(&mut enc, &v).unwrap(),
            }
        }
        let bad = enc.finish();
        let err = decode_context_consumption_attestation(&bad).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }

    fn encode_value(enc: &mut Encoder, value: &CborValue) -> Result<(), MnemeError> {
        match value {
            CborValue::Unsigned(v) => enc.encode_unsigned(*v)?,
            CborValue::Bytes(bytes) => enc.encode_bytes(bytes)?,
            _ => return Err(MnemeError::SchemaDrift),
        }
        Ok(())
    }
}
