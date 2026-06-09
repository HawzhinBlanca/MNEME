//! Output-binding wire (Phase II software slice).

use crate::{CborValue, Decoder, Encoder, MnemeError, OutputBinding};
use std::convert::TryFrom;

pub const OUTPUT_BINDING_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputBindingWireFailure {
    UnknownField { field: u16 },
    DecodeUnsupportedVersion { got: u16 },
    MissingVersion,
    MissingContextHash,
    MissingOutputHash,
    MissingModelIdentity,
    FieldKey,
    U16Value,
    Fixed32,
}

pub fn encode_output_binding(binding: &OutputBinding) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    enc.begin_map(4)?;
    enc.encode_unsigned(1)?;
    enc.encode_unsigned(u64::from(OUTPUT_BINDING_VERSION))?;
    enc.encode_unsigned(2)?;
    enc.encode_bytes(&binding.context_hash)?;
    enc.encode_unsigned(3)?;
    enc.encode_bytes(&binding.output_hash)?;
    enc.encode_unsigned(4)?;
    enc.encode_bytes(&binding.model_identity)?;
    Ok(enc.finish())
}

fn output_binding_wire_failure_to_mneme(failure: OutputBindingWireFailure) -> MnemeError {
    match failure {
        OutputBindingWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        OutputBindingWireFailure::DecodeUnsupportedVersion { got } => {
            MnemeError::UnsupportedVersion { got }
        }
        OutputBindingWireFailure::MissingVersion
        | OutputBindingWireFailure::MissingContextHash
        | OutputBindingWireFailure::MissingOutputHash
        | OutputBindingWireFailure::MissingModelIdentity
        | OutputBindingWireFailure::FieldKey
        | OutputBindingWireFailure::U16Value
        | OutputBindingWireFailure::Fixed32 => MnemeError::SchemaDrift,
    }
}

fn unknown_output_binding_field_error(field: u16) -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::UnknownField { field })
}

fn unsupported_output_binding_version_error(got: u16) -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::DecodeUnsupportedVersion { got })
}

fn missing_output_binding_version_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::MissingVersion)
}

fn missing_output_binding_context_hash_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::MissingContextHash)
}

fn missing_output_binding_output_hash_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::MissingOutputHash)
}

fn missing_output_binding_model_identity_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::MissingModelIdentity)
}

fn output_binding_field_key_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::FieldKey)
}

fn output_binding_u16_value_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::U16Value)
}

fn output_binding_fixed32_error() -> MnemeError {
    output_binding_wire_failure_to_mneme(OutputBindingWireFailure::Fixed32)
}

pub fn decode_output_binding(bytes: &[u8]) -> Result<OutputBinding, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut version = None;
    let mut context_hash = None;
    let mut output_hash = None;
    let mut model_identity = None;
    for (key, value) in map {
        let field = parse_field_key(&key)?;
        match field {
            1 => version = Some(parse_u16(&value)?),
            2 => context_hash = Some(parse_fixed32(&value)?),
            3 => output_hash = Some(parse_fixed32(&value)?),
            4 => model_identity = Some(parse_fixed32(&value)?),
            _ => return Err(unknown_output_binding_field_error(field)),
        }
    }
    let version = version.ok_or_else(missing_output_binding_version_error)?;
    if version != OUTPUT_BINDING_VERSION {
        return Err(unsupported_output_binding_version_error(version));
    }
    Ok(OutputBinding {
        context_hash: context_hash.ok_or_else(missing_output_binding_context_hash_error)?,
        output_hash: output_hash.ok_or_else(missing_output_binding_output_hash_error)?,
        model_identity: model_identity.ok_or_else(missing_output_binding_model_identity_error)?,
    })
}

fn parse_field_key(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(output_binding_field_key_error)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(output_binding_u16_value_error)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(output_binding_fixed32_error()),
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

    #[test]
    fn output_binding_decoder_failures_are_classified_not_collapsed() {
        let source = include_str!("output.rs");
        let section = source_between_markers(
            source,
            "pub fn decode_output_binding",
            "#[cfg(test)]",
            "output binding decoder",
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
                "output binding decoder should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum OutputBindingWireFailure",
            "fn output_binding_wire_failure_to_mneme(",
            "fn unknown_output_binding_field_error(",
            "fn unsupported_output_binding_version_error(",
            "fn missing_output_binding_version_error(",
            "fn missing_output_binding_context_hash_error(",
            "fn missing_output_binding_output_hash_error(",
            "fn missing_output_binding_model_identity_error(",
            "fn output_binding_field_key_error(",
            "fn output_binding_u16_value_error(",
            "fn output_binding_fixed32_error(",
            "OutputBindingWireFailure::UnknownField",
            "OutputBindingWireFailure::DecodeUnsupportedVersion",
            "OutputBindingWireFailure::MissingVersion",
            "OutputBindingWireFailure::MissingContextHash",
            "OutputBindingWireFailure::MissingOutputHash",
            "OutputBindingWireFailure::MissingModelIdentity",
            "OutputBindingWireFailure::FieldKey",
            "OutputBindingWireFailure::U16Value",
            "OutputBindingWireFailure::Fixed32",
        ] {
            assert!(
                source.contains(required),
                "output binding classification should include `{required}`"
            );
        }
    }

    #[test]
    fn output_binding_wire_failure_classifier_preserves_public_errors() {
        assert_eq!(
            output_binding_wire_failure_to_mneme(
                OutputBindingWireFailure::DecodeUnsupportedVersion { got: 9 }
            ),
            MnemeError::UnsupportedVersion { got: 9 }
        );
        assert_eq!(
            output_binding_wire_failure_to_mneme(OutputBindingWireFailure::UnknownField {
                field: 99
            }),
            MnemeError::UnknownField { field: 99 }
        );
        for failure in [
            OutputBindingWireFailure::MissingVersion,
            OutputBindingWireFailure::MissingContextHash,
            OutputBindingWireFailure::MissingOutputHash,
            OutputBindingWireFailure::MissingModelIdentity,
            OutputBindingWireFailure::FieldKey,
            OutputBindingWireFailure::U16Value,
            OutputBindingWireFailure::Fixed32,
        ] {
            assert_eq!(
                output_binding_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn output_binding_wire_roundtrips() {
        let binding = OutputBinding {
            context_hash: [0x01; 32],
            output_hash: [0x02; 32],
            model_identity: [0x03; 32],
        };
        let bytes = encode_output_binding(&binding).unwrap();
        assert_eq!(decode_output_binding(&bytes).unwrap(), binding);
    }

    /// Forgery: elevated wire version must not decode as v1.
    #[test]
    fn forgery_unsupported_version_rejects() {
        let binding = OutputBinding {
            context_hash: [0x01; 32],
            output_hash: [0x02; 32],
            model_identity: [0x03; 32],
        };
        let mut bytes = encode_output_binding(&binding).unwrap();
        // CBOR map key 1 → version field; flip low byte of encoded u64(1) payload.
        if let Some(idx) = bytes.iter().position(|&b| b == 0x01) {
            bytes[idx + 1] = 0x02;
        }
        assert!(matches!(
            decode_output_binding(&bytes),
            Err(MnemeError::UnsupportedVersion { .. }) | Err(MnemeError::SchemaDrift)
        ));
    }

    /// Forgery: swap context_hash and output_hash fields on wire (hash-swap attack).
    #[test]
    fn forgery_hash_field_swap_rejects_or_decodes_distinct() {
        let binding = OutputBinding {
            context_hash: [0x01; 32],
            output_hash: [0x02; 32],
            model_identity: [0x03; 32],
        };
        let mut swapped = binding.clone();
        swapped.context_hash = binding.output_hash;
        swapped.output_hash = binding.context_hash;
        assert_ne!(binding, swapped);
        let wire = encode_output_binding(&swapped).unwrap();
        assert_eq!(decode_output_binding(&wire).unwrap(), swapped);
    }

    /// Forgery: truncated wire must not yield a binding.
    #[test]
    fn forgery_truncated_wire_rejects() {
        let binding = OutputBinding {
            context_hash: [0x01; 32],
            output_hash: [0x02; 32],
            model_identity: [0x03; 32],
        };
        let bytes = encode_output_binding(&binding).unwrap();
        for trim in 1..=8 {
            assert!(decode_output_binding(&bytes[..bytes.len() - trim]).is_err());
        }
    }

    /// Forgery: wrong fixed32 length on model_identity field.
    #[test]
    fn forgery_wrong_model_identity_length_rejects() {
        let mut enc = Encoder::new();
        enc.begin_map(4).unwrap();
        enc.encode_unsigned(1).unwrap();
        enc.encode_unsigned(u64::from(OUTPUT_BINDING_VERSION))
            .unwrap();
        enc.encode_unsigned(2).unwrap();
        enc.encode_bytes(&[0x01; 32]).unwrap();
        enc.encode_unsigned(3).unwrap();
        enc.encode_bytes(&[0x02; 32]).unwrap();
        enc.encode_unsigned(4).unwrap();
        enc.encode_bytes(&[0x03; 16]).unwrap(); // 16 bytes, not 32
        let bytes = enc.finish();
        assert_eq!(decode_output_binding(&bytes), Err(MnemeError::SchemaDrift));
    }
}
