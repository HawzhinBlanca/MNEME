//! Enclave attestation report placeholder wire (Phase II software slice).

use crate::{CborValue, Decoder, Encoder, MnemeError};
use std::convert::TryFrom;

pub const ENCLAVE_REPORT_PLACEHOLDER_VERSION: u16 = 1;
pub const ENCLAVE_REPORT_PLACEHOLDER_STATUS: &str = "no_enclave_present_gate_closed";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnclaveReportWireFailure {
    UnknownField { field: u16 },
    DecodeUnsupportedVersion { got: u16 },
    MissingVersion,
    MissingStatus,
    MissingReportDigest,
    FieldKey,
    U16Value,
    Text,
    Fixed32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveReportPlaceholder {
    pub status: String,
    pub report_digest: [u8; 32],
}

impl EnclaveReportPlaceholder {
    pub fn honest_absent() -> Self {
        Self {
            status: ENCLAVE_REPORT_PLACEHOLDER_STATUS.to_string(),
            report_digest: [0u8; 32],
        }
    }
}

pub fn encode_enclave_report_placeholder(
    report: &EnclaveReportPlaceholder,
) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    enc.begin_map(3)?;
    enc.encode_unsigned(1)?;
    enc.encode_unsigned(u64::from(ENCLAVE_REPORT_PLACEHOLDER_VERSION))?;
    enc.encode_unsigned(2)?;
    enc.encode_text(&report.status)?;
    enc.encode_unsigned(3)?;
    enc.encode_bytes(&report.report_digest)?;
    Ok(enc.finish())
}

fn enclave_report_wire_failure_to_mneme(failure: EnclaveReportWireFailure) -> MnemeError {
    match failure {
        EnclaveReportWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        EnclaveReportWireFailure::DecodeUnsupportedVersion { got } => {
            MnemeError::UnsupportedVersion { got }
        }
        EnclaveReportWireFailure::MissingVersion
        | EnclaveReportWireFailure::MissingStatus
        | EnclaveReportWireFailure::MissingReportDigest
        | EnclaveReportWireFailure::FieldKey
        | EnclaveReportWireFailure::U16Value
        | EnclaveReportWireFailure::Text
        | EnclaveReportWireFailure::Fixed32 => MnemeError::SchemaDrift,
    }
}

fn unknown_enclave_report_field_error(field: u16) -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::UnknownField { field })
}

fn unsupported_enclave_report_version_error(got: u16) -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::DecodeUnsupportedVersion { got })
}

fn missing_enclave_report_version_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::MissingVersion)
}

fn missing_enclave_report_status_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::MissingStatus)
}

fn missing_enclave_report_digest_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::MissingReportDigest)
}

fn enclave_report_field_key_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::FieldKey)
}

fn enclave_report_u16_value_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::U16Value)
}

fn enclave_report_text_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::Text)
}

fn enclave_report_fixed32_error() -> MnemeError {
    enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::Fixed32)
}

pub fn decode_enclave_report_placeholder(
    bytes: &[u8],
) -> Result<EnclaveReportPlaceholder, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut version = None;
    let mut status = None;
    let mut report_digest = None;
    for (key, value) in map {
        let field = parse_field_key(&key)?;
        match field {
            1 => version = Some(parse_u16(&value)?),
            2 => status = Some(parse_text(&value)?),
            3 => report_digest = Some(parse_fixed32(&value)?),
            _ => return Err(unknown_enclave_report_field_error(field)),
        }
    }
    let version = version.ok_or_else(missing_enclave_report_version_error)?;
    if version != ENCLAVE_REPORT_PLACEHOLDER_VERSION {
        return Err(unsupported_enclave_report_version_error(version));
    }
    Ok(EnclaveReportPlaceholder {
        status: status.ok_or_else(missing_enclave_report_status_error)?,
        report_digest: report_digest.ok_or_else(missing_enclave_report_digest_error)?,
    })
}

fn parse_field_key(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(enclave_report_field_key_error)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(enclave_report_u16_value_error)
}

fn parse_text(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(|s| s.to_string())
        .ok_or_else(enclave_report_text_error)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(enclave_report_fixed32_error()),
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
    fn enclave_report_decoder_failures_are_classified_not_collapsed() {
        let source = include_str!("enclave.rs");
        let section = source_between_markers(
            source,
            "pub fn decode_enclave_report_placeholder",
            "#[cfg(test)]",
            "enclave report decoder",
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
                "enclave report decoder should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum EnclaveReportWireFailure",
            "fn enclave_report_wire_failure_to_mneme(",
            "fn unknown_enclave_report_field_error(",
            "fn unsupported_enclave_report_version_error(",
            "fn missing_enclave_report_version_error(",
            "fn missing_enclave_report_status_error(",
            "fn missing_enclave_report_digest_error(",
            "fn enclave_report_field_key_error(",
            "fn enclave_report_u16_value_error(",
            "fn enclave_report_text_error(",
            "fn enclave_report_fixed32_error(",
            "EnclaveReportWireFailure::UnknownField",
            "EnclaveReportWireFailure::DecodeUnsupportedVersion",
            "EnclaveReportWireFailure::MissingVersion",
            "EnclaveReportWireFailure::MissingStatus",
            "EnclaveReportWireFailure::MissingReportDigest",
            "EnclaveReportWireFailure::FieldKey",
            "EnclaveReportWireFailure::U16Value",
            "EnclaveReportWireFailure::Text",
            "EnclaveReportWireFailure::Fixed32",
        ] {
            assert!(
                source.contains(required),
                "enclave report classification should include `{required}`"
            );
        }
    }

    #[test]
    fn enclave_report_wire_failure_classifier_preserves_public_errors() {
        assert_eq!(
            enclave_report_wire_failure_to_mneme(
                EnclaveReportWireFailure::DecodeUnsupportedVersion { got: 9 }
            ),
            MnemeError::UnsupportedVersion { got: 9 }
        );
        assert_eq!(
            enclave_report_wire_failure_to_mneme(EnclaveReportWireFailure::UnknownField {
                field: 99
            }),
            MnemeError::UnknownField { field: 99 }
        );
        for failure in [
            EnclaveReportWireFailure::MissingVersion,
            EnclaveReportWireFailure::MissingStatus,
            EnclaveReportWireFailure::MissingReportDigest,
            EnclaveReportWireFailure::FieldKey,
            EnclaveReportWireFailure::U16Value,
            EnclaveReportWireFailure::Text,
            EnclaveReportWireFailure::Fixed32,
        ] {
            assert_eq!(
                enclave_report_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn placeholder_wire_roundtrips() {
        let report = EnclaveReportPlaceholder::honest_absent();
        let bytes = encode_enclave_report_placeholder(&report).unwrap();
        assert_eq!(decode_enclave_report_placeholder(&bytes).unwrap(), report);
    }
}
