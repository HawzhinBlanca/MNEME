#![forbid(unsafe_code)]
//! Panic-free attestation evidence parser for host-provided blobs.
//!
//! Honesty: this is **not** a production TEE attestor or vendor binding. It only
//! validates that input bytes look like PEM/DER-encoded attestation evidence and
//! fails closed on anything malformed or unsupported.

use der::Decode;
use der::asn1::Any;
use mneme_core::MnemeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttestationParseFailure {
    EmptyInput,
    PemUtf8,
    PemDecode,
    EmptyPemDer,
    PemDerDecode,
    RawDerDecode,
}

fn attestation_parse_failure_to_mneme(failure: AttestationParseFailure) -> MnemeError {
    match failure {
        AttestationParseFailure::EmptyInput
        | AttestationParseFailure::PemUtf8
        | AttestationParseFailure::PemDecode
        | AttestationParseFailure::EmptyPemDer
        | AttestationParseFailure::PemDerDecode
        | AttestationParseFailure::RawDerDecode => MnemeError::SchemaDrift,
    }
}

fn empty_attestation_input_error() -> MnemeError {
    attestation_parse_failure_to_mneme(AttestationParseFailure::EmptyInput)
}

fn pem_utf8_error() -> MnemeError {
    attestation_parse_failure_to_mneme(AttestationParseFailure::PemUtf8)
}

fn pem_decode_error() -> MnemeError {
    attestation_parse_failure_to_mneme(AttestationParseFailure::PemDecode)
}

fn empty_pem_der_error() -> MnemeError {
    attestation_parse_failure_to_mneme(AttestationParseFailure::EmptyPemDer)
}

fn pem_der_decode_error() -> MnemeError {
    attestation_parse_failure_to_mneme(AttestationParseFailure::PemDerDecode)
}

fn raw_der_decode_error() -> MnemeError {
    attestation_parse_failure_to_mneme(AttestationParseFailure::RawDerDecode)
}

/// Supported evidence encodings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceEncoding {
    /// PEM wrapper around DER bytes.
    Pem { label: String },
    /// Raw DER bytes.
    Der,
}

/// Parsed attestation evidence (stub, vendor-agnostic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub encoding: EvidenceEncoding,
    /// Validated DER bytes extracted from the evidence.
    pub der: Vec<u8>,
}

impl AttestationEvidence {
    /// Parse PEM or DER evidence, rejecting malformed inputs.
    pub fn parse(input: &[u8]) -> Result<Self, MnemeError> {
        parse_attestation_evidence(input)
    }
}

/// Parse PEM/DER evidence and reject malformed shapes.
pub fn parse_attestation_evidence(input: &[u8]) -> Result<AttestationEvidence, MnemeError> {
    if input.is_empty() {
        return Err(empty_attestation_input_error());
    }

    if looks_like_pem(input) {
        return parse_pem(input);
    }

    parse_der(input)
}

/// libFuzzer hook: ensure parsing stays panic-free.
pub fn fuzz_attest_parse(input: &[u8]) {
    let _ = parse_attestation_evidence(input);
}

fn parse_pem(input: &[u8]) -> Result<AttestationEvidence, MnemeError> {
    let pem_str = std::str::from_utf8(input).map_err(|_| pem_utf8_error())?;
    let (label, der) =
        pem_rfc7468::decode_vec(pem_str.as_bytes()).map_err(|_| pem_decode_error())?;
    if der.is_empty() {
        return Err(empty_pem_der_error());
    }
    validate_der(&der, pem_der_decode_error)?;
    Ok(AttestationEvidence {
        encoding: EvidenceEncoding::Pem {
            label: label.to_string(),
        },
        der,
    })
}

fn parse_der(input: &[u8]) -> Result<AttestationEvidence, MnemeError> {
    validate_der(input, raw_der_decode_error)?;
    Ok(AttestationEvidence {
        encoding: EvidenceEncoding::Der,
        der: input.to_vec(),
    })
}

fn validate_der(input: &[u8], decode_error: fn() -> MnemeError) -> Result<(), MnemeError> {
    Any::from_der(input).map_err(|_| decode_error())?;
    Ok(())
}

fn looks_like_pem(input: &[u8]) -> bool {
    input.starts_with(b"-----BEGIN ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    const DER_SAMPLE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01]; // SEQUENCE { INTEGER 1 }

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
    fn attestation_parse_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("lib.rs");
        let section = source_between_markers(
            source,
            "use der::Decode",
            "#[cfg(test)]",
            "attestation parser production section",
        );

        for forbidden in [
            "return Err(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "attestation parser should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum AttestationParseFailure",
            "fn attestation_parse_failure_to_mneme(",
            "fn empty_attestation_input_error(",
            "fn pem_utf8_error(",
            "fn pem_decode_error(",
            "fn empty_pem_der_error(",
            "fn pem_der_decode_error(",
            "fn raw_der_decode_error(",
            "AttestationParseFailure::EmptyInput",
            "AttestationParseFailure::PemUtf8",
            "AttestationParseFailure::PemDecode",
            "AttestationParseFailure::EmptyPemDer",
            "AttestationParseFailure::PemDerDecode",
            "AttestationParseFailure::RawDerDecode",
        ] {
            assert!(
                section.contains(required),
                "attestation parser failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn attestation_parse_failure_classifier_preserves_public_schema_drift() {
        for failure in [
            AttestationParseFailure::EmptyInput,
            AttestationParseFailure::PemUtf8,
            AttestationParseFailure::PemDecode,
            AttestationParseFailure::EmptyPemDer,
            AttestationParseFailure::PemDerDecode,
            AttestationParseFailure::RawDerDecode,
        ] {
            assert_eq!(
                attestation_parse_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }

        assert_eq!(empty_attestation_input_error(), MnemeError::SchemaDrift);
        assert_eq!(pem_utf8_error(), MnemeError::SchemaDrift);
        assert_eq!(pem_decode_error(), MnemeError::SchemaDrift);
        assert_eq!(empty_pem_der_error(), MnemeError::SchemaDrift);
        assert_eq!(pem_der_decode_error(), MnemeError::SchemaDrift);
        assert_eq!(raw_der_decode_error(), MnemeError::SchemaDrift);
    }

    #[test]
    fn parses_valid_pem() {
        let pem = format!(
            "-----BEGIN ATTESTATION-----\n{}\n-----END ATTESTATION-----\n",
            STANDARD.encode(DER_SAMPLE)
        );

        let parsed = AttestationEvidence::parse(pem.as_bytes()).expect("valid pem");
        assert!(matches!(
            parsed.encoding,
            EvidenceEncoding::Pem { ref label } if label == "ATTESTATION"
        ));
        assert_eq!(parsed.der, DER_SAMPLE);
    }

    #[test]
    fn rejects_invalid_pem_body() {
        let pem = "-----BEGIN ATTESTATION-----\n@@@\n-----END ATTESTATION-----";
        let err = AttestationEvidence::parse(pem.as_bytes()).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn rejects_non_utf8_pem() {
        let mut pem = b"-----BEGIN ATTESTATION-----\n".to_vec();
        pem.push(0xff);
        let err = AttestationEvidence::parse(&pem).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn parses_valid_der() {
        let parsed = AttestationEvidence::parse(DER_SAMPLE).expect("valid der");
        assert!(matches!(parsed.encoding, EvidenceEncoding::Der));
        assert_eq!(parsed.der, DER_SAMPLE);
    }

    #[test]
    fn rejects_invalid_der() {
        let err = AttestationEvidence::parse(&[0u8; 4]).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }

    #[test]
    fn rejects_empty_input() {
        let err = AttestationEvidence::parse(&[]).unwrap_err();
        assert_eq!(err, MnemeError::SchemaDrift);
    }
}
