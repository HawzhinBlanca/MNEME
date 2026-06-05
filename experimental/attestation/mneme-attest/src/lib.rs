#![forbid(unsafe_code)]
//! Panic-free attestation evidence parser for host-provided blobs.
//!
//! Honesty: this is **not** a production TEE attestor or vendor binding. It only
//! validates that input bytes look like PEM/DER-encoded attestation evidence and
//! fails closed on anything malformed or unsupported.

use der::Decode;
use der::asn1::Any;
use mneme_core::MnemeError;

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
        return Err(MnemeError::SchemaDrift);
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
    let pem_str = std::str::from_utf8(input).map_err(|_| MnemeError::SchemaDrift)?;
    let (label, der) =
        pem_rfc7468::decode_vec(pem_str.as_bytes()).map_err(|_| MnemeError::SchemaDrift)?;
    if der.is_empty() {
        return Err(MnemeError::SchemaDrift);
    }
    validate_der(&der)?;
    Ok(AttestationEvidence {
        encoding: EvidenceEncoding::Pem {
            label: label.to_string(),
        },
        der,
    })
}

fn parse_der(input: &[u8]) -> Result<AttestationEvidence, MnemeError> {
    validate_der(input)?;
    Ok(AttestationEvidence {
        encoding: EvidenceEncoding::Der,
        der: input.to_vec(),
    })
}

fn validate_der(input: &[u8]) -> Result<(), MnemeError> {
    Any::from_der(input).map_err(|_| MnemeError::SchemaDrift)?;
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
