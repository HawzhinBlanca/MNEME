//! Enclave attestation report placeholder wire (Phase II software slice).

use crate::{CborValue, Decoder, Encoder, MnemeError};
use std::convert::TryFrom;

pub const ENCLAVE_REPORT_PLACEHOLDER_VERSION: u16 = 1;
pub const ENCLAVE_REPORT_PLACEHOLDER_STATUS: &str = "no_enclave_present_gate_closed";

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
            _ => return Err(MnemeError::UnknownField { field }),
        }
    }
    let version = version.ok_or(MnemeError::SchemaDrift)?;
    if version != ENCLAVE_REPORT_PLACEHOLDER_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: version });
    }
    Ok(EnclaveReportPlaceholder {
        status: status.ok_or(MnemeError::SchemaDrift)?,
        report_digest: report_digest.ok_or(MnemeError::SchemaDrift)?,
    })
}

fn parse_field_key(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_text(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(|s| s.to_string())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err(MnemeError::SchemaDrift),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn placeholder_wire_roundtrips() {
        let report = EnclaveReportPlaceholder::honest_absent();
        let bytes = encode_enclave_report_placeholder(&report).unwrap();
        assert_eq!(decode_enclave_report_placeholder(&bytes).unwrap(), report);
    }
}
