//! Output-binding wire (Phase II software slice).

use crate::{CborValue, Decoder, Encoder, MnemeError, OutputBinding};
use std::convert::TryFrom;

pub const OUTPUT_BINDING_VERSION: u16 = 1;

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
            _ => return Err(MnemeError::UnknownField { field }),
        }
    }
    let version = version.ok_or(MnemeError::SchemaDrift)?;
    if version != OUTPUT_BINDING_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: version });
    }
    Ok(OutputBinding {
        context_hash: context_hash.ok_or(MnemeError::SchemaDrift)?,
        output_hash: output_hash.ok_or(MnemeError::SchemaDrift)?,
        model_identity: model_identity.ok_or(MnemeError::SchemaDrift)?,
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
    fn output_binding_wire_roundtrips() {
        let binding = OutputBinding {
            context_hash: [0x01; 32],
            output_hash: [0x02; 32],
            model_identity: [0x03; 32],
        };
        let bytes = encode_output_binding(&binding).unwrap();
        assert_eq!(decode_output_binding(&bytes).unwrap(), binding);
    }
}
