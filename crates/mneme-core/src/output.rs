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
