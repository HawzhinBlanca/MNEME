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
            _ => return Err(MnemeError::UnknownField { field }),
        }
    }
    let version = version.ok_or(MnemeError::SchemaDrift)?;
    if version != CONTEXT_ATTESTATION_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: version });
    }
    Ok(ContextConsumptionAttestation {
        assembly_profile: AssemblyProfile {
            id: profile.ok_or(MnemeError::SchemaDrift)?,
        },
        context_hash: context_hash.ok_or(MnemeError::SchemaDrift)?,
        certified_memory_set_hash: certified_hash.ok_or(MnemeError::SchemaDrift)?,
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

    fn sample_attestation(byte: u8) -> ContextConsumptionAttestation {
        ContextConsumptionAttestation {
            assembly_profile: AssemblyProfile { id: [byte; 32] },
            context_hash: [byte.wrapping_add(1); 32],
            certified_memory_set_hash: [byte.wrapping_add(2); 32],
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

    fn encode_value(enc: &mut Encoder, value: &CborValue) -> Result<(), MnemeError> {
        match value {
            CborValue::Unsigned(v) => enc.encode_unsigned(*v)?,
            CborValue::Bytes(bytes) => enc.encode_bytes(bytes)?,
            _ => return Err(MnemeError::SchemaDrift),
        }
        Ok(())
    }
}
