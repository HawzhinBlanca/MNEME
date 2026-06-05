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
            return Err(MnemeError::UnsupportedVersion { got: self.version });
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
            let field = k.as_u64().ok_or(MnemeError::SchemaDrift)?;
            match field {
                1 => version = Some(parse_u16(&v)?),
                2 => key_hash = Some(parse_fixed32(&v)?),
                3 => old_object_id = Some(parse_fixed32(&v)?),
                4 => redactor = Some(parse_fixed32(&v)?),
                5 => wall_ms = Some(parse_u64(&v)?),
                6 => reason = Some(v.as_text().ok_or(MnemeError::SchemaDrift)?.to_string()),
                7 => signature = Some(parse_sig(&v)?),
                _ => {
                    return Err(MnemeError::UnknownField {
                        field: field as u16,
                    });
                }
            }
        }
        dec.ensure_consumed()?;
        Ok(Self {
            version: version.ok_or(MnemeError::SchemaDrift)?,
            key_hash: key_hash.ok_or(MnemeError::SchemaDrift)?,
            old_object_id: old_object_id.ok_or(MnemeError::SchemaDrift)?,
            redactor: redactor.ok_or(MnemeError::SchemaDrift)?,
            wall_ms: wall_ms.ok_or(MnemeError::SchemaDrift)?,
            reason: reason.ok_or(MnemeError::SchemaDrift)?,
            signature: signature.ok_or(MnemeError::SchemaDrift)?,
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
    Ok(parse_u64(v)? as u16)
}

fn parse_u64(v: &mneme_core::CborValue) -> Result<u64, MnemeError> {
    v.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32(v: &mneme_core::CborValue) -> Result<[u8; 32], MnemeError> {
    let b = v.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if b.len() != 32 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

fn parse_sig(v: &mneme_core::CborValue) -> Result<[u8; 64], MnemeError> {
    let b = v.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    b.try_into().map_err(|_| MnemeError::RootSigInvalid)
}
