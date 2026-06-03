//! MNEME object record (blueprint §5.5).

use crate::MnemeError;
use crate::dcbor::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, assert_canonical, decode_strict,
    encode_canonical,
};
use crate::domain::hash_obj;
use crate::hlc::Hlc;
use crate::interface::ObjectId;
use std::collections::BTreeMap;

pub const OBJECT_VERSION: u16 = 1;

const F_VERSION: u64 = 0;
const F_KIND: u64 = 1;
const F_PARENT_IDS: u64 = 2;
const F_WRITER: u64 = 3;
const F_SESSION: u64 = 4;
const F_HLC: u64 = 5;
const F_TRUST_TIER: u64 = 6;
const F_PAYLOAD_ENC: u64 = 7;
const F_EMBEDDING_COMMIT: u64 = 8;
const F_REDACTION_SLOT: u64 = 9;
const F_EXT: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MemoryKind {
    Episodic = 0,
    Semantic = 1,
    Procedural = 2,
    Working = 3,
    Identity = 4,
}

impl MemoryKind {
    pub const ALL: [Self; 5] = [
        Self::Episodic,
        Self::Semantic,
        Self::Procedural,
        Self::Working,
        Self::Identity,
    ];

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for MemoryKind {
    type Error = MnemeError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Episodic),
            1 => Ok(Self::Semantic),
            2 => Ok(Self::Procedural),
            3 => Ok(Self::Working),
            4 => Ok(Self::Identity),
            _ => Err(MnemeError::SchemaDrift),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustTier {
    Quarantine = 0,
    Working = 1,
    Trusted = 2,
    Identity = 3,
}

impl TrustTier {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Result<Self, MnemeError> {
        match v {
            0 => Ok(Self::Quarantine),
            1 => Ok(Self::Working),
            2 => Ok(Self::Trusted),
            3 => Ok(Self::Identity),
            _ => Err(MnemeError::SchemaDrift),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadEnc {
    pub alg: u8,
    pub key_id: Option<[u8; 16]>,
    pub nonce: Option<[u8; 24]>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HlcWire {
    pub wall_ms: u64,
    pub counter: u32,
    pub node_id: [u8; 16],
}

impl From<&Hlc> for HlcWire {
    fn from(h: &Hlc) -> Self {
        Self {
            wall_ms: h.wall_ms,
            counter: h.counter,
            node_id: h.node_id.0,
        }
    }
}

impl From<HlcWire> for Hlc {
    fn from(w: HlcWire) -> Self {
        Self {
            wall_ms: w.wall_ms,
            counter: w.counter,
            node_id: crate::hlc::NodeId(w.node_id),
        }
    }
}

/// Canonical v1 object map (§5.5). The `id` is never stored inside this map (INV-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    pub version: u16,
    pub kind: u8,
    pub parent_ids: Vec<[u8; 32]>,
    pub writer: [u8; 32],
    pub session: [u8; 16],
    pub hlc: HlcWire,
    pub trust_tier: u8,
    pub payload_enc: PayloadEnc,
    pub embedding_commit: Option<[u8; 32]>,
    pub redaction_slot: Option<[u8; 32]>,
    pub ext: Option<BTreeMap<u16, Vec<u8>>>,
}

impl ObjectRecord {
    pub fn compute_id(&self) -> Result<ObjectId, MnemeError> {
        let bytes = self.to_canonical_bytes()?;
        Ok(ObjectId(hash_obj(&bytes)))
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MnemeError> {
        encode_canonical(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, MnemeError> {
        assert_canonical(bytes)?;
        decode_strict(bytes)
    }

    pub fn validate_invariants(&self) -> Result<(), MnemeError> {
        if self.version != OBJECT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: self.version });
        }
        MemoryKind::try_from(self.kind)?;
        TrustTier::from_u8(self.trust_tier)?;
        if !is_sorted_asc(&self.parent_ids) {
            return Err(MnemeError::SchemaDrift);
        }
        if self.payload_enc.alg == 1
            && (self.payload_enc.key_id.is_none() || self.payload_enc.nonce.is_none())
        {
            return Err(MnemeError::SchemaDrift);
        }
        Ok(())
    }

    /// Build a deterministic fixture for test vectors (all kinds).
    pub fn fixture(kind: MemoryKind) -> Self {
        let kind_u8 = kind.as_u8();
        Self {
            version: OBJECT_VERSION,
            kind: kind_u8,
            parent_ids: vec![],
            writer: [0x11; 32],
            session: [0x22; 16],
            hlc: HlcWire {
                wall_ms: 1_700_000_000_000,
                counter: 0,
                node_id: [0x33; 16],
            },
            trust_tier: TrustTier::Quarantine.as_u8(),
            payload_enc: PayloadEnc {
                alg: 0,
                key_id: None,
                nonce: None,
                body: format!("mneme-fixture-kind-{kind_u8}").into_bytes(),
            },
            embedding_commit: None,
            redaction_slot: None,
            ext: None,
        }
    }
}

impl DcborEncode for ObjectRecord {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        self.validate_invariants()?;

        let mut fields: Vec<(u64, _)> = vec![
            (F_VERSION, true),
            (F_KIND, true),
            (F_PARENT_IDS, true),
            (F_WRITER, true),
            (F_SESSION, true),
            (F_HLC, true),
            (F_TRUST_TIER, true),
            (F_PAYLOAD_ENC, true),
        ];
        if self.embedding_commit.is_some() {
            fields.push((F_EMBEDDING_COMMIT, true));
        }
        if self.redaction_slot.is_some() {
            fields.push((F_REDACTION_SLOT, true));
        }
        if self.ext.is_some() {
            fields.push((F_EXT, true));
        }

        enc.begin_map(fields.len() as u64)?;
        for (key, _) in &fields {
            enc.encode_unsigned(*key)?;
            match *key {
                F_VERSION => enc.encode_unsigned(u64::from(self.version))?,
                F_KIND => enc.encode_unsigned(u64::from(self.kind))?,
                F_PARENT_IDS => {
                    enc.begin_array(self.parent_ids.len() as u64)?;
                    for pid in &self.parent_ids {
                        enc.encode_bytes(pid)?;
                    }
                }
                F_WRITER => enc.encode_bytes(&self.writer)?,
                F_SESSION => enc.encode_bytes(&self.session)?,
                F_HLC => encode_hlc_wire(enc, &self.hlc)?,
                F_TRUST_TIER => enc.encode_unsigned(u64::from(self.trust_tier))?,
                F_PAYLOAD_ENC => self.payload_enc.dcbor_encode(enc)?,
                F_EMBEDDING_COMMIT => {
                    enc.encode_bytes(self.embedding_commit.as_ref().expect("checked"))?;
                }
                F_REDACTION_SLOT => {
                    enc.encode_bytes(self.redaction_slot.as_ref().expect("checked"))?;
                }
                F_EXT => encode_ext_map(enc, self.ext.as_ref().expect("checked"))?,
                _ => return Err(MnemeError::UnknownField { field: *key as u16 }),
            }
        }
        Ok(())
    }
}

impl DcborDecode for ObjectRecord {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut kind = None;
        let mut parent_ids = None;
        let mut writer = None;
        let mut session = None;
        let mut hlc = None;
        let mut trust_tier = None;
        let mut payload_enc = None;
        let mut embedding_commit = None;
        let mut redaction_slot = None;
        let mut ext = None;

        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_VERSION => version = Some(parse_u16(&value)?),
                F_KIND => kind = Some(parse_u8(&value)?),
                F_PARENT_IDS => parent_ids = Some(parse_parent_ids(&value)?),
                F_WRITER => writer = Some(parse_fixed32(&value)?),
                F_SESSION => session = Some(parse_fixed16(&value)?),
                F_HLC => hlc = Some(parse_hlc_wire(&value)?),
                F_TRUST_TIER => trust_tier = Some(parse_u8(&value)?),
                F_PAYLOAD_ENC => payload_enc = Some(PayloadEnc::from_cbor_value(&value)?),
                F_EMBEDDING_COMMIT => embedding_commit = Some(Some(parse_fixed32(&value)?)),
                F_REDACTION_SLOT => redaction_slot = Some(Some(parse_fixed32(&value)?)),
                F_EXT => ext = Some(Some(parse_ext_map(&value)?)),
                _ => {
                    return Err(MnemeError::UnknownField {
                        field: field as u16,
                    });
                }
            }
        }

        let record = Self {
            version: version.ok_or(MnemeError::SchemaDrift)?,
            kind: kind.ok_or(MnemeError::SchemaDrift)?,
            parent_ids: parent_ids.ok_or(MnemeError::SchemaDrift)?,
            writer: writer.ok_or(MnemeError::SchemaDrift)?,
            session: session.ok_or(MnemeError::SchemaDrift)?,
            hlc: hlc.ok_or(MnemeError::SchemaDrift)?,
            trust_tier: trust_tier.ok_or(MnemeError::SchemaDrift)?,
            payload_enc: payload_enc.ok_or(MnemeError::SchemaDrift)?,
            embedding_commit: embedding_commit.unwrap_or(None),
            redaction_slot: redaction_slot.unwrap_or(None),
            ext: ext.unwrap_or(None),
        };
        record.validate_invariants()?;
        Ok(record)
    }
}

impl DcborEncode for PayloadEnc {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let mut count = 2u64;
        if self.key_id.is_some() {
            count += 1;
        }
        if self.nonce.is_some() {
            count += 1;
        }
        enc.begin_map(count)?;
        // MNEME-dCBOR map keys: bytewise lexicographic order of encoded keys (nonce before key_id).
        enc.encode_text("alg")?;
        enc.encode_unsigned(u64::from(self.alg))?;
        enc.encode_text("body")?;
        enc.encode_bytes(&self.body)?;
        if let Some(nonce) = &self.nonce {
            enc.encode_text("nonce")?;
            enc.encode_bytes(nonce)?;
        }
        if let Some(key_id) = &self.key_id {
            enc.encode_text("key_id")?;
            enc.encode_bytes(key_id)?;
        }
        Ok(())
    }
}

impl PayloadEnc {
    /// Decode from an already-parsed CBOR map (avoids non-canonical re-encode in `decode_nested`).
    pub fn from_cbor_value(value: &CborValue) -> Result<Self, MnemeError> {
        let map = value.as_map().ok_or(MnemeError::SchemaDrift)?;
        parse_payload_enc_map(map.iter().map(|(k, v)| (k, v)))
    }
}

impl DcborDecode for PayloadEnc {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        parse_payload_enc_map(map.iter())
    }
}

fn parse_payload_enc_map<'a>(
    map: impl IntoIterator<Item = (&'a CborValue, &'a CborValue)>,
) -> Result<PayloadEnc, MnemeError> {
    let mut alg = None;
    let mut key_id = None;
    let mut nonce = None;
    let mut body = None;

    for (key, value) in map {
        let name = key.as_text().ok_or(MnemeError::SchemaDrift)?;
        match name {
            "alg" => alg = Some(parse_u8(value)?),
            "key_id" => key_id = Some(Some(parse_fixed16(value)?)),
            "nonce" => nonce = Some(Some(parse_fixed24(value)?)),
            "body" => body = Some(parse_bytes(value)?),
            other => {
                return Err(MnemeError::UnknownField {
                    field: hash_field(other),
                });
            }
        }
    }

    Ok(PayloadEnc {
        alg: alg.ok_or(MnemeError::SchemaDrift)?,
        key_id: key_id.unwrap_or(None),
        nonce: nonce.unwrap_or(None),
        body: body.ok_or(MnemeError::SchemaDrift)?,
    })
}

fn encode_hlc_wire(enc: &mut Encoder, hlc: &HlcWire) -> Result<(), MnemeError> {
    enc.begin_array(3)?;
    enc.encode_unsigned(hlc.wall_ms)?;
    enc.encode_unsigned(u64::from(hlc.counter))?;
    enc.encode_bytes(&hlc.node_id)?;
    Ok(())
}

fn parse_hlc_wire(value: &CborValue) -> Result<HlcWire, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::HlcMalformed)?;
    if arr.len() != 3 {
        return Err(MnemeError::HlcMalformed);
    }
    let wall_ms = arr[0].as_u64().ok_or(MnemeError::HlcMalformed)?;
    let counter = u32::try_from(arr[1].as_u64().ok_or(MnemeError::HlcMalformed)?)
        .map_err(|_| MnemeError::HlcMalformed)?;
    let node_bytes = arr[2].as_bytes().ok_or(MnemeError::HlcMalformed)?;
    if node_bytes.len() != 16 {
        return Err(MnemeError::HlcMalformed);
    }
    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(node_bytes);
    Ok(HlcWire {
        wall_ms,
        counter,
        node_id,
    })
}

fn encode_ext_map(enc: &mut Encoder, ext: &BTreeMap<u16, Vec<u8>>) -> Result<(), MnemeError> {
    enc.begin_map(ext.len() as u64)?;
    for (k, v) in ext {
        enc.encode_unsigned(u64::from(*k))?;
        enc.encode_bytes(v)?;
    }
    Ok(())
}

fn parse_ext_map(value: &CborValue) -> Result<BTreeMap<u16, Vec<u8>>, MnemeError> {
    let entries = value.as_map().ok_or(MnemeError::SchemaDrift)?;
    let mut out = BTreeMap::new();
    for (k, v) in entries {
        let key = u16::try_from(k.as_u64().ok_or(MnemeError::SchemaDrift)?)
            .map_err(|_| MnemeError::SchemaDrift)?;
        if key > 999 {
            return Err(MnemeError::UnknownField { field: key });
        }
        out.insert(key, parse_bytes(v)?);
    }
    Ok(out)
}

fn parse_parent_ids(value: &CborValue) -> Result<Vec<[u8; 32]>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(parse_fixed32(item)?);
    }
    if !is_sorted_asc(&out) {
        return Err(MnemeError::SerializationNonCanonical);
    }
    Ok(out)
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    u16::try_from(value.as_u64().ok_or(MnemeError::SchemaDrift)?)
        .map_err(|_| MnemeError::SchemaDrift)
}

fn parse_u8(value: &CborValue) -> Result<u8, MnemeError> {
    u8::try_from(value.as_u64().ok_or(MnemeError::SchemaDrift)?)
        .map_err(|_| MnemeError::SchemaDrift)
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != 32 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fixed16(value: &CborValue) -> Result<[u8; 16], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != 16 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fixed24(value: &CborValue) -> Result<[u8; 24], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != 24 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 24];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn is_sorted_asc(ids: &[[u8; 32]]) -> bool {
    ids.windows(2).all(|w| w[0] <= w[1])
}

fn hash_field(name: &str) -> u16 {
    let mut sum: u16 = 0;
    for b in name.as_bytes() {
        sum = sum.wrapping_mul(31).wrapping_add(u16::from(*b));
    }
    sum
}

/// Extension field: valid-time (world time) in milliseconds since epoch.
pub const EXT_VALID_TIME_MS: u16 = 1;

pub fn ext_map_with_valid_time(ms: u64) -> BTreeMap<u16, Vec<u8>> {
    let mut m = BTreeMap::new();
    m.insert(EXT_VALID_TIME_MS, ms.to_le_bytes().to_vec());
    m
}

pub fn valid_time_from_ext(ext: &Option<BTreeMap<u16, Vec<u8>>>) -> Option<u64> {
    let bytes = ext.as_ref()?.get(&EXT_VALID_TIME_MS)?;
    if bytes.len() != 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Some(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv1_object_id_is_pure_function_of_bytes() {
        let rec = ObjectRecord::fixture(MemoryKind::Episodic);
        let id1 = rec.compute_id().unwrap();
        let id2 = rec.compute_id().unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn inv7_rejects_unknown_object_field() {
        let mut enc = Encoder::new();
        enc.begin_map(1).unwrap();
        enc.encode_unsigned(99).unwrap();
        enc.encode_unsigned(1).unwrap();
        let bytes = enc.finish();
        assert_eq!(
            ObjectRecord::from_canonical_bytes(&bytes).unwrap_err(),
            MnemeError::UnknownField { field: 99 }
        );
    }
}
