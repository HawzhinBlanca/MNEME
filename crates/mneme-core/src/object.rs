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
            _ => Err(invalid_memory_kind_error()),
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
            _ => Err(invalid_trust_tier_error()),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectRecordDecodeFailure {
    Version,
    Kind,
    ParentIds,
    Writer,
    Session,
    Hlc,
    TrustTier,
    PayloadEnc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadEncDecodeFailure {
    Map,
    KeyName,
    Alg,
    Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectCollectionParseFailure {
    ExtMap,
    ExtKeyUnsigned,
    ExtKeyWidth,
    ParentIdsArray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectScalarParseFailure {
    FieldKeyUnsigned,
    U16Unsigned,
    U16Width,
    U8Unsigned,
    U8Width,
    BytesValue,
    Fixed32Bytes,
    Fixed32Length,
    Fixed16Bytes,
    Fixed16Length,
    Fixed24Bytes,
    Fixed24Length,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectEnumDecodeFailure {
    InvalidMemoryKind,
    InvalidTrustTier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectInvariantFailure {
    ParentIdsNotSorted,
    EncryptedPayloadMissingMaterial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectHlcWireParseFailure {
    Array,
    ArrayLength,
    WallMsUnsigned,
    CounterUnsigned,
    CounterWidth,
    NodeIdBytes,
    NodeIdLength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectTypedFailure {
    UnsupportedVersion { got: u16 },
    ObjectEncodeUnknownField { field: u16 },
    ObjectDecodeUnknownField { field: u16 },
    PayloadUnknownField { field: u16 },
    ExtUnknownField { field: u16 },
    ParentIdsNonCanonical,
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
            return Err(unsupported_object_version_error(self.version));
        }
        MemoryKind::try_from(self.kind)?;
        TrustTier::from_u8(self.trust_tier)?;
        if !is_sorted_asc(&self.parent_ids) {
            return Err(unsorted_parent_ids_error());
        }
        if self.payload_enc.alg == 1
            && (self.payload_enc.key_id.is_none() || self.payload_enc.nonce.is_none())
        {
            return Err(encrypted_payload_missing_material_error());
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
                _ => return Err(object_encode_unknown_field_error(*key)),
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
                    return Err(object_decode_unknown_field_error(field));
                }
            }
        }

        let record = Self {
            version: version.ok_or_else(missing_object_version_error)?,
            kind: kind.ok_or_else(missing_object_kind_error)?,
            parent_ids: parent_ids.ok_or_else(missing_object_parent_ids_error)?,
            writer: writer.ok_or_else(missing_object_writer_error)?,
            session: session.ok_or_else(missing_object_session_error)?,
            hlc: hlc.ok_or_else(missing_object_hlc_error)?,
            trust_tier: trust_tier.ok_or_else(missing_object_trust_tier_error)?,
            payload_enc: payload_enc.ok_or_else(missing_object_payload_enc_error)?,
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
        let map = value.as_map().ok_or_else(expected_payload_map_error)?;
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
        let name = key.as_text().ok_or_else(payload_key_name_error)?;
        match name {
            "alg" => alg = Some(parse_u8(value)?),
            "key_id" => key_id = Some(Some(parse_fixed16(value)?)),
            "nonce" => nonce = Some(Some(parse_fixed24(value)?)),
            "body" => body = Some(parse_bytes(value)?),
            other => {
                return Err(payload_unknown_field_error(other));
            }
        }
    }

    Ok(PayloadEnc {
        alg: alg.ok_or_else(missing_payload_alg_error)?,
        key_id: key_id.unwrap_or(None),
        nonce: nonce.unwrap_or(None),
        body: body.ok_or_else(missing_payload_body_error)?,
    })
}

fn object_enum_decode_failure_to_mneme(failure: ObjectEnumDecodeFailure) -> MnemeError {
    match failure {
        ObjectEnumDecodeFailure::InvalidMemoryKind | ObjectEnumDecodeFailure::InvalidTrustTier => {
            MnemeError::SchemaDrift
        }
    }
}

fn invalid_memory_kind_error() -> MnemeError {
    object_enum_decode_failure_to_mneme(ObjectEnumDecodeFailure::InvalidMemoryKind)
}

fn invalid_trust_tier_error() -> MnemeError {
    object_enum_decode_failure_to_mneme(ObjectEnumDecodeFailure::InvalidTrustTier)
}

fn object_invariant_failure_to_mneme(failure: ObjectInvariantFailure) -> MnemeError {
    match failure {
        ObjectInvariantFailure::ParentIdsNotSorted
        | ObjectInvariantFailure::EncryptedPayloadMissingMaterial => MnemeError::SchemaDrift,
    }
}

fn unsorted_parent_ids_error() -> MnemeError {
    object_invariant_failure_to_mneme(ObjectInvariantFailure::ParentIdsNotSorted)
}

fn encrypted_payload_missing_material_error() -> MnemeError {
    object_invariant_failure_to_mneme(ObjectInvariantFailure::EncryptedPayloadMissingMaterial)
}

fn object_typed_failure_to_mneme(failure: ObjectTypedFailure) -> MnemeError {
    match failure {
        ObjectTypedFailure::UnsupportedVersion { got } => MnemeError::UnsupportedVersion { got },
        ObjectTypedFailure::ObjectEncodeUnknownField { field }
        | ObjectTypedFailure::ObjectDecodeUnknownField { field }
        | ObjectTypedFailure::PayloadUnknownField { field }
        | ObjectTypedFailure::ExtUnknownField { field } => MnemeError::UnknownField { field },
        ObjectTypedFailure::ParentIdsNonCanonical => MnemeError::SerializationNonCanonical,
    }
}

fn unsupported_object_version_error(got: u16) -> MnemeError {
    object_typed_failure_to_mneme(ObjectTypedFailure::UnsupportedVersion { got })
}

fn object_encode_unknown_field_error(field: u64) -> MnemeError {
    object_typed_failure_to_mneme(ObjectTypedFailure::ObjectEncodeUnknownField {
        field: field as u16,
    })
}

fn object_decode_unknown_field_error(field: u64) -> MnemeError {
    object_typed_failure_to_mneme(ObjectTypedFailure::ObjectDecodeUnknownField {
        field: field as u16,
    })
}

fn payload_unknown_field_error(name: &str) -> MnemeError {
    object_typed_failure_to_mneme(ObjectTypedFailure::PayloadUnknownField {
        field: hash_field(name),
    })
}

fn ext_unknown_field_error(field: u16) -> MnemeError {
    object_typed_failure_to_mneme(ObjectTypedFailure::ExtUnknownField { field })
}

fn parent_ids_non_canonical_error() -> MnemeError {
    object_typed_failure_to_mneme(ObjectTypedFailure::ParentIdsNonCanonical)
}

fn object_record_decode_failure_to_mneme(failure: ObjectRecordDecodeFailure) -> MnemeError {
    match failure {
        ObjectRecordDecodeFailure::Version
        | ObjectRecordDecodeFailure::Kind
        | ObjectRecordDecodeFailure::ParentIds
        | ObjectRecordDecodeFailure::Writer
        | ObjectRecordDecodeFailure::Session
        | ObjectRecordDecodeFailure::Hlc
        | ObjectRecordDecodeFailure::TrustTier
        | ObjectRecordDecodeFailure::PayloadEnc => MnemeError::SchemaDrift,
    }
}

fn missing_object_version_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::Version)
}

fn missing_object_kind_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::Kind)
}

fn missing_object_parent_ids_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::ParentIds)
}

fn missing_object_writer_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::Writer)
}

fn missing_object_session_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::Session)
}

fn missing_object_hlc_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::Hlc)
}

fn missing_object_trust_tier_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::TrustTier)
}

fn missing_object_payload_enc_error() -> MnemeError {
    object_record_decode_failure_to_mneme(ObjectRecordDecodeFailure::PayloadEnc)
}

fn payload_enc_decode_failure_to_mneme(failure: PayloadEncDecodeFailure) -> MnemeError {
    match failure {
        PayloadEncDecodeFailure::Map
        | PayloadEncDecodeFailure::KeyName
        | PayloadEncDecodeFailure::Alg
        | PayloadEncDecodeFailure::Body => MnemeError::SchemaDrift,
    }
}

fn expected_payload_map_error() -> MnemeError {
    payload_enc_decode_failure_to_mneme(PayloadEncDecodeFailure::Map)
}

fn payload_key_name_error() -> MnemeError {
    payload_enc_decode_failure_to_mneme(PayloadEncDecodeFailure::KeyName)
}

fn missing_payload_alg_error() -> MnemeError {
    payload_enc_decode_failure_to_mneme(PayloadEncDecodeFailure::Alg)
}

fn missing_payload_body_error() -> MnemeError {
    payload_enc_decode_failure_to_mneme(PayloadEncDecodeFailure::Body)
}

fn object_collection_parse_failure_to_mneme(failure: ObjectCollectionParseFailure) -> MnemeError {
    match failure {
        ObjectCollectionParseFailure::ExtMap
        | ObjectCollectionParseFailure::ExtKeyUnsigned
        | ObjectCollectionParseFailure::ExtKeyWidth
        | ObjectCollectionParseFailure::ParentIdsArray => MnemeError::SchemaDrift,
    }
}

fn expected_ext_map_error() -> MnemeError {
    object_collection_parse_failure_to_mneme(ObjectCollectionParseFailure::ExtMap)
}

fn ext_key_unsigned_error() -> MnemeError {
    object_collection_parse_failure_to_mneme(ObjectCollectionParseFailure::ExtKeyUnsigned)
}

fn ext_key_width_error() -> MnemeError {
    object_collection_parse_failure_to_mneme(ObjectCollectionParseFailure::ExtKeyWidth)
}

fn expected_parent_ids_array_error() -> MnemeError {
    object_collection_parse_failure_to_mneme(ObjectCollectionParseFailure::ParentIdsArray)
}

fn object_scalar_parse_failure_to_mneme(failure: ObjectScalarParseFailure) -> MnemeError {
    match failure {
        ObjectScalarParseFailure::FieldKeyUnsigned
        | ObjectScalarParseFailure::U16Unsigned
        | ObjectScalarParseFailure::U16Width
        | ObjectScalarParseFailure::U8Unsigned
        | ObjectScalarParseFailure::U8Width
        | ObjectScalarParseFailure::BytesValue
        | ObjectScalarParseFailure::Fixed32Bytes
        | ObjectScalarParseFailure::Fixed32Length
        | ObjectScalarParseFailure::Fixed16Bytes
        | ObjectScalarParseFailure::Fixed16Length
        | ObjectScalarParseFailure::Fixed24Bytes
        | ObjectScalarParseFailure::Fixed24Length => MnemeError::SchemaDrift,
    }
}

fn field_key_unsigned_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::FieldKeyUnsigned)
}

fn u16_unsigned_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::U16Unsigned)
}

fn u16_width_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::U16Width)
}

fn u8_unsigned_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::U8Unsigned)
}

fn u8_width_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::U8Width)
}

fn bytes_value_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::BytesValue)
}

fn fixed32_bytes_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::Fixed32Bytes)
}

fn fixed32_length_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::Fixed32Length)
}

fn fixed16_bytes_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::Fixed16Bytes)
}

fn fixed16_length_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::Fixed16Length)
}

fn fixed24_bytes_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::Fixed24Bytes)
}

fn fixed24_length_error() -> MnemeError {
    object_scalar_parse_failure_to_mneme(ObjectScalarParseFailure::Fixed24Length)
}

fn object_hlc_wire_parse_failure_to_mneme(failure: ObjectHlcWireParseFailure) -> MnemeError {
    match failure {
        ObjectHlcWireParseFailure::Array
        | ObjectHlcWireParseFailure::ArrayLength
        | ObjectHlcWireParseFailure::WallMsUnsigned
        | ObjectHlcWireParseFailure::CounterUnsigned
        | ObjectHlcWireParseFailure::CounterWidth
        | ObjectHlcWireParseFailure::NodeIdBytes
        | ObjectHlcWireParseFailure::NodeIdLength => MnemeError::HlcMalformed,
    }
}

fn expected_hlc_array_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::Array)
}

fn invalid_hlc_array_length_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::ArrayLength)
}

fn hlc_wall_ms_unsigned_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::WallMsUnsigned)
}

fn hlc_counter_unsigned_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::CounterUnsigned)
}

fn hlc_counter_width_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::CounterWidth)
}

fn hlc_node_id_bytes_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::NodeIdBytes)
}

fn hlc_node_id_length_error() -> MnemeError {
    object_hlc_wire_parse_failure_to_mneme(ObjectHlcWireParseFailure::NodeIdLength)
}

fn encode_hlc_wire(enc: &mut Encoder, hlc: &HlcWire) -> Result<(), MnemeError> {
    enc.begin_array(3)?;
    enc.encode_unsigned(hlc.wall_ms)?;
    enc.encode_unsigned(u64::from(hlc.counter))?;
    enc.encode_bytes(&hlc.node_id)?;
    Ok(())
}

fn parse_hlc_wire(value: &CborValue) -> Result<HlcWire, MnemeError> {
    let arr = value.as_array().ok_or_else(expected_hlc_array_error)?;
    if arr.len() != 3 {
        return Err(invalid_hlc_array_length_error());
    }
    let wall_ms = arr[0].as_u64().ok_or_else(hlc_wall_ms_unsigned_error)?;
    let counter = u32::try_from(arr[1].as_u64().ok_or_else(hlc_counter_unsigned_error)?)
        .map_err(|_| hlc_counter_width_error())?;
    let node_bytes = arr[2].as_bytes().ok_or_else(hlc_node_id_bytes_error)?;
    if node_bytes.len() != 16 {
        return Err(hlc_node_id_length_error());
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
    let entries = value.as_map().ok_or_else(expected_ext_map_error)?;
    let mut out = BTreeMap::new();
    for (k, v) in entries {
        let key = u16::try_from(k.as_u64().ok_or_else(ext_key_unsigned_error)?)
            .map_err(|_| ext_key_width_error())?;
        if key > 999 {
            return Err(ext_unknown_field_error(key));
        }
        out.insert(key, parse_bytes(v)?);
    }
    Ok(out)
}

fn parse_parent_ids(value: &CborValue) -> Result<Vec<[u8; 32]>, MnemeError> {
    let arr = value
        .as_array()
        .ok_or_else(expected_parent_ids_array_error)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(parse_fixed32(item)?);
    }
    if !is_sorted_asc(&out) {
        return Err(parent_ids_non_canonical_error());
    }
    Ok(out)
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or_else(field_key_unsigned_error)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    u16::try_from(value.as_u64().ok_or_else(u16_unsigned_error)?).map_err(|_| u16_width_error())
}

fn parse_u8(value: &CborValue) -> Result<u8, MnemeError> {
    u8::try_from(value.as_u64().ok_or_else(u8_unsigned_error)?).map_err(|_| u8_width_error())
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(bytes_value_error)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or_else(fixed32_bytes_error)?;
    if bytes.len() != 32 {
        return Err(fixed32_length_error());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fixed16(value: &CborValue) -> Result<[u8; 16], MnemeError> {
    let bytes = value.as_bytes().ok_or_else(fixed16_bytes_error)?;
    if bytes.len() != 16 {
        return Err(fixed16_length_error());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fixed24(value: &CborValue) -> Result<[u8; 24], MnemeError> {
    let bytes = value.as_bytes().ok_or_else(fixed24_bytes_error)?;
    if bytes.len() != 24 {
        return Err(fixed24_length_error());
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

/// Extension field: embargo round.
pub const EXT_EMBARGO_ROUND: u16 = 2;

/// Extension field: tlock key ciphertext.
pub const EXT_TLOCK_KEY_CIPHERTEXT: u16 = 3;

pub fn ext_map_with_embargo(
    valid_time_ms: Option<u64>,
    round: Option<u64>,
    ciphertext: Option<&[u8]>,
) -> BTreeMap<u16, Vec<u8>> {
    let mut m = BTreeMap::new();
    if let Some(ms) = valid_time_ms {
        m.insert(EXT_VALID_TIME_MS, ms.to_le_bytes().to_vec());
    }
    if let Some(r) = round {
        m.insert(EXT_EMBARGO_ROUND, r.to_be_bytes().to_vec());
    }
    if let Some(ct) = ciphertext {
        m.insert(EXT_TLOCK_KEY_CIPHERTEXT, ct.to_vec());
    }
    m
}

pub fn embargo_from_ext(ext: &Option<BTreeMap<u16, Vec<u8>>>) -> Option<(u64, Vec<u8>)> {
    let ext_map = ext.as_ref()?;
    let round_bytes = ext_map.get(&EXT_EMBARGO_ROUND)?;
    if round_bytes.len() != 8 {
        return None;
    }
    let mut round_arr = [0u8; 8];
    round_arr.copy_from_slice(round_bytes);
    let round = u64::from_be_bytes(round_arr);

    let ciphertext = ext_map.get(&EXT_TLOCK_KEY_CIPHERTEXT)?.clone();
    Some((round, ciphertext))
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
        let (_, after_start) = source
            .split_once(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let (section, _) = after_start
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        section
    }

    #[test]
    fn object_enum_value_failures_are_classified_not_schema_drift_collapsed() {
        let object = include_str!("object.rs");
        let memory_kind_section = source_between_markers(
            object,
            "impl TryFrom<u8> for MemoryKind",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]\n#[repr(u8)]\npub enum TrustTier",
            "MemoryKind decode",
        );
        let trust_tier_section = source_between_markers(
            object,
            "impl TrustTier",
            "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct PayloadEnc",
            "TrustTier decode",
        );

        for forbidden in [
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !memory_kind_section.contains(forbidden),
                "MemoryKind decode should route `{forbidden}` through named classifiers"
            );
            assert!(
                !trust_tier_section.contains(forbidden),
                "TrustTier decode should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ObjectEnumDecodeFailure",
            "fn object_enum_decode_failure_to_mneme(",
            "fn invalid_memory_kind_error(",
            "fn invalid_trust_tier_error(",
            "ObjectEnumDecodeFailure::InvalidMemoryKind",
            "ObjectEnumDecodeFailure::InvalidTrustTier",
        ] {
            assert!(
                object.contains(required),
                "object enum decode classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_enum_decode_failure_classifier_preserves_schema_failures() {
        for failure in [
            ObjectEnumDecodeFailure::InvalidMemoryKind,
            ObjectEnumDecodeFailure::InvalidTrustTier,
        ] {
            assert_eq!(
                object_enum_decode_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn object_invariant_failures_are_classified_not_schema_drift_collapsed() {
        let object = include_str!("object.rs");
        let section = source_between_markers(
            object,
            "pub fn validate_invariants(&self)",
            "/// Build a deterministic fixture",
            "ObjectRecord invariant validation",
        );

        for forbidden in [
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "ObjectRecord invariant validation should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ObjectInvariantFailure",
            "fn object_invariant_failure_to_mneme(",
            "fn unsorted_parent_ids_error(",
            "fn encrypted_payload_missing_material_error(",
            "ObjectInvariantFailure::ParentIdsNotSorted",
            "ObjectInvariantFailure::EncryptedPayloadMissingMaterial",
        ] {
            assert!(
                object.contains(required),
                "ObjectRecord invariant classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_invariant_failure_classifier_preserves_schema_failures() {
        for failure in [
            ObjectInvariantFailure::ParentIdsNotSorted,
            ObjectInvariantFailure::EncryptedPayloadMissingMaterial,
        ] {
            assert_eq!(
                object_invariant_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn object_hlc_wire_parse_failures_are_classified_not_malformed_collapsed() {
        let object = include_str!("object.rs");
        let section = source_between_markers(
            object,
            "fn parse_hlc_wire(",
            "fn encode_ext_map(",
            "HLC wire parser",
        );

        for forbidden in [
            "ok_or(MnemeError::HlcMalformed)",
            "return Err(MnemeError::HlcMalformed)",
            "map_err(|_| MnemeError::HlcMalformed)",
        ] {
            assert!(
                !section.contains(forbidden),
                "HLC wire parser should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ObjectHlcWireParseFailure",
            "fn object_hlc_wire_parse_failure_to_mneme(",
            "fn expected_hlc_array_error(",
            "fn invalid_hlc_array_length_error(",
            "fn hlc_wall_ms_unsigned_error(",
            "fn hlc_counter_unsigned_error(",
            "fn hlc_counter_width_error(",
            "fn hlc_node_id_bytes_error(",
            "fn hlc_node_id_length_error(",
            "ObjectHlcWireParseFailure::Array",
            "ObjectHlcWireParseFailure::ArrayLength",
            "ObjectHlcWireParseFailure::WallMsUnsigned",
            "ObjectHlcWireParseFailure::CounterUnsigned",
            "ObjectHlcWireParseFailure::CounterWidth",
            "ObjectHlcWireParseFailure::NodeIdBytes",
            "ObjectHlcWireParseFailure::NodeIdLength",
        ] {
            assert!(
                object.contains(required),
                "HLC wire parser classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_hlc_wire_parse_failure_classifier_preserves_hlc_malformed() {
        for failure in [
            ObjectHlcWireParseFailure::Array,
            ObjectHlcWireParseFailure::ArrayLength,
            ObjectHlcWireParseFailure::WallMsUnsigned,
            ObjectHlcWireParseFailure::CounterUnsigned,
            ObjectHlcWireParseFailure::CounterWidth,
            ObjectHlcWireParseFailure::NodeIdBytes,
            ObjectHlcWireParseFailure::NodeIdLength,
        ] {
            assert_eq!(
                object_hlc_wire_parse_failure_to_mneme(failure),
                MnemeError::HlcMalformed
            );
        }
    }

    #[test]
    fn object_typed_error_sites_are_classified_not_directly_returned() {
        let object = include_str!("object.rs");
        let sections = [
            source_between_markers(
                object,
                "pub fn validate_invariants(&self)",
                "/// Build a deterministic fixture",
                "ObjectRecord invariant validation",
            ),
            source_between_markers(
                object,
                "impl DcborEncode for ObjectRecord",
                "impl DcborDecode for ObjectRecord",
                "ObjectRecord dCBOR encode",
            ),
            source_between_markers(
                object,
                "impl DcborDecode for ObjectRecord",
                "impl DcborEncode for PayloadEnc",
                "ObjectRecord dCBOR decode",
            ),
            source_between_markers(
                object,
                "fn parse_payload_enc_map",
                "fn object_typed_failure_to_mneme",
                "PayloadEnc parser",
            ),
            source_between_markers(
                object,
                "fn parse_ext_map(",
                "fn parse_parent_ids(",
                "extension map parser",
            ),
            source_between_markers(
                object,
                "fn parse_parent_ids(",
                "fn parse_u64_field_key(",
                "parent IDs parser",
            ),
        ];

        for section in sections {
            for forbidden in [
                "return Err(MnemeError::UnsupportedVersion",
                "return Err(MnemeError::UnknownField",
                "return Err(MnemeError::SerializationNonCanonical)",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "object typed error site should route `{forbidden}` through named classifiers"
                );
            }
        }

        for required in [
            "enum ObjectTypedFailure",
            "fn object_typed_failure_to_mneme(",
            "fn unsupported_object_version_error(",
            "fn object_encode_unknown_field_error(",
            "fn object_decode_unknown_field_error(",
            "fn payload_unknown_field_error(",
            "fn ext_unknown_field_error(",
            "fn parent_ids_non_canonical_error(",
            "ObjectTypedFailure::UnsupportedVersion",
            "ObjectTypedFailure::ObjectEncodeUnknownField",
            "ObjectTypedFailure::ObjectDecodeUnknownField",
            "ObjectTypedFailure::PayloadUnknownField",
            "ObjectTypedFailure::ExtUnknownField",
            "ObjectTypedFailure::ParentIdsNonCanonical",
        ] {
            assert!(
                object.contains(required),
                "object typed error classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_typed_error_classifier_preserves_public_errors() {
        assert_eq!(
            unsupported_object_version_error(7),
            MnemeError::UnsupportedVersion { got: 7 }
        );
        assert_eq!(
            object_encode_unknown_field_error(65_537),
            MnemeError::UnknownField { field: 1 }
        );
        assert_eq!(
            object_decode_unknown_field_error(65_538),
            MnemeError::UnknownField { field: 2 }
        );
        assert_eq!(
            payload_unknown_field_error("surprise"),
            MnemeError::UnknownField {
                field: hash_field("surprise")
            }
        );
        assert_eq!(
            ext_unknown_field_error(1_000),
            MnemeError::UnknownField { field: 1_000 }
        );
        assert_eq!(
            parent_ids_non_canonical_error(),
            MnemeError::SerializationNonCanonical
        );
    }

    #[test]
    fn object_record_decode_missing_fields_are_classified_not_schema_drift_collapsed() {
        let object = include_str!("object.rs");
        let section = source_between_markers(
            object,
            "impl DcborDecode for ObjectRecord",
            "impl DcborEncode for PayloadEnc",
            "ObjectRecord dCBOR decode",
        );

        assert!(
            !section.contains("ok_or(MnemeError::SchemaDrift)"),
            "ObjectRecord decode missing required fields should route through named classifiers"
        );

        for required in [
            "enum ObjectRecordDecodeFailure",
            "fn object_record_decode_failure_to_mneme(",
            "fn missing_object_version_error(",
            "fn missing_object_kind_error(",
            "fn missing_object_parent_ids_error(",
            "fn missing_object_writer_error(",
            "fn missing_object_session_error(",
            "fn missing_object_hlc_error(",
            "fn missing_object_trust_tier_error(",
            "fn missing_object_payload_enc_error(",
            "ObjectRecordDecodeFailure::Version",
            "ObjectRecordDecodeFailure::Kind",
            "ObjectRecordDecodeFailure::ParentIds",
            "ObjectRecordDecodeFailure::Writer",
            "ObjectRecordDecodeFailure::Session",
            "ObjectRecordDecodeFailure::Hlc",
            "ObjectRecordDecodeFailure::TrustTier",
            "ObjectRecordDecodeFailure::PayloadEnc",
        ] {
            assert!(
                object.contains(required),
                "ObjectRecord decode missing-field classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_record_decode_failure_classifier_preserves_schema_failures() {
        for failure in [
            ObjectRecordDecodeFailure::Version,
            ObjectRecordDecodeFailure::Kind,
            ObjectRecordDecodeFailure::ParentIds,
            ObjectRecordDecodeFailure::Writer,
            ObjectRecordDecodeFailure::Session,
            ObjectRecordDecodeFailure::Hlc,
            ObjectRecordDecodeFailure::TrustTier,
            ObjectRecordDecodeFailure::PayloadEnc,
        ] {
            assert_eq!(
                object_record_decode_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn payload_enc_decode_failures_are_classified_not_schema_drift_collapsed() {
        let object = include_str!("object.rs");
        let section = source_between_markers(
            object,
            "impl PayloadEnc",
            "fn object_record_decode_failure_to_mneme",
            "PayloadEnc decode",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "PayloadEnc decode should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum PayloadEncDecodeFailure",
            "fn payload_enc_decode_failure_to_mneme(",
            "fn expected_payload_map_error(",
            "fn payload_key_name_error(",
            "fn missing_payload_alg_error(",
            "fn missing_payload_body_error(",
            "PayloadEncDecodeFailure::Map",
            "PayloadEncDecodeFailure::KeyName",
            "PayloadEncDecodeFailure::Alg",
            "PayloadEncDecodeFailure::Body",
        ] {
            assert!(
                object.contains(required),
                "PayloadEnc decode failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn payload_enc_decode_failure_classifier_preserves_schema_failures() {
        for failure in [
            PayloadEncDecodeFailure::Map,
            PayloadEncDecodeFailure::KeyName,
            PayloadEncDecodeFailure::Alg,
            PayloadEncDecodeFailure::Body,
        ] {
            assert_eq!(
                payload_enc_decode_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn object_collection_parse_failures_are_classified_not_schema_drift_collapsed() {
        let object = include_str!("object.rs");
        let section = source_between_markers(
            object,
            "fn parse_ext_map(",
            "fn parse_u64_field_key(",
            "object collection parsers",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "object collection parsers should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ObjectCollectionParseFailure",
            "fn object_collection_parse_failure_to_mneme(",
            "fn expected_ext_map_error(",
            "fn ext_key_unsigned_error(",
            "fn ext_key_width_error(",
            "fn expected_parent_ids_array_error(",
            "ObjectCollectionParseFailure::ExtMap",
            "ObjectCollectionParseFailure::ExtKeyUnsigned",
            "ObjectCollectionParseFailure::ExtKeyWidth",
            "ObjectCollectionParseFailure::ParentIdsArray",
        ] {
            assert!(
                object.contains(required),
                "object collection parser classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_collection_parse_failure_classifier_preserves_schema_failures() {
        for failure in [
            ObjectCollectionParseFailure::ExtMap,
            ObjectCollectionParseFailure::ExtKeyUnsigned,
            ObjectCollectionParseFailure::ExtKeyWidth,
            ObjectCollectionParseFailure::ParentIdsArray,
        ] {
            assert_eq!(
                object_collection_parse_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn object_scalar_parse_failures_are_classified_not_schema_drift_collapsed() {
        let object = include_str!("object.rs");
        let section = source_between_markers(
            object,
            "fn parse_u64_field_key(",
            "fn is_sorted_asc(",
            "object scalar parsers",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "object scalar parsers should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ObjectScalarParseFailure",
            "fn object_scalar_parse_failure_to_mneme(",
            "fn field_key_unsigned_error(",
            "fn u16_unsigned_error(",
            "fn u16_width_error(",
            "fn u8_unsigned_error(",
            "fn u8_width_error(",
            "fn bytes_value_error(",
            "fn fixed32_bytes_error(",
            "fn fixed32_length_error(",
            "fn fixed16_bytes_error(",
            "fn fixed16_length_error(",
            "fn fixed24_bytes_error(",
            "fn fixed24_length_error(",
            "ObjectScalarParseFailure::FieldKeyUnsigned",
            "ObjectScalarParseFailure::U16Unsigned",
            "ObjectScalarParseFailure::U16Width",
            "ObjectScalarParseFailure::U8Unsigned",
            "ObjectScalarParseFailure::U8Width",
            "ObjectScalarParseFailure::BytesValue",
            "ObjectScalarParseFailure::Fixed32Bytes",
            "ObjectScalarParseFailure::Fixed32Length",
            "ObjectScalarParseFailure::Fixed16Bytes",
            "ObjectScalarParseFailure::Fixed16Length",
            "ObjectScalarParseFailure::Fixed24Bytes",
            "ObjectScalarParseFailure::Fixed24Length",
        ] {
            assert!(
                object.contains(required),
                "object scalar parser classification should include `{required}`"
            );
        }
    }

    #[test]
    fn object_scalar_parse_failure_classifier_preserves_schema_failures() {
        for failure in [
            ObjectScalarParseFailure::FieldKeyUnsigned,
            ObjectScalarParseFailure::U16Unsigned,
            ObjectScalarParseFailure::U16Width,
            ObjectScalarParseFailure::U8Unsigned,
            ObjectScalarParseFailure::U8Width,
            ObjectScalarParseFailure::BytesValue,
            ObjectScalarParseFailure::Fixed32Bytes,
            ObjectScalarParseFailure::Fixed32Length,
            ObjectScalarParseFailure::Fixed16Bytes,
            ObjectScalarParseFailure::Fixed16Length,
            ObjectScalarParseFailure::Fixed24Bytes,
            ObjectScalarParseFailure::Fixed24Length,
        ] {
            assert_eq!(
                object_scalar_parse_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

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
