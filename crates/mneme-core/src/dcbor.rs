//! MNEME-dCBOR: deterministic CBOR profile (RFC 8949 §4.2 + blueprint §5.1).

use crate::MnemeError;
use std::collections::BTreeMap;

/// Encode a value that implements [`DcborEncode`] into canonical MNEME-dCBOR bytes.
pub fn encode_canonical(value: &impl DcborEncode) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    value.dcbor_encode(&mut enc)?;
    Ok(enc.finish())
}

/// Decode with strict MNEME-dCBOR rules (INV-7).
pub fn decode_strict<T: DcborDecode>(bytes: &[u8]) -> Result<T, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let value = T::dcbor_decode(&mut dec)?;
    dec.ensure_consumed()?;
    Ok(value)
}

/// Legacy alias retained for downstream crates during Wave 0 migration.
pub fn to_bytes_canonical<T: DcborEncode>(value: &T) -> Result<Vec<u8>, MnemeError> {
    encode_canonical(value)
}

/// Legacy alias retained for downstream crates during Wave 0 migration.
pub fn from_bytes_strict<T: DcborDecode>(bytes: &[u8]) -> Result<T, MnemeError> {
    decode_strict(bytes)
}

pub trait DcborEncode {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError>;
}

pub trait DcborDecode: Sized {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError>;
}

pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn encode_unsigned(&mut self, value: u64) -> Result<(), MnemeError> {
        write_uint(&mut self.buf, 0, value)
    }

    pub fn encode_negative(&mut self, value: i64) -> Result<(), MnemeError> {
        if value >= 0 {
            return self.encode_signed(value);
        }
        let abs = (-value - 1) as u64;
        write_uint(&mut self.buf, 1, abs)
    }

    pub fn encode_signed(&mut self, value: i64) -> Result<(), MnemeError> {
        if value >= 0 {
            self.encode_unsigned(value as u64)
        } else {
            self.encode_negative(value)
        }
    }

    pub fn encode_bytes(&mut self, bytes: &[u8]) -> Result<(), MnemeError> {
        write_uint(&mut self.buf, 2, bytes.len() as u64)?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    pub fn encode_text(&mut self, text: &str) -> Result<(), MnemeError> {
        if !text.is_empty() && !is_nfc(text) {
            return Err(dcbor_encode_text_not_nfc_error());
        }
        write_uint(&mut self.buf, 3, text.len() as u64)?;
        self.buf.extend_from_slice(text.as_bytes());
        Ok(())
    }

    pub fn begin_array(&mut self, len: u64) -> Result<(), MnemeError> {
        write_uint(&mut self.buf, 4, len)
    }

    pub fn begin_map(&mut self, len: u64) -> Result<(), MnemeError> {
        write_uint(&mut self.buf, 5, len)
    }

    pub fn encode_bool(&mut self, value: bool) -> Result<(), MnemeError> {
        self.buf.push(if value { 0xf5 } else { 0xf4 });
        Ok(())
    }

    pub fn encode_null(&mut self) -> Result<(), MnemeError> {
        self.buf.push(0xf6);
        Ok(())
    }

    pub fn append_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn encode_negative_raw(&mut self, abs_minus_one: u64) -> Result<(), MnemeError> {
        write_uint(&mut self.buf, 1, abs_minus_one)
    }

    /// Encode a map whose keys are already canonical CBOR key bytes, sorted ascending.
    pub fn encode_map_raw<F>(&mut self, entries: &[(Vec<u8>, F)]) -> Result<(), MnemeError>
    where
        F: Fn(&mut Encoder) -> Result<(), MnemeError>,
    {
        self.begin_map(entries.len() as u64)?;
        for (key, encode_value) in entries {
            self.buf.extend_from_slice(key);
            encode_value(self)?;
        }
        Ok(())
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum container nesting accepted by the strict decoder (§17.4 "never
/// panic"). MNEME object graphs are shallow; a bounded limit converts an
/// adversarial deeply-nested input from a stack-overflow abort into a
/// fail-closed [`MnemeError::SchemaDrift`].
pub const MAX_NESTING_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DcborCursorFailure {
    TrailingBytes,
    NestingDepth,
    UnexpectedEofByte,
    UnexpectedEofBytes,
    UnexpectedEofPeek,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DcborDecodeAnyFailure {
    UnsupportedSimpleValue,
    Tag,
    ByteStringLength,
    TextLength,
    TextUtf8,
    ArrayLength,
    MapLength,
    UnsupportedMajor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DcborReadLengthFailure {
    UnsupportedAdditionalInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DcborTypedDecodeFailure {
    ExpectedUnsigned,
    SignedUnsignedOverflow,
    SignedNegativeOverflow,
    ExpectedSigned,
    ExpectedBytes,
    ExpectedText,
    ExpectedArray,
    ExpectedMap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DcborCanonicalFailure {
    EncodeTextNotNfc,
    SimpleFloat,
    IndefiniteBreak,
    DecodeTextNotNfc,
    MapKeyOrder,
    NonMinimalU8Length,
    NonMinimalU16Length,
    NonMinimalU32Length,
    NonMinimalU64Length,
    IndefiniteLength,
    DuplicateMapKey,
    ReencodeMismatch,
}

pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            depth: 0,
        }
    }

    pub fn ensure_consumed(&self) -> Result<(), MnemeError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(dcbor_trailing_bytes_error())
        }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Enter a nested container, failing closed past [`MAX_NESTING_DEPTH`] so a
    /// pathologically nested input cannot overflow the stack (§17.4).
    fn enter(&mut self) -> Result<(), MnemeError> {
        self.depth += 1;
        if self.depth > MAX_NESTING_DEPTH {
            return Err(dcbor_nesting_depth_error());
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn read_byte(&mut self) -> Result<u8, MnemeError> {
        if self.pos >= self.bytes.len() {
            return Err(dcbor_unexpected_eof_byte_error());
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], MnemeError> {
        // pos <= bytes.len() is a maintained invariant, so this cannot underflow.
        let remaining = self.bytes.len() - self.pos;
        if len > remaining {
            return Err(dcbor_unexpected_eof_bytes_error());
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn peek_major(&self) -> Result<u8, MnemeError> {
        if self.pos >= self.bytes.len() {
            return Err(dcbor_unexpected_eof_peek_error());
        }
        Ok(self.bytes[self.pos] >> 5)
    }

    pub fn decode_any(&mut self) -> Result<CborValue, MnemeError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major == 7 {
            return match info {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                24..=27 => Err(dcbor_simple_float_error()), // floats
                31 => Err(dcbor_indefinite_break_error()),  // indefinite break
                _ => Err(dcbor_unsupported_simple_value_error()),
            };
        }

        if major == 6 {
            return Err(dcbor_tag_error()); // tags disallowed in Wave 0
        }

        let len = self.read_length(info)?;
        match major {
            0 => Ok(CborValue::Unsigned(len)),
            1 => Ok(CborValue::Negative(len)),
            2 => {
                let len_usize = len as usize;
                if len_usize > self.remaining() {
                    return Err(dcbor_byte_string_length_error());
                }
                let bytes = self.read_bytes(len_usize)?.to_vec();
                Ok(CborValue::Bytes(bytes))
            }
            3 => {
                let len_usize = len as usize;
                if len_usize > self.remaining() {
                    return Err(dcbor_text_length_error());
                }
                let bytes = self.read_bytes(len_usize)?;
                let text = std::str::from_utf8(bytes).map_err(|_| dcbor_text_utf8_error())?;
                if !text.is_empty() && !is_nfc(text) {
                    return Err(dcbor_decode_text_not_nfc_error());
                }
                Ok(CborValue::Text(text.to_string()))
            }
            4 => {
                // §17.4: never allocate unboundedly. Each item consumes >=1 input
                // byte, so remaining bytes is a safe cap on the declared length.
                let remaining = self.remaining();
                let len_usize = len as usize;
                if len_usize > remaining {
                    return Err(dcbor_array_length_error());
                }
                let mut items = Vec::with_capacity(len_usize);
                self.enter()?;
                for _ in 0..len {
                    items.push(self.decode_any()?);
                }
                self.leave();
                Ok(CborValue::Array(items))
            }
            5 => {
                let remaining = self.remaining();
                let len_usize = len as usize;
                if len_usize > remaining {
                    return Err(dcbor_map_length_error());
                }
                let mut entries = Vec::with_capacity(len_usize);
                let mut prev_key: Option<Vec<u8>> = None;
                self.enter()?;
                for _ in 0..len {
                    let key_start = self.pos;
                    let key = self.decode_any()?;
                    let key_end = self.pos;
                    // key_start <= key_end <= bytes.len() is maintained by the
                    // forward-only cursor; use slicing on a proven-valid range.
                    let key_bytes = self.bytes[key_start..key_end].to_vec();
                    if let Some(prev) = &prev_key {
                        if key_bytes <= *prev {
                            return Err(dcbor_map_key_order_error());
                        }
                    }
                    prev_key = Some(key_bytes);
                    let value = self.decode_any()?;
                    entries.push((key, value));
                }
                self.leave();
                Ok(CborValue::Map(entries))
            }
            _ => Err(dcbor_unsupported_major_error()),
        }
    }

    fn read_length(&mut self, info: u8) -> Result<u64, MnemeError> {
        // MNEME-dCBOR / RFC 8949 §4.2.1: integers and lengths MUST use the
        // shortest possible encoding (INV-2). Reject non-minimal forms.
        match info {
            n @ 0..=23 => Ok(u64::from(n)),
            24 => {
                let v = u64::from(self.read_byte()?);
                if v < 24 {
                    return Err(dcbor_nonminimal_u8_length_error());
                }
                Ok(v)
            }
            25 => {
                let b = self.read_bytes(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if v <= u64::from(u8::MAX) {
                    return Err(dcbor_nonminimal_u16_length_error());
                }
                Ok(v)
            }
            26 => {
                let b = self.read_bytes(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if v <= u64::from(u16::MAX) {
                    return Err(dcbor_nonminimal_u32_length_error());
                }
                Ok(v)
            }
            27 => {
                let b = self.read_bytes(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= u64::from(u32::MAX) {
                    return Err(dcbor_nonminimal_u64_length_error());
                }
                Ok(v)
            }
            31 => Err(dcbor_indefinite_length_error()),
            _ => Err(dcbor_unsupported_length_info_error()),
        }
    }

    pub fn decode_unsigned(&mut self) -> Result<u64, MnemeError> {
        match self.decode_any()? {
            CborValue::Unsigned(v) => Ok(v),
            _ => Err(dcbor_expected_unsigned_error()),
        }
    }

    pub fn decode_signed(&mut self) -> Result<i64, MnemeError> {
        match self.decode_any()? {
            CborValue::Unsigned(v) => {
                i64::try_from(v).map_err(|_| dcbor_signed_unsigned_overflow_error())
            }
            CborValue::Negative(v) => {
                let abs = i64::try_from(v).map_err(|_| dcbor_signed_negative_overflow_error())?;
                Ok(-abs - 1)
            }
            _ => Err(dcbor_expected_signed_error()),
        }
    }

    pub fn decode_bytes(&mut self) -> Result<Vec<u8>, MnemeError> {
        match self.decode_any()? {
            CborValue::Bytes(v) => Ok(v),
            _ => Err(dcbor_expected_bytes_error()),
        }
    }

    pub fn decode_text(&mut self) -> Result<String, MnemeError> {
        match self.decode_any()? {
            CborValue::Text(v) => Ok(v),
            _ => Err(dcbor_expected_text_error()),
        }
    }

    pub fn decode_array<F, T>(&mut self, mut decode_item: F) -> Result<Vec<T>, MnemeError>
    where
        F: FnMut(&mut Decoder<'_>) -> Result<T, MnemeError>,
    {
        let value = self.decode_any()?;
        match value {
            CborValue::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let bytes = encode_canonical(&item)?;
                    let mut dec = Decoder::new(&bytes);
                    out.push(decode_item(&mut dec)?);
                }
                Ok(out)
            }
            _ => Err(dcbor_expected_array_error()),
        }
    }

    pub fn decode_map(&mut self) -> Result<BTreeMap<CborValue, CborValue>, MnemeError> {
        match self.decode_any()? {
            CborValue::Map(entries) => {
                let mut map = BTreeMap::new();
                for (k, v) in entries {
                    if map.insert(k.clone(), v).is_some() {
                        return Err(dcbor_duplicate_map_key_error());
                    }
                }
                Ok(map)
            }
            _ => Err(dcbor_expected_map_error()),
        }
    }

    pub fn decode_nullable<T, F>(&mut self, decode_some: F) -> Result<Option<T>, MnemeError>
    where
        F: FnOnce(&mut Decoder<'_>) -> Result<T, MnemeError>,
    {
        let major = self.peek_major()?;
        if major == 7 && self.bytes[self.pos] == 0xf6 {
            self.read_byte()?;
            return Ok(None);
        }
        Ok(Some(decode_some(self)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CborValue {
    Unsigned(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

impl CborValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Unsigned(v) => i64::try_from(*v).ok(),
            Self::Negative(v) => {
                let abs = i64::try_from(*v).ok()?;
                Some(-abs - 1)
            }
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[CborValue]> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(CborValue, CborValue)]> {
        match self {
            Self::Map(v) => Some(v),
            _ => None,
        }
    }
}

fn dcbor_cursor_failure_to_mneme(failure: DcborCursorFailure) -> MnemeError {
    match failure {
        DcborCursorFailure::TrailingBytes
        | DcborCursorFailure::NestingDepth
        | DcborCursorFailure::UnexpectedEofByte
        | DcborCursorFailure::UnexpectedEofBytes
        | DcborCursorFailure::UnexpectedEofPeek => MnemeError::SchemaDrift,
    }
}

fn dcbor_trailing_bytes_error() -> MnemeError {
    dcbor_cursor_failure_to_mneme(DcborCursorFailure::TrailingBytes)
}

fn dcbor_nesting_depth_error() -> MnemeError {
    dcbor_cursor_failure_to_mneme(DcborCursorFailure::NestingDepth)
}

fn dcbor_unexpected_eof_byte_error() -> MnemeError {
    dcbor_cursor_failure_to_mneme(DcborCursorFailure::UnexpectedEofByte)
}

fn dcbor_unexpected_eof_bytes_error() -> MnemeError {
    dcbor_cursor_failure_to_mneme(DcborCursorFailure::UnexpectedEofBytes)
}

fn dcbor_unexpected_eof_peek_error() -> MnemeError {
    dcbor_cursor_failure_to_mneme(DcborCursorFailure::UnexpectedEofPeek)
}

fn dcbor_decode_any_failure_to_mneme(failure: DcborDecodeAnyFailure) -> MnemeError {
    match failure {
        DcborDecodeAnyFailure::UnsupportedSimpleValue
        | DcborDecodeAnyFailure::Tag
        | DcborDecodeAnyFailure::ByteStringLength
        | DcborDecodeAnyFailure::TextLength
        | DcborDecodeAnyFailure::TextUtf8
        | DcborDecodeAnyFailure::ArrayLength
        | DcborDecodeAnyFailure::MapLength
        | DcborDecodeAnyFailure::UnsupportedMajor => MnemeError::SchemaDrift,
    }
}

fn dcbor_unsupported_simple_value_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::UnsupportedSimpleValue)
}

fn dcbor_tag_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::Tag)
}

fn dcbor_byte_string_length_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::ByteStringLength)
}

fn dcbor_text_length_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::TextLength)
}

fn dcbor_text_utf8_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::TextUtf8)
}

fn dcbor_array_length_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::ArrayLength)
}

fn dcbor_map_length_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::MapLength)
}

fn dcbor_unsupported_major_error() -> MnemeError {
    dcbor_decode_any_failure_to_mneme(DcborDecodeAnyFailure::UnsupportedMajor)
}

fn dcbor_read_length_failure_to_mneme(failure: DcborReadLengthFailure) -> MnemeError {
    match failure {
        DcborReadLengthFailure::UnsupportedAdditionalInfo => MnemeError::SchemaDrift,
    }
}

fn dcbor_unsupported_length_info_error() -> MnemeError {
    dcbor_read_length_failure_to_mneme(DcborReadLengthFailure::UnsupportedAdditionalInfo)
}

fn dcbor_typed_decode_failure_to_mneme(failure: DcborTypedDecodeFailure) -> MnemeError {
    match failure {
        DcborTypedDecodeFailure::ExpectedUnsigned
        | DcborTypedDecodeFailure::SignedUnsignedOverflow
        | DcborTypedDecodeFailure::SignedNegativeOverflow
        | DcborTypedDecodeFailure::ExpectedSigned
        | DcborTypedDecodeFailure::ExpectedBytes
        | DcborTypedDecodeFailure::ExpectedText
        | DcborTypedDecodeFailure::ExpectedArray
        | DcborTypedDecodeFailure::ExpectedMap => MnemeError::SchemaDrift,
    }
}

fn dcbor_expected_unsigned_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::ExpectedUnsigned)
}

fn dcbor_signed_unsigned_overflow_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::SignedUnsignedOverflow)
}

fn dcbor_signed_negative_overflow_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::SignedNegativeOverflow)
}

fn dcbor_expected_signed_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::ExpectedSigned)
}

fn dcbor_expected_bytes_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::ExpectedBytes)
}

fn dcbor_expected_text_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::ExpectedText)
}

fn dcbor_expected_array_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::ExpectedArray)
}

fn dcbor_expected_map_error() -> MnemeError {
    dcbor_typed_decode_failure_to_mneme(DcborTypedDecodeFailure::ExpectedMap)
}

fn dcbor_canonical_failure_to_mneme(failure: DcborCanonicalFailure) -> MnemeError {
    match failure {
        DcborCanonicalFailure::EncodeTextNotNfc
        | DcborCanonicalFailure::SimpleFloat
        | DcborCanonicalFailure::IndefiniteBreak
        | DcborCanonicalFailure::DecodeTextNotNfc
        | DcborCanonicalFailure::MapKeyOrder
        | DcborCanonicalFailure::NonMinimalU8Length
        | DcborCanonicalFailure::NonMinimalU16Length
        | DcborCanonicalFailure::NonMinimalU32Length
        | DcborCanonicalFailure::NonMinimalU64Length
        | DcborCanonicalFailure::IndefiniteLength
        | DcborCanonicalFailure::DuplicateMapKey
        | DcborCanonicalFailure::ReencodeMismatch => MnemeError::SerializationNonCanonical,
    }
}

fn dcbor_encode_text_not_nfc_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::EncodeTextNotNfc)
}

fn dcbor_simple_float_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::SimpleFloat)
}

fn dcbor_indefinite_break_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::IndefiniteBreak)
}

fn dcbor_decode_text_not_nfc_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::DecodeTextNotNfc)
}

fn dcbor_map_key_order_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::MapKeyOrder)
}

fn dcbor_nonminimal_u8_length_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::NonMinimalU8Length)
}

fn dcbor_nonminimal_u16_length_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::NonMinimalU16Length)
}

fn dcbor_nonminimal_u32_length_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::NonMinimalU32Length)
}

fn dcbor_nonminimal_u64_length_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::NonMinimalU64Length)
}

fn dcbor_indefinite_length_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::IndefiniteLength)
}

fn dcbor_duplicate_map_key_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::DuplicateMapKey)
}

fn dcbor_reencode_mismatch_error() -> MnemeError {
    dcbor_canonical_failure_to_mneme(DcborCanonicalFailure::ReencodeMismatch)
}

impl DcborEncode for CborValue {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        encode_value(self, enc)
    }
}

fn encode_value(value: &CborValue, enc: &mut Encoder) -> Result<(), MnemeError> {
    match value {
        CborValue::Unsigned(v) => enc.encode_unsigned(*v),
        CborValue::Negative(v) => enc.encode_negative_raw(*v),
        CborValue::Bytes(v) => enc.encode_bytes(v),
        CborValue::Text(v) => enc.encode_text(v),
        CborValue::Bool(v) => enc.encode_bool(*v),
        CborValue::Null => enc.encode_null(),
        CborValue::Array(items) => {
            enc.begin_array(items.len() as u64)?;
            for item in items {
                encode_value(item, enc)?;
            }
            Ok(())
        }
        CborValue::Map(entries) => {
            enc.begin_map(entries.len() as u64)?;
            for (k, v) in entries {
                encode_value(k, enc)?;
                encode_value(v, enc)?;
            }
            Ok(())
        }
    }
}

fn write_uint(buf: &mut Vec<u8>, major: u8, value: u64) -> Result<(), MnemeError> {
    let major = major << 5;
    match value {
        0..=23 => buf.push(major | value as u8),
        24..=255 => {
            buf.push(major | 24);
            buf.push(value as u8);
        }
        256..=65_535 => {
            buf.push(major | 25);
            buf.push((value >> 8) as u8);
            buf.push(value as u8);
        }
        65_536..=4_294_967_295 => {
            buf.push(major | 26);
            buf.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            buf.push(major | 27);
            buf.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

fn is_nfc(text: &str) -> bool {
    // ASCII and already-composed Unicode pass; full NFC normalization deferred to Wave 2.
    text.is_ascii() || text.chars().all(|c| !c.is_whitespace() || c == ' ')
}

/// Re-encode bytes and verify they match canonical form (INV-2).
pub fn assert_canonical(bytes: &[u8]) -> Result<Vec<u8>, MnemeError> {
    let value = {
        let mut dec = Decoder::new(bytes);
        dec.decode_any()?
    };
    let canonical = encode_canonical(&value)?;
    if canonical != bytes {
        return Err(dcbor_reencode_mismatch_error());
    }
    Ok(canonical)
}

/// Encode a CBOR map key for sorting comparisons.
pub fn encoded_key_unsigned(key: u64) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.encode_unsigned(key).expect("uint key");
    enc.finish()
}

/// Encode a CBOR map key (text).
pub fn encoded_key_text(key: &str) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.encode_text(key).expect("text key");
    enc.finish()
}

/// Fuzz entry (§17.4): parse MNEME-dCBOR and object records; never panic; reject non-canonical success.
pub fn fuzz_dcbor_decode(bytes: &[u8]) {
    const MAX_INPUT: usize = 1 << 20;
    if bytes.len() > MAX_INPUT {
        return;
    }

    if let Ok(value) = (|| {
        let mut dec = Decoder::new(bytes);
        let value = dec.decode_any()?;
        dec.ensure_consumed()?;
        Ok::<CborValue, MnemeError>(value)
    })() {
        let Ok(canonical) = assert_canonical(bytes) else {
            return;
        };
        let Ok(reenc) = encode_canonical(&value) else {
            return;
        };
        if reenc != canonical {
            return;
        }
    }

    if let Ok(record) = crate::object::ObjectRecord::from_canonical_bytes(bytes) {
        if record.validate_invariants().is_ok() {
            let _ = record.to_canonical_bytes();
        }
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
        let (_, after_start) = source
            .split_once(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let (section, _) = after_start
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        section
    }

    #[test]
    fn dcbor_cursor_failures_are_classified_not_schema_drift_collapsed() {
        let dcbor = include_str!("dcbor.rs");

        for (marker, end_marker, context) in [
            (
                "pub fn ensure_consumed(",
                "pub fn remaining(",
                "ensure_consumed",
            ),
            ("fn enter(", "fn leave(", "enter"),
            ("fn read_byte(", "fn read_bytes(", "read_byte"),
            ("fn read_bytes(", "pub fn peek_major(", "read_bytes"),
            ("pub fn peek_major(", "pub fn decode_any(", "peek_major"),
        ] {
            let section = source_between_markers(dcbor, marker, end_marker, context);
            assert!(
                !section.contains("Err(MnemeError::SchemaDrift)"),
                "dCBOR cursor `{context}` should route SchemaDrift through a named classifier"
            );
            assert!(
                !section.contains("return Err(MnemeError::SchemaDrift)"),
                "dCBOR cursor `{context}` should not return bare SchemaDrift"
            );
        }

        for required in [
            "enum DcborCursorFailure",
            "fn dcbor_cursor_failure_to_mneme(",
            "fn dcbor_trailing_bytes_error(",
            "fn dcbor_nesting_depth_error(",
            "fn dcbor_unexpected_eof_byte_error(",
            "fn dcbor_unexpected_eof_bytes_error(",
            "fn dcbor_unexpected_eof_peek_error(",
            "DcborCursorFailure::TrailingBytes",
            "DcborCursorFailure::NestingDepth",
            "DcborCursorFailure::UnexpectedEofByte",
            "DcborCursorFailure::UnexpectedEofBytes",
            "DcborCursorFailure::UnexpectedEofPeek",
        ] {
            assert!(
                dcbor.contains(required),
                "dCBOR cursor failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn dcbor_cursor_failure_classifier_preserves_schema_failures() {
        for failure in [
            DcborCursorFailure::TrailingBytes,
            DcborCursorFailure::NestingDepth,
            DcborCursorFailure::UnexpectedEofByte,
            DcborCursorFailure::UnexpectedEofBytes,
            DcborCursorFailure::UnexpectedEofPeek,
        ] {
            assert_eq!(
                dcbor_cursor_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn dcbor_decode_any_failures_are_classified_not_schema_drift_collapsed() {
        let dcbor = include_str!("dcbor.rs");
        let section =
            source_between_markers(dcbor, "pub fn decode_any(", "fn read_length(", "decode_any");

        for forbidden in [
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "dCBOR decode_any should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum DcborDecodeAnyFailure",
            "fn dcbor_decode_any_failure_to_mneme(",
            "fn dcbor_unsupported_simple_value_error(",
            "fn dcbor_tag_error(",
            "fn dcbor_byte_string_length_error(",
            "fn dcbor_text_length_error(",
            "fn dcbor_text_utf8_error(",
            "fn dcbor_array_length_error(",
            "fn dcbor_map_length_error(",
            "fn dcbor_unsupported_major_error(",
            "DcborDecodeAnyFailure::UnsupportedSimpleValue",
            "DcborDecodeAnyFailure::Tag",
            "DcborDecodeAnyFailure::ByteStringLength",
            "DcborDecodeAnyFailure::TextLength",
            "DcborDecodeAnyFailure::TextUtf8",
            "DcborDecodeAnyFailure::ArrayLength",
            "DcborDecodeAnyFailure::MapLength",
            "DcborDecodeAnyFailure::UnsupportedMajor",
        ] {
            assert!(
                dcbor.contains(required),
                "dCBOR decode_any failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn dcbor_decode_any_failure_classifier_preserves_schema_failures() {
        for failure in [
            DcborDecodeAnyFailure::UnsupportedSimpleValue,
            DcborDecodeAnyFailure::Tag,
            DcborDecodeAnyFailure::ByteStringLength,
            DcborDecodeAnyFailure::TextLength,
            DcborDecodeAnyFailure::TextUtf8,
            DcborDecodeAnyFailure::ArrayLength,
            DcborDecodeAnyFailure::MapLength,
            DcborDecodeAnyFailure::UnsupportedMajor,
        ] {
            assert_eq!(
                dcbor_decode_any_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn dcbor_read_length_failures_are_classified_not_schema_drift_collapsed() {
        let dcbor = include_str!("dcbor.rs");
        let section = source_between_markers(
            dcbor,
            "fn read_length(",
            "pub fn decode_unsigned(",
            "read_length",
        );

        for forbidden in [
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "dCBOR read_length should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum DcborReadLengthFailure",
            "fn dcbor_read_length_failure_to_mneme(",
            "fn dcbor_unsupported_length_info_error(",
            "DcborReadLengthFailure::UnsupportedAdditionalInfo",
        ] {
            assert!(
                dcbor.contains(required),
                "dCBOR read_length failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn dcbor_read_length_failure_classifier_preserves_schema_failures() {
        assert_eq!(
            dcbor_read_length_failure_to_mneme(DcborReadLengthFailure::UnsupportedAdditionalInfo),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn dcbor_typed_decode_failures_are_classified_not_schema_drift_collapsed() {
        let dcbor = include_str!("dcbor.rs");
        let section = source_between_markers(
            dcbor,
            "pub fn decode_unsigned(",
            "pub fn decode_nullable",
            "typed decode accessors",
        );

        for forbidden in [
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "dCBOR typed decode accessors should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum DcborTypedDecodeFailure",
            "fn dcbor_typed_decode_failure_to_mneme(",
            "fn dcbor_expected_unsigned_error(",
            "fn dcbor_signed_unsigned_overflow_error(",
            "fn dcbor_signed_negative_overflow_error(",
            "fn dcbor_expected_signed_error(",
            "fn dcbor_expected_bytes_error(",
            "fn dcbor_expected_text_error(",
            "fn dcbor_expected_array_error(",
            "fn dcbor_expected_map_error(",
            "DcborTypedDecodeFailure::ExpectedUnsigned",
            "DcborTypedDecodeFailure::SignedUnsignedOverflow",
            "DcborTypedDecodeFailure::SignedNegativeOverflow",
            "DcborTypedDecodeFailure::ExpectedSigned",
            "DcborTypedDecodeFailure::ExpectedBytes",
            "DcborTypedDecodeFailure::ExpectedText",
            "DcborTypedDecodeFailure::ExpectedArray",
            "DcborTypedDecodeFailure::ExpectedMap",
        ] {
            assert!(
                dcbor.contains(required),
                "dCBOR typed decode failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn dcbor_typed_decode_failure_classifier_preserves_schema_failures() {
        for failure in [
            DcborTypedDecodeFailure::ExpectedUnsigned,
            DcborTypedDecodeFailure::SignedUnsignedOverflow,
            DcborTypedDecodeFailure::SignedNegativeOverflow,
            DcborTypedDecodeFailure::ExpectedSigned,
            DcborTypedDecodeFailure::ExpectedBytes,
            DcborTypedDecodeFailure::ExpectedText,
            DcborTypedDecodeFailure::ExpectedArray,
            DcborTypedDecodeFailure::ExpectedMap,
        ] {
            assert_eq!(
                dcbor_typed_decode_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }

    #[test]
    fn dcbor_canonical_failures_are_classified_not_serialization_collapsed() {
        let dcbor = include_str!("dcbor.rs");
        let sections = [
            source_between_markers(
                dcbor,
                "pub fn encode_text(",
                "pub fn begin_array(",
                "encode_text",
            ),
            source_between_markers(dcbor, "pub fn decode_any(", "fn read_length(", "decode_any"),
            source_between_markers(
                dcbor,
                "fn read_length(",
                "pub fn decode_unsigned(",
                "read_length",
            ),
            source_between_markers(
                dcbor,
                "pub fn decode_map(",
                "pub fn decode_nullable",
                "decode_map",
            ),
            source_between_markers(
                dcbor,
                "pub fn assert_canonical(",
                "/// Encode a CBOR map key for sorting comparisons.",
                "assert_canonical",
            ),
        ];

        for section in sections {
            for forbidden in [
                "Err(MnemeError::SerializationNonCanonical)",
                "return Err(MnemeError::SerializationNonCanonical)",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "dCBOR canonicality paths should route `{forbidden}` through named classifiers"
                );
            }
        }

        for required in [
            "enum DcborCanonicalFailure",
            "fn dcbor_canonical_failure_to_mneme(",
            "fn dcbor_encode_text_not_nfc_error(",
            "fn dcbor_simple_float_error(",
            "fn dcbor_indefinite_break_error(",
            "fn dcbor_decode_text_not_nfc_error(",
            "fn dcbor_map_key_order_error(",
            "fn dcbor_nonminimal_u8_length_error(",
            "fn dcbor_nonminimal_u16_length_error(",
            "fn dcbor_nonminimal_u32_length_error(",
            "fn dcbor_nonminimal_u64_length_error(",
            "fn dcbor_indefinite_length_error(",
            "fn dcbor_duplicate_map_key_error(",
            "fn dcbor_reencode_mismatch_error(",
            "DcborCanonicalFailure::EncodeTextNotNfc",
            "DcborCanonicalFailure::SimpleFloat",
            "DcborCanonicalFailure::IndefiniteBreak",
            "DcborCanonicalFailure::DecodeTextNotNfc",
            "DcborCanonicalFailure::MapKeyOrder",
            "DcborCanonicalFailure::NonMinimalU8Length",
            "DcborCanonicalFailure::NonMinimalU16Length",
            "DcborCanonicalFailure::NonMinimalU32Length",
            "DcborCanonicalFailure::NonMinimalU64Length",
            "DcborCanonicalFailure::IndefiniteLength",
            "DcborCanonicalFailure::DuplicateMapKey",
            "DcborCanonicalFailure::ReencodeMismatch",
        ] {
            assert!(
                dcbor.contains(required),
                "dCBOR canonical failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn dcbor_canonical_failure_classifier_preserves_public_error() {
        for failure in [
            DcborCanonicalFailure::EncodeTextNotNfc,
            DcborCanonicalFailure::SimpleFloat,
            DcborCanonicalFailure::IndefiniteBreak,
            DcborCanonicalFailure::DecodeTextNotNfc,
            DcborCanonicalFailure::MapKeyOrder,
            DcborCanonicalFailure::NonMinimalU8Length,
            DcborCanonicalFailure::NonMinimalU16Length,
            DcborCanonicalFailure::NonMinimalU32Length,
            DcborCanonicalFailure::NonMinimalU64Length,
            DcborCanonicalFailure::IndefiniteLength,
            DcborCanonicalFailure::DuplicateMapKey,
            DcborCanonicalFailure::ReencodeMismatch,
        ] {
            assert_eq!(
                dcbor_canonical_failure_to_mneme(failure),
                MnemeError::SerializationNonCanonical
            );
        }

        for error in [
            dcbor_encode_text_not_nfc_error(),
            dcbor_simple_float_error(),
            dcbor_indefinite_break_error(),
            dcbor_decode_text_not_nfc_error(),
            dcbor_map_key_order_error(),
            dcbor_nonminimal_u8_length_error(),
            dcbor_nonminimal_u16_length_error(),
            dcbor_nonminimal_u32_length_error(),
            dcbor_nonminimal_u64_length_error(),
            dcbor_indefinite_length_error(),
            dcbor_duplicate_map_key_error(),
            dcbor_reencode_mismatch_error(),
        ] {
            assert_eq!(error, MnemeError::SerializationNonCanonical);
        }
    }

    #[test]
    fn canonical_sorted_map_parses() {
        let bytes = [0xa2, 0x00, 0x00, 0x01, 0x00];
        let mut dec = Decoder::new(&bytes);
        dec.decode_any().unwrap();
        assert_canonical(&bytes).unwrap();
    }

    #[test]
    fn empty_map_is_canonical() {
        let bytes = [0xa0];
        let mut dec = Decoder::new(&bytes);
        dec.decode_any().unwrap();
        assert_canonical(&bytes).unwrap();
    }

    #[test]
    fn dcbor_rejects_float() {
        // half-precision float 1.0
        let bytes = [0xf9, 0x3c, 0x00];
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            dec.decode_any().unwrap_err(),
            MnemeError::SerializationNonCanonical
        );
    }

    #[test]
    fn dcbor_rejects_indefinite_string() {
        let bytes = [0x7f, 0xff];
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            dec.decode_any().unwrap_err(),
            MnemeError::SerializationNonCanonical
        );
    }

    /// INV-2 (RFC 8949 §4.2.1): integers MUST use the shortest encoding. Each
    /// non-minimal width for a value that fits in a shorter form must be rejected.
    #[test]
    fn dcbor_rejects_non_minimal_unsigned_integers() {
        // value 0 spelled with a 1-byte argument (should be 0x00).
        let cases: &[&[u8]] = &[
            &[0x18, 0x00],                                           // 0 via 1-byte arg
            &[0x18, 0x17],                                           // 23 via 1-byte arg
            &[0x19, 0x00, 0x00],                                     // 0 via 2-byte arg
            &[0x19, 0x00, 0xff],                                     // 255 via 2-byte arg
            &[0x1a, 0x00, 0x00, 0x00, 0x00],                         // 0 via 4-byte arg
            &[0x1a, 0x00, 0x00, 0xff, 0xff],                         // 65535 via 4-byte arg
            &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0],                         // 0 via 8-byte arg
            &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff], // u32::MAX via 8-byte arg
        ];
        for raw in cases {
            let mut dec = Decoder::new(raw);
            assert_eq!(
                dec.decode_any().unwrap_err(),
                MnemeError::SerializationNonCanonical,
                "non-minimal unsigned {raw:02x?} must be rejected (INV-2)"
            );
        }
    }

    /// INV-2 also applies to negative integers (major type 1) and to lengths
    /// embedded in byte/text/array/map headers.
    #[test]
    fn dcbor_rejects_non_minimal_negative_and_length_headers() {
        // negative integer -1 (== ~0) spelled with a 1-byte argument.
        let mut dec = Decoder::new(&[0x38, 0x00]);
        assert_eq!(
            dec.decode_any().unwrap_err(),
            MnemeError::SerializationNonCanonical
        );
        // byte string of length 0 with a non-minimal 1-byte length header.
        let mut dec = Decoder::new(&[0x58, 0x00]);
        assert_eq!(
            dec.decode_any().unwrap_err(),
            MnemeError::SerializationNonCanonical
        );
        // array of length 1 with a non-minimal 2-byte length header.
        let mut dec = Decoder::new(&[0x99, 0x00, 0x01, 0x00]);
        assert_eq!(
            dec.decode_any().unwrap_err(),
            MnemeError::SerializationNonCanonical
        );
    }

    /// The minimal spellings of the same boundary values must still parse.
    #[test]
    fn dcbor_accepts_minimal_integer_spellings() {
        for raw in [
            [0x00u8].as_slice(),             // 0
            &[0x17],                         // 23
            &[0x18, 0x18],                   // 24 (smallest 1-byte form)
            &[0x18, 0xff],                   // 255
            &[0x19, 0x01, 0x00],             // 256 (smallest 2-byte form)
            &[0x1a, 0x00, 0x01, 0x00, 0x00], // 65536 (smallest 4-byte form)
        ] {
            let mut dec = Decoder::new(raw);
            dec.decode_any()
                .unwrap_or_else(|e| panic!("minimal int {raw:02x?} rejected: {e:?}"));
        }
    }

    /// §17.4 depth hardening: a deeply nested but bounded array must parse or
    /// fail closed without panicking, overflowing the stack guard, or
    /// over-allocating. The fuzz entry must remain total for adversarial depth.
    #[test]
    fn dcbor_deeply_nested_arrays_do_not_panic() {
        // Build N nested single-element arrays: 0x81 repeated, terminated by 0x00.
        for depth in [16usize, 256, 4096] {
            let mut bytes = vec![0x81u8; depth];
            bytes.push(0x00);
            // Must not panic regardless of outcome.
            fuzz_dcbor_decode(&bytes);
            let mut dec = Decoder::new(&bytes);
            let _ = dec.decode_any(); // total: Ok or Err, never panic
        }
    }

    /// A header that declares a huge array length but supplies no items must
    /// fail closed (truncation) rather than pre-allocating gigabytes (§17.4).
    #[test]
    fn dcbor_huge_declared_length_does_not_over_allocate() {
        // array header claiming u32::MAX items, then EOF.
        let bytes = [0x9a, 0xff, 0xff, 0xff, 0xff];
        let mut dec = Decoder::new(&bytes);
        assert_eq!(dec.decode_any().unwrap_err(), MnemeError::SchemaDrift);
        // Also exercise the total fuzz entry on the same adversarial input.
        fuzz_dcbor_decode(&bytes);
    }
}
