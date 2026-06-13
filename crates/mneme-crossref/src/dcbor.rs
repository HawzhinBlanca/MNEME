//! MNEME-dCBOR: deterministic CBOR profile (RFC 8949 §4.2 + blueprint §5.1).

use crate::CrossrefError;
use std::collections::BTreeMap;

/// Encode a value that implements [`DcborEncode`] into canonical MNEME-dCBOR bytes.
pub fn encode_canonical(value: &impl DcborEncode) -> Result<Vec<u8>, CrossrefError> {
    let mut enc = Encoder::new();
    value.dcbor_encode(&mut enc)?;
    Ok(enc.finish())
}

/// Decode with strict MNEME-dCBOR rules (INV-7).
pub fn decode_strict<T: DcborDecode>(bytes: &[u8]) -> Result<T, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let value = T::dcbor_decode(&mut dec)?;
    dec.ensure_consumed()?;
    Ok(value)
}

/// Legacy alias retained for downstream crates during Wave 0 migration.
pub fn to_bytes_canonical<T: DcborEncode>(value: &T) -> Result<Vec<u8>, CrossrefError> {
    encode_canonical(value)
}

/// Legacy alias retained for downstream crates during Wave 0 migration.
pub fn from_bytes_strict<T: DcborDecode>(bytes: &[u8]) -> Result<T, CrossrefError> {
    decode_strict(bytes)
}

pub trait DcborEncode {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), CrossrefError>;
}

pub trait DcborDecode: Sized {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, CrossrefError>;
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

    pub fn encode_unsigned(&mut self, value: u64) -> Result<(), CrossrefError> {
        write_uint(&mut self.buf, 0, value)
    }

    pub fn encode_negative(&mut self, value: i64) -> Result<(), CrossrefError> {
        if value >= 0 {
            return self.encode_signed(value);
        }
        let abs = (-value - 1) as u64;
        write_uint(&mut self.buf, 1, abs)
    }

    pub fn encode_signed(&mut self, value: i64) -> Result<(), CrossrefError> {
        if value >= 0 {
            self.encode_unsigned(value as u64)
        } else {
            self.encode_negative(value)
        }
    }

    pub fn encode_bytes(&mut self, bytes: &[u8]) -> Result<(), CrossrefError> {
        write_uint(&mut self.buf, 2, bytes.len() as u64)?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    pub fn encode_text(&mut self, text: &str) -> Result<(), CrossrefError> {
        if !text.is_empty() && !is_nfc(text) {
            return Err(CrossrefError::SerializationNonCanonical);
        }
        write_uint(&mut self.buf, 3, text.len() as u64)?;
        self.buf.extend_from_slice(text.as_bytes());
        Ok(())
    }

    pub fn begin_array(&mut self, len: u64) -> Result<(), CrossrefError> {
        write_uint(&mut self.buf, 4, len)
    }

    pub fn begin_map(&mut self, len: u64) -> Result<(), CrossrefError> {
        write_uint(&mut self.buf, 5, len)
    }

    pub fn encode_bool(&mut self, value: bool) -> Result<(), CrossrefError> {
        self.buf.push(if value { 0xf5 } else { 0xf4 });
        Ok(())
    }

    pub fn encode_null(&mut self) -> Result<(), CrossrefError> {
        self.buf.push(0xf6);
        Ok(())
    }

    pub fn append_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn encode_negative_raw(&mut self, abs_minus_one: u64) -> Result<(), CrossrefError> {
        write_uint(&mut self.buf, 1, abs_minus_one)
    }

    /// Encode a map whose keys are already canonical CBOR key bytes, sorted ascending.
    pub fn encode_map_raw<F>(&mut self, entries: &[(Vec<u8>, F)]) -> Result<(), CrossrefError>
    where
        F: Fn(&mut Encoder) -> Result<(), CrossrefError>,
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

pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn ensure_consumed(&self) -> Result<(), CrossrefError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(CrossrefError::SchemaDrift)
        }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8, CrossrefError> {
        if self.pos >= self.bytes.len() {
            return Err(CrossrefError::SchemaDrift);
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CrossrefError> {
        if self.pos + len > self.bytes.len() {
            return Err(CrossrefError::SchemaDrift);
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn peek_major(&self) -> Result<u8, CrossrefError> {
        if self.pos >= self.bytes.len() {
            return Err(CrossrefError::SchemaDrift);
        }
        Ok(self.bytes[self.pos] >> 5)
    }

    pub fn decode_any(&mut self) -> Result<CborValue, CrossrefError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major == 7 {
            return match info {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                24..=27 => Err(CrossrefError::SerializationNonCanonical), // floats
                31 => Err(CrossrefError::SerializationNonCanonical),      // indefinite break
                _ => Err(CrossrefError::SchemaDrift),
            };
        }

        if major == 6 {
            return Err(CrossrefError::SchemaDrift); // tags disallowed in Wave 0
        }

        let len = self.read_length(info)?;
        match major {
            0 => Ok(CborValue::Unsigned(len)),
            1 => Ok(CborValue::Negative(len)),
            2 => {
                let bytes = self.read_bytes(len as usize)?.to_vec();
                Ok(CborValue::Bytes(bytes))
            }
            3 => {
                let bytes = self.read_bytes(len as usize)?;
                let text = std::str::from_utf8(bytes).map_err(|_| CrossrefError::SchemaDrift)?;
                if !text.is_empty() && !is_nfc(text) {
                    return Err(CrossrefError::SerializationNonCanonical);
                }
                Ok(CborValue::Text(text.to_string()))
            }
            4 => {
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(self.decode_any()?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let mut entries = Vec::with_capacity(len as usize);
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let key_start = self.pos;
                    let key = self.decode_any()?;
                    let key_end = self.pos;
                    let key_bytes = self.bytes[key_start..key_end].to_vec();
                    if let Some(prev) = &prev_key {
                        if key_bytes <= *prev {
                            return Err(CrossrefError::SerializationNonCanonical);
                        }
                    }
                    prev_key = Some(key_bytes);
                    let value = self.decode_any()?;
                    entries.push((key, value));
                }
                Ok(CborValue::Map(entries))
            }
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    fn read_length(&mut self, info: u8) -> Result<u64, CrossrefError> {
        match info {
            n @ 0..=23 => Ok(u64::from(n)),
            24 => Ok(u64::from(self.read_byte()?)),
            25 => {
                let b = self.read_bytes(2)?;
                Ok(u64::from(u16::from_be_bytes([b[0], b[1]])))
            }
            26 => {
                let b = self.read_bytes(4)?;
                Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            }
            27 => {
                let b = self.read_bytes(8)?;
                Ok(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            31 => Err(CrossrefError::SerializationNonCanonical),
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_unsigned(&mut self) -> Result<u64, CrossrefError> {
        match self.decode_any()? {
            CborValue::Unsigned(v) => Ok(v),
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_signed(&mut self) -> Result<i64, CrossrefError> {
        match self.decode_any()? {
            CborValue::Unsigned(v) => i64::try_from(v).map_err(|_| CrossrefError::SchemaDrift),
            CborValue::Negative(v) => {
                let abs = i64::try_from(v).map_err(|_| CrossrefError::SchemaDrift)?;
                Ok(-abs - 1)
            }
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_bytes(&mut self) -> Result<Vec<u8>, CrossrefError> {
        match self.decode_any()? {
            CborValue::Bytes(v) => Ok(v),
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_text(&mut self) -> Result<String, CrossrefError> {
        match self.decode_any()? {
            CborValue::Text(v) => Ok(v),
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_array<F, T>(&mut self, mut decode_item: F) -> Result<Vec<T>, CrossrefError>
    where
        F: FnMut(&mut Decoder<'_>) -> Result<T, CrossrefError>,
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
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_map(&mut self) -> Result<BTreeMap<CborValue, CborValue>, CrossrefError> {
        match self.decode_any()? {
            CborValue::Map(entries) => {
                let mut map = BTreeMap::new();
                for (k, v) in entries {
                    if map.insert(k.clone(), v).is_some() {
                        return Err(CrossrefError::SerializationNonCanonical);
                    }
                }
                Ok(map)
            }
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn decode_nullable<T, F>(&mut self, decode_some: F) -> Result<Option<T>, CrossrefError>
    where
        F: FnOnce(&mut Decoder<'_>) -> Result<T, CrossrefError>,
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

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl DcborEncode for CborValue {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), CrossrefError> {
        encode_value(self, enc)
    }
}

fn encode_value(value: &CborValue, enc: &mut Encoder) -> Result<(), CrossrefError> {
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

fn write_uint(buf: &mut Vec<u8>, major: u8, value: u64) -> Result<(), CrossrefError> {
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
pub fn assert_canonical(bytes: &[u8]) -> Result<Vec<u8>, CrossrefError> {
    let value = {
        let mut dec = Decoder::new(bytes);
        dec.decode_any()?
    };
    let canonical = encode_canonical(&value)?;
    if canonical != bytes {
        return Err(CrossrefError::SerializationNonCanonical);
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
        Ok::<CborValue, CrossrefError>(value)
    })() {
        let canonical = assert_canonical(bytes).expect("accepted non-canonical dCBOR");
        let reenc = encode_canonical(&value).expect("re-encode failed after successful parse");
        assert_eq!(
            reenc, canonical,
            "round-trip drift on canonical dCBOR input"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            CrossrefError::SerializationNonCanonical
        );
    }

    #[test]
    fn dcbor_rejects_indefinite_string() {
        let bytes = [0x7f, 0xff];
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            dec.decode_any().unwrap_err(),
            CrossrefError::SerializationNonCanonical
        );
    }
}
