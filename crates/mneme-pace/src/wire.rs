use crate::PaceError;
use mneme_core::MnemeError;
use mneme_core::dcbor::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, decode_strict, encode_canonical,
};

const F_VERSION: u64 = 1;
const F_GENESIS: u64 = 2;
const F_CALIBRATION: u64 = 3;
const F_SEGMENTS: u64 = 4;
const F_ALG: u64 = 1;
const F_ITERATIONS_PER_TICK: u64 = 2;
const F_TICK_TARGET_MS: u64 = 3;
const F_INDEX: u64 = 1;
const F_PREV_OUTPUT: u64 = 2;
const F_ITERATIONS: u64 = 3;
const F_OUTPUT: u64 = 4;
const F_LABEL: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaceCalibration {
    pub alg: u8,
    pub iterations_per_tick: u64,
    pub tick_target_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaceSegment {
    pub index: u64,
    pub prev_output: [u8; 32],
    pub iterations: u64,
    pub output: [u8; 32],
    pub label: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaceLog {
    pub version: u8,
    pub genesis: [u8; 32],
    pub calibration: PaceCalibration,
    pub segments: Vec<PaceSegment>,
}

pub fn encode_pace_calibration(value: &PaceCalibration) -> Result<Vec<u8>, PaceError> {
    encode_canonical(value).map_err(|_| PaceError::UnsupportedAlg(value.alg))
}

pub fn decode_pace_calibration(bytes: &[u8]) -> Result<PaceCalibration, PaceError> {
    decode_strict(bytes).map_err(|_| PaceError::UnsupportedAlg(0))
}

pub fn encode_pace_log(value: &PaceLog) -> Result<Vec<u8>, PaceError> {
    encode_canonical(value).map_err(|_| PaceError::UnsupportedAlg(value.calibration.alg))
}

pub fn decode_pace_log(bytes: &[u8]) -> Result<PaceLog, PaceError> {
    decode_strict(bytes).map_err(|_| PaceError::UnsupportedAlg(0))
}

impl DcborEncode for PaceCalibration {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        enc.begin_map(3)?;
        enc.encode_unsigned(F_ALG)?;
        enc.encode_unsigned(u64::from(self.alg))?;
        enc.encode_unsigned(F_ITERATIONS_PER_TICK)?;
        enc.encode_unsigned(self.iterations_per_tick)?;
        enc.encode_unsigned(F_TICK_TARGET_MS)?;
        enc.encode_unsigned(self.tick_target_ms)?;
        Ok(())
    }
}

impl DcborDecode for PaceCalibration {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut alg = None;
        let mut iterations_per_tick = None;
        let mut tick_target_ms = None;
        for (key, value) in map {
            match parse_u64_field_key(&key)? {
                F_ALG => alg = Some(parse_u8_value(&value)?),
                F_ITERATIONS_PER_TICK => iterations_per_tick = Some(parse_u64_value(&value)?),
                F_TICK_TARGET_MS => tick_target_ms = Some(parse_u64_value(&value)?),
                _ => return Err(MnemeError::SchemaDrift),
            }
        }
        Ok(Self {
            alg: alg.ok_or(MnemeError::SchemaDrift)?,
            iterations_per_tick: iterations_per_tick.ok_or(MnemeError::SchemaDrift)?,
            tick_target_ms: tick_target_ms.ok_or(MnemeError::SchemaDrift)?,
        })
    }
}

impl DcborEncode for PaceSegment {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let field_count = if self.label.is_some() { 5 } else { 4 };
        enc.begin_map(field_count as u64)?;
        enc.encode_unsigned(F_INDEX)?;
        enc.encode_unsigned(self.index)?;
        enc.encode_unsigned(F_PREV_OUTPUT)?;
        enc.encode_bytes(&self.prev_output)?;
        enc.encode_unsigned(F_ITERATIONS)?;
        enc.encode_unsigned(self.iterations)?;
        enc.encode_unsigned(F_OUTPUT)?;
        enc.encode_bytes(&self.output)?;
        if let Some(label) = &self.label {
            enc.encode_unsigned(F_LABEL)?;
            enc.encode_text(label)?;
        }
        Ok(())
    }
}

impl DcborDecode for PaceSegment {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut index = None;
        let mut prev_output = None;
        let mut iterations = None;
        let mut output = None;
        let mut label = None;
        for (key, value) in map {
            match parse_u64_field_key(&key)? {
                F_INDEX => index = Some(parse_u64_value(&value)?),
                F_PREV_OUTPUT => prev_output = Some(parse_fixed32_value(&value)?),
                F_ITERATIONS => iterations = Some(parse_u64_value(&value)?),
                F_OUTPUT => output = Some(parse_fixed32_value(&value)?),
                F_LABEL => label = Some(parse_text_value(&value)?),
                _ => return Err(MnemeError::SchemaDrift),
            }
        }
        Ok(Self {
            index: index.ok_or(MnemeError::SchemaDrift)?,
            prev_output: prev_output.ok_or(MnemeError::SchemaDrift)?,
            iterations: iterations.ok_or(MnemeError::SchemaDrift)?,
            output: output.ok_or(MnemeError::SchemaDrift)?,
            label,
        })
    }
}

impl DcborEncode for PaceLog {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        enc.begin_map(4)?;
        enc.encode_unsigned(F_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_GENESIS)?;
        enc.encode_bytes(&self.genesis)?;
        enc.encode_unsigned(F_CALIBRATION)?;
        self.calibration.dcbor_encode(enc)?;
        enc.encode_unsigned(F_SEGMENTS)?;
        enc.begin_array(self.segments.len() as u64)?;
        for segment in &self.segments {
            segment.dcbor_encode(enc)?;
        }
        Ok(())
    }
}

impl DcborDecode for PaceLog {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut genesis = None;
        let mut calibration = None;
        let mut segments = None;
        for (key, value) in map {
            match parse_u64_field_key(&key)? {
                F_VERSION => version = Some(parse_u8_value(&value)?),
                F_GENESIS => genesis = Some(parse_fixed32_value(&value)?),
                F_CALIBRATION => calibration = Some(PaceCalibration::from_cbor_value(&value)?),
                F_SEGMENTS => segments = Some(parse_segment_array(&value)?),
                _ => return Err(MnemeError::SchemaDrift),
            }
        }
        Ok(Self {
            version: version.ok_or(MnemeError::SchemaDrift)?,
            genesis: genesis.ok_or(MnemeError::SchemaDrift)?,
            calibration: calibration.ok_or(MnemeError::SchemaDrift)?,
            segments: segments.unwrap_or_default(),
        })
    }
}

impl PaceCalibration {
    fn from_cbor_value(value: &CborValue) -> Result<Self, MnemeError> {
        decode_strict(&encode_canonical(value)?)
    }
}

fn parse_segment_array(value: &CborValue) -> Result<Vec<PaceSegment>, MnemeError> {
    let items = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(decode_strict(&encode_canonical(item)?)?);
    }
    Ok(out)
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_u64_value(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_u8_value(value: &CborValue) -> Result<u8, MnemeError> {
    u8::try_from(parse_u64_value(value)?).map_err(|_| MnemeError::SchemaDrift)
}

fn parse_text_value(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(|s| s.to_string())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32_value(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    if bytes.len() != 32 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calibration() -> PaceCalibration {
        PaceCalibration {
            alg: 1,
            iterations_per_tick: 10_000,
            tick_target_ms: 50,
        }
    }

    fn segment(index: u64, label: Option<&str>) -> PaceSegment {
        PaceSegment {
            index,
            prev_output: [index as u8; 32],
            iterations: 1_000 + index,
            output: [(index + 1) as u8; 32],
            label: label.map(|s| s.to_string()),
        }
    }

    /// PACE-WIRE-1: PaceCalibration encode/decode roundtrip.
    #[test]
    fn pace_calibration_roundtrip() {
        let cal = calibration();
        let bytes = encode_pace_calibration(&cal).expect("calibration must encode");
        let decoded = decode_pace_calibration(&bytes).expect("calibration must decode");
        assert_eq!(
            decoded, cal,
            "calibration roundtrip must preserve all fields"
        );
    }

    /// PACE-WIRE-2: PaceLog encode/decode roundtrip with a labeled segment.
    #[test]
    fn pace_log_roundtrip_with_labeled_segment() {
        let log = PaceLog {
            version: 1,
            genesis: [0xAB; 32],
            calibration: calibration(),
            segments: vec![segment(0, Some("root-seq-7"))],
        };
        let bytes = encode_pace_log(&log).expect("log must encode");
        let decoded = decode_pace_log(&bytes).expect("log must decode");
        assert_eq!(decoded, log, "log roundtrip must preserve all fields");
        assert_eq!(decoded.segments[0].label, Some("root-seq-7".to_string()));
    }

    /// PACE-WIRE-3: PaceLog with no segments roundtrips correctly.
    #[test]
    fn pace_log_roundtrip_no_segments() {
        let log = PaceLog {
            version: 2,
            genesis: [0xCC; 32],
            calibration: calibration(),
            segments: vec![],
        };
        let bytes = encode_pace_log(&log).expect("log must encode");
        let decoded = decode_pace_log(&bytes).expect("log must decode");
        assert_eq!(decoded, log);
        assert!(
            decoded.segments.is_empty(),
            "no-segment log must decode as empty"
        );
    }

    /// PACE-WIRE-4: Empty bytes must fail decode for both types.
    #[test]
    fn empty_bytes_fail_decode() {
        assert!(
            decode_pace_calibration(&[]).is_err(),
            "empty bytes must not decode calibration"
        );
        assert!(
            decode_pace_log(&[]).is_err(),
            "empty bytes must not decode log"
        );
    }

    /// PACE-WIRE-5: encode_pace_calibration is deterministic (idempotent).
    #[test]
    fn pace_calibration_encode_is_deterministic() {
        let cal = calibration();
        let b1 = encode_pace_calibration(&cal).unwrap();
        let b2 = encode_pace_calibration(&cal).unwrap();
        assert_eq!(b1, b2, "calibration encoding must be deterministic");
        assert!(!b1.is_empty(), "encoding must not be empty");
    }
}
