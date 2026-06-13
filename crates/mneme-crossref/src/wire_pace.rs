//! VCP A1 sequential work pace log (reference path).

use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;

pub const PACE_ALG_BLAKE3_SEQUENTIAL: u8 = 2;
const PACE_DOMAIN_GENESIS: &[u8] = b"MNEME-PACE/v1/genesis";

pub fn pace_genesis_anchor(genesis: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(PACE_DOMAIN_GENESIS)
        .update(genesis)
        .finalize()
        .as_bytes()
}

pub fn blake3_sequential(seed: &[u8; 32], iterations: u64) -> [u8; 32] {
    let mut state = *seed;
    for _ in 0..iterations {
        state = *blake3::hash(&state).as_bytes();
    }
    state
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPaceCalibration {
    pub alg: u8,
    pub iterations_per_tick: u64,
    pub tick_target_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPaceSegment {
    pub index: u64,
    pub prev_output: [u8; 32],
    pub iterations: u64,
    pub output: [u8; 32],
    pub label: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPaceLog {
    pub version: u8,
    pub genesis: [u8; 32],
    pub calibration: StoredPaceCalibration,
    pub segments: Vec<StoredPaceSegment>,
}

impl StoredPaceLog {
    pub fn decode(bytes: &[u8]) -> Result<Self, CrossrefError> {
        let mut dec = Decoder::new(bytes);
        let map = dec.decode_map()?;
        dec.ensure_consumed()?;

        let mut version = None;
        let mut genesis = None;
        let mut calibration = None;
        let mut segments = None;

        for (key, value) in map {
            let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
            match field {
                1 => version = Some(parse_u8(&value)?),
                2 => genesis = Some(parse_fixed32(&value)?),
                3 => calibration = Some(parse_calibration(&value)?),
                4 => segments = Some(parse_segments(&value)?),
                _ => return Err(CrossrefError::SchemaDrift),
            }
        }

        Ok(Self {
            version: version.ok_or(CrossrefError::SchemaDrift)?,
            genesis: genesis.ok_or(CrossrefError::SchemaDrift)?,
            calibration: calibration.ok_or(CrossrefError::SchemaDrift)?,
            segments: segments.ok_or(CrossrefError::SchemaDrift)?,
        })
    }

    pub fn verify(&self) -> Result<(), CrossrefError> {
        if self.calibration.alg != PACE_ALG_BLAKE3_SEQUENTIAL {
            return Err(CrossrefError::SchemaDrift);
        }
        let mut prev_output = pace_genesis_anchor(&self.genesis);
        for (i, segment) in self.segments.iter().enumerate() {
            if segment.index != i as u64 {
                return Err(CrossrefError::SchemaDrift);
            }
            if segment.prev_output != prev_output {
                return Err(CrossrefError::SchemaDrift);
            }
            if blake3_sequential(&segment.prev_output, segment.iterations) != segment.output {
                return Err(CrossrefError::SchemaDrift);
            }
            prev_output = segment.output;
        }
        Ok(())
    }
}

fn parse_u8(v: &CborValue) -> Result<u8, CrossrefError> {
    let n = v.as_u64().ok_or(CrossrefError::SchemaDrift)?;
    u8::try_from(n).map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_u64(v: &CborValue) -> Result<u64, CrossrefError> {
    v.as_u64().ok_or(CrossrefError::SchemaDrift)
}

fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let b = v.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    b.try_into().map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_text(v: &CborValue) -> Result<String, CrossrefError> {
    v.as_text()
        .map(|s| s.to_string())
        .ok_or(CrossrefError::SchemaDrift)
}

fn parse_calibration(v: &CborValue) -> Result<StoredPaceCalibration, CrossrefError> {
    let map = v.as_map().ok_or(CrossrefError::SchemaDrift)?;
    let mut alg = None;
    let mut iterations_per_tick = None;
    let mut tick_target_ms = None;
    for (key, val) in map {
        let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        match field {
            1 => alg = Some(parse_u8(val)?),
            2 => iterations_per_tick = Some(parse_u64(val)?),
            3 => tick_target_ms = Some(parse_u64(val)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(StoredPaceCalibration {
        alg: alg.ok_or(CrossrefError::SchemaDrift)?,
        iterations_per_tick: iterations_per_tick.ok_or(CrossrefError::SchemaDrift)?,
        tick_target_ms: tick_target_ms.ok_or(CrossrefError::SchemaDrift)?,
    })
}

fn parse_segments(v: &CborValue) -> Result<Vec<StoredPaceSegment>, CrossrefError> {
    let arr = v.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(parse_segment(item)?);
    }
    Ok(out)
}

fn parse_segment(v: &CborValue) -> Result<StoredPaceSegment, CrossrefError> {
    let map = v.as_map().ok_or(CrossrefError::SchemaDrift)?;
    let mut index = None;
    let mut prev_output = None;
    let mut iterations = None;
    let mut output = None;
    let mut label = None;
    for (key, val) in map {
        let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        match field {
            1 => index = Some(parse_u64(val)?),
            2 => prev_output = Some(parse_fixed32(val)?),
            3 => iterations = Some(parse_u64(val)?),
            4 => output = Some(parse_fixed32(val)?),
            5 => {
                if val.is_null() {
                    label = None;
                } else {
                    label = Some(parse_text(val)?);
                }
            }
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(StoredPaceSegment {
        index: index.ok_or(CrossrefError::SchemaDrift)?,
        prev_output: prev_output.ok_or(CrossrefError::SchemaDrift)?,
        iterations: iterations.ok_or(CrossrefError::SchemaDrift)?,
        output: output.ok_or(CrossrefError::SchemaDrift)?,
        label,
    })
}
