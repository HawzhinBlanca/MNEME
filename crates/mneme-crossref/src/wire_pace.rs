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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cal(alg: u8) -> StoredPaceCalibration {
        StoredPaceCalibration {
            alg,
            iterations_per_tick: 10,
            tick_target_ms: 50,
        }
    }

    /// Build a 2-segment log that will pass verify().
    fn make_valid_log(genesis: [u8; 32]) -> StoredPaceLog {
        let anchor = pace_genesis_anchor(&genesis);
        let out0 = blake3_sequential(&anchor, 3);
        let out1 = blake3_sequential(&out0, 5);
        StoredPaceLog {
            version: 1,
            genesis,
            calibration: make_cal(PACE_ALG_BLAKE3_SEQUENTIAL),
            segments: vec![
                StoredPaceSegment {
                    index: 0,
                    prev_output: anchor,
                    iterations: 3,
                    output: out0,
                    label: None,
                },
                StoredPaceSegment {
                    index: 1,
                    prev_output: out0,
                    iterations: 5,
                    output: out1,
                    label: Some("root-seq-1".into()),
                },
            ],
        }
    }

    /// XPACE-1: pace_genesis_anchor is domain-separated — non-zero and input-dependent.
    #[test]
    fn pace_genesis_anchor_is_domain_separated() {
        let a = pace_genesis_anchor(&[0x01; 32]);
        let b = pace_genesis_anchor(&[0x02; 32]);
        assert_ne!(a, [0u8; 32], "genesis anchor must not be all-zeros");
        assert_ne!(
            a, b,
            "different genesis values must yield different anchors"
        );
    }

    /// XPACE-2: blake3_sequential is deterministic and changes output each step.
    #[test]
    fn blake3_sequential_deterministic_and_progressive() {
        let seed = [0xABu8; 32];
        let r1 = blake3_sequential(&seed, 5);
        let r2 = blake3_sequential(&seed, 5);
        assert_eq!(r1, r2, "blake3_sequential must be deterministic");
        assert_ne!(r1, seed, "output must differ from seed after 5 iterations");
        let r3 = blake3_sequential(&seed, 6);
        assert_ne!(
            r1, r3,
            "different iteration counts must yield different outputs"
        );
    }

    /// XPACE-3: verify() passes for a correctly constructed 2-segment log.
    #[test]
    fn verify_passes_for_correct_log() {
        let log = make_valid_log([0x77; 32]);
        log.verify().expect("valid 2-segment pace log must verify");
    }

    /// XPACE-4: verify() rejects an unsupported algorithm (fail-closed).
    #[test]
    fn verify_rejects_wrong_alg() {
        let mut log = make_valid_log([0x88; 32]);
        log.calibration.alg = 99; // unknown alg
        assert!(log.verify().is_err(), "wrong alg must be rejected");
    }

    /// XPACE-5: verify() rejects a tampered prev_output (broken chain linkage).
    #[test]
    fn verify_rejects_tampered_prev_output() {
        let mut log = make_valid_log([0x99; 32]);
        log.segments[1].prev_output[0] ^= 0xFF; // break chain link
        assert!(
            log.verify().is_err(),
            "tampered prev_output must break chain verification"
        );
    }

    /// XPACE-6: verify() rejects a falsified output (wrong PoW value).
    #[test]
    fn verify_rejects_falsified_output() {
        let mut log = make_valid_log([0xAA; 32]);
        log.segments[0].output = [0x00; 32]; // wrong PoW output
        assert!(
            log.verify().is_err(),
            "falsified segment output must be rejected"
        );
    }
}
