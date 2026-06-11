#![forbid(unsafe_code)]
#![deny(warnings)]

mod alg;
mod wire;

pub use alg::{
    PACE_ALG_BLAKE3_SEQUENTIAL, PACE_DOMAIN_GENESIS, blake3_sequential, pace_genesis_anchor,
};
pub use wire::{PaceCalibration, decode_pace_log, encode_pace_calibration, encode_pace_log};

use mneme_core::MnemeError;
use wire::{PaceLog, PaceSegment, decode_pace_calibration};

pub const PACE_HONESTY_BOUNDARY: &str = "pace log proves sequential BLAKE3 work (alg=2), not wall time; authenticated chain order only; not semantic truth";
pub const PACE_T5_MIN_INTERVAL_ONLY: &str = "offline verifier can prove minimum sequential-work intervals only — maximum elapsed time is impossible (T5)";
pub const PACE_T7_NO_PQ: &str =
    "alg=2 BLAKE3 sequential scaffold carries no post-quantum sequential-work guarantee (T7)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaceError {
    UnsupportedAlg(u8),
    EmptyLog,
    SegmentOrder,
    PrevLinkMismatch { index: u64 },
    OutputMismatch { index: u64 },
    GenesisMismatch,
    BelowMinIterations { index: u64, got: u64, min: u64 },
}

impl PaceError {
    pub fn to_mneme(self) -> MnemeError {
        MnemeError::SchemaDrift
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaceVerifyReport {
    pub segment_count: u64,
    pub total_iterations: u64,
    pub min_iterations_between_last_pair: Option<u64>,
}

pub fn calibrate_blake3(target_ms: u64) -> PaceCalibration {
    let target_ms = target_ms.max(1);
    let anchor = pace_genesis_anchor(&[0xA1u8; 32]);
    let start = std::time::Instant::now();
    let mut iterations: u64 = 0;
    let mut state = anchor;
    while start.elapsed().as_millis() < u128::from(target_ms) {
        state = blake3_sequential(&state, 1);
        iterations = iterations.saturating_add(1);
    }
    PaceCalibration {
        alg: PACE_ALG_BLAKE3_SEQUENTIAL,
        iterations_per_tick: iterations.max(1),
        tick_target_ms: target_ms,
    }
}

pub fn create_log(genesis: [u8; 32], calibration: PaceCalibration) -> Result<PaceLog, PaceError> {
    if calibration.alg != PACE_ALG_BLAKE3_SEQUENTIAL {
        return Err(PaceError::UnsupportedAlg(calibration.alg));
    }
    Ok(PaceLog {
        version: 1,
        genesis,
        calibration,
        segments: Vec::new(),
    })
}

pub fn append_segment(
    log: &mut PaceLog,
    iterations: u64,
    label: Option<String>,
) -> Result<&PaceSegment, PaceError> {
    if log.calibration.alg != PACE_ALG_BLAKE3_SEQUENTIAL {
        return Err(PaceError::UnsupportedAlg(log.calibration.alg));
    }
    let prev_output = if let Some(last) = log.segments.last() {
        last.output
    } else {
        pace_genesis_anchor(&log.genesis)
    };
    let output = blake3_sequential(&prev_output, iterations);
    let index = log.segments.len() as u64;
    log.segments.push(PaceSegment {
        index,
        prev_output,
        iterations,
        output,
        label,
    });
    Ok(log.segments.last().expect("just pushed"))
}

pub fn verify_log(
    log: &PaceLog,
    min_iterations_per_gap: Option<u64>,
) -> Result<PaceVerifyReport, PaceError> {
    if log.calibration.alg != PACE_ALG_BLAKE3_SEQUENTIAL {
        return Err(PaceError::UnsupportedAlg(log.calibration.alg));
    }
    let mut prev_output = pace_genesis_anchor(&log.genesis);
    let mut total_iterations = 0u64;
    for (expected_index, segment) in log.segments.iter().enumerate() {
        if segment.index != expected_index as u64 {
            return Err(PaceError::SegmentOrder);
        }
        if segment.prev_output != prev_output {
            return Err(PaceError::PrevLinkMismatch {
                index: segment.index,
            });
        }
        if blake3_sequential(&segment.prev_output, segment.iterations) != segment.output {
            return Err(PaceError::OutputMismatch {
                index: segment.index,
            });
        }
        if let Some(min) = min_iterations_per_gap {
            if segment.iterations < min {
                return Err(PaceError::BelowMinIterations {
                    index: segment.index,
                    got: segment.iterations,
                    min,
                });
            }
        }
        total_iterations = total_iterations.saturating_add(segment.iterations);
        prev_output = segment.output;
    }
    Ok(PaceVerifyReport {
        segment_count: log.segments.len() as u64,
        total_iterations,
        min_iterations_between_last_pair: log.segments.last().map(|s| s.iterations),
    })
}

pub fn load_log(bytes: &[u8]) -> Result<PaceLog, MnemeError> {
    decode_pace_log(bytes).map_err(|e| e.to_mneme())
}

pub fn load_calibration(bytes: &[u8]) -> Result<PaceCalibration, MnemeError> {
    decode_pace_calibration(bytes).map_err(|e| e.to_mneme())
}

pub fn save_log(log: &PaceLog) -> Result<Vec<u8>, MnemeError> {
    encode_pace_log(log).map_err(|e| e.to_mneme())
}

pub fn save_calibration(calibration: &PaceCalibration) -> Result<Vec<u8>, MnemeError> {
    encode_pace_calibration(calibration).map_err(|e| e.to_mneme())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_verify_roundtrip() {
        let cal = PaceCalibration {
            alg: PACE_ALG_BLAKE3_SEQUENTIAL,
            iterations_per_tick: 64,
            tick_target_ms: 0,
        };
        let mut log = create_log([0x42u8; 32], cal).unwrap();
        append_segment(&mut log, 64, Some("event-a".into())).unwrap();
        append_segment(&mut log, 128, None).unwrap();
        let report = verify_log(&log, None).unwrap();
        assert_eq!(report.segment_count, 2);
        assert_eq!(report.total_iterations, 192);
        verify_log(&load_log(&save_log(&log).unwrap()).unwrap(), None).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_output() {
        let mut log = create_log([1u8; 32], calibrate_blake3(1)).unwrap();
        append_segment(&mut log, 8, None).unwrap();
        log.segments[0].output[0] ^= 0x01;
        assert!(matches!(
            verify_log(&log, None),
            Err(PaceError::OutputMismatch { index: 0 })
        ));
    }

    #[test]
    fn honesty_constants_present() {
        assert!(PACE_T5_MIN_INTERVAL_ONLY.contains("maximum"));
        assert!(PACE_T7_NO_PQ.contains("post-quantum"));
    }
}
