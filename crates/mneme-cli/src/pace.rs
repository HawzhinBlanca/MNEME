//! VCP A1 pace log CLI (`mneme pace calibrate|run|verify`).

use mneme_pace::{
    PACE_HONESTY_BOUNDARY, PACE_T5_MIN_INTERVAL_ONLY, PACE_T7_NO_PQ, PaceError, append_segment,
    calibrate_blake3, create_log, load_calibration, load_log, save_calibration, save_log,
    verify_log,
};
use std::path::Path;

pub fn run_calibrate(out: &Path, target_ms: u64) -> Result<(), PaceError> {
    let calibration = calibrate_blake3(target_ms);
    let bytes =
        save_calibration(&calibration).map_err(|_| PaceError::UnsupportedAlg(calibration.alg))?;
    std::fs::write(out, bytes).map_err(|_| PaceError::UnsupportedAlg(calibration.alg))?;
    eprintln!("honesty: {PACE_HONESTY_BOUNDARY}");
    eprintln!("honesty: {PACE_T5_MIN_INTERVAL_ONLY}");
    eprintln!("honesty: {PACE_T7_NO_PQ}");
    println!(
        "pace calibrate ok: alg={} iterations_per_tick={} target_ms={} -> {}",
        calibration.alg,
        calibration.iterations_per_tick,
        calibration.tick_target_ms,
        out.display()
    );
    Ok(())
}

pub fn run_append(
    log_path: &Path,
    calib_path: Option<&Path>,
    genesis_hex: Option<&str>,
    iterations: Option<u64>,
    label: Option<String>,
) -> Result<(), PaceError> {
    let mut log = if log_path.exists() {
        let bytes = std::fs::read(log_path).map_err(|_| PaceError::EmptyLog)?;
        load_log(&bytes).map_err(|_| PaceError::UnsupportedAlg(0))?
    } else {
        let calib_bytes = match calib_path {
            Some(path) => std::fs::read(path).map_err(|_| PaceError::EmptyLog)?,
            None => return Err(PaceError::EmptyLog),
        };
        let calibration =
            load_calibration(&calib_bytes).map_err(|_| PaceError::UnsupportedAlg(0))?;
        create_log(parse_genesis_hex(genesis_hex)?, calibration)?
    };
    let iters = iterations.unwrap_or(log.calibration.iterations_per_tick);
    let segment = append_segment(&mut log, iters, label)?;
    let segment_index = segment.index;
    let segment_iterations = segment.iterations;
    let segment_output = segment.output;
    let alg = log.calibration.alg;
    let bytes = save_log(&log).map_err(|_| PaceError::UnsupportedAlg(alg))?;
    std::fs::write(log_path, bytes).map_err(|_| PaceError::UnsupportedAlg(alg))?;
    eprintln!("honesty: {PACE_HONESTY_BOUNDARY}");
    println!(
        "pace run ok: segment={} iterations={} output={} -> {}",
        segment_index,
        segment_iterations,
        hex::encode(segment_output),
        log_path.display()
    );
    Ok(())
}

pub fn run_verify(log_path: &Path, min_iterations: Option<u64>) -> Result<(), PaceError> {
    let bytes = std::fs::read(log_path).map_err(|_| PaceError::EmptyLog)?;
    let log = load_log(&bytes).map_err(|_| PaceError::UnsupportedAlg(0))?;
    let report = verify_log(&log, min_iterations)?;
    eprintln!("honesty: {PACE_HONESTY_BOUNDARY}");
    eprintln!("honesty: {PACE_T5_MIN_INTERVAL_ONLY}");
    eprintln!("honesty: {PACE_T7_NO_PQ}");
    println!(
        "pace verify ok: alg={} segments={} total_iterations={} last_gap_iterations={}",
        log.calibration.alg,
        report.segment_count,
        report.total_iterations,
        report
            .min_iterations_between_last_pair
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".into())
    );
    Ok(())
}

fn parse_genesis_hex(genesis_hex: Option<&str>) -> Result<[u8; 32], PaceError> {
    let hex_str = genesis_hex.ok_or(PaceError::GenesisMismatch)?;
    let bytes = hex::decode(hex_str).map_err(|_| PaceError::GenesisMismatch)?;
    if bytes.len() != 32 {
        return Err(PaceError::GenesisMismatch);
    }
    let mut genesis = [0u8; 32];
    genesis.copy_from_slice(&bytes);
    Ok(genesis)
}
