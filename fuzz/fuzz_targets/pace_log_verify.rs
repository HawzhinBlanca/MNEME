#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_pace::{decode_pace_log, verify_log};

fuzz_target!(|data: &[u8]| {
    if let Ok(log) = decode_pace_log(data) {
        // Cap segments and iterations to prevent slow execution or timeouts in the fuzzer.
        if log.segments.len() <= 10 && log.segments.iter().all(|s| s.iterations <= 1000) {
            let _ = verify_log(&log, None);
        }
    }
});
