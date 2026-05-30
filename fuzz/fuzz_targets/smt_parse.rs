#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_smt::fuzz_parse_and_verify;

fuzz_target!(|data: &[u8]| {
    fuzz_parse_and_verify(data);
});
