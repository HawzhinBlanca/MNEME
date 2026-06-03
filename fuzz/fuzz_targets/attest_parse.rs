#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_attest::fuzz_attest_parse;

fuzz_target!(|data: &[u8]| {
    fuzz_attest_parse(data);
});
