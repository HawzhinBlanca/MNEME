#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_core::fuzz_dcbor_decode;

fuzz_target!(|data: &[u8]| {
    fuzz_dcbor_decode(data);
});
