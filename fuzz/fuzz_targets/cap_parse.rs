#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_cap::fuzz_decode_capability;

fuzz_target!(|data: &[u8]| {
    fuzz_decode_capability(data);
});
