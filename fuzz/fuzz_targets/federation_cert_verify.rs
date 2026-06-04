#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_index::fuzz_federation_cert_verify;

fuzz_target!(|data: &[u8]| {
    fuzz_federation_cert_verify(data);
});
