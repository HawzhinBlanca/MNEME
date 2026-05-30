#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_index::fuzz_receipt_wire;

fuzz_target!(|data: &[u8]| {
    fuzz_receipt_wire(data);
});
