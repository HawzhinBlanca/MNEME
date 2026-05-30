#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_index::fuzz_index_path_wire;

fuzz_target!(|data: &[u8]| {
    fuzz_index_path_wire(data);
});
