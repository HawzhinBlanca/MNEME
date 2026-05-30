#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_crdt::fuzz_sync_parse;

fuzz_target!(|data: &[u8]| {
    fuzz_sync_parse(data);
});
