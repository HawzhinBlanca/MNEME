#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_account::robr::RobrReceiptV1;

fuzz_target!(|data: &[u8]| {
    let _ = RobrReceiptV1::verify(data, None);
});
