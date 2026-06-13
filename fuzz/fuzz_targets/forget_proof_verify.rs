#![no_main]

use libfuzzer_sys::fuzz_target;
use mneme_core::Root;
use mneme_account::verify_forget_proof_wire;

fuzz_target!(|data: &[u8]| {
    let root = Root {
        version: 1,
        preimage_hash: [0; 32],
        dag_head_root: [0; 32],
        key_index_root: [0; 32],
        semantic_commit: [0; 32],
        hlc_max: [0; 14],
        prev_root: [0; 32],
        signature: Vec::new(),
        sequence: 0,
    };
    let _ = verify_forget_proof_wire(data, &root);
});
