//! P3-2 integration: shred witness + SMT absence mint/verify (feature-gated).

use mneme_account::{
    ForgetProofWitness, PHASE_III_PROVE_FORGET_OPEN, prove_forget, verify_forget_proof_bound,
    verify_forget_proof_wire,
};
use mneme_core::{ForgetMode, ForgetTarget, LogicalKey, Root, encode_forget_proof};
use mneme_crypto::{MemoryKeyVault, seal_payload};
use mneme_forget::{ShredForgetInput, forget_shred, payload_aad, prove_absent};
use mneme_smt::SparseMerkleTree;

fn sample_root(key_index_root: [u8; 32]) -> Root {
    Root {
        version: 1,
        preimage_hash: [0x10; 32],
        dag_head_root: [0x11; 32],
        key_index_root,
        semantic_commit: [0x13; 32],
        hlc_max: [0x14; 14],
        prev_root: [0x15; 32],
        signature: vec![0x00; 64],
        sequence: 7,
    }
}

#[test]
fn prove_forget_gate_opens_with_feature() {
    assert!(std::hint::black_box(PHASE_III_PROVE_FORGET_OPEN));
}

#[test]
fn prove_forget_mints_wire_and_verifies() {
    let key = LogicalKey {
        namespace: "gdpr".into(),
        name: "pii".into(),
    };
    let mut vault = MemoryKeyVault::new();
    let mut record = mneme_core::ObjectRecord::fixture(mneme_core::MemoryKind::Semantic);
    let aad = payload_aad(&key);
    record.payload_enc = seal_payload(&mut vault, b"secret", &aad).expect("seal");
    let bytes = mneme_core::to_bytes_canonical(&record).expect("encode");
    let id = mneme_core::hash_obj(&bytes);
    let mut smt = SparseMerkleTree::new();
    smt.upsert(key.hash(), id);

    let shred = forget_shred(ShredForgetInput {
        logical_key: &key,
        key_index: &mut smt,
        vault: &mut vault,
        object_bytes: Some(&bytes),
    })
    .expect("forget");
    let absence = prove_absent(&smt, &key).expect("absent");
    let root = sample_root(smt.root());
    let target = ForgetTarget::LogicalKey(key);
    let witness = ForgetProofWitness {
        shred: &shred,
        absence: &absence,
    };
    let proof = prove_forget(&target, ForgetMode::Shred, &root, None, &witness).unwrap();
    verify_forget_proof_bound(&proof, &root, &target, &shred).unwrap();
    verify_forget_proof_wire(&encode_forget_proof(&proof).unwrap(), &root).unwrap();
}
