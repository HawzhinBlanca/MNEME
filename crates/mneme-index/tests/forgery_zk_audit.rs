//! Forgery-rejection audit — CHECK 6: ZK retrieval-match proof (plonky2_prover).
//!
//! Run with: `cargo test -p mneme-index --features plonky2_prover --test forgery_zk_audit`.
//! Without the feature this file compiles to an empty (passing) test binary.
//!
//! Backend honesty: this is a transparent Pedersen+Schnorr NIZK over Ristretto, NOT
//! Plonky2/FRI and NOT a SNARK (see plonky2_prover.rs). All forgeries fail closed with
//! MnemeError::ZkProofInvalid (the audit's "ZkProofInvalid" expectation).

#![cfg(feature = "plonky2_prover")]

use mneme_core::MnemeError;
use mneme_index::{
    Plonky2RetrievalProof, RetrievalWitness, prove_plonky2_retrieval, verify_plonky2_retrieval,
};

fn baseline() -> Plonky2RetrievalProof {
    let entry = [0x42; 32];
    let proof = prove_plonky2_retrieval(&RetrievalWitness::matching(entry)).expect("prove");
    verify_plonky2_retrieval(&proof, &proof.public_commit).expect("baseline verifies");
    proof
}

// Forgery 6a: bind the proof against a public commitment it does not open to.
#[test]
fn check06a_wrong_public_commit_zk_proof_invalid() {
    let proof = baseline();
    let mut wrong = proof.public_commit;
    wrong[0] ^= 0x01;
    assert_eq!(
        verify_plonky2_retrieval(&proof, &wrong),
        Err(MnemeError::ZkProofInvalid),
    );
}

// Forgery 6b: corrupt the Schnorr response scalar z.
#[test]
fn check06b_forged_response_scalar_zk_proof_invalid() {
    let mut proof = baseline();
    proof.proof_bytes[64] = proof.proof_bytes[64].wrapping_add(1);
    assert_eq!(
        verify_plonky2_retrieval(&proof, &proof.public_commit),
        Err(MnemeError::ZkProofInvalid),
    );
}

// Forgery 6c: splice a query commitment from a DIFFERENT proof (procedure-result swap analog).
#[test]
fn check06c_spliced_query_commitment_zk_proof_invalid() {
    let a = prove_plonky2_retrieval(&RetrievalWitness::matching([1u8; 32])).expect("a");
    let b = prove_plonky2_retrieval(&RetrievalWitness::matching([2u8; 32])).expect("b");
    let mut spliced = a.clone();
    spliced.proof_bytes[0..32].copy_from_slice(&b.proof_bytes[0..32]);
    assert_eq!(
        verify_plonky2_retrieval(&spliced, &spliced.public_commit),
        Err(MnemeError::ZkProofInvalid),
    );
}

// Forgery 6d: an unsatisfiable statement (query != entry) is unprovable — fail closed at prove.
#[test]
fn check06d_unsatisfiable_witness_cannot_prove_zk_proof_invalid() {
    let mut entry = [3u8; 32];
    let mut query = [3u8; 32];
    entry[0] = 1;
    query[0] = 2;
    assert_eq!(
        prove_plonky2_retrieval(&RetrievalWitness { entry, query }),
        Err(MnemeError::ZkProofInvalid),
    );
}

// Forgery 6e: tampered nonce point R.
#[test]
fn check06e_tampered_nonce_point_zk_proof_invalid() {
    let mut proof = baseline();
    proof.proof_bytes[32] ^= 0xff;
    assert_eq!(
        verify_plonky2_retrieval(&proof, &proof.public_commit),
        Err(MnemeError::ZkProofInvalid),
    );
}
