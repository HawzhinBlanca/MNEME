//! Trick #4 Byzantine inference consistency integration tests.

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
    RetrievalProofLevel,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_index::{
    BYZANTINE_INFERENCE_HONESTY, InferenceReplica, SemanticIndex,
    assemble_cognition_certificate_v1_with_extensions, parse_cognition_certificate,
    prove_inference_consistency, verify_byzantine_inference,
    verify_cognition_certificate_v1_with_spot_check,
};
use mneme_root::StoredRoot;

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

fn signed_fixture() -> (StoredRoot, mneme_index::SemanticRecallReceipt, TrustConfig) {
    let operator = KeyPair::from_seed([0x81; 32]);
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(
            ObjectId([1; 32]),
            FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
        )
        .unwrap();
    let stored = StoredRoot::assemble(
        [0x82; 32],
        [0x83; 32],
        index.semantic_commit(),
        [0x84; 14],
        [0x00; 32],
        1,
        &operator,
    )
    .unwrap();
    let receipt = index
        .recall_receipt_zkann(
            &proc(),
            &q,
            stored.preimage_hash,
            RetrievalProofLevel::ExactDominance,
        )
        .unwrap();
    (
        stored,
        receipt,
        TrustConfig::new(operator.public_key_bytes()),
    )
}

#[test]
fn byzantine_honesty_mentions_consistency_not_correctness() {
    assert!(BYZANTINE_INFERENCE_HONESTY.contains("consistency"));
    assert!(BYZANTINE_INFERENCE_HONESTY.contains("not a proof of model correctness"));
}

#[test]
fn cert_with_byzantine_field_roundtrips_and_verifies() {
    let (stored, receipt, trust) = signed_fixture();
    let output = *blake3::hash(b"unanimous-model-output").as_bytes();
    let witness = prove_inference_consistency(
        b"gpt-test-v1",
        [0xDE; 32],
        0,
        2,
        vec![
            InferenceReplica {
                endpoint_id: b"a".to_vec(),
                output_digest: output,
                logit_commitment_digest: None,
            },
            InferenceReplica {
                endpoint_id: b"b".to_vec(),
                output_digest: output,
                logit_commitment_digest: None,
            },
        ],
        &receipt,
    )
    .unwrap();
    let bytes = assemble_cognition_certificate_v1_with_extensions(
        &stored,
        &receipt,
        None,
        None,
        Some(witness),
    )
    .unwrap();
    let parsed = parse_cognition_certificate(&bytes).unwrap();
    verify_byzantine_inference(
        parsed.inference_consistency.as_ref().unwrap(),
        &parsed.receipt,
    )
    .unwrap();
    verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), None).unwrap();
}

#[test]
fn divergent_replica_outputs_fail_cert_verify() {
    let (stored, receipt, trust) = signed_fixture();
    let output = *blake3::hash(b"agreed").as_bytes();
    let mut witness = prove_inference_consistency(
        b"model",
        [0xEF; 32],
        0,
        2,
        vec![
            InferenceReplica {
                endpoint_id: b"a".to_vec(),
                output_digest: output,
                logit_commitment_digest: None,
            },
            InferenceReplica {
                endpoint_id: b"b".to_vec(),
                output_digest: output,
                logit_commitment_digest: None,
            },
        ],
        &receipt,
    )
    .unwrap();
    witness.replicas[1].output_digest = [0xFF; 32];
    let bytes = assemble_cognition_certificate_v1_with_extensions(
        &stored,
        &receipt,
        None,
        None,
        Some(witness),
    )
    .unwrap();
    assert_eq!(
        verify_cognition_certificate_v1_with_spot_check(&bytes, &trust, &proc(), None).err(),
        Some(MnemeError::CertificateInvalid)
    );
}
