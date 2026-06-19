//! CR-6: Cognition Certificate v1 round-trip for `RetrievalProofLevel::CompleteTopK`.

use mneme_core::{
    AsOf, DistanceMetric, FixedPointEmbedding, ObjectId, Procedure, ProcedureAlgo,
    RetrievalProofLevel, VerificationObject,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_index::{
    AuthenticatedBallTree, CompleteKnnAttachment, CompleteKnnCertAttachment, SemanticIndex,
    SemanticRecallReceipt, ZkannAttachment, assemble_cognition_certificate_v1,
    encode_complete_knn_attachment, prove_complete_knn, verify_cognition_certificate_v1,
};
use mneme_root::StoredRoot;

fn fixture_points() -> Vec<Vec<f64>> {
    vec![
        vec![0.0, 0.0],
        vec![1.0, 0.0],
        vec![3.0, 1.0],
        vec![7.0, 2.0],
        vec![2.0, 9.0],
        vec![11.0, 4.0],
        vec![5.0, 5.0],
    ]
}

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 3,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

fn build_complete_topk_cert() -> (Vec<u8>, TrustConfig) {
    let operator = KeyPair::from_seed([0x71; 32]);
    let tree = AuthenticatedBallTree::from_points(fixture_points());
    let q = vec![0.0, 0.0];
    let k = 3usize;
    let proof = prove_complete_knn(&tree, &q, k).expect("prove");
    let returned_len = proof.returned.len();
    let att = CompleteKnnCertAttachment {
        commitment: tree.commitment(),
        query: q.clone(),
        k: k as u32,
        proof,
        beacon: None,
        constant_proof_hash: None,
        merkle_hnsw_root: None,
        constant_size: false,
    };
    let proof_bytes = encode_complete_knn_attachment(&att).expect("encode attachment");
    let mut receipt = SemanticRecallReceipt::new(
        [0xab; 32],
        [0xcd; 32],
        VerificationObject {
            nodes: Vec::new(),
            candidates: Vec::new(),
            leaf_indices: Vec::new(),
            procedure_id: [0xee; 32],
            query_commit: [0x11; 32],
            result_ids: (0..returned_len).map(|_| ObjectId([0x22; 32])).collect(),
            candidates_embeddings: None,
        },
    );
    receipt.zkann = Some(ZkannAttachment {
        level: RetrievalProofLevel::CompleteTopK,
        visited_order: Vec::new(),
    });
    receipt.complete_knn = Some(CompleteKnnAttachment {
        commitment: tree.commitment(),
        query: q,
        k: k as u32,
        proof_bytes,
    });
    let stored = StoredRoot::assemble(
        [0x01; 32], [0x02; 32], [0xcd; 32], [0x03; 14], [0x00; 32], 1, &operator,
    )
    .expect("stored root");
    receipt.root_bound = stored.preimage_hash;
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, Some(AsOf::RootSeq(1)))
        .expect("assemble");
    (bytes, TrustConfig::new(operator.public_key_bytes()))
}

#[test]
fn complete_topk_cert_round_trip() {
    let (bytes, trust) = build_complete_topk_cert();
    verify_cognition_certificate_v1(&bytes, &trust, &proc()).expect("verify-cert");
}

#[test]
fn complete_topk_cert_is_byte_identical_across_two_assemblies() {
    let (a, _) = build_complete_topk_cert();
    let (b, _) = build_complete_topk_cert();
    assert_eq!(a, b, "deterministic cert bytes");
}

#[test]
fn semantic_index_complete_topk_receipt_issues_and_verifies() {
    let operator = KeyPair::from_seed([0x71; 32]);
    let mut index = SemanticIndex::new();
    for (byte, coords) in [
        (0x01u8, vec![0, 0]),
        (0x02, vec![10, 0]),
        (0x03, vec![3, 4]),
    ] {
        index
            .insert(
                ObjectId([byte; 32]),
                FixedPointEmbedding::new(2, 0, coords).unwrap(),
            )
            .unwrap();
    }
    let proc = proc();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    let stored = StoredRoot::assemble(
        [0x01; 32],
        [0x02; 32],
        index.semantic_commit(),
        [0x03; 14],
        [0x00; 32],
        1,
        &operator,
    )
    .expect("stored root");
    let receipt = index
        .recall_receipt_zkann(
            &proc,
            &q,
            stored.preimage_hash,
            RetrievalProofLevel::CompleteTopK,
        )
        .expect("complete-topk receipt");
    assert_eq!(
        receipt.zkann.as_ref().map(|z| z.level),
        Some(RetrievalProofLevel::CompleteTopK)
    );
    assert!(receipt.complete_knn.is_some());
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, Some(AsOf::RootSeq(1)))
        .expect("assemble");
    verify_cognition_certificate_v1(
        &bytes,
        &TrustConfig::new(operator.public_key_bytes()),
        &proc,
    )
    .expect("verify-cert");
}

fn appendix_b_complete_topk_operator() -> KeyPair {
    KeyPair::from_seed([0x51; 32])
}

fn appendix_b_complete_topk_fixture() -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let operator = appendix_b_complete_topk_operator();
    let mut index = SemanticIndex::new();
    for (byte, coords) in [
        (0x01u8, vec![0, 0]),
        (0x02, vec![10, 0]),
        (0x03, vec![3, 4]),
        (0x04, vec![7, 2]),
    ] {
        index
            .insert(
                ObjectId([byte; 32]),
                FixedPointEmbedding::new(2, 0, coords).unwrap(),
            )
            .unwrap();
    }
    let semantic_commit = index.semantic_commit();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 2,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    let stored = StoredRoot::assemble(
        [0x60; 32],
        [0x61; 32],
        semantic_commit,
        [0x62; 14],
        [0x00; 32],
        4,
        &operator,
    )
    .expect("stored root");
    let receipt = index
        .recall_receipt_zkann(
            &proc,
            &q,
            stored.preimage_hash,
            RetrievalProofLevel::CompleteTopK,
        )
        .expect("complete-topk receipt");
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, Some(AsOf::RootSeq(4)))
        .expect("assemble");
    (bytes, stored.preimage_hash, semantic_commit)
}

#[test]
fn cognition_cert_complete_topk_appendix_b_vector_verifies() {
    use std::{fs, path::PathBuf};

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../proof/vectors/certs/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let entry = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"].as_str() == Some("cognition_cert_complete_topk"))
        .expect("complete_topk manifest entry");
    let bytes = fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../proof/vectors/certs")
            .join(entry["cbor_file"].as_str().unwrap()),
    )
    .unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: entry["procedure"]["k"].as_u64().unwrap() as u32,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    verify_cognition_certificate_v1(
        &bytes,
        &TrustConfig::new(appendix_b_complete_topk_operator().public_key_bytes()),
        &proc,
    )
    .expect("verify-cert");
}

#[test]
#[ignore]
fn dump_cognition_cert_complete_topk_fixture() {
    use std::{fs, path::PathBuf};

    let (bytes, preimage_hash, semantic_commit) = appendix_b_complete_topk_fixture();
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../proof/vectors/certs/cognition_cert_complete_topk.cbor");
    fs::write(&out, &bytes).expect("write vector");
    eprintln!(
        "cognition_cert_complete_topk_wire_hex={}",
        hex::encode(&bytes)
    );
    eprintln!(
        "cognition_cert_complete_topk_preimage_hash_hex={}",
        hex::encode(preimage_hash)
    );
    eprintln!(
        "cognition_cert_complete_topk_semantic_commit_hex={}",
        hex::encode(semantic_commit)
    );
    eprintln!(
        "cognition_cert_complete_topk_operator_pubkey_hex={}",
        hex::encode(appendix_b_complete_topk_operator().public_key_bytes())
    );
}
