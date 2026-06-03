//! Regression: provenance receipts must not skip Merkle membership or filtered dominance.

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MemoryKind, ObjectId, ObjectRecord, PayloadEnc, Procedure,
    ProcedureAlgo, ProvenanceFilter, TrustTier, hash_obj, object::HlcWire, to_bytes_canonical,
};
use mneme_index::{SemanticIndex, build_provenance_attestation, verify_semantic_receipt_tcb_gate};
use std::collections::BTreeMap;

#[test]
fn provenance_bearing_non_topk_smuggle_rejected() {
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 2,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let mut semantic = SemanticIndex::new();
    let embeddings = [
        FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
        FixedPointEmbedding::new(2, 0, vec![2, 0]).unwrap(),
        FixedPointEmbedding::new(2, 0, vec![10, 0]).unwrap(),
    ];
    let mut objects = BTreeMap::new();
    for (idx, emb) in embeddings.iter().enumerate() {
        let record = ObjectRecord {
            version: mneme_core::object::OBJECT_VERSION,
            kind: MemoryKind::Semantic.as_u8(),
            parent_ids: vec![],
            writer: [0x01; 32],
            session: [0x55; 16],
            hlc: HlcWire {
                wall_ms: u64::try_from(idx + 1).unwrap_or(1),
                counter: 0,
                node_id: [0x06; 16],
            },
            trust_tier: TrustTier::Working.as_u8(),
            payload_enc: PayloadEnc {
                alg: 0,
                key_id: None,
                nonce: None,
                body: vec![idx as u8],
            },
            embedding_commit: Some(emb.commit()),
            redaction_slot: None,
            ext: None,
        };
        let bytes = to_bytes_canonical(&record).unwrap();
        let oid = hash_obj(&bytes);
        objects.insert(oid, bytes);
        semantic.insert(ObjectId(oid), emb.clone()).unwrap();
    }
    let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    let mut receipt = semantic
        .recall_receipt(&proc, &query, [0u8; 32])
        .expect("receipt");
    let filter = ProvenanceFilter {
        written_by: None,
        since: None,
        min_tier: TrustTier::Working,
    };
    receipt.provenance =
        Some(build_provenance_attestation(&receipt, &filter, &objects).expect("attestation"));
    verify_semantic_receipt_tcb_gate(&receipt, &proc, Some(&objects)).unwrap();
    let farthest = receipt.verification_object.candidates.last().unwrap().0;
    receipt.verification_object.result_ids = vec![farthest];
    assert_eq!(
        verify_semantic_receipt_tcb_gate(&receipt, &proc, Some(&objects)).unwrap_err(),
        mneme_core::MnemeError::ProvenanceFilterViolation,
    );
}
