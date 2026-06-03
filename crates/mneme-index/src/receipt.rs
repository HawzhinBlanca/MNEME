//! Semantic recall receipt bound to `semantic_commit` (blueprint §9.2, ADS backend).

use mneme_core::{
    CandidateProvenance, ProvenanceFilter, RetrievalProofLevel, VerificationObject,
    hash_receipt_preimage,
};

/// Optional transparent ZK retrieval-match proof bytes (12-month `pedersen_schnorr_zk` feature).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ZkRetrievalAttachment {
    pub public_commit: [u8; 32],
    pub proof_bytes: Vec<u8>,
}

/// Phase I zkANN-1 attachment on a semantic receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkannAttachment {
    pub level: RetrievalProofLevel,
    pub visited_order: Vec<mneme_core::ObjectId>,
}

/// Phase I provenance-scoped recall attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceAttestation {
    pub filter: ProvenanceFilter,
    pub candidates: Vec<CandidateProvenance>,
}

/// Receipt for semantic/ANN recall — lives in `mneme-index` (key `Receipt` remains key-index only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticRecallReceipt {
    /// Signed root preimage hash this recall is bound to.
    pub root_bound: [u8; 32],
    /// Semantic index Merkle root at recall time.
    pub semantic_commit: [u8; 32],
    /// ADS verification object (§9.2).
    pub verification_object: VerificationObject,
    /// When present, a real transparent ZK proof (`pedersen_schnorr_zk`) binds the top-1 result's
    /// embedding commit to the query commit without expanding the verifier TCB.
    pub zk_retrieval: Option<ZkRetrievalAttachment>,
    /// Phase I zkANN-1 dominance / audit-on-demand proof level.
    pub zkann: Option<ZkannAttachment>,
    /// Phase I provenance-filter attestation (optional).
    pub provenance: Option<ProvenanceAttestation>,
}

impl SemanticRecallReceipt {
    pub fn new(
        root_bound: [u8; 32],
        semantic_commit: [u8; 32],
        verification_object: VerificationObject,
    ) -> Self {
        Self {
            root_bound,
            semantic_commit,
            verification_object,
            zk_retrieval: None,
            zkann: None,
            provenance: None,
        }
    }

    /// `BLAKE3(RCPT ‖ root_bound ‖ semantic_commit ‖ P_id ‖ query_commit ‖ result_ids…)`.
    pub fn digest(&self) -> [u8; 32] {
        let vo = &self.verification_object;
        let mut payload =
            Vec::with_capacity(96 + vo.result_ids.len() * 32 + vo.candidates.len() * 72);
        payload.extend_from_slice(&self.root_bound);
        payload.extend_from_slice(&self.semantic_commit);
        payload.extend_from_slice(&vo.procedure_id);
        payload.extend_from_slice(&vo.query_commit);
        for id in &vo.result_ids {
            payload.extend_from_slice(id.as_bytes());
        }
        hash_receipt_preimage(&payload)
    }

    pub fn binds_to_semantic_commit(&self, expected: &[u8; 32]) -> bool {
        self.semantic_commit == *expected
    }
}
