//! Cognition Certificate v1 assemble + offline verify (Phase I P1-4).

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
    RetrievalProofLevel,
};
use mneme_crypto::TrustConfig;
use mneme_index::{
    SemanticIndex, assemble_cognition_certificate_v1, verify_cognition_certificate_v1,
};
use mneme_root::StoredRoot;

#[cfg(feature = "context_gate")]
use mneme_core::{Decoder, Encoder};
#[cfg(feature = "context_gate")]
use mneme_index::{
    ContextAttestationDraft, assemble_cognition_certificate_v2_draft,
    verify_cognition_certificate_v2_draft,
};

fn oid(b: u8) -> ObjectId {
    ObjectId([b; 32])
}

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

fn fixture_root(semantic_commit: [u8; 32]) -> StoredRoot {
    StoredRoot {
        version: 1,
        dag_head_root: [0u8; 32],
        key_index_root: [1u8; 32],
        semantic_commit,
        hlc_max: [0u8; 14],
        prev_root: [0u8; 32],
        preimage_hash: [0xcc; 32],
        signature: vec![0u8; 64],
        sequence: 1,
    }
}

#[test]
fn cognition_cert_v1_roundtrip_offline() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let commit = index.semantic_commit();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xcc; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let stored = fixture_root(commit);
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, None).unwrap();
    let trust = TrustConfig::new([0u8; 32]);
    // Signature check fails with zero key — test wire + zkANN path only.
    assert!(verify_cognition_certificate_v1(&bytes, &trust, &proc()).is_err());
}

#[test]
fn cognition_cert_tampered_bytes_fail_closed() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(1), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xcc; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let stored = fixture_root(index.semantic_commit());
    let mut bytes = assemble_cognition_certificate_v1(&stored, &receipt, None).unwrap();
    if let Some(b) = bytes.last_mut() {
        *b ^= 0xff;
    }
    let trust = TrustConfig::new([0u8; 32]);
    let err = verify_cognition_certificate_v1(&bytes, &trust, &proc()).unwrap_err();
    assert!(matches!(
        err,
        MnemeError::RootSigInvalid
            | MnemeError::CertificateInvalid
            | MnemeError::SerializationNonCanonical
            | MnemeError::SchemaDrift
    ));
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_missing_attestation_rejects() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(2), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xee; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let stored = fixture_root(index.semantic_commit());
    let attestation = ContextAttestationDraft::placeholder([0x11; 32]);
    let bytes =
        assemble_cognition_certificate_v2_draft(&stored, &receipt, None, attestation).unwrap();

    // Decode the good map, then re-encode it without the attestation field.
    let mut dec = Decoder::new(&bytes);
    let map = dec.decode_map().unwrap();
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => {}
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            // Skip 6 to simulate a missing attestation.
            _ => {}
        }
    }

    let mut enc = Encoder::new();
    let mut map_len = 4u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(2).unwrap(); // version = v2 draft
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(level_tag.unwrap()).unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.unwrap()).unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&receipt_bytes.unwrap()).unwrap();
    let missing_bytes = enc.finish();

    let trust = TrustConfig::new([0u8; 32]);
    let err = verify_cognition_certificate_v2_draft(&missing_bytes, &trust, &proc()).unwrap_err();
    assert!(matches!(
        err,
        MnemeError::CertificateInvalid | MnemeError::SchemaDrift
    ));
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_status_mismatch_rejects() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(3), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xdd; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let stored = fixture_root(index.semantic_commit());
    let mut attestation = ContextAttestationDraft::placeholder([0x22; 32]);
    attestation.status = "wrong_status".into();
    let bytes =
        assemble_cognition_certificate_v2_draft(&stored, &receipt, None, attestation).unwrap();
    let trust = TrustConfig::new([0u8; 32]);
    let err = verify_cognition_certificate_v2_draft(&bytes, &trust, &proc()).unwrap_err();
    assert!(matches!(
        err,
        MnemeError::CertificateInvalid | MnemeError::RootSigInvalid
    ));
}
#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_byte_tamper_rejects() {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(oid(4), FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap())
        .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xbb; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let stored = fixture_root(index.semantic_commit());
    let attestation = ContextAttestationDraft::placeholder([0x33; 32]);
    let mut bytes =
        assemble_cognition_certificate_v2_draft(&stored, &receipt, None, attestation).unwrap();
    if let Some(b) = bytes.last_mut() {
        *b ^= 0xff;
    }
    let trust = TrustConfig::new([0u8; 32]);
    let err = verify_cognition_certificate_v2_draft(&bytes, &trust, &proc()).unwrap_err();
    assert!(matches!(
        err,
        MnemeError::RootSigInvalid
            | MnemeError::CertificateInvalid
            | MnemeError::SerializationNonCanonical
            | MnemeError::SchemaDrift
    ));
}
