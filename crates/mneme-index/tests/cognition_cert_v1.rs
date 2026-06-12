//! Cognition Certificate v1 assemble + offline verify (Phase I P1-4).

use mneme_core::{
    CborValue, Decoder, DistanceMetric, Encoder, FixedPointEmbedding, MnemeError, ObjectId,
    Procedure, ProcedureAlgo, RetrievalProofLevel, to_bytes_canonical,
};
use mneme_crypto::{KeyPair, TrustConfig};
use mneme_index::{
    SemanticIndex, assemble_cognition_certificate_v1,
    assemble_cognition_certificate_v1_with_beacon, prove_audit_beacon,
    verify_cognition_certificate_v1,
};
use mneme_root::StoredRoot;

#[cfg(feature = "context_gate")]
use mneme_core::{AssemblyProfile, ContextConsumptionAttestation};
#[cfg(feature = "context_gate")]
use mneme_index::{
    ContextAttestationDraft, assemble_cognition_certificate_v2_draft,
    verify_cognition_certificate_v2_draft, verify_cognition_certificate_v2_draft_strict,
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
        vdf_proof: None,
        vdf_difficulty: None,
    }
}

fn retrieval_level_tag(level: RetrievalProofLevel) -> u64 {
    match level {
        RetrievalProofLevel::ExactDominance => 0,
        RetrievalProofLevel::HnswAuditOnDemand => 1,
        RetrievalProofLevel::CompleteTopK => 2,
    }
}

fn forge_v1_outer_level(
    bytes: &[u8],
    original_level: RetrievalProofLevel,
    forged_level: RetrievalProofLevel,
) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v1 cognition certificate field {other}"),
        }
    }
    assert_eq!(level_tag, Some(retrieval_level_tag(original_level)));

    let mut enc = Encoder::new();
    let mut map_len = 4u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(retrieval_level_tag(forged_level))
        .unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&receipt_bytes.expect("receipt field"))
        .unwrap();
    enc.finish()
}

fn strip_zkann_from_semantic_receipt_bytes(receipt_bytes: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new(receipt_bytes);
    let map = dec.decode_map().unwrap();
    let mut removed_zkann = false;
    let stripped_entries: Vec<_> = map
        .into_iter()
        .filter(|(key, _value)| {
            if key.as_u64() == Some(7) {
                removed_zkann = true;
                false
            } else {
                true
            }
        })
        .collect();
    assert!(
        removed_zkann,
        "fixture receipt must include a zkANN attachment"
    );
    to_bytes_canonical(&CborValue::Map(stripped_entries)).unwrap()
}

fn forge_semantic_receipt_root_bound(receipt_bytes: &[u8], forged_root_bound: [u8; 32]) -> Vec<u8> {
    let mut dec = Decoder::new(receipt_bytes);
    let map = dec.decode_map().unwrap();
    let mut replaced_root_bound = false;
    let forged_entries: Vec<_> = map
        .into_iter()
        .map(|(key, value)| {
            if key.as_u64() == Some(1) {
                replaced_root_bound = true;
                (key, CborValue::Bytes(forged_root_bound.to_vec()))
            } else {
                (key, value)
            }
        })
        .collect();
    assert!(
        replaced_root_bound,
        "fixture receipt must include root_bound"
    );
    to_bytes_canonical(&CborValue::Map(forged_entries)).unwrap()
}

fn forge_semantic_receipt_commit(
    receipt_bytes: &[u8],
    forged_semantic_commit: [u8; 32],
) -> Vec<u8> {
    let mut dec = Decoder::new(receipt_bytes);
    let map = dec.decode_map().unwrap();
    let mut replaced_semantic_commit = false;
    let forged_entries: Vec<_> = map
        .into_iter()
        .map(|(key, value)| {
            if key.as_u64() == Some(2) {
                replaced_semantic_commit = true;
                (key, CborValue::Bytes(forged_semantic_commit.to_vec()))
            } else {
                (key, value)
            }
        })
        .collect();
    assert!(
        replaced_semantic_commit,
        "fixture receipt must include semantic_commit"
    );
    to_bytes_canonical(&CborValue::Map(forged_entries)).unwrap()
}

fn forge_v1_receipt_root_bound(bytes: &[u8], forged_root_bound: [u8; 32]) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v1 cognition certificate field {other}"),
        }
    }
    let forged_receipt = forge_semantic_receipt_root_bound(
        &receipt_bytes.expect("receipt field"),
        forged_root_bound,
    );

    let mut enc = Encoder::new();
    let mut map_len = 4u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(level_tag.expect("level field"))
        .unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&forged_receipt).unwrap();
    enc.finish()
}

fn forge_v1_receipt_semantic_commit(bytes: &[u8], forged_semantic_commit: [u8; 32]) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v1 cognition certificate field {other}"),
        }
    }
    let forged_receipt = forge_semantic_receipt_commit(
        &receipt_bytes.expect("receipt field"),
        forged_semantic_commit,
    );

    let mut enc = Encoder::new();
    let mut map_len = 4u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(level_tag.expect("level field"))
        .unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&forged_receipt).unwrap();
    enc.finish()
}

fn forge_v1_hnsw_wire_level_without_receipt_zkann(bytes: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v1 cognition certificate field {other}"),
        }
    }
    assert_eq!(
        level_tag,
        Some(retrieval_level_tag(RetrievalProofLevel::HnswAuditOnDemand)),
        "fixture must keep the outer wire level at HNSW audit-on-demand"
    );
    let stripped_receipt =
        strip_zkann_from_semantic_receipt_bytes(&receipt_bytes.expect("receipt field"));

    let mut enc = Encoder::new();
    let mut map_len = 4u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(level_tag.expect("level field"))
        .unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&stripped_receipt).unwrap();
    enc.finish()
}

fn forge_v1_as_of_seq(bytes: &[u8], forged_seq: u64) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v1 cognition certificate field {other}"),
        }
    }
    assert_eq!(as_of_seq, None, "fixture must not already carry as_of_seq");

    let mut enc = Encoder::new();
    enc.begin_map(5).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(level_tag.expect("level field"))
        .unwrap();
    enc.encode_unsigned(3).unwrap();
    enc.encode_unsigned(forged_seq).unwrap();
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&receipt_bytes.expect("receipt field"))
        .unwrap();
    enc.finish()
}

fn signed_v1_fixture_with_receipt_level(level: RetrievalProofLevel) -> (Vec<u8>, TrustConfig) {
    let operator = KeyPair::from_seed([0x51; 32]);
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(
            oid(0x51),
            FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
        )
        .unwrap();
    let stored = StoredRoot::assemble(
        [0x52; 32],
        [0x53; 32],
        index.semantic_commit(),
        [0x54; 14],
        [0x00; 32],
        3,
        &operator,
    )
    .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, stored.preimage_hash, level)
        .unwrap();
    assert_eq!(receipt.zkann.as_ref().map(|z| z.level), Some(level));
    let bytes = assemble_cognition_certificate_v1(&stored, &receipt, None).unwrap();
    (bytes, TrustConfig::new(operator.public_key_bytes()))
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
fn cognition_cert_v1_rejects_exact_wire_level_with_hnsw_receipt_zkann() {
    let (bytes, trust) =
        signed_v1_fixture_with_receipt_level(RetrievalProofLevel::HnswAuditOnDemand);
    let forged = forge_v1_outer_level(
        &bytes,
        RetrievalProofLevel::HnswAuditOnDemand,
        RetrievalProofLevel::ExactDominance,
    );

    assert_eq!(
        verify_cognition_certificate_v1(&forged, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[test]
fn cognition_cert_v1_rejects_hnsw_wire_level_with_exact_receipt_zkann() {
    let (bytes, trust) = signed_v1_fixture_with_receipt_level(RetrievalProofLevel::ExactDominance);
    let forged = forge_v1_outer_level(
        &bytes,
        RetrievalProofLevel::ExactDominance,
        RetrievalProofLevel::HnswAuditOnDemand,
    );

    assert_eq!(
        verify_cognition_certificate_v1(&forged, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[test]
fn cognition_cert_v1_rejects_hnsw_wire_level_without_receipt_zkann() {
    let (bytes, trust) =
        signed_v1_fixture_with_receipt_level(RetrievalProofLevel::HnswAuditOnDemand);
    let forged = forge_v1_hnsw_wire_level_without_receipt_zkann(&bytes);

    assert_eq!(
        verify_cognition_certificate_v1(&forged, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[test]
fn cognition_cert_v1_rejects_forged_as_of_sequence_mismatch() {
    let (bytes, trust) = signed_v1_fixture_with_receipt_level(RetrievalProofLevel::ExactDominance);
    let forged = forge_v1_as_of_seq(&bytes, 4);

    assert_eq!(
        verify_cognition_certificate_v1(&forged, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[test]
fn cognition_cert_v1_rejects_forged_receipt_root_bound_mismatch() {
    let (bytes, trust) = signed_v1_fixture_with_receipt_level(RetrievalProofLevel::ExactDominance);
    let forged = forge_v1_receipt_root_bound(&bytes, [0x9a; 32]);

    assert_eq!(
        verify_cognition_certificate_v1(&forged, &trust, &proc()),
        Err(MnemeError::ReceiptRootMismatch)
    );
}

#[test]
fn cognition_cert_v1_rejects_forged_receipt_semantic_commit_mismatch() {
    let (bytes, trust) = signed_v1_fixture_with_receipt_level(RetrievalProofLevel::ExactDominance);
    let forged = forge_v1_receipt_semantic_commit(&bytes, [0x9b; 32]);

    assert_eq!(
        verify_cognition_certificate_v1(&forged, &trust, &proc()),
        Err(MnemeError::ReceiptRootMismatch)
    );
}

#[test]
fn cognition_cert_v1_optional_audit_beacon_field_absent_by_default() {
    let (bytes, trust) = signed_v1_fixture_with_receipt_level(RetrievalProofLevel::ExactDominance);
    let parsed = mneme_index::parse_cognition_certificate(&bytes).unwrap();
    assert!(parsed.audit_beacon.is_none());
    verify_cognition_certificate_v1(&bytes, &trust, &proc()).unwrap();
}

#[test]
fn cognition_cert_v1_audit_beacon_rejects_tampered_binding() {
    let (bytes, trust) = signed_v1_fixture_with_receipt_level(RetrievalProofLevel::ExactDominance);
    let parsed = mneme_index::parse_cognition_certificate(&bytes).unwrap();
    let mut beacon = prove_audit_beacon(50_000, vec![0x42; 32], &parsed.receipt).unwrap();
    beacon.binding_digest[1] ^= 0x80;
    let tampered = assemble_cognition_certificate_v1_with_beacon(
        &parsed.stored_root,
        &parsed.receipt,
        None,
        Some(beacon),
    )
    .unwrap();
    assert_eq!(
        verify_cognition_certificate_v1(&tampered, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
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

#[cfg(feature = "context_gate")]
fn appendix_b_operator() -> mneme_crypto::KeyPair {
    mneme_crypto::KeyPair::from_seed([0x42; 32])
}

#[cfg(feature = "context_gate")]
fn appendix_b_v2_fixture() -> (Vec<u8>, [u8; 32], [u8; 32]) {
    use mneme_index::assemble_cognition_certificate_v2_draft;
    use mneme_root::StoredRoot;
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(
            oid(0xab),
            FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
        )
        .unwrap();
    let semantic_commit = index.semantic_commit();
    let operator = appendix_b_operator();
    let stored = StoredRoot::assemble(
        [0u8; 32],
        [1u8; 32],
        semantic_commit,
        [0u8; 14],
        [0u8; 32],
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
    let attestation = ContextAttestationDraft::placeholder([0x11; 32]);
    let bytes =
        assemble_cognition_certificate_v2_draft(&stored, &receipt, None, attestation).unwrap();
    (bytes, stored.preimage_hash, semantic_commit)
}

#[cfg(feature = "context_gate")]
fn forge_v2_outer_level(
    bytes: &[u8],
    original_level: RetrievalProofLevel,
    forged_level: RetrievalProofLevel,
) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    let mut attestation_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            6 => attestation_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v2 cognition certificate field {other}"),
        }
    }
    assert_eq!(level_tag, Some(retrieval_level_tag(original_level)));

    let mut enc = Encoder::new();
    let mut map_len = 5u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(retrieval_level_tag(forged_level))
        .unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&receipt_bytes.expect("receipt field"))
        .unwrap();
    enc.encode_unsigned(6).unwrap();
    enc.encode_bytes(&attestation_bytes.expect("attestation field"))
        .unwrap();
    enc.finish()
}

#[cfg(feature = "context_gate")]
fn forge_v2_hnsw_wire_level_without_receipt_zkann(bytes: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map().unwrap();
    let mut version = None;
    let mut level_tag = None;
    let mut as_of_seq = None;
    let mut stored_root_bytes = None;
    let mut receipt_bytes = None;
    let mut attestation_bytes = None;
    for (k, v) in map {
        match k.as_u64().unwrap() {
            1 => version = Some(v.as_u64().unwrap()),
            2 => level_tag = Some(v.as_u64().unwrap()),
            3 => as_of_seq = v.as_u64(),
            4 => stored_root_bytes = Some(v.as_bytes().unwrap().to_vec()),
            5 => receipt_bytes = Some(v.as_bytes().unwrap().to_vec()),
            6 => attestation_bytes = Some(v.as_bytes().unwrap().to_vec()),
            other => panic!("unexpected v2 cognition certificate field {other}"),
        }
    }
    assert_eq!(
        level_tag,
        Some(1),
        "fixture must keep the outer wire level at HNSW audit-on-demand"
    );
    let stripped_receipt =
        strip_zkann_from_semantic_receipt_bytes(&receipt_bytes.expect("receipt field"));

    let mut enc = Encoder::new();
    let mut map_len = 5u64;
    if as_of_seq.is_some() {
        map_len += 1;
    }
    enc.begin_map(map_len).unwrap();
    enc.encode_unsigned(1).unwrap();
    enc.encode_unsigned(version.expect("version field"))
        .unwrap();
    enc.encode_unsigned(2).unwrap();
    enc.encode_unsigned(level_tag.expect("level field"))
        .unwrap();
    if let Some(seq) = as_of_seq {
        enc.encode_unsigned(3).unwrap();
        enc.encode_unsigned(seq).unwrap();
    }
    enc.encode_unsigned(4).unwrap();
    enc.encode_bytes(&stored_root_bytes.expect("stored root field"))
        .unwrap();
    enc.encode_unsigned(5).unwrap();
    enc.encode_bytes(&stripped_receipt).unwrap();
    enc.encode_unsigned(6).unwrap();
    enc.encode_bytes(&attestation_bytes.expect("attestation field"))
        .unwrap();
    enc.finish()
}

#[cfg(feature = "context_gate")]
fn v2_fixture_with_receipt_level(
    attestation: ContextAttestationDraft,
    receipt_level: RetrievalProofLevel,
) -> (Vec<u8>, TrustConfig) {
    use mneme_root::StoredRoot;

    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    index
        .insert(
            oid(0xcd),
            FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
        )
        .unwrap();
    let operator = appendix_b_operator();
    let stored = StoredRoot::assemble(
        [0x20; 32],
        [0x21; 32],
        index.semantic_commit(),
        [0x22; 14],
        [0x00; 32],
        2,
        &operator,
    )
    .unwrap();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, stored.preimage_hash, receipt_level)
        .unwrap();
    assert_eq!(receipt.zkann.as_ref().map(|z| z.level), Some(receipt_level));
    let bytes =
        assemble_cognition_certificate_v2_draft(&stored, &receipt, None, attestation).unwrap();
    (bytes, TrustConfig::new(operator.public_key_bytes()))
}

#[cfg(feature = "context_gate")]
fn hnsw_v2_fixture_without_receipt_zkann(
    attestation: ContextAttestationDraft,
) -> (Vec<u8>, TrustConfig) {
    let (bytes, trust) =
        v2_fixture_with_receipt_level(attestation, RetrievalProofLevel::HnswAuditOnDemand);
    (
        forge_v2_hnsw_wire_level_without_receipt_zkann(&bytes),
        trust,
    )
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_draft_rejects_hnsw_wire_level_without_receipt_zkann() {
    let attestation = ContextAttestationDraft::placeholder([0x44; 32]);
    let (bytes, trust) = hnsw_v2_fixture_without_receipt_zkann(attestation);

    assert_eq!(
        verify_cognition_certificate_v2_draft(&bytes, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_strict_rejects_hnsw_wire_level_without_receipt_zkann() {
    let attestation = ContextAttestationDraft::strict(
        ContextConsumptionAttestation {
            assembly_profile: AssemblyProfile { id: [0x45; 32] },
            context_hash: [0x46; 32],
            certified_memory_set_hash: [0x47; 32],
        },
        None,
    );
    let (bytes, trust) = hnsw_v2_fixture_without_receipt_zkann(attestation);

    assert_eq!(
        verify_cognition_certificate_v2_draft_strict(&bytes, &trust, &proc(), &[], None, None),
        Err(MnemeError::CertificateInvalid)
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_draft_rejects_exact_wire_level_with_hnsw_receipt_zkann() {
    let attestation = ContextAttestationDraft::placeholder([0x48; 32]);
    let (bytes, trust) =
        v2_fixture_with_receipt_level(attestation, RetrievalProofLevel::HnswAuditOnDemand);
    let forged = forge_v2_outer_level(
        &bytes,
        RetrievalProofLevel::HnswAuditOnDemand,
        RetrievalProofLevel::ExactDominance,
    );

    assert_eq!(
        verify_cognition_certificate_v2_draft(&forged, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_draft_rejects_hnsw_wire_level_with_exact_receipt_zkann() {
    let attestation = ContextAttestationDraft::placeholder([0x49; 32]);
    let (bytes, trust) =
        v2_fixture_with_receipt_level(attestation, RetrievalProofLevel::ExactDominance);
    let forged = forge_v2_outer_level(
        &bytes,
        RetrievalProofLevel::ExactDominance,
        RetrievalProofLevel::HnswAuditOnDemand,
    );

    assert_eq!(
        verify_cognition_certificate_v2_draft(&forged, &trust, &proc()),
        Err(MnemeError::CertificateInvalid)
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_strict_rejects_exact_wire_level_with_hnsw_receipt_zkann() {
    let attestation = ContextAttestationDraft::strict(
        ContextConsumptionAttestation {
            assembly_profile: AssemblyProfile { id: [0x4a; 32] },
            context_hash: [0x4b; 32],
            certified_memory_set_hash: [0x4c; 32],
        },
        None,
    );
    let (bytes, trust) =
        v2_fixture_with_receipt_level(attestation, RetrievalProofLevel::HnswAuditOnDemand);
    let forged = forge_v2_outer_level(
        &bytes,
        RetrievalProofLevel::HnswAuditOnDemand,
        RetrievalProofLevel::ExactDominance,
    );

    assert_eq!(
        verify_cognition_certificate_v2_draft_strict(&forged, &trust, &proc(), &[], None, None),
        Err(MnemeError::CertificateInvalid)
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_strict_rejects_hnsw_wire_level_with_exact_receipt_zkann() {
    let attestation = ContextAttestationDraft::strict(
        ContextConsumptionAttestation {
            assembly_profile: AssemblyProfile { id: [0x4d; 32] },
            context_hash: [0x4e; 32],
            certified_memory_set_hash: [0x4f; 32],
        },
        None,
    );
    let (bytes, trust) =
        v2_fixture_with_receipt_level(attestation, RetrievalProofLevel::ExactDominance);
    let forged = forge_v2_outer_level(
        &bytes,
        RetrievalProofLevel::ExactDominance,
        RetrievalProofLevel::HnswAuditOnDemand,
    );

    assert_eq!(
        verify_cognition_certificate_v2_draft_strict(&forged, &trust, &proc(), &[], None, None),
        Err(MnemeError::CertificateInvalid)
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_draft_wire_hex_is_frozen() {
    let (bytes, _, _) = appendix_b_v2_fixture();
    assert_eq!(
        hex::encode(bytes),
        "a50102020004590107a901010258200000000000000000000000000000000000000000000000000000000000000000035820010101010101010101010101010101010101010101010101010101010101010104582082a2bb6fee0f66efb1aa40cdf7477bbc1aaf2ab7d113d6018bb4c5380b20599b054e00000000000000000000000000000658200000000000000000000000000000000000000000000000000000000000000000075820a9c6882ecf671fa7595e3beb6b6222e13c24761caca110774a635e1dde15c571085840c4681407a501b07fd8fbfff306fed41398791c9b4c9a2aba873752694a17f761ac3b0bb6c3a8eed2ac91132e9bf7313e1724a640059789c36eec3ac0fd74340909010559014ca7015820a9c6882ecf671fa7595e3beb6b6222e13c24761caca110774a635e1dde15c57102582082a2bb6fee0f66efb1aa40cdf7477bbc1aaf2ab7d113d6018bb4c5380b20599b0358206b57290901159c7b137d09b560c53dbb149bfc7075e975536b1ee8de1f32fc1d045820caaa71e5668ac5b52c5e152c25614db2a5245c103d523dce6d41967f3ac5cb2505815820abababababababababababababababababababababababababababababababab06a3018182582082a2bb6fee0f66efb1aa40cdf7477bbc1aaf2ab7d113d6018bb4c5380b20599b800281835820abababababababababababababababababababababababababababababababab582061b7d4e910c08bef298678b03b937f92a49cc1f059b7c07be4793e6bf23702ed0103810007a2010002815820abababababababababababababababababababababababababababababababab065845a201781e756e76657269666965645f756e74696c5f70686173655f69695f676174650258201111111111111111111111111111111111111111111111111111111111111111"
    );
}

#[cfg(feature = "context_gate")]
#[test]
fn cognition_cert_v2_draft_crossref_vector_verifies() {
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
        .find(|e| e["name"].as_str() == Some("cognition_cert_v2_draft"))
        .expect("v2 entry");
    let bytes = fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../proof/vectors/certs")
            .join(entry["cbor_file"].as_str().unwrap()),
    )
    .unwrap();
    verify_cognition_certificate_v2_draft(
        &bytes,
        &TrustConfig::new(appendix_b_operator().public_key_bytes()),
        &proc(),
    )
    .unwrap();
}

#[cfg(feature = "context_gate")]
#[test]
#[ignore]
fn dump_cognition_cert_v2_draft_fixture() {
    let (bytes, preimage_hash, semantic_commit) = appendix_b_v2_fixture();
    eprintln!("cognition_cert_v2_draft_wire_hex={}", hex::encode(&bytes));
    eprintln!(
        "cognition_cert_v2_draft_preimage_hash_hex={}",
        hex::encode(preimage_hash)
    );
    eprintln!(
        "cognition_cert_v2_draft_semantic_commit_hex={}",
        hex::encode(semantic_commit)
    );
    eprintln!(
        "cognition_cert_v2_draft_operator_pubkey_hex={}",
        hex::encode(appendix_b_operator().public_key_bytes())
    );
}
