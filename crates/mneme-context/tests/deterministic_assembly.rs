//! Cross-fixture determinism checks for P2-3 context assembly.

use mneme_context::{
    ASSEMBLY_PROFILE_V1, assemble_verified_context, certified_memory_set_payload,
    encode_assembled_prompt_v1,
};
use mneme_core::object::{MemoryKind, OBJECT_VERSION, ObjectRecord, PayloadEnc, TrustTier};
use mneme_core::{
    Entry, HlcWire, MnemeError, ObjectId, hash_certified_memory_set, hash_context_assembled,
    hash_obj, to_bytes_canonical,
};

fn entry(body: &[u8], wall_ms: u64) -> Entry {
    let record = ObjectRecord {
        version: OBJECT_VERSION,
        kind: MemoryKind::Semantic.as_u8(),
        parent_ids: vec![],
        writer: [0xaa; 32],
        session: [0xbb; 16],
        hlc: HlcWire {
            wall_ms,
            counter: 0,
            node_id: [0x07; 16],
        },
        trust_tier: TrustTier::Trusted.as_u8(),
        payload_enc: PayloadEnc {
            alg: 0,
            key_id: None,
            nonce: None,
            body: body.to_vec(),
        },
        embedding_commit: Some([0xcc; 32]),
        redaction_slot: None,
        ext: None,
    };
    let canonical = to_bytes_canonical(&record).expect("canonical");
    let id = ObjectId(hash_obj(&canonical));
    Entry {
        id,
        record,
        plaintext: body.to_vec(),
    }
}

#[test]
fn context_hash_is_independent_of_entry_container_order() {
    let e1 = entry(b"first", 1);
    let e2 = entry(b"second", 2);
    let e3 = entry(b"third", 3);
    let ids = vec![e1.id, e2.id, e3.id];
    let entries = vec![e1, e2, e3];
    let outcome = assemble_verified_context(&ids, &entries, ASSEMBLY_PROFILE_V1).unwrap();

    let payloads: Vec<&[u8]> = entries.iter().map(|e| e.plaintext.as_slice()).collect();
    let bytes = encode_assembled_prompt_v1(&ids, &payloads);
    assert_eq!(outcome.assembled_bytes, bytes);
    assert_eq!(outcome.context_hash, hash_context_assembled(&bytes));

    let cms = certified_memory_set_payload(&ids);
    assert_eq!(
        outcome.certified_memory_set_hash,
        hash_certified_memory_set(&cms)
    );
}

#[test]
fn certified_set_hash_depends_only_on_result_ids() {
    let e = entry(b"payload-a", 10);
    let cms = certified_memory_set_payload(&[e.id]);
    let hash = hash_certified_memory_set(&cms);
    assert_eq!(
        hash,
        hash_certified_memory_set(&certified_memory_set_payload(&[e.id]))
    );

    let other = entry(b"payload-b", 11);
    assert_ne!(
        hash,
        hash_certified_memory_set(&certified_memory_set_payload(&[other.id]))
    );
}

#[test]
fn context_hash_changes_with_payload() {
    let a = entry(b"payload-a", 10);
    let b = entry(b"payload-b", 10);
    let outcome_a = assemble_verified_context(&[a.id], &[a], ASSEMBLY_PROFILE_V1).unwrap();
    let outcome_b = assemble_verified_context(&[b.id], &[b], ASSEMBLY_PROFILE_V1).unwrap();
    assert_ne!(outcome_a.context_hash, outcome_b.context_hash);
}

#[test]
fn golden_context_hash_v1() {
    let e = entry(b"golden", 99);
    let outcome = assemble_verified_context(&[e.id], &[e], ASSEMBLY_PROFILE_V1).unwrap();
    // Frozen cross-run digest for foundation-gate style determinism checks.
    assert_eq!(
        hex::encode(outcome.context_hash),
        "950db4dc4c290285c6c31769b7f17f9ba0a03ba343455fd5bb7380148425a7e4"
    );
}

#[test]
fn rejects_unknown_profile() {
    let e = entry(b"x", 1);
    let unknown = mneme_core::AssemblyProfile { id: [0xff; 32] };
    assert_eq!(
        assemble_verified_context(&[e.id], &[e], unknown),
        Err(MnemeError::SchemaDrift)
    );
}
