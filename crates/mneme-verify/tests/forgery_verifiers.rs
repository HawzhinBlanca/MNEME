//! Hand-crafted forgery attempts — one per public verifier entry point (§17.2).

mod helpers;

use std::path::Path;

use helpers::{
    build_root_chain_fixture, build_valid_recall, build_valid_semantic_recall, sample_procedure,
    sample_query_embedding, theme_key,
};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_crypto::KeyPair;
use mneme_smt::{MembershipProof, TREE_DEPTH};
use mneme_verify::{
    RecallContext, verify_membership_proof, verify_recall, verify_root, verify_semantic_recall,
    verify_semantic_receipt, verify_signed_head_only, verify_store,
};

#[test]
fn forgery_membership_proof_replays_valid_path_under_wrong_root() {
    let f = build_valid_recall();
    let mut proof = MembershipProof {
        key: f.input.receipt.logical_key,
        value: f.input.receipt.object_id,
        path: f.input.receipt.membership_proof.clone(),
        root: f.input.receipt.key_index_root,
        leaf_index: 0,
    };
    proof.root[0] ^= 0x01;
    assert_eq!(
        verify_membership_proof(&proof).unwrap_err(),
        MnemeError::IndexPathInvalid
    );
}

#[test]
fn forgery_membership_proof_empty_path_with_claimed_depth() {
    let f = build_valid_recall();
    let proof = MembershipProof {
        key: f.input.receipt.logical_key,
        value: f.input.receipt.object_id,
        path: vec![[0u8; 32]; TREE_DEPTH - 1],
        root: f.input.receipt.key_index_root,
        leaf_index: 0,
    };
    assert_eq!(
        verify_membership_proof(&proof).unwrap_err(),
        MnemeError::IndexPathInvalid
    );
}

#[test]
fn forgery_root_signed_by_untrusted_operator() {
    let fixture = build_root_chain_fixture();
    let attacker = KeyPair::from_seed([0x99; 32]);
    let mut root = fixture.root.clone();
    let bound = mneme_core::RootPreimage {
        version: root.version,
        dag_head_root: root.dag_head_root,
        key_index_root: root.key_index_root,
        semantic_commit: root.semantic_commit,
        hlc_max: root.hlc_max,
        prev_root: root.prev_root,
    };
    root.preimage_hash = bound.hash();
    root.signature = attacker.sign(&root.preimage_hash).to_vec();
    assert_eq!(
        verify_root(&root, &fixture.trust, fixture.previous_root.as_ref()).unwrap_err(),
        MnemeError::RootSigInvalid
    );
}

#[test]
fn forgery_recall_swaps_object_id_while_reusing_membership_path() {
    let mut f = build_valid_recall();
    f.input.receipt.object_id[0] ^= 0x01;
    let query = Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Working,
        embedding: None,
        drand_signature: None,
    };
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    };
    assert_eq!(
        verify_recall(&f.input, &query, &f.trust, &ctx).unwrap_err(),
        MnemeError::IndexPathInvalid
    );
}

#[test]
fn forgery_store_head_accepts_no_objects_but_rejects_bad_sig() {
    let fixture = build_root_chain_fixture();
    let mut root = fixture.root.clone();
    root.signature[0] ^= 0x01;
    match verify_signed_head_only(&root, &fixture.trust) {
        Err(MnemeError::RootSigInvalid) => {}
        Err(e) => panic!("expected RootSigInvalid, got {e:?}"),
        Ok(_) => panic!("expected RootSigInvalid, verify_signed_head_only succeeded"),
    }
}

#[test]
fn forgery_store_head_skips_object_integrity_verify_store_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let f = build_valid_recall();
    persist_forgery_store(dir.path(), &f);
    let object_id = f.input.receipt.object_id;
    let obj_hex = hex32(&object_id);
    let obj_path = dir
        .path()
        .join(format!("objects/{}/{}.cbor", &obj_hex[..2], obj_hex));
    let mut bytes = std::fs::read(&obj_path).expect("object bytes");
    bytes[0] ^= 0x01;
    std::fs::write(&obj_path, &bytes).expect("tamper object");

    let head =
        verify_signed_head_only(&f.input.root, &f.trust).expect("signature-only accepts head");
    assert_eq!(head.root.preimage_hash, f.input.root.preimage_hash);

    match verify_store(dir.path(), &f.trust) {
        Err(MnemeError::ObjectTampered)
        | Err(MnemeError::SchemaDrift)
        | Err(MnemeError::RootInconsistent) => {}
        Err(e) => panic!("verify_store must fail closed on tampered object, got {e:?}"),
        Ok(_) => panic!("verify_store must reject tampered object bytes"),
    }
}

#[test]
fn forgery_semantic_receipt_binds_to_alien_semantic_commit() {
    let mut f = build_valid_semantic_recall();
    f.receipt.semantic_commit[0] ^= 0x01;
    assert_eq!(
        verify_semantic_receipt(
            &f.receipt,
            &f.root,
            &f.procedure,
            &f.trust,
            f.previous_root.as_ref(),
            None,
        )
        .unwrap_err(),
        MnemeError::ReceiptRootMismatch
    );
}

#[test]
fn forgery_verify_store_signed_head_mismatched_key_index_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let f = build_valid_recall();
    persist_forgery_store(dir.path(), &f);
    let key_hex = hex32(&f.input.receipt.logical_key);
    let bogus_object = hex32(&[0xab; 32]);
    let payload = format!(r#"{{"entries":{{"{key_hex}":"{bogus_object}"}},"tombstones":[]}}"#);
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");
    match verify_store(dir.path(), &f.trust) {
        Err(MnemeError::RootInconsistent) => {}
        Err(e) => panic!("expected RootInconsistent, got {e:?}"),
        Ok(_) => panic!("expected RootInconsistent, verify_store succeeded"),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn persist_forgery_store(path: &Path, fixture: &helpers::RecallFixture) {
    use mneme_crypto::KeyPair;
    use mneme_root::StoredRoot;

    std::fs::create_dir_all(path.join("objects")).expect("objects dir");
    std::fs::create_dir_all(path.join("roots")).expect("roots dir");
    std::fs::create_dir_all(path.join("meta")).expect("meta dir");

    for (id, bytes) in &fixture.objects {
        let hex = hex32(id);
        let obj_path = path.join(format!("objects/{}/{}.cbor", &hex[..2], hex));
        std::fs::create_dir_all(obj_path.parent().expect("parent")).expect("shard dir");
        std::fs::write(&obj_path, bytes).expect("object bytes");
    }

    let operator = KeyPair::from_seed([0x01; 32]);
    if let Some(prev) = &fixture.previous_root {
        let prev_stored = StoredRoot::assemble(
            prev.dag_head_root,
            prev.key_index_root,
            prev.semantic_commit,
            prev.hlc_max,
            prev.prev_root,
            prev.sequence,
            &operator,
        )
        .expect("prev stored");
        std::fs::write(
            path.join(format!("roots/{}.root.cbor", prev.sequence)),
            prev_stored.to_bytes().expect("prev bytes"),
        )
        .expect("prev checkpoint");
    }

    let stored = StoredRoot::assemble(
        fixture.input.root.dag_head_root,
        fixture.input.root.key_index_root,
        fixture.input.root.semantic_commit,
        fixture.input.root.hlc_max,
        fixture.input.root.prev_root,
        fixture.input.root.sequence,
        &operator,
    )
    .expect("head stored");
    std::fs::write(
        path.join("roots/HEAD"),
        stored.to_bytes().expect("head bytes"),
    )
    .expect("head");
}

#[test]
fn forgery_semantic_recall_swaps_object_bytes_under_valid_receipt() {
    let mut f = build_valid_semantic_recall();
    let id = f.receipt.verification_object.result_ids[0];
    f.objects.get_mut(id.as_bytes()).unwrap()[0] ^= 0x01;
    let query = Query {
        logical_key: theme_key("semantic", "query"),
        min_tier: TrustTier::Working,
        embedding: Some(sample_query_embedding()),
        drand_signature: None,
    };
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    };
    assert_eq!(
        verify_semantic_recall(
            &mneme_verify::SemanticRecallInput {
                receipt: f.receipt.clone(),
                root: f.root.clone(),
            },
            &sample_procedure(),
            &query,
            &f.trust,
            &ctx,
        )
        .unwrap_err(),
        MnemeError::ObjectTampered
    );
}
