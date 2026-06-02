//! Tamper suite for mneme-verify (§17.2, v0 ≥40 cases).

mod helpers;

use helpers::{build_valid_recall, theme_key};
use mneme_core::{MnemeError, Query, TrustTier};
use mneme_verify::{
    RecallContext, verify_membership_proof, verify_recall, verify_root, verify_store,
};

macro_rules! tamper_case {
    ($name:ident, |$var:ident| $body:stmt, $expected:expr) => {
        #[test]
        fn $name() {
            let mut fixture = build_valid_recall();
            {
                let $var = &mut fixture;
                $body
            }
            let err = run_verify(&fixture).unwrap_err();
            assert_eq!(err, $expected, "case {}", stringify!($name));
        }
    };
}

fn run_verify(f: &helpers::RecallFixture) -> Result<(), MnemeError> {
    let query = Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    };
    verify_recall(&f.input, &query, &f.trust, &ctx).map(|_| ())
}

// --- object bytes ---

tamper_case!(
    tamper_object_byte_0,
    |f| f.input.object_bytes[0] ^= 0x01,
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_mid,
    |f| {
        let i = f.input.object_bytes.len() / 2;
        f.input.object_bytes[i] ^= 0x80;
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_last,
    |f| {
        let i = f.input.object_bytes.len() - 1;
        f.input.object_bytes[i] ^= 0x04;
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_truncated,
    |f| {
        f.input.object_bytes.pop();
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_garbage_appended,
    |f| f.input.object_bytes.push(0xff),
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_1,
    |f| {
        if f.input.object_bytes.len() > 1 {
            f.input.object_bytes[1] ^= 0x02;
        }
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_2,
    |f| {
        if f.input.object_bytes.len() > 2 {
            f.input.object_bytes[2] ^= 0x04;
        }
    },
    MnemeError::ObjectTampered
);

// --- receipt fields ---

tamper_case!(
    tamper_receipt_root_bound,
    |f| f.input.receipt.root_bound[0] ^= 0xff,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_receipt_key_index_root,
    |f| f.input.receipt.key_index_root[31] ^= 0x01,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_receipt_logical_key,
    |f| f.input.receipt.logical_key[0] ^= 0x02,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_receipt_object_id,
    |f| f.input.receipt.object_id[5] ^= 0x10,
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_receipt_leaf_index,
    |f| f.input.receipt.leaf_index = 1,
    MnemeError::IndexPathInvalid
);

// --- SMT path siblings (immudb: every element) ---

tamper_case!(
    tamper_path_depth_0,
    |f| flip_path(&mut f.input.receipt.membership_proof, 0),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_1,
    |f| flip_path(&mut f.input.receipt.membership_proof, 1),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_2,
    |f| flip_path(&mut f.input.receipt.membership_proof, 2),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_8,
    |f| flip_path(&mut f.input.receipt.membership_proof, 8),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_16,
    |f| flip_path(&mut f.input.receipt.membership_proof, 16),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_32,
    |f| flip_path(&mut f.input.receipt.membership_proof, 32),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_64,
    |f| flip_path(&mut f.input.receipt.membership_proof, 64),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_96,
    |f| flip_path(&mut f.input.receipt.membership_proof, 96),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_128,
    |f| flip_path(&mut f.input.receipt.membership_proof, 128),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_200,
    |f| flip_path(&mut f.input.receipt.membership_proof, 200),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_255,
    |f| flip_path(&mut f.input.receipt.membership_proof, 255),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_truncated,
    |f| {
        f.input.receipt.membership_proof.pop();
    },
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_root_mismatch,
    |f| f.input.receipt.membership_proof[0][0] ^= 0xaa,
    MnemeError::IndexPathInvalid
);

// --- signed root / checkpoint ---

tamper_case!(
    tamper_root_signature,
    |f| f.input.root.signature[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_preimage_hash,
    |f| f.input.root.preimage_hash[10] ^= 0x20,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_hlc_replay,
    |f| {
        f.input.root.hlc_max = [0u8; 14];
        f.trust.last_seen_hlc = Some([0xff; 14]);
    },
    MnemeError::RootReplayed
);
tamper_case!(
    tamper_root_chain_break,
    |f| {
        let prev = f.previous_root.as_ref().expect("prev").clone();
        f.input.root.prev_root = [0xee; 32];
        f.previous_root = Some(prev);
    },
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_key_index_mismatch,
    |f| f.input.root.key_index_root[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_checkpoint_sequence_zero,
    |f| f.input.root.sequence = 0,
    MnemeError::RootInconsistent
);
tamper_case!(
    tamper_root_dag_head_mismatch,
    |f| f.input.root.dag_head_root[0] ^= 0x01,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_semantic_commit_mismatch,
    |f| f.input.root.semantic_commit[0] ^= 0x02,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_hlc_max_byte,
    |f| f.input.root.hlc_max[3] ^= 0x04,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_receipt_membership_tombstone_value,
    |f| f.input.receipt.object_id = mneme_smt::TOMBSTONE,
    MnemeError::Forgotten
);
tamper_case!(
    tamper_tombstone_then_recall,
    |f| {
        let key = f.input.receipt.logical_key;
        f.key_index.tombstone(key);
        f.key_index.rebuild_root_cache();
    },
    MnemeError::Forgotten
);
tamper_case!(
    tamper_tombstone_membership_proof_stale,
    |f| {
        let key = f.input.receipt.logical_key;
        f.key_index.tombstone(key);
    },
    MnemeError::Forgotten
);
tamper_case!(
    tamper_path_depth_4,
    |f| flip_path(&mut f.input.receipt.membership_proof, 4),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_12,
    |f| flip_path(&mut f.input.receipt.membership_proof, 12),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_24,
    |f| flip_path(&mut f.input.receipt.membership_proof, 24),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_path_depth_100,
    |f| flip_path(&mut f.input.receipt.membership_proof, 100),
    MnemeError::IndexPathInvalid
);
tamper_case!(
    tamper_object_byte_3,
    |f| {
        if f.input.object_bytes.len() > 3 {
            f.input.object_bytes[3] ^= 0x08;
        }
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_object_byte_4,
    |f| {
        if f.input.object_bytes.len() > 4 {
            f.input.object_bytes[4] ^= 0x10;
        }
    },
    MnemeError::ObjectTampered
);
tamper_case!(
    tamper_receipt_root_bound_last,
    |f| f.input.receipt.root_bound[31] ^= 0x01,
    MnemeError::ReceiptRootMismatch
);
tamper_case!(
    tamper_checkpoint_prev_root_zeroed,
    |f| f.input.root.prev_root = [0u8; 32],
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_sequence_regression,
    |f| {
        if let Some(prev) = f.previous_root.clone() {
            f.input.root.sequence = prev.sequence;
        }
    },
    MnemeError::RootInconsistent
);
tamper_case!(
    tamper_root_version_without_preimage_update,
    |f| f.input.root.version = f.input.root.version.wrapping_add(1),
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_version_zero,
    |f| f.input.root.version = 0,
    MnemeError::RootSigInvalid
);
tamper_case!(
    tamper_root_version_unsupported,
    |f| f.input.root.version = 99,
    MnemeError::RootSigInvalid
);

// --- authorization / tier / forgotten / provenance ---

tamper_case!(
    tamper_unauthorized_writer,
    |f| f.trust.authorized_writers.clear(),
    MnemeError::UnauthorizedWriter
);
tamper_case!(
    tamper_forgotten_tombstone,
    |f| {
        let key = f.input.receipt.logical_key;
        f.key_index.tombstone(key);
    },
    MnemeError::Forgotten
);
#[test]
fn tamper_provenance_missing_parent() {
    let mut fixture = helpers::build_valid_recall_with_parent();
    let record: mneme_core::ObjectRecord =
        mneme_core::from_bytes_strict(&fixture.input.object_bytes).expect("parse");
    let parent = record.parent_ids[0];
    fixture.objects.remove(&parent);
    let err = run_verify(&fixture).unwrap_err();
    assert_eq!(err, MnemeError::ProvenanceBroken);
}

#[test]
fn tamper_below_tier_policy() {
    let fixture = build_valid_recall();
    let query = Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Trusted,
        embedding: None,
    };
    let ctx = RecallContext {
        key_index: &fixture.key_index,
        dag: &fixture.dag,
        objects: &fixture.objects,
        previous_root: fixture.previous_root.as_ref(),
    };
    let err = verify_recall(&fixture.input, &query, &fixture.trust, &ctx).unwrap_err();
    assert_eq!(
        err,
        MnemeError::BelowTierPolicy {
            required: TrustTier::Trusted.as_u8(),
            got: TrustTier::Working.as_u8(),
        }
    );
    assert!(err.to_string().contains("§3 honesty boundary"));
}

#[test]
fn tamper_verify_root_bad_sig() {
    let f = build_valid_recall();
    let mut root = f.input.root.clone();
    root.signature = vec![0u8; 64];
    let err = verify_root(&root, &f.trust, f.previous_root.as_ref()).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn tamper_verify_store_incomplete_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".incomplete"), b"1").expect("write");
    let f = build_valid_recall();
    match verify_store(dir.path(), &f.trust) {
        Err(err) => assert_eq!(err, MnemeError::IncompleteTransaction),
        Ok(_) => panic!("expected incomplete transaction rejection"),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn persist_recall_fixture_store(
    path: &std::path::Path,
    fixture: &helpers::RecallFixture,
) -> mneme_root::StoredRoot {
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
    // A real commit appends `roots/<seq>.root.cbor` before writing HEAD; mirror
    // that here so the store passes the F-3 head-checkpoint-existence gate and the
    // intended downstream tamper (key_index / tombstone) is what fails closed.
    std::fs::write(
        path.join(format!("roots/{}.root.cbor", stored.sequence)),
        stored.to_bytes().expect("head checkpoint bytes"),
    )
    .expect("head checkpoint");
    std::fs::write(
        path.join("roots/HEAD"),
        stored.to_bytes().expect("head bytes"),
    )
    .expect("head");
    stored
}

/// A-DB: multibyte UTF-8 in `meta/key_index.json` must return `SchemaDrift`, never panic (B1).
#[test]
fn tamper_verify_store_multibyte_key_index_schema_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = build_valid_recall();
    persist_recall_fixture_store(dir.path(), &fixture);

    let malicious_key = format!("\u{20AC}{}", "a".repeat(61));
    assert_eq!(malicious_key.len(), 64, "64-byte key hits len guard");
    let payload = format!(
        "{{\"entries\":{{\"{}\":\"{}\"}},\"tombstones\":[]}}",
        malicious_key,
        "0".repeat(64)
    );
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &fixture.trust)
    }));
    assert!(
        result.is_ok(),
        "verify_store must not panic on attacker-controlled key_index.json"
    );
    match result.unwrap() {
        Err(MnemeError::SchemaDrift) => {}
        Err(other) => panic!("expected SchemaDrift, got {other:?}"),
        Ok(_) => panic!("expected SchemaDrift, verify_store succeeded"),
    }
}

/// Tombstone entries with multibyte UTF-8 must also fail closed as `SchemaDrift`.
#[test]
fn tamper_verify_store_multibyte_key_index_tombstone_schema_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = build_valid_recall();
    persist_recall_fixture_store(dir.path(), &fixture);

    let malicious_tombstone = format!("\u{20AC}{}", "b".repeat(61));
    assert_eq!(malicious_tombstone.len(), 64);
    let payload = format!(
        "{{\"entries\":{{}},\"tombstones\":[\"{}\"]}}",
        malicious_tombstone
    );
    std::fs::write(dir.path().join("meta/key_index.json"), payload).expect("sidecar");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &fixture.trust)
    }));
    assert!(
        result.is_ok(),
        "verify_store must not panic on tombstone tamper"
    );
    match result.unwrap() {
        Err(MnemeError::SchemaDrift) => {}
        Err(other) => panic!("expected SchemaDrift, got {other:?}"),
        Ok(_) => panic!("expected SchemaDrift, verify_store succeeded"),
    }
}

#[test]
fn tamper_membership_proof_each_element_checked() {
    let f = build_valid_recall();
    let proof = mneme_smt::MembershipProof {
        key: f.input.receipt.logical_key,
        value: f.input.receipt.object_id,
        path: f.input.receipt.membership_proof.clone(),
        root: f.input.receipt.key_index_root,
        leaf_index: 0,
    };
    verify_membership_proof(&proof).expect("valid proof");
    let mut bad = proof.clone();
    for depth in [0usize, 7, 63, 200, 255] {
        bad.path[depth][depth % 32] ^= 0x01;
        assert_eq!(
            verify_membership_proof(&bad).unwrap_err(),
            MnemeError::IndexPathInvalid,
            "depth {depth}"
        );
        bad = proof.clone();
    }
}

#[test]
fn tamper_stored_root_checkpoint_byte() {
    use mneme_crypto::KeyPair;
    use mneme_root::StoredRoot;

    let fixture = build_valid_recall();
    let operator = KeyPair::from_seed([0x01; 32]);
    let stored = StoredRoot::assemble(
        fixture.input.root.dag_head_root,
        fixture.input.root.key_index_root,
        fixture.input.root.semantic_commit,
        fixture.input.root.hlc_max,
        fixture.input.root.prev_root,
        fixture.input.root.sequence,
        &operator,
    )
    .expect("assemble");
    let bytes = stored.to_bytes().expect("bytes");
    let mut tampered = bytes.clone();
    tampered[0] ^= 0x01;
    assert!(StoredRoot::from_bytes(&tampered).is_err());
}

/// Hex object id of the sole object written by [`persisted_store_with_entry`],
/// read straight from the content-addressed `objects/<shard>/<hex>.cbor` layout
/// (independent of the sidecar persistence format).
fn sole_object_id_hex(store: &std::path::Path) -> String {
    for shard in std::fs::read_dir(store.join("objects"))
        .expect("objects dir")
        .flatten()
    {
        if shard.path().is_dir() {
            for f in std::fs::read_dir(shard.path())
                .expect("shard dir")
                .flatten()
            {
                let p = f.path();
                if p.extension().is_some_and(|e| e == "cbor") {
                    return p.file_stem().expect("stem").to_string_lossy().into_owned();
                }
            }
        }
    }
    panic!("no object found under objects/");
}

/// Build a real on-disk store (create + one `remember`) so the object-keys sidecar
/// (`meta/object_keys.{json,journal}`), the signed checkpoint log, and HEAD all
/// exist and are mutually consistent.
fn persisted_store_with_entry() -> (tempfile::TempDir, mneme_crypto::TrustConfig) {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x21; 32]);
    let agent = KeyPair::from_seed([0x22; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    store
        .remember(
            mneme_core::Draft {
                namespace: "sidecar".into(),
                logical_name: "obj".into(),
                kind: mneme_core::MemoryKind::Semantic,
                body: b"sidecar-body".to_vec(),
                parent_ids: vec![],
                session: [0x23; 16],
                trust_tier: None,
                embedding: None,
            },
            &cap,
        )
        .expect("remember");
    drop(store);
    (dir, trust)
}

/// B-1: a byte flip in the persisted object-keys sidecar (the `object_keys.journal`
/// holds the single-`remember` mapping) must now make `verify_store` itself fail
/// closed (typed Err, no panic) — previously caught only by `Store::open`.
#[test]
fn tamper_verify_store_object_keys_byteflip_fails_closed() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let journal = dir.path().join("meta/object_keys.journal");
    let mut bytes = std::fs::read(&journal).expect("read object_keys.journal");
    assert!(!bytes.is_empty(), "journal must hold the remember mapping");
    bytes[0] ^= 0x55;
    std::fs::write(&journal, &bytes).expect("write corrupt journal");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_store(dir.path(), &trust)
    }));
    assert!(
        result.is_ok(),
        "verify_store must not panic on a corrupted object_keys sidecar"
    );
    match result.unwrap() {
        Err(_) => {}
        Ok(_) => panic!("verify_store returned Ok on a corrupted object_keys sidecar (B-1 gap)"),
    }
}

/// F-A: a byte flip in a content-addressed object file must surface as
/// `ObjectTampered` from `verify_store`'s re-hash loop (previously the loop was
/// tautological — objects were re-keyed by their own recomputed hash — and the
/// flip was caught only indirectly as `RootInconsistent` via the rebuilt DAG).
#[test]
fn tamper_verify_store_object_byteflip_is_object_tampered() {
    let (dir, trust) = persisted_store_with_entry();
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let id_hex = sole_object_id_hex(dir.path());
    let obj_path = dir
        .path()
        .join(format!("objects/{}/{}.cbor", &id_hex[..2], id_hex));
    // Re-encode a valid-but-different record under the SAME filename so the bytes
    // still parse: this forces the re-hash loop (not the decoder) to reject, with
    // the filename id fixed while `hash_obj` of the new bytes differs.
    let bytes = std::fs::read(&obj_path).expect("read object");
    let mut record: mneme_core::ObjectRecord =
        mneme_core::from_bytes_strict(&bytes).expect("parse object");
    record.payload_enc.body.push(0xAB);
    let tampered = mneme_core::to_bytes_canonical(&record).expect("re-encode");
    assert_ne!(tampered, bytes, "tamper must change bytes");
    std::fs::write(&obj_path, &tampered).expect("write tampered object");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(
            e,
            MnemeError::ObjectTampered,
            "object byte flip must surface as ObjectTampered, not {e:?}"
        ),
        Ok(_) => panic!("tampered object must fail closed"),
    }
}

/// F-A: a `.cbor` file in `objects/` whose name is not a 64-hex content address
/// is a malformed (attacker-injected) store and must fail closed, not be silently
/// re-keyed by its content hash.
#[test]
fn tamper_verify_store_non_content_addressed_object_rejected() {
    let (dir, trust) = persisted_store_with_entry();
    let shard = dir.path().join("objects/zz");
    std::fs::create_dir_all(&shard).expect("shard");
    std::fs::write(shard.join("not-a-hash.cbor"), b"\x80").expect("rogue object");
    match verify_store(dir.path(), &trust) {
        Err(MnemeError::SchemaDrift) => {}
        Err(other) => panic!("expected SchemaDrift, got {other:?}"),
        Ok(_) => panic!("non-content-addressed object must fail closed"),
    }
}

/// B-1: rebinding an object to a well-formed logical key whose hash is unknown to
/// the verified key-index is rejected as `RootInconsistent`. The journal is the
/// authoritative (last-write-wins) source for the mapping, so we rewrite it.
#[test]
fn tamper_verify_store_object_keys_namespace_rebind() {
    let (dir, trust) = persisted_store_with_entry();
    let id = sole_object_id_hex(dir.path());
    let journal = dir.path().join("meta/object_keys.journal");
    let rebound = format!("{{\"id\":\"{id}\",\"namespace\":\"attacker\",\"name\":\"rebound\"}}\n");
    std::fs::write(&journal, rebound).expect("write rebound journal");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("rebound logical key must fail closed as RootInconsistent"),
    }
}

/// B-1: an entry whose object id is absent from the verified object set is rejected
/// as `RootInconsistent` (exercises the `object_keys.json` snapshot path too).
#[test]
fn tamper_verify_store_object_keys_unknown_object_id() {
    let (dir, trust) = persisted_store_with_entry();
    let sidecar = dir.path().join("meta/object_keys.json");
    let payload = format!(
        "{{\"entries\":{{\"{}\":{{\"namespace\":\"sidecar\",\"name\":\"obj\"}}}}}}",
        "0".repeat(64)
    );
    std::fs::write(&sidecar, payload).expect("write unknown-id snapshot");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(e, MnemeError::RootInconsistent),
        Ok(_) => panic!("unknown object id must fail closed as RootInconsistent"),
    }
}

/// B-2: flipping ONLY the signature bytes after an otherwise-valid decode exercises
/// the genuine `RootSigInvalid` path (not the `schema drift` that a raw byte flip in
/// the CBOR framing produces).
#[test]
fn tamper_verify_store_head_signature_only_rootsiginvalid() {
    use mneme_root::StoredRoot;
    let (dir, trust) = persisted_store_with_entry();
    let head = dir.path().join("roots/HEAD");
    let stored = StoredRoot::from_bytes(&std::fs::read(&head).expect("read head")).expect("decode");
    let mut tampered = stored.clone();
    assert!(!tampered.signature.is_empty(), "signature present");
    tampered.signature[0] ^= 0x01;
    std::fs::write(&head, tampered.to_bytes().expect("encode")).expect("write head");
    match verify_store(dir.path(), &trust) {
        Err(e) => assert_eq!(
            e,
            MnemeError::RootSigInvalid,
            "well-formed decode with a bad signature must surface RootSigInvalid"
        ),
        Ok(_) => panic!("bad signature must fail closed"),
    }
}

/// F-3: a tampered NON-adjacent intermediate checkpoint (`roots/1.root.cbor` while
/// HEAD is seq 3) must now fail closed; previously only HEAD's `seq-1` predecessor
/// was re-verified, so this left `verify_store == Ok`.
#[test]
fn tamper_verify_store_intermediate_checkpoint_fails_closed() {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x31; 32]);
    let agent = KeyPair::from_seed([0x32; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    for i in 0..2 {
        store
            .remember(
                mneme_core::Draft {
                    namespace: "chain".into(),
                    logical_name: format!("k{i}"),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: b"chain-body".to_vec(),
                    parent_ids: vec![],
                    session: [0x33; 16],
                    trust_tier: None,
                    embedding: None,
                },
                &cap,
            )
            .expect("remember");
    }
    drop(store);
    let intermediate = dir.path().join("roots/1.root.cbor");
    assert!(
        intermediate.exists(),
        "non-adjacent intermediate checkpoint"
    );
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline 3-checkpoint store must verify clean"
    );
    let mut bytes = std::fs::read(&intermediate).expect("read checkpoint");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x55;
    std::fs::write(&intermediate, &bytes).expect("write corrupt checkpoint");
    match verify_store(dir.path(), &trust) {
        Err(err) => assert!(
            matches!(
                err,
                MnemeError::RootSigInvalid
                    | MnemeError::RootInconsistent
                    | MnemeError::SchemaDrift
                    | MnemeError::SerializationNonCanonical
            ),
            "tampered intermediate checkpoint must fail closed, got {err:?}"
        ),
        Ok(_) => panic!("tampered intermediate checkpoint must fail closed (F-3 gap)"),
    }
}

/// F-3: deleting the checkpoint file at HEAD's own sequence (`roots/<HEAD-seq>.root.cbor`)
/// must fail closed. HEAD is signature-gated, but a legitimate commit always appends the
/// current checkpoint before writing HEAD, so a missing current checkpoint is a truncated
/// / tampered append-only log — previously `verify_store` returned `Ok` (HEAD authoritative).
#[test]
fn tamper_verify_store_missing_head_checkpoint_fails_closed() {
    use mneme_cap::agent_cap;
    use mneme_crypto::KeyPair;
    use mneme_store::Store;
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::from_seed([0x41; 32]);
    let agent = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let trust = store.trust().clone();
    store
        .remember(
            mneme_core::Draft {
                namespace: "head".into(),
                logical_name: "k".into(),
                kind: mneme_core::MemoryKind::Semantic,
                body: b"head-body".to_vec(),
                parent_ids: vec![],
                session: [0x43; 16],
                trust_tier: None,
                embedding: None,
            },
            &cap,
        )
        .expect("remember");
    let head_seq = store.current_root().expect("root").sequence;
    drop(store);
    assert!(
        verify_store(dir.path(), &trust).is_ok(),
        "baseline store must verify clean"
    );
    let head_checkpoint = dir.path().join(format!("roots/{head_seq}.root.cbor"));
    assert!(
        head_checkpoint.exists(),
        "current checkpoint present pre-attack"
    );
    std::fs::remove_file(&head_checkpoint).expect("delete current checkpoint");
    match verify_store(dir.path(), &trust) {
        Err(MnemeError::RootInconsistent) => {}
        Err(other) => {
            panic!("missing current checkpoint: expected RootInconsistent, got {other:?}")
        }
        Ok(_) => panic!("missing current checkpoint must fail closed (F-3 gap)"),
    }
}

/// F-C: the tamper count is derived **dynamically from the test sources**, never a
/// hand-typed constant that can silently drift from reality. For each `tamper_*.rs`
/// file we count its generated `#[test]`s as: literal `#[test]` attributes, minus
/// one phantom per `macro_rules!` definition (the `#[test]` inside the macro body),
/// plus one per invocation of that file's locally-defined generator macro. This
/// auto-adapts to macro renames/additions; the assertion is the real §19/§17.2
/// guarantee (≥150 tamper cases that actually compile into the test binary).
#[test]
fn tamper_suite_meets_150_floor_counted_from_source() {
    let counts = tamper_counts_by_file();
    let total: usize = counts.values().sum();
    assert!(
        total >= 150,
        "§19/§17.2 tamper floor: need ≥150 verify tamper cases compiled into the \
         test binary, source scan found {total}: {counts:?}"
    );
    eprintln!("verify tamper cases (counted from source): {total} {counts:?}");
}

/// Scan the verify `tests/` dir and count generated tamper `#[test]`s per
/// `tamper_*.rs` file directly from the source — single source of truth.
pub fn tamper_counts_by_file() -> std::collections::BTreeMap<String, usize> {
    use std::collections::BTreeMap;
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut m = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("read tests dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.starts_with("tamper_") || !name.ends_with(".rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        let test_attrs = src.matches("#[test]").count();
        let macro_defs = src.matches("macro_rules!").count();
        // Sum invocations of every macro this file defines (e.g. `cap_tamper!(`).
        let mut invocations = 0usize;
        for line in src.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("macro_rules!") {
                let macro_name = rest.trim().trim_end_matches('{').trim();
                if !macro_name.is_empty() {
                    invocations += src.matches(&format!("{macro_name}!(")).count();
                }
            }
        }
        let generated = test_attrs.saturating_sub(macro_defs) + invocations;
        m.insert(name, generated);
    }
    m
}

#[allow(clippy::ptr_arg)]
fn flip_path(path: &mut Vec<[u8; 32]>, depth: usize) {
    if depth < path.len() {
        path[depth][0] ^= 0xff;
    }
}
