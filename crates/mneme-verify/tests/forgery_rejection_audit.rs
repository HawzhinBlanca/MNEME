//! Forgery-rejection audit (READINESS adversarial gate).
//!
//! Crash-free != forgery-rejecting. For EVERY verifier check we (1) prove a VALID
//! baseline passes, (2) hand-craft a TARGETED forgery for that specific check, and
//! (3) prove it fails closed with the EXACT typed `MnemeError` variant.
//!
//! The frozen `MnemeError` enum (mneme-core/src/error.rs, INV-9) is the normative
//! source of truth for variant names. Where the audit brief used a descriptive name
//! that is not a real enum variant, the comment records the mapping:
//!   ReceiptBindingInvalid   -> MnemeError::ReceiptRootMismatch
//!   MembershipProofInvalid  -> MnemeError::IndexPathInvalid
//!   ProcedureReplayFailed   -> MnemeError::ProcedureMismatch
//!   CapabilityInvalid       -> MnemeError::CapDenied
//! ZK verification (check 6) lives behind mneme-index `plonky2_prover`; see
//! crates/mneme-index/tests/forgery_zk_audit.rs.

mod helpers;

use std::collections::BTreeMap;

use helpers::{
    SemanticFixture, build_root_chain_fixture, build_valid_recall, build_valid_recall_with_parent,
    build_valid_semantic_recall, sample_procedure, theme_key,
};
use mneme_cap::{Capability, Permissions, agent_cap};
use mneme_core::{
    Caveat, Hlc, MemoryKind, MnemeError, NodeId, ObjectId, Query, Root, RootPreimage, TrustTier,
};
use mneme_crypto::KeyPair;
use mneme_root::StoredRoot;
use mneme_smt::{MembershipProof, SparseMerkleTree, TOMBSTONE};
use mneme_verify::{
    RecallContext, SemanticRecallInput, verify_membership_proof, verify_recall, verify_root,
    verify_semantic_recall, verify_semantic_receipt,
};

fn working_query() -> Query {
    Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Working,
        embedding: None,
    }
}

fn recall_ctx(f: &helpers::RecallFixture) -> RecallContext<'_> {
    RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    }
}

fn run_recall(f: &helpers::RecallFixture, q: &Query) -> Result<(), MnemeError> {
    let ctx = recall_ctx(f);
    verify_recall(&f.input, q, &f.trust, &ctx).map(|_| ())
}

fn run_semantic_receipt(f: &SemanticFixture) -> Result<(), MnemeError> {
    verify_semantic_receipt(
        &f.receipt,
        &f.root,
        &f.procedure,
        &f.trust,
        f.previous_root.as_ref(),
    )
}

fn test_hlc(wall_ms: u64) -> Hlc {
    Hlc {
        wall_ms,
        counter: 0,
        node_id: NodeId([0x07; 16]),
    }
}

// ===========================================================================
// CHECK 1 — Root signature verification (verify_root)
// Forgery: re-sign root under attacker key not in operator_keys.
// Expected: RootSigInvalid
// ===========================================================================

#[test]
fn check01_root_signature_resigned_under_wrong_key_root_sig_invalid() {
    let f = build_root_chain_fixture();
    // Baseline passes.
    verify_root(&f.root, &f.trust, f.previous_root.as_ref()).expect("baseline root verifies");

    // Forgery: attacker re-signs the (otherwise valid) preimage with a key that is
    // NOT an operator. preimage_hash stays correct so we exercise the sig check, not
    // the preimage-hash gate.
    let attacker = KeyPair::from_seed([0x99; 32]);
    let mut forged = f.root.clone();
    let bound = RootPreimage {
        version: forged.version,
        dag_head_root: forged.dag_head_root,
        key_index_root: forged.key_index_root,
        semantic_commit: forged.semantic_commit,
        hlc_max: forged.hlc_max,
        prev_root: forged.prev_root,
    };
    forged.preimage_hash = bound.hash();
    forged.signature = attacker.sign(&forged.preimage_hash).to_vec();

    assert_eq!(
        verify_root(&forged, &f.trust, f.previous_root.as_ref()).unwrap_err(),
        MnemeError::RootSigInvalid,
    );
}

// ===========================================================================
// CHECK 2 — Consistency / replay (verify_root_chain, check_replay)
// Forgery 2a: validly-signed root whose prev_root does not chain to predecessor.
//   Expected: RootInconsistent
// Forgery 2b: validly-signed root whose hlc_max regresses below last_seen_hlc.
//   Expected: RootReplayed
// ===========================================================================

#[test]
fn check02a_chain_break_validly_signed_wrong_predecessor_root_inconsistent() {
    let f = build_root_chain_fixture();
    verify_root(&f.root, &f.trust, f.previous_root.as_ref()).expect("baseline");

    // Forgery: present the (validly-signed) HEAD against a predecessor it does not
    // link to. prev_root != predecessor.preimage_hash -> chain succession broken.
    let bogus_prev = f.root.clone();
    assert_eq!(
        verify_root(&f.root, &f.trust, Some(&bogus_prev)).unwrap_err(),
        MnemeError::RootInconsistent,
    );
}

#[test]
fn check02b_sequence_regression_validly_signed_root_inconsistent() {
    let f = build_root_chain_fixture();
    let prev = f.previous_root.as_ref().expect("prev");
    // A validly-signed root that does chain (prev_root correct) but whose sequence
    // does not advance is a non-monotonic succession.
    let operator = KeyPair::from_seed([0x01; 32]);
    let forged = StoredRoot::assemble(
        f.root.dag_head_root,
        f.root.key_index_root,
        f.root.semantic_commit,
        f.root.hlc_max,
        prev.preimage_hash,
        prev.sequence, // <= prev.sequence: regression
        &operator,
    )
    .expect("assemble")
    .to_root();
    assert_eq!(
        verify_root(&forged, &f.trust, Some(prev)).unwrap_err(),
        MnemeError::RootInconsistent,
    );
}

#[test]
fn check02c_hlc_replay_below_last_seen_root_replayed() {
    let mut f = build_root_chain_fixture();
    // Validly-signed root, but its HLC high-water mark is below the monotonic floor.
    f.root.hlc_max = [0u8; 14];
    f.trust.last_seen_hlc = Some([0xff; 14]);
    // Re-sign so we exercise check_replay, not the preimage/sig gate.
    let operator = KeyPair::from_seed([0x01; 32]);
    let prev = f.previous_root.as_ref().expect("prev");
    let forged = StoredRoot::assemble(
        f.root.dag_head_root,
        f.root.key_index_root,
        f.root.semantic_commit,
        [0u8; 14],
        prev.preimage_hash,
        f.root.sequence,
        &operator,
    )
    .expect("assemble")
    .to_root();
    assert_eq!(
        verify_root(&forged, &f.trust, Some(prev)).unwrap_err(),
        MnemeError::RootReplayed,
    );
}

// ===========================================================================
// CHECK 3 — Receipt <-> root binding (verify_receipt_binding)
// Forgery: bind the receipt to a DIFFERENT (also validly-signed) root.
// Expected (audit "ReceiptBindingInvalid"): ReceiptRootMismatch
// ===========================================================================

#[test]
fn check03_receipt_bound_to_different_valid_root_receipt_root_mismatch() {
    let mut f = build_valid_recall();
    assert!(run_recall(&f, &working_query()).is_ok(), "baseline recall");

    // Build a second, independently-valid signed root (different sequence/prev) and
    // rebind the receipt to it while the recall still carries the original root.
    let operator = KeyPair::from_seed([0x01; 32]);
    let other = StoredRoot::assemble(
        f.input.root.dag_head_root,
        f.input.root.key_index_root,
        f.input.root.semantic_commit,
        f.input.root.hlc_max,
        f.input.root.preimage_hash, // chains onto current head
        f.input.root.sequence + 1,
        &operator,
    )
    .expect("assemble")
    .to_root();
    assert_ne!(other.preimage_hash, f.input.root.preimage_hash);
    f.input.receipt.root_bound = other.preimage_hash;

    assert_eq!(
        run_recall(&f, &working_query()).unwrap_err(),
        MnemeError::ReceiptRootMismatch,
    );
}

// ===========================================================================
// CHECK 4 — Index Merkle paths (verify_membership_proof, SMT membership)
// Forgery: a path that folds CORRECTLY to a real-but-wrong root (locally
//          self-consistent), spliced under the signed key_index_root.
// Expected (audit "MembershipProofInvalid"): IndexPathInvalid
// ===========================================================================

#[test]
fn check04_membership_path_hashes_to_wrong_root_index_path_invalid() {
    // Tree A: the "signed" key index.
    let key = theme_key("tamper", "key").hash();
    let val_a = [0xa1; 32];
    let mut tree_a = SparseMerkleTree::new();
    tree_a.upsert(key, val_a);
    tree_a.rebuild_root_cache();
    let proof_a = tree_a.prove_membership(key).expect("proof A");
    // Baseline: a correct proof verifies.
    verify_membership_proof(&proof_a).expect("baseline membership");

    // Tree B: attacker's parallel tree with a DIFFERENT value -> different root.
    let val_b = [0xb2; 32];
    let mut tree_b = SparseMerkleTree::new();
    tree_b.upsert(key, val_b);
    tree_b.rebuild_root_cache();
    let proof_b = tree_b.prove_membership(key).expect("proof B");
    assert_ne!(proof_b.root, proof_a.root);

    // Forgery: present tree B's self-consistent path+value but CLAIM the signed
    // root (tree A). It folds locally to tree B's root, which != claimed root.
    let forged = MembershipProof {
        key,
        value: val_b,
        path: proof_b.path,
        root: proof_a.root, // claim the signed root
        leaf_index: 0,
    };
    assert_eq!(
        verify_membership_proof(&forged).unwrap_err(),
        MnemeError::IndexPathInvalid,
    );
}

#[test]
fn check04b_membership_path_sibling_flipped_index_path_invalid() {
    let f = build_valid_recall();
    let proof = MembershipProof {
        key: f.input.receipt.logical_key,
        value: f.input.receipt.object_id,
        path: f.input.receipt.membership_proof.clone(),
        root: f.input.receipt.key_index_root,
        leaf_index: 0,
    };
    verify_membership_proof(&proof).expect("baseline");
    let mut forged = proof.clone();
    forged.path[0][0] ^= 0xff;
    assert_eq!(
        verify_membership_proof(&forged).unwrap_err(),
        MnemeError::IndexPathInvalid,
    );
}

// ===========================================================================
// CHECK 5 — Procedure replay (verify_ads_vo / replay_from_candidates)
// Forgery: swap the procedure-replay result set in the semantic receipt.
// Expected (audit "ProcedureReplayFailed"): ProcedureMismatch
// ===========================================================================

#[test]
fn check05_procedure_replay_result_swapped_procedure_mismatch() {
    let mut f = build_valid_semantic_recall();
    assert!(
        run_semantic_receipt(&f).is_ok(),
        "baseline semantic receipt"
    );

    // Forgery: inject an extra result id so the receipt's result set no longer
    // equals the deterministic replay over committed candidates.
    f.receipt
        .verification_object
        .result_ids
        .push(ObjectId([0xee; 32]));
    let err = run_semantic_receipt(&f).unwrap_err();
    assert_eq!(err, MnemeError::ProcedureMismatch);
    assert!(err.to_string().contains("not true nearest neighbors"));
}

#[test]
fn check05b_procedure_candidate_distance_tampered_procedure_mismatch() {
    let mut f = build_valid_semantic_recall();
    if let Some((_, _, dist)) = f.receipt.verification_object.candidates.first_mut() {
        *dist = i64::MAX;
    }
    assert_eq!(
        run_semantic_receipt(&f).unwrap_err(),
        MnemeError::ProcedureMismatch,
    );
}

// ===========================================================================
// CHECK 7 — Object re-hash (verify_recall)
// Forgery: re-encode a valid-but-different record under the same receipt object_id.
// Expected: ObjectTampered
// ===========================================================================

#[test]
fn check07_object_bytes_no_longer_match_id_object_tampered() {
    let mut f = build_valid_recall();
    assert!(run_recall(&f, &working_query()).is_ok(), "baseline");

    // Forgery: flip a content byte while keeping the receipt's object_id (and its
    // membership proof) bound to the ORIGINAL id. To reach the re-hash gate (not the
    // membership gate) we must keep the receipt's object_id == original; the verifier
    // recomputes hash_obj(object_bytes) and compares to receipt.object_id.
    let mid = f.input.object_bytes.len() / 2;
    f.input.object_bytes[mid] ^= 0x80;
    assert_eq!(
        run_recall(&f, &working_query()).unwrap_err(),
        MnemeError::ObjectTampered,
    );
}

// ===========================================================================
// CHECK 8 — Provenance DAG (verify_provenance)
// Forgery: object references a parent that is absent from the object set.
// Expected: ProvenanceBroken
// ===========================================================================

#[test]
fn check08_parent_reference_to_missing_ancestor_provenance_broken() {
    let mut f = build_valid_recall_with_parent();
    assert!(
        run_recall(&f, &working_query()).is_ok(),
        "baseline w/ parent"
    );

    let record: mneme_core::ObjectRecord =
        mneme_core::from_bytes_strict(&f.input.object_bytes).expect("parse");
    let parent = record.parent_ids[0];
    // Forgery: drop the ancestor so the parent reference dangles.
    f.objects.remove(&parent);
    assert_eq!(
        run_recall(&f, &working_query()).unwrap_err(),
        MnemeError::ProvenanceBroken,
    );
}

#[test]
fn check08b_parent_present_but_content_mismatched_provenance_broken() {
    let mut f = build_valid_recall_with_parent();
    let record: mneme_core::ObjectRecord =
        mneme_core::from_bytes_strict(&f.input.object_bytes).expect("parse");
    let parent = record.parent_ids[0];
    // Forgery: keep the parent id present but serve bytes that hash differently.
    let mut bad = f.objects.get(&parent).expect("parent bytes").clone();
    bad.push(0xAB);
    f.objects.insert(parent, bad);
    assert_eq!(
        run_recall(&f, &working_query()).unwrap_err(),
        MnemeError::ProvenanceBroken,
    );
}

// ===========================================================================
// CHECK 9 — Capability sig-chain (Capability::verify)
// Forgery: attenuated capability "widened" by stripping its narrowing caveat
//          while keeping the 2-link signature chain.
// Expected (audit "CapabilityInvalid"): CapDenied
// ===========================================================================

#[test]
fn check09_attenuated_capability_widened_beyond_chain_cap_denied() {
    let issuer = KeyPair::from_seed([0x05; 32]);
    let subject = KeyPair::from_seed([0x06; 32]);
    let root = agent_cap(&issuer, subject.public_key_bytes()).expect("root cap");
    let narrowed = root
        .attenuate(&subject, vec![Caveat::NamespacePrefix("tools/".into())])
        .expect("attenuate");
    // Baseline: legitimately narrowed cap verifies.
    narrowed
        .verify(&issuer, &test_hlc(1))
        .expect("baseline attenuated cap verifies");
    assert_eq!(narrowed.sig_chain().expect("chain").len(), 2);

    // Forgery: strip the narrowing caveat (widening the authority) while retaining
    // both signatures. The attenuation signature no longer binds the caveat set.
    let mut widened = narrowed.into_core();
    widened
        .caveats
        .retain(|c| !matches!(c, Caveat::NamespacePrefix(_)));
    let widened = Capability::from_core(widened);
    assert_eq!(
        widened.verify(&issuer, &test_hlc(1)).unwrap_err(),
        MnemeError::CapDenied,
    );
}

#[test]
fn check09b_capability_permissions_widened_cap_denied() {
    let issuer = KeyPair::from_seed([0x15; 32]);
    let subject = KeyPair::from_seed([0x16; 32]);
    let mut cap = mneme_cap::tool_channel_cap(&issuer, subject.public_key_bytes()).expect("cap");
    cap.verify(&issuer, &test_hlc(1)).expect("baseline");
    // Forgery: flip on PROMOTE bit the issuer never granted.
    cap.permissions |= Permissions::PROMOTE.bits();
    assert_eq!(
        cap.verify(&issuer, &test_hlc(1)).unwrap_err(),
        MnemeError::CapDenied,
    );
}

// ===========================================================================
// CHECK 10 — Tombstone / forgotten (verify_not_forgotten, SMT tombstone)
// Forgery: a forgotten (tombstoned) key is served as still-present.
// Expected: Forgotten
// ===========================================================================

#[test]
fn check10_forgotten_key_served_as_present_forgotten() {
    let mut f = build_valid_recall();
    assert!(run_recall(&f, &working_query()).is_ok(), "baseline");

    // Forgery: operator forgot the key (tombstone in the live key index) but the
    // attacker replays the old receipt/object to surface it.
    let key = f.input.receipt.logical_key;
    f.key_index.tombstone(key);
    f.key_index.rebuild_root_cache();
    assert_eq!(
        run_recall(&f, &working_query()).unwrap_err(),
        MnemeError::Forgotten,
    );
}

#[test]
fn check10b_membership_value_is_tombstone_forgotten() {
    // A receipt whose proven value is the TOMBSTONE sentinel must fail closed as
    // Forgotten, not be treated as a live membership.
    let f = build_valid_recall();
    let proof = MembershipProof {
        key: f.input.receipt.logical_key,
        value: TOMBSTONE,
        path: f.input.receipt.membership_proof.clone(),
        root: f.input.receipt.key_index_root,
        leaf_index: 0,
    };
    assert_eq!(
        verify_membership_proof(&proof).unwrap_err(),
        MnemeError::Forgotten,
    );
}

// ===========================================================================
// CHECK 11 — Tier policy (verify_writer_and_tier)
// Forgery: a Quarantine/Working-tier entry surfaced at min_tier=Trusted.
// Expected: BelowTierPolicy
// ===========================================================================

#[test]
fn check11_below_tier_policy_quarantine_at_trusted_min_tier() {
    let f = build_valid_recall(); // object is Working tier
    let query = Query {
        logical_key: theme_key("tamper", "key"),
        min_tier: TrustTier::Trusted,
        embedding: None,
    };
    let err = run_recall(&f, &query).unwrap_err();
    assert_eq!(
        err,
        MnemeError::BelowTierPolicy {
            required: TrustTier::Trusted.as_u8(),
            got: TrustTier::Working.as_u8(),
        },
    );
    assert!(err.to_string().contains("§3 honesty boundary"));
}

// ===========================================================================
// Bonus — full recall pipeline forgery: swap object_id, reuse membership path.
// Demonstrates the gate ordering (membership before re-hash).
// ===========================================================================

#[test]
fn pipeline_object_id_swap_reusing_path_index_path_invalid() {
    let mut f = build_valid_recall();
    f.input.receipt.object_id[0] ^= 0x01;
    assert_eq!(
        run_recall(&f, &working_query()).unwrap_err(),
        MnemeError::IndexPathInvalid,
    );
}

// ===========================================================================
// Bonus — semantic recall object swap under a valid receipt.
// Expected: ObjectTampered
// ===========================================================================

#[test]
fn semantic_recall_object_swapped_object_tampered() {
    let mut f = build_valid_semantic_recall();
    let id = f.receipt.verification_object.result_ids[0];
    f.objects.get_mut(id.as_bytes()).expect("obj")[0] ^= 0x01;
    let query = Query {
        logical_key: theme_key("semantic", "query"),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    };
    let input = SemanticRecallInput {
        receipt: f.receipt.clone(),
        root: f.root.clone(),
    };
    assert_eq!(
        verify_semantic_recall(&input, &sample_procedure(), &query, &f.trust, &ctx).unwrap_err(),
        MnemeError::ObjectTampered,
    );
}

// Compile-time guard: keep unused-import noise out if helpers evolve.
#[allow(dead_code)]
fn _unused(_: BTreeMap<[u8; 32], Vec<u8>>, _: Root, _: MemoryKind) {}
