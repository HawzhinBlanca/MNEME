//! Root invariant tests (§17.1 red→green, INV-4, INV-6).

use mneme_core::{Hlc, MnemeError, NodeId, RootPreimage, hash_ckpt, to_bytes_canonical};
use mneme_crypto::KeyPair;
use mneme_root::{
    CheckpointLog, ROOT_VERSION, RootHistoryProofDirection, StoredRoot, check_replay,
    read_root_history_peak_state, root_history_consistency_proof, root_history_digest,
    root_history_inclusion_proof, root_history_peak_consistency_proof, root_history_peak_digest,
    root_history_peak_frontier_proof, root_history_peak_inclusion_proof, update_root_history_peaks,
    verify_root_chain, verify_root_history_consistency, verify_root_history_digest,
    verify_root_history_inclusion, verify_root_history_peak_consistency,
    verify_root_history_peak_frontier, verify_root_history_peak_inclusion,
};
use std::path::Path;

fn sample_hlc(n: u8) -> [u8; 14] {
    let mut out = [0u8; 14];
    out[0] = n;
    out
}

fn hlc_wire(wall_ms: u64, counter: u32) -> [u8; 14] {
    Hlc {
        wall_ms,
        counter,
        node_id: NodeId([0; 16]),
    }
    .to_bytes()
}

fn sample_roots() -> ([u8; 32], [u8; 32], [u8; 32]) {
    ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32])
}

fn operator() -> KeyPair {
    KeyPair::from_seed([0x42; 32])
}

#[test]
fn root_preimage_hash_matches_domain_tag_layout() {
    let (dag, key, sem) = sample_roots();
    let preimage = RootPreimage {
        version: ROOT_VERSION,
        dag_head_root: dag,
        key_index_root: key,
        semantic_commit: sem,
        hlc_max: sample_hlc(1),
        prev_root: [0u8; 32],
    };
    let payload = preimage.encode_payload();
    assert_eq!(payload.len(), 2 + 32 * 4 + 14);
    assert_eq!(payload[0..2], ROOT_VERSION.to_le_bytes());
    let hash_a = preimage.hash();
    let hash_b = preimage.hash();
    assert_eq!(hash_a, hash_b);
    assert_ne!(hash_a, [0u8; 32]);
}

#[test]
fn assemble_sign_verify_roundtrip() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(2), [0u8; 32], 1, &op).expect("assemble");
    stored.verify(&op.verifying_key()).expect("verify");
    assert_eq!(stored.preimage().hash(), stored.preimage_hash);
}

#[test]
fn fault_injection_rejects_tampered_signature() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let mut stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(3), [0u8; 32], 1, &op).expect("assemble");
    stored.signature[0] ^= 0xff;
    let err = stored.verify(&op.verifying_key()).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn fault_injection_rejects_tampered_preimage_hash() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let mut stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(4), [0u8; 32], 1, &op).expect("assemble");
    stored.preimage_hash[0] ^= 0xff;
    let err = stored.verify(&op.verifying_key()).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn dcbor_roundtrip_is_canonical() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let stored =
        StoredRoot::assemble(dag, key, sem, sample_hlc(5), [0u8; 32], 7, &op).expect("assemble");
    let bytes = stored.to_bytes().expect("encode");
    let decoded = StoredRoot::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, stored);
    let again = StoredRoot::from_bytes(&bytes).expect("re-decode");
    assert_eq!(
        stored.to_bytes().expect("re-encode"),
        again.to_bytes().expect("re-encode2")
    );
}

#[test]
fn root_chain_links_prev_hash_and_sequence() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(10), [0u8; 32], 1, &op).expect("first");
    let second = StoredRoot::assemble(dag, key, sem, sample_hlc(11), first.preimage_hash, 2, &op)
        .expect("second");
    verify_root_chain(&second.to_root(), Some(&first.to_root())).expect("chain");
}

#[test]
fn root_chain_rejects_sequence_regression() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(12), [0u8; 32], 2, &op).expect("first");
    let stale = StoredRoot::assemble(dag, key, sem, sample_hlc(13), first.preimage_hash, 2, &op)
        .expect("stale");
    let err = verify_root_chain(&stale.to_root(), Some(&first.to_root())).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn check_replay_rejects_older_hlc() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let root = StoredRoot::assemble(dag, key, sem, sample_hlc(1), [0u8; 32], 1, &op).expect("root");
    check_replay(&root.to_root(), Some(sample_hlc(2))).unwrap_err();
    check_replay(&root.to_root(), Some(sample_hlc(1))).expect("equal ok");
    check_replay(&root.to_root(), Some(sample_hlc(0))).expect("older ok");
}

#[test]
fn check_replay_rejects_numeric_hlc_regression_across_byte_boundary() {
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let advanced =
        StoredRoot::assemble(dag, key, sem, hlc_wire(256, 0), [0u8; 32], 1, &op).expect("root");
    let regressed =
        StoredRoot::assemble(dag, key, sem, hlc_wire(255, 0), [0u8; 32], 2, &op).expect("root");
    let err = check_replay(&regressed.to_root(), Some(hlc_wire(256, 0))).unwrap_err();
    assert_eq!(err, MnemeError::RootReplayed);
    check_replay(&advanced.to_root(), Some(hlc_wire(255, 0))).expect("advance ok");
}

#[test]
fn checkpoint_log_append_is_create_new() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let root =
        StoredRoot::assemble(dag, key, sem, sample_hlc(20), [0u8; 32], 1, &op).expect("root");
    CheckpointLog::append(store, &root).expect("append");
    let loaded = CheckpointLog::read_checkpoint(store, 1).expect("read");
    assert_eq!(loaded, root);
    let err = CheckpointLog::append(store, &root).unwrap_err();
    assert!(matches!(err, MnemeError::IoFailed { kind, .. } if kind == "exists"));
}

#[test]
fn head_write_and_read_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let (dag, key, sem) = sample_roots();
    let op = operator();
    let root =
        StoredRoot::assemble(dag, key, sem, sample_hlc(21), [0u8; 32], 3, &op).expect("root");
    CheckpointLog::commit(store, &root).expect("commit");
    let head = CheckpointLog::read_head(store).expect("head");
    assert_eq!(head, root);
    assert!(checkpoint_file(store, 3).exists());
}

#[test]
fn root_history_digest_extends_on_append_and_rejects_stale_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 3);

    let digest_two =
        root_history_digest(store, &[op.public_key_bytes()], &roots[1]).expect("digest two");
    assert_eq!(digest_two.sequence, 2);
    assert_eq!(digest_two.checkpoint_count, 2);
    assert_eq!(digest_two.head_preimage_hash, roots[1].preimage_hash);

    let digest_three =
        root_history_digest(store, &[op.public_key_bytes()], &roots[2]).expect("digest three");
    assert_eq!(digest_three.sequence, 3);
    assert_eq!(digest_three.checkpoint_count, 3);
    assert_ne!(digest_two.accumulator_root, digest_three.accumulator_root);
    verify_root_history_digest(store, &[op.public_key_bytes()], &roots[2], &digest_three)
        .expect("fresh digest verifies");

    let err = verify_root_history_digest(store, &[op.public_key_bytes()], &roots[2], &digest_two)
        .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_digest_rejects_valid_signature_with_wrong_prev_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let op = operator();
    let (dag, key, sem) = sample_roots();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(30), [0u8; 32], 1, &op).expect("first");
    let wrong_second =
        StoredRoot::assemble(dag, key, sem, sample_hlc(31), [0u8; 32], 2, &op).expect("second");
    CheckpointLog::append(store, &first).expect("append first");
    CheckpointLog::append(store, &wrong_second).expect("append wrong second");
    CheckpointLog::write_head(store, &wrong_second).expect("head");

    let err = root_history_digest(store, &[op.public_key_bytes()], &wrong_second).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_digest_requires_contiguous_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 3);
    std::fs::remove_file(checkpoint_file(store, 2)).expect("remove intermediate");

    let err = root_history_digest(store, &[op.public_key_bytes()], &roots[2]).unwrap_err();
    assert!(
        matches!(
            err,
            MnemeError::IoFailed { .. } | MnemeError::RootInconsistent
        ),
        "missing checkpoint must fail closed, got {err:?}"
    );
}

#[test]
fn root_history_inclusion_proof_verifies_each_checkpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 5);
    let head = roots.last().expect("head");
    let digest = root_history_digest(store, &[op.public_key_bytes()], head).expect("digest");

    for root in &roots {
        let proof =
            root_history_inclusion_proof(store, &[op.public_key_bytes()], head, root.sequence)
                .expect("proof");
        assert_eq!(proof.sequence, root.sequence);
        assert_eq!(proof.checkpoint_count, digest.checkpoint_count);
        verify_root_history_inclusion(&digest, root, &proof).expect("inclusion");
    }
}

#[test]
fn root_history_inclusion_proof_rejects_tampered_sibling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 5);
    let head = roots.last().expect("head");
    let digest = root_history_digest(store, &[op.public_key_bytes()], head).expect("digest");
    let mut proof =
        root_history_inclusion_proof(store, &[op.public_key_bytes()], head, 3).expect("proof");
    proof.path[0].sibling_hash[0] ^= 0xff;

    let err = verify_root_history_inclusion(&digest, &roots[2], &proof).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_inclusion_proof_rejects_wrong_checkpoint_and_stale_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 4);
    let digest_two =
        root_history_digest(store, &[op.public_key_bytes()], &roots[1]).expect("digest two");
    let digest_four =
        root_history_digest(store, &[op.public_key_bytes()], &roots[3]).expect("digest four");
    let proof =
        root_history_inclusion_proof(store, &[op.public_key_bytes()], &roots[3], 2).expect("proof");

    let wrong_checkpoint_err =
        verify_root_history_inclusion(&digest_four, &roots[2], &proof).unwrap_err();
    assert_eq!(wrong_checkpoint_err, MnemeError::RootInconsistent);

    let stale_digest_err =
        verify_root_history_inclusion(&digest_two, &roots[1], &proof).unwrap_err();
    assert_eq!(stale_digest_err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_inclusion_proof_rejects_wrong_direction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 3);
    let head = roots.last().expect("head");
    let digest = root_history_digest(store, &[op.public_key_bytes()], head).expect("digest");
    let mut proof =
        root_history_inclusion_proof(store, &[op.public_key_bytes()], head, 2).expect("proof");
    proof.path[0].direction = match proof.path[0].direction {
        RootHistoryProofDirection::Left => RootHistoryProofDirection::Right,
        RootHistoryProofDirection::Right => RootHistoryProofDirection::Left,
    };

    let err = verify_root_history_inclusion(&digest, &roots[1], &proof).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_consistency_proof_verifies_append_only_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 7);
    let older = root_history_digest(store, &[op.public_key_bytes()], &roots[2]).expect("older");
    let newer = root_history_digest(store, &[op.public_key_bytes()], &roots[6]).expect("newer");
    let proof =
        root_history_consistency_proof(store, &[op.public_key_bytes()], &roots[6], older.sequence)
            .expect("proof");

    assert_eq!(proof.from_sequence, older.sequence);
    assert_eq!(proof.to_sequence, newer.sequence);
    verify_root_history_consistency(&older, &newer, &proof).expect("consistency");
}

#[test]
fn root_history_consistency_proof_rejects_tampered_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 7);
    let older = root_history_digest(store, &[op.public_key_bytes()], &roots[2]).expect("older");
    let newer = root_history_digest(store, &[op.public_key_bytes()], &roots[6]).expect("newer");
    let mut proof =
        root_history_consistency_proof(store, &[op.public_key_bytes()], &roots[6], older.sequence)
            .expect("proof");
    assert!(!proof.path.is_empty());
    proof.path[0][0] ^= 0xff;

    let err = verify_root_history_consistency(&older, &newer, &proof).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_consistency_proof_rejects_reversed_or_wrong_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 6);
    let older = root_history_digest(store, &[op.public_key_bytes()], &roots[1]).expect("older");
    let middle = root_history_digest(store, &[op.public_key_bytes()], &roots[3]).expect("middle");
    let newer = root_history_digest(store, &[op.public_key_bytes()], &roots[5]).expect("newer");
    let proof =
        root_history_consistency_proof(store, &[op.public_key_bytes()], &roots[5], older.sequence)
            .expect("proof");

    let reversed = verify_root_history_consistency(&newer, &older, &proof).unwrap_err();
    assert_eq!(reversed, MnemeError::RootInconsistent);

    let wrong_target = verify_root_history_consistency(&older, &middle, &proof).unwrap_err();
    assert_eq!(wrong_target, MnemeError::RootInconsistent);
}

#[test]
fn root_history_consistency_proof_accepts_equal_digest_only_with_empty_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence(store, &op, 3);
    let digest = root_history_digest(store, &[op.public_key_bytes()], &roots[2]).expect("digest");
    let mut proof =
        root_history_consistency_proof(store, &[op.public_key_bytes()], &roots[2], digest.sequence)
            .expect("proof");
    assert!(proof.path.is_empty());
    verify_root_history_consistency(&digest, &digest, &proof).expect("equal digest");

    proof.path.push([0x42; 32]);
    let err = verify_root_history_consistency(&digest, &digest, &proof).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_proofs_roundtrip_many_tree_shapes() {
    for count in 1..=18 {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path();
        let op = operator();
        let roots = commit_root_sequence(store, &op, count);
        let head = roots.last().expect("head");
        let digest = root_history_digest(store, &[op.public_key_bytes()], head).expect("digest");

        for sequence in 1..=count {
            let checkpoint = roots
                .get(usize::try_from(sequence - 1).expect("sequence index"))
                .expect("checkpoint");
            let proof =
                root_history_inclusion_proof(store, &[op.public_key_bytes()], head, sequence)
                    .expect("inclusion proof");
            verify_root_history_inclusion(&digest, checkpoint, &proof).expect("inclusion");

            let older =
                root_history_digest(store, &[op.public_key_bytes()], checkpoint).expect("older");
            let proof =
                root_history_consistency_proof(store, &[op.public_key_bytes()], head, sequence)
                    .expect("consistency proof");
            verify_root_history_consistency(&older, &digest, &proof).expect("consistency");
        }
    }
}

#[test]
fn root_history_peaks_update_logarithmically_and_bind_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence_with_peaks(store, &op, 7);
    let state = read_root_history_peak_state(store).expect("peak state");
    assert_eq!(state.sequence, 7);
    assert_eq!(state.head_preimage_hash, roots[6].preimage_hash);
    assert_eq!(
        state
            .peaks
            .iter()
            .map(|peak| peak.height)
            .collect::<Vec<_>>(),
        vec![2, 1, 0]
    );
    let digest =
        root_history_peak_digest(store, &[op.public_key_bytes()], &roots[6]).expect("peak digest");
    assert_eq!(digest.sequence, 7);
    assert_eq!(digest.checkpoint_count, 7);
    assert_eq!(digest.peak_count, 3);
    assert_eq!(digest.head_preimage_hash, roots[6].preimage_hash);
}

#[test]
fn root_history_peaks_match_binary_decomposition_for_many_sequences() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let op = operator();
    let (dag, key, sem) = sample_roots();
    let mut prev = [0u8; 32];

    for sequence in 1..=32 {
        let root = StoredRoot::assemble(
            dag,
            key,
            sem,
            sample_hlc(u8::try_from(sequence + 60).expect("sample hlc")),
            prev,
            sequence,
            &op,
        )
        .expect("root");
        CheckpointLog::append(store, &root).expect("append");
        update_root_history_peaks(store, &[op.public_key_bytes()], &root).expect("peaks");
        CheckpointLog::write_head(store, &root).expect("head");

        let state = read_root_history_peak_state(store).expect("peak state");
        assert_eq!(state.sequence, sequence);
        assert_eq!(state.head_preimage_hash, root.preimage_hash);
        assert_eq!(
            state
                .peaks
                .iter()
                .map(|peak| peak.height)
                .collect::<Vec<_>>(),
            expected_peak_heights(sequence)
        );
        let digest =
            root_history_peak_digest(store, &[op.public_key_bytes()], &root).expect("peak digest");
        assert_eq!(digest.peak_count, u64::from(sequence.count_ones()));

        prev = root.preimage_hash;
    }
}

#[test]
fn root_history_peak_consistency_verifies_delta_from_compact_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let mut roots = commit_root_sequence_with_peaks(store, &op, 3);
    let older = read_root_history_peak_state(store).expect("older peak state");
    append_roots_with_peaks(store, &op, &mut roots, 8);

    let head = roots.last().expect("head");
    let newer =
        root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("newer peak digest");
    let proof = root_history_peak_consistency_proof(store, &[op.public_key_bytes()], &older, head)
        .expect("peak consistency proof");
    assert_eq!(proof.from_sequence, older.sequence);
    assert_eq!(proof.to_sequence, newer.sequence);
    assert_eq!(
        proof.appended_checkpoints.len(),
        usize::try_from(newer.sequence - older.sequence).expect("delta len")
    );
    verify_root_history_peak_consistency(&[op.public_key_bytes()], &older, &newer, &proof)
        .expect("peak consistency");
}

#[test]
fn root_history_peak_inclusion_verifies_checkpoint_against_compact_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence_with_peaks(store, &op, 13);
    let head = roots.last().expect("head");
    let digest = root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("digest");

    for sequence in [1_u64, 4, 5, 8, 9, 12, 13] {
        let checkpoint = &roots[usize::try_from(sequence - 1).expect("checkpoint index")];
        let proof =
            root_history_peak_inclusion_proof(store, &[op.public_key_bytes()], head, sequence)
                .expect("peak inclusion proof");
        verify_root_history_peak_inclusion(&[op.public_key_bytes()], &digest, checkpoint, &proof)
            .expect("peak inclusion verifies");
        assert_eq!(proof.sequence, sequence);
        assert_eq!(proof.peaks.len(), digest.peak_count as usize);
        assert!(
            proof.path.len() <= 4,
            "13 checkpoints should produce logarithmic leaf-to-peak paths, got {}",
            proof.path.len()
        );
    }
}

#[test]
fn root_history_peak_inclusion_rejects_tampering_and_wrong_trust_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let wrong_op = KeyPair::from_seed([0x25; 32]);
    let roots = commit_root_sequence_with_peaks(store, &op, 9);
    let head = roots.last().expect("head");
    let digest = root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("digest");
    let checkpoint = &roots[4];
    let proof = root_history_peak_inclusion_proof(store, &[op.public_key_bytes()], head, 5)
        .expect("peak inclusion proof");
    verify_root_history_peak_inclusion(&[op.public_key_bytes()], &digest, checkpoint, &proof)
        .expect("baseline inclusion");

    let err = verify_root_history_peak_inclusion(
        &[wrong_op.public_key_bytes()],
        &digest,
        checkpoint,
        &proof,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);

    let wrong_checkpoint = &roots[5];
    let err = verify_root_history_peak_inclusion(
        &[op.public_key_bytes()],
        &digest,
        wrong_checkpoint,
        &proof,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut tampered_path = proof.clone();
    tampered_path.path[0].sibling_hash[0] ^= 0xff;
    let err = verify_root_history_peak_inclusion(
        &[op.public_key_bytes()],
        &digest,
        checkpoint,
        &tampered_path,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut wrong_peak_index = proof.clone();
    wrong_peak_index.peak_index += 1;
    let err = verify_root_history_peak_inclusion(
        &[op.public_key_bytes()],
        &digest,
        checkpoint,
        &wrong_peak_index,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut stale_digest = digest;
    stale_digest.sequence += 1;
    stale_digest.checkpoint_count += 1;
    let err = verify_root_history_peak_inclusion(
        &[op.public_key_bytes()],
        &stale_digest,
        checkpoint,
        &proof,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_peak_consistency_rejects_tampered_or_truncated_delta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let mut roots = commit_root_sequence_with_peaks(store, &op, 2);
    let older = read_root_history_peak_state(store).expect("older peak state");
    append_roots_with_peaks(store, &op, &mut roots, 6);
    let head = roots.last().expect("head");
    let newer =
        root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("newer peak digest");
    let proof = root_history_peak_consistency_proof(store, &[op.public_key_bytes()], &older, head)
        .expect("peak consistency proof");
    verify_root_history_peak_consistency(&[op.public_key_bytes()], &older, &newer, &proof)
        .expect("baseline proof");

    let mut tampered_signature = proof.clone();
    tampered_signature.appended_checkpoints[0].signature[0] ^= 0xff;
    let err = verify_root_history_peak_consistency(
        &[op.public_key_bytes()],
        &older,
        &newer,
        &tampered_signature,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut tampered_link = proof.clone();
    tampered_link.appended_checkpoints[0].prev_root[0] ^= 0xff;
    let err = verify_root_history_peak_consistency(
        &[op.public_key_bytes()],
        &older,
        &newer,
        &tampered_link,
    )
    .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut truncated = proof;
    truncated.appended_checkpoints.pop();
    let err =
        verify_root_history_peak_consistency(&[op.public_key_bytes()], &older, &newer, &truncated)
            .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_peak_consistency_accepts_equal_state_only_with_empty_delta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence_with_peaks(store, &op, 4);
    let state = read_root_history_peak_state(store).expect("peak state");
    let head = roots.last().expect("head");
    let digest = root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("digest");
    let mut proof =
        root_history_peak_consistency_proof(store, &[op.public_key_bytes()], &state, head)
            .expect("same-state proof");
    assert!(proof.appended_checkpoints.is_empty());
    verify_root_history_peak_consistency(&[op.public_key_bytes()], &state, &digest, &proof)
        .expect("same-state proof verifies");

    proof.appended_checkpoints.push(roots[0].clone());
    let err =
        verify_root_history_peak_consistency(&[op.public_key_bytes()], &state, &digest, &proof)
            .unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_peak_frontier_proves_compact_structural_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let mut roots = commit_root_sequence_with_peaks(store, &op, 3);
    let older = read_root_history_peak_state(store).expect("older peak state");
    append_roots_with_peaks(store, &op, &mut roots, 19);
    let head = roots.last().expect("head");
    let newer = root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("digest");
    let signed_delta =
        root_history_peak_consistency_proof(store, &[op.public_key_bytes()], &older, head)
            .expect("signed delta proof");
    let frontier = root_history_peak_frontier_proof(store, &[op.public_key_bytes()], &older, head)
        .expect("frontier proof");

    verify_root_history_peak_frontier(&older, &newer, &frontier).expect("frontier verifies");
    assert_eq!(frontier.from_sequence, older.sequence);
    assert_eq!(frontier.to_sequence, newer.sequence);
    assert!(
        frontier.appended_subtrees.len() < signed_delta.appended_checkpoints.len(),
        "frontier proof should summarize aligned subtrees, not carry every checkpoint"
    );
}

#[test]
fn root_history_peak_frontier_rejects_tampered_subtree_or_wrong_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let mut roots = commit_root_sequence_with_peaks(store, &op, 5);
    let older = read_root_history_peak_state(store).expect("older peak state");
    append_roots_with_peaks(store, &op, &mut roots, 13);
    let head = roots.last().expect("head");
    let newer = root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("digest");
    let proof = root_history_peak_frontier_proof(store, &[op.public_key_bytes()], &older, head)
        .expect("frontier proof");
    verify_root_history_peak_frontier(&older, &newer, &proof).expect("baseline frontier");

    let mut tampered = proof.clone();
    tampered.appended_subtrees[0].hash[0] ^= 0xff;
    let err = verify_root_history_peak_frontier(&older, &newer, &tampered).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut wrong_digest = newer.clone();
    wrong_digest.peak_bag_root[0] ^= 0xff;
    let err = verify_root_history_peak_frontier(&older, &wrong_digest, &proof).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);

    let mut misaligned = proof;
    misaligned.appended_subtrees[0].height += 1;
    let err = verify_root_history_peak_frontier(&older, &newer, &misaligned).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_peak_update_rejects_skipped_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let op = operator();
    let (dag, key, sem) = sample_roots();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(40), [0u8; 32], 1, &op).expect("first");
    CheckpointLog::append(store, &first).expect("append first");
    update_root_history_peaks(store, &[op.public_key_bytes()], &first).expect("peak first");

    let skipped = StoredRoot::assemble(dag, key, sem, sample_hlc(41), first.preimage_hash, 3, &op)
        .expect("skipped");
    CheckpointLog::append(store, &skipped).expect("append skipped");
    let err = update_root_history_peaks(store, &[op.public_key_bytes()], &skipped).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_peak_update_rejects_wrong_prev_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let op = operator();
    let (dag, key, sem) = sample_roots();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(42), [0u8; 32], 1, &op).expect("first");
    CheckpointLog::append(store, &first).expect("append first");
    update_root_history_peaks(store, &[op.public_key_bytes()], &first).expect("peak first");

    let wrong_second =
        StoredRoot::assemble(dag, key, sem, sample_hlc(43), [0u8; 32], 2, &op).expect("second");
    CheckpointLog::append(store, &wrong_second).expect("append wrong second");
    let err =
        update_root_history_peaks(store, &[op.public_key_bytes()], &wrong_second).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn root_history_peak_update_rejects_wrong_operator_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    CheckpointLog::ensure_dir(store).expect("ensure");
    let op = operator();
    let other = KeyPair::from_seed([0x24; 32]);
    let (dag, key, sem) = sample_roots();
    let first =
        StoredRoot::assemble(dag, key, sem, sample_hlc(45), [0u8; 32], 1, &op).expect("first");
    CheckpointLog::append(store, &first).expect("append first");

    let err = update_root_history_peaks(store, &[other.public_key_bytes()], &first).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
    assert!(
        !store.join("roots/HISTORY_PEAKS.cbor").exists(),
        "forged peak update must not leave a sidecar"
    );
}

#[test]
fn root_history_peak_digest_rejects_stale_or_tampered_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence_with_peaks(store, &op, 3);
    root_history_peak_digest(store, &[op.public_key_bytes()], &roots[2])
        .expect("fresh peak digest");

    let (dag, key, sem) = sample_roots();
    let fourth = StoredRoot::assemble(
        dag,
        key,
        sem,
        sample_hlc(44),
        roots[2].preimage_hash,
        4,
        &op,
    )
    .expect("fourth");
    CheckpointLog::append(store, &fourth).expect("append fourth");
    CheckpointLog::write_head(store, &fourth).expect("head fourth");
    let stale = root_history_peak_digest(store, &[op.public_key_bytes()], &fourth).unwrap_err();
    assert_eq!(stale, MnemeError::RootInconsistent);

    update_root_history_peaks(store, &[op.public_key_bytes()], &fourth)
        .expect("repair peak fourth");
    let peaks_path = store.join("roots/HISTORY_PEAKS.cbor");
    let mut bytes = std::fs::read(&peaks_path).expect("read peaks");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&peaks_path, bytes).expect("tamper peaks");
    let tampered = root_history_peak_digest(store, &[op.public_key_bytes()], &fourth).unwrap_err();
    assert!(
        matches!(
            tampered,
            MnemeError::SchemaDrift
                | MnemeError::SerializationNonCanonical
                | MnemeError::RootInconsistent
        ),
        "tampered peak sidecar must fail closed, got {tampered:?}"
    );
}

#[test]
fn root_history_peak_digest_rejects_well_formed_but_false_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path();
    let op = operator();
    let roots = commit_root_sequence_with_peaks(store, &op, 5);
    let head = roots.last().expect("head");
    root_history_peak_digest(store, &[op.public_key_bytes()], head).expect("fresh peak digest");

    let mut state = read_root_history_peak_state(store).expect("read sidecar");
    state.peaks[0].hash[0] ^= 0xff;
    state.peak_bag_root =
        test_peak_bag_root(state.sequence, &state.head_preimage_hash, &state.peaks);
    let forged = to_bytes_canonical(&state).expect("well-formed forged sidecar");
    std::fs::write(store.join("roots/HISTORY_PEAKS.cbor"), forged).expect("write forged sidecar");

    read_root_history_peak_state(store).expect("forged sidecar is syntactically valid");
    let err = root_history_peak_digest(store, &[op.public_key_bytes()], head).unwrap_err();
    assert_eq!(err, MnemeError::RootInconsistent);
}

#[test]
fn pinned_root_preimage_hash_for_fixture_seed() {
    let (dag, key, sem) = sample_roots();
    let preimage = RootPreimage {
        version: ROOT_VERSION,
        dag_head_root: dag,
        key_index_root: key,
        semantic_commit: sem,
        hlc_max: sample_hlc(0),
        prev_root: [0u8; 32],
    };
    let hash = preimage.hash();
    // Byte-pinned once computed from MNEME-root-v1 domain tag + §5.7 layout.
    assert_eq!(
        hash,
        hex32("9194a7f3d98cf4aa8e3f3094bc886e5ab71bee9097b467f42a57bbe52509aa69")
    );
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("hex32");
    out
}

fn checkpoint_file(store: &Path, sequence: u64) -> std::path::PathBuf {
    store.join(format!("roots/{sequence}.root.cbor"))
}

fn expected_peak_heights(sequence: u64) -> Vec<u32> {
    assert!(sequence > 0);
    let max_height = 63 - sequence.leading_zeros();
    (0..=max_height)
        .rev()
        .filter(|height| sequence & (1_u64 << height) != 0)
        .collect()
}

fn test_peak_bag_root(
    sequence: u64,
    head_preimage_hash: &[u8; 32],
    peaks: &[mneme_root::RootHistoryPeak],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(27 + 8 + 32 + 8 + peaks.len() * 36);
    payload.extend_from_slice(b"root-history-peak-bag-v1\x00");
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.extend_from_slice(head_preimage_hash);
    payload.extend_from_slice(&(peaks.len() as u64).to_le_bytes());
    for peak in peaks {
        payload.extend_from_slice(&peak.height.to_le_bytes());
        payload.extend_from_slice(&peak.hash);
    }
    hash_ckpt(&payload)
}

fn commit_root_sequence(store: &Path, op: &KeyPair, count: u64) -> Vec<StoredRoot> {
    CheckpointLog::ensure_dir(store).expect("ensure");
    let (dag, key, sem) = sample_roots();
    let mut prev = [0u8; 32];
    let mut roots = Vec::new();
    for sequence in 1..=count {
        let root = StoredRoot::assemble(
            dag,
            key,
            sem,
            sample_hlc(u8::try_from(sequence + 21).expect("sample hlc")),
            prev,
            sequence,
            op,
        )
        .expect("root");
        CheckpointLog::append(store, &root).expect("append");
        CheckpointLog::write_head(store, &root).expect("head");
        prev = root.preimage_hash;
        roots.push(root);
    }
    roots
}

fn commit_root_sequence_with_peaks(store: &Path, op: &KeyPair, count: u64) -> Vec<StoredRoot> {
    CheckpointLog::ensure_dir(store).expect("ensure");
    let (dag, key, sem) = sample_roots();
    let mut prev = [0u8; 32];
    let mut roots = Vec::new();
    for sequence in 1..=count {
        let root = StoredRoot::assemble(
            dag,
            key,
            sem,
            sample_hlc(u8::try_from(sequence + 30).expect("sample hlc")),
            prev,
            sequence,
            op,
        )
        .expect("root");
        CheckpointLog::append(store, &root).expect("append");
        update_root_history_peaks(store, &[op.public_key_bytes()], &root).expect("peaks");
        CheckpointLog::write_head(store, &root).expect("head");
        prev = root.preimage_hash;
        roots.push(root);
    }
    roots
}

fn append_roots_with_peaks(
    store: &Path,
    op: &KeyPair,
    roots: &mut Vec<StoredRoot>,
    target_count: u64,
) {
    let (dag, key, sem) = sample_roots();
    let mut prev = roots
        .last()
        .map(|root| root.preimage_hash)
        .unwrap_or([0u8; 32]);
    let start = u64::try_from(roots.len()).expect("root count") + 1;
    for sequence in start..=target_count {
        let root = StoredRoot::assemble(
            dag,
            key,
            sem,
            sample_hlc(u8::try_from(sequence + 100).expect("sample hlc")),
            prev,
            sequence,
            op,
        )
        .expect("root");
        CheckpointLog::append(store, &root).expect("append");
        update_root_history_peaks(store, &[op.public_key_bytes()], &root).expect("peaks");
        CheckpointLog::write_head(store, &root).expect("head");
        prev = root.preimage_hash;
        roots.push(root);
    }
}
