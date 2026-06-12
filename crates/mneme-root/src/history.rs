//! Strict root-history accumulator over signed checkpoints.
//!
//! This is the first operator-facing append-only digest layer: a compact Merkle
//! tree commitment to the contiguous checkpoint history through HEAD plus
//! inclusion/consistency proofs. It is not a persisted append-efficient MMR yet;
//! it is the falsifiable pin future MMR peaks can extend without changing the
//! signed-root wire format.

use crate::atomic;
use crate::checkpoint::checkpoint_signature_valid;
use crate::{CheckpointLog, StoredRoot};
use mneme_core::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, MnemeError, from_bytes_strict,
    hash_ckpt, to_bytes_canonical,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const PEAKS_VERSION: u16 = 1;
const F_PEAKS_VERSION: u64 = 1;
const F_PEAKS_SEQUENCE: u64 = 2;
const F_PEAKS_HEAD: u64 = 3;
const F_PEAKS: u64 = 4;
const F_PEAKS_BAG_ROOT: u64 = 5;
const F_PEAK_HEIGHT: u64 = 1;
const F_PEAK_HASH: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryDigest {
    pub sequence: u64,
    pub checkpoint_count: u64,
    pub head_preimage_hash: [u8; 32],
    pub accumulator_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootHistoryProofDirection {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryProofStep {
    pub direction: RootHistoryProofDirection,
    pub sibling_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryInclusionProof {
    pub sequence: u64,
    pub checkpoint_count: u64,
    pub leaf_hash: [u8; 32],
    pub path: Vec<RootHistoryProofStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryConsistencyProof {
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryPeakInclusionProof {
    pub sequence: u64,
    pub checkpoint_count: u64,
    pub leaf_hash: [u8; 32],
    pub peak_index: u64,
    pub peak_height: u32,
    pub peak_hash: [u8; 32],
    pub peaks: Vec<RootHistoryPeak>,
    pub path: Vec<RootHistoryProofStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryPeak {
    pub height: u32,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryPeakDigest {
    pub sequence: u64,
    pub checkpoint_count: u64,
    pub head_preimage_hash: [u8; 32],
    pub peak_count: u64,
    pub peak_bag_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryPeakConsistencyProof {
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub from_peak_bag_root: [u8; 32],
    pub to_peak_bag_root: [u8; 32],
    pub appended_checkpoints: Vec<StoredRoot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryPeakFrontierProof {
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub from_peak_bag_root: [u8; 32],
    pub to_peak_bag_root: [u8; 32],
    /// Complete appended subtree roots. This is a compact structural frontier
    /// proof, not a signature transcript for every appended checkpoint.
    pub appended_subtrees: Vec<RootHistoryPeak>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHistoryPeakState {
    pub version: u16,
    pub sequence: u64,
    pub head_preimage_hash: [u8; 32],
    pub peaks: Vec<RootHistoryPeak>,
    pub peak_bag_root: [u8; 32],
}

pub fn root_history_digest(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
) -> Result<RootHistoryDigest, MnemeError> {
    let checkpoints = read_contiguous_verified_checkpoints(store, operator_keys, head)?;
    let leaves = checkpoints
        .iter()
        .map(root_history_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoint_count = u64::try_from(leaves.len()).map_err(|_| MnemeError::RootInconsistent)?;
    Ok(RootHistoryDigest {
        sequence: head.sequence,
        checkpoint_count,
        head_preimage_hash: head.preimage_hash,
        accumulator_root: merkle_root(&leaves),
    })
}

pub fn verify_root_history_digest(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
    expected: &RootHistoryDigest,
) -> Result<(), MnemeError> {
    let actual = root_history_digest(store, operator_keys, head)?;
    if &actual != expected {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

pub fn root_history_inclusion_proof(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
    sequence: u64,
) -> Result<RootHistoryInclusionProof, MnemeError> {
    if sequence == 0 || sequence > head.sequence {
        return Err(MnemeError::RootInconsistent);
    }
    let checkpoints = read_contiguous_verified_checkpoints(store, operator_keys, head)?;
    let leaves = checkpoints
        .iter()
        .map(root_history_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let target_index = usize::try_from(sequence - 1).map_err(|_| MnemeError::RootInconsistent)?;
    let leaf_hash = *leaves
        .get(target_index)
        .ok_or(MnemeError::RootInconsistent)?;
    let checkpoint_count = u64::try_from(leaves.len()).map_err(|_| MnemeError::RootInconsistent)?;
    Ok(RootHistoryInclusionProof {
        sequence,
        checkpoint_count,
        leaf_hash,
        path: inclusion_path(&leaves, target_index),
    })
}

pub fn verify_root_history_inclusion(
    digest: &RootHistoryDigest,
    checkpoint: &StoredRoot,
    proof: &RootHistoryInclusionProof,
) -> Result<(), MnemeError> {
    if proof.sequence == 0
        || proof.sequence != checkpoint.sequence
        || proof.checkpoint_count != digest.checkpoint_count
        || digest.sequence != proof.checkpoint_count
        || proof.sequence > proof.checkpoint_count
    {
        return Err(MnemeError::RootInconsistent);
    }
    if digest.head_preimage_hash == [0u8; 32] {
        return Err(MnemeError::RootInconsistent);
    }
    let leaf_hash = root_history_leaf(checkpoint)?;
    if leaf_hash != proof.leaf_hash {
        return Err(MnemeError::RootInconsistent);
    }
    let mut root = proof.leaf_hash;
    for step in &proof.path {
        root = match step.direction {
            RootHistoryProofDirection::Left => root_history_node(&step.sibling_hash, &root),
            RootHistoryProofDirection::Right => root_history_node(&root, &step.sibling_hash),
        };
    }
    if root != digest.accumulator_root {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

pub fn root_history_consistency_proof(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
    from_sequence: u64,
) -> Result<RootHistoryConsistencyProof, MnemeError> {
    if from_sequence == 0 || from_sequence > head.sequence {
        return Err(MnemeError::RootInconsistent);
    }
    let checkpoints = read_contiguous_verified_checkpoints(store, operator_keys, head)?;
    let leaves = checkpoints
        .iter()
        .map(root_history_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let from = usize::try_from(from_sequence).map_err(|_| MnemeError::RootInconsistent)?;
    let path = if from_sequence == head.sequence {
        Vec::new()
    } else {
        consistency_subproof(&leaves, from, true)
    };
    Ok(RootHistoryConsistencyProof {
        from_sequence,
        to_sequence: head.sequence,
        path,
    })
}

pub fn verify_root_history_consistency(
    older: &RootHistoryDigest,
    newer: &RootHistoryDigest,
    proof: &RootHistoryConsistencyProof,
) -> Result<(), MnemeError> {
    if proof.from_sequence == 0
        || proof.from_sequence != older.sequence
        || proof.to_sequence != newer.sequence
        || older.checkpoint_count != older.sequence
        || newer.checkpoint_count != newer.sequence
        || older.sequence > newer.sequence
    {
        return Err(MnemeError::RootInconsistent);
    }
    if older.sequence == newer.sequence {
        if older == newer && proof.path.is_empty() {
            return Ok(());
        }
        return Err(MnemeError::RootInconsistent);
    }

    let from = usize::try_from(older.sequence).map_err(|_| MnemeError::RootInconsistent)?;
    let to = usize::try_from(newer.sequence).map_err(|_| MnemeError::RootInconsistent)?;
    let mut proof_nodes = proof.path.iter();
    let (computed_old, computed_new) =
        verify_consistency_subproof(from, to, true, older.accumulator_root, &mut proof_nodes)?;
    if proof_nodes.next().is_some()
        || computed_old != older.accumulator_root
        || computed_new != newer.accumulator_root
    {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

pub fn update_root_history_peaks(
    store: &Path,
    operator_keys: &[[u8; 32]],
    root: &StoredRoot,
) -> Result<RootHistoryPeakState, MnemeError> {
    if !checkpoint_signature_valid(root, operator_keys) {
        return Err(MnemeError::RootSigInvalid);
    }
    let peaks_path = root_history_peaks_path(store);
    let previous = if peaks_path.exists() {
        Some(read_root_history_peak_state(store)?)
    } else {
        None
    };
    let next = match previous {
        Some(state) => {
            if root.sequence != state.sequence + 1
                || root.prev_root != state.head_preimage_hash
                || !peaks_are_strictly_descending(&state.peaks)
                || state.peak_bag_root
                    != peak_bag_root(state.sequence, &state.head_preimage_hash, &state.peaks)
            {
                return Err(MnemeError::RootInconsistent);
            }
            append_peak_state(state.peaks, root)?
        }
        None => {
            if root.sequence != 1 || root.prev_root != [0u8; 32] {
                return Err(MnemeError::RootInconsistent);
            }
            append_peak_state(Vec::new(), root)?
        }
    };
    atomic::atomic_write(&peaks_path, &to_bytes_canonical(&next)?)?;
    Ok(next)
}

pub fn read_root_history_peak_state(store: &Path) -> Result<RootHistoryPeakState, MnemeError> {
    let path = root_history_peaks_path(store);
    let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
    let state: RootHistoryPeakState = from_bytes_strict(&bytes)?;
    validate_peak_state(&state)?;
    Ok(state)
}

pub fn root_history_peak_digest(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
) -> Result<RootHistoryPeakDigest, MnemeError> {
    let state = verify_root_history_peak_state(store, operator_keys, head)?;
    root_history_peak_state_digest(&state)
}

pub fn verify_root_history_peak_state(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
) -> Result<RootHistoryPeakState, MnemeError> {
    let sidecar = read_root_history_peak_state(store)?;
    if sidecar.sequence != head.sequence || sidecar.head_preimage_hash != head.preimage_hash {
        return Err(MnemeError::RootInconsistent);
    }
    let expected = recompute_peak_state_from_verified_checkpoints(store, operator_keys, head)?;
    if sidecar != expected {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(sidecar)
}

pub fn root_history_peak_state_digest(
    state: &RootHistoryPeakState,
) -> Result<RootHistoryPeakDigest, MnemeError> {
    validate_peak_state(state)?;
    Ok(RootHistoryPeakDigest {
        sequence: state.sequence,
        checkpoint_count: state.sequence,
        head_preimage_hash: state.head_preimage_hash,
        peak_count: u64::try_from(state.peaks.len()).map_err(|_| MnemeError::RootInconsistent)?,
        peak_bag_root: state.peak_bag_root,
    })
}

pub fn root_history_peak_consistency_proof(
    store: &Path,
    operator_keys: &[[u8; 32]],
    from_state: &RootHistoryPeakState,
    head: &StoredRoot,
) -> Result<RootHistoryPeakConsistencyProof, MnemeError> {
    validate_peak_state(from_state)?;
    if head.sequence == 0
        || from_state.sequence > head.sequence
        || !checkpoint_signature_valid(head, operator_keys)
    {
        return Err(MnemeError::RootInconsistent);
    }
    if from_state.sequence == head.sequence && from_state.head_preimage_hash != head.preimage_hash {
        return Err(MnemeError::RootInconsistent);
    }

    let appended_checkpoints = if from_state.sequence == head.sequence {
        Vec::new()
    } else {
        let first_sequence = from_state
            .sequence
            .checked_add(1)
            .ok_or(MnemeError::RootInconsistent)?;
        read_verified_checkpoint_delta(
            store,
            operator_keys,
            from_state.head_preimage_hash,
            first_sequence,
            head,
        )?
    };
    let to_state = replay_peak_delta(from_state, operator_keys, &appended_checkpoints)?;
    if to_state.sequence != head.sequence || to_state.head_preimage_hash != head.preimage_hash {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(RootHistoryPeakConsistencyProof {
        from_sequence: from_state.sequence,
        to_sequence: to_state.sequence,
        from_peak_bag_root: from_state.peak_bag_root,
        to_peak_bag_root: to_state.peak_bag_root,
        appended_checkpoints,
    })
}

pub fn root_history_peak_frontier_proof(
    store: &Path,
    operator_keys: &[[u8; 32]],
    from_state: &RootHistoryPeakState,
    head: &StoredRoot,
) -> Result<RootHistoryPeakFrontierProof, MnemeError> {
    validate_peak_state(from_state)?;
    if head.sequence == 0
        || from_state.sequence > head.sequence
        || !checkpoint_signature_valid(head, operator_keys)
    {
        return Err(MnemeError::RootInconsistent);
    }
    if from_state.sequence == head.sequence && from_state.head_preimage_hash != head.preimage_hash {
        return Err(MnemeError::RootInconsistent);
    }
    let to_state = verify_root_history_peak_state(store, operator_keys, head)?;
    let checkpoints = read_contiguous_verified_checkpoints(store, operator_keys, head)?;
    let appended_subtrees =
        appended_subtree_roots(&checkpoints, from_state.sequence, head.sequence)?;
    let proof = RootHistoryPeakFrontierProof {
        from_sequence: from_state.sequence,
        to_sequence: to_state.sequence,
        from_peak_bag_root: from_state.peak_bag_root,
        to_peak_bag_root: to_state.peak_bag_root,
        appended_subtrees,
    };
    verify_root_history_peak_frontier(
        from_state,
        &root_history_peak_state_digest(&to_state)?,
        &proof,
    )?;
    Ok(proof)
}

pub fn root_history_peak_inclusion_proof(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
    sequence: u64,
) -> Result<RootHistoryPeakInclusionProof, MnemeError> {
    if sequence == 0 || sequence > head.sequence {
        return Err(MnemeError::RootInconsistent);
    }
    let state = verify_root_history_peak_state(store, operator_keys, head)?;
    let checkpoints = read_contiguous_verified_checkpoints(store, operator_keys, head)?;
    let (peak_index, start_sequence, end_sequence) =
        peak_range_for_sequence(&state.peaks, sequence)?;
    let range_start =
        usize::try_from(start_sequence - 1).map_err(|_| MnemeError::RootInconsistent)?;
    let range_end = usize::try_from(end_sequence).map_err(|_| MnemeError::RootInconsistent)?;
    let target_index =
        usize::try_from(sequence - start_sequence).map_err(|_| MnemeError::RootInconsistent)?;
    let peak_checkpoints = checkpoints
        .get(range_start..range_end)
        .ok_or(MnemeError::RootInconsistent)?;
    let leaves = peak_checkpoints
        .iter()
        .map(root_history_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_hash = *leaves
        .get(target_index)
        .ok_or(MnemeError::RootInconsistent)?;
    let peak = state
        .peaks
        .get(peak_index)
        .ok_or(MnemeError::RootInconsistent)?;
    Ok(RootHistoryPeakInclusionProof {
        sequence,
        checkpoint_count: head.sequence,
        leaf_hash,
        peak_index: u64::try_from(peak_index).map_err(|_| MnemeError::RootInconsistent)?,
        peak_height: peak.height,
        peak_hash: peak.hash,
        peaks: state.peaks,
        path: inclusion_path(&leaves, target_index),
    })
}

pub fn verify_root_history_peak_inclusion(
    operator_keys: &[[u8; 32]],
    digest: &RootHistoryPeakDigest,
    checkpoint: &StoredRoot,
    proof: &RootHistoryPeakInclusionProof,
) -> Result<(), MnemeError> {
    if proof.sequence == 0
        || proof.sequence != checkpoint.sequence
        || proof.checkpoint_count != digest.checkpoint_count
        || digest.sequence != digest.checkpoint_count
        || proof.sequence > proof.checkpoint_count
        || digest.head_preimage_hash == [0u8; 32]
        || digest.peak_count != u64::from(digest.sequence.count_ones())
        || proof.peaks.len()
            != usize::try_from(digest.peak_count).map_err(|_| MnemeError::RootInconsistent)?
    {
        return Err(MnemeError::RootInconsistent);
    }
    if !checkpoint_signature_valid(checkpoint, operator_keys) {
        return Err(MnemeError::RootSigInvalid);
    }
    if !peaks_are_strictly_descending(&proof.peaks)
        || !peaks_cover_sequence(digest.sequence, &proof.peaks)
        || digest.peak_bag_root
            != peak_bag_root(digest.sequence, &digest.head_preimage_hash, &proof.peaks)
    {
        return Err(MnemeError::RootInconsistent);
    }
    let peak_index = usize::try_from(proof.peak_index).map_err(|_| MnemeError::RootInconsistent)?;
    let peak = proof
        .peaks
        .get(peak_index)
        .ok_or(MnemeError::RootInconsistent)?;
    if proof.peak_height != peak.height || proof.peak_hash != peak.hash {
        return Err(MnemeError::RootInconsistent);
    }
    let (actual_peak_index, start_sequence, end_sequence) =
        peak_range_for_sequence(&proof.peaks, proof.sequence)?;
    if actual_peak_index != peak_index {
        return Err(MnemeError::RootInconsistent);
    }
    if proof.sequence < start_sequence || proof.sequence > end_sequence {
        return Err(MnemeError::RootInconsistent);
    }
    if usize::try_from(peak.height).map_err(|_| MnemeError::RootInconsistent)? != proof.path.len() {
        return Err(MnemeError::RootInconsistent);
    }
    let leaf_hash = root_history_leaf(checkpoint)?;
    if proof.leaf_hash != leaf_hash {
        return Err(MnemeError::RootInconsistent);
    }
    let mut computed_peak = proof.leaf_hash;
    for step in &proof.path {
        computed_peak = match step.direction {
            RootHistoryProofDirection::Left => {
                root_history_node(&step.sibling_hash, &computed_peak)
            }
            RootHistoryProofDirection::Right => {
                root_history_node(&computed_peak, &step.sibling_hash)
            }
        };
    }
    if computed_peak != proof.peak_hash {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

pub fn verify_root_history_peak_consistency(
    operator_keys: &[[u8; 32]],
    older: &RootHistoryPeakState,
    newer: &RootHistoryPeakDigest,
    proof: &RootHistoryPeakConsistencyProof,
) -> Result<(), MnemeError> {
    let older_digest = root_history_peak_state_digest(older)?;
    if proof.from_sequence != older.sequence
        || proof.to_sequence != newer.sequence
        || proof.from_peak_bag_root != older.peak_bag_root
        || proof.to_peak_bag_root != newer.peak_bag_root
        || older.sequence > newer.sequence
        || newer.checkpoint_count != newer.sequence
        || newer.peak_count != u64::from(newer.sequence.count_ones())
    {
        return Err(MnemeError::RootInconsistent);
    }

    if older.sequence == newer.sequence {
        if proof.appended_checkpoints.is_empty() && &older_digest == newer {
            return Ok(());
        }
        return Err(MnemeError::RootInconsistent);
    }

    let expected_len = usize::try_from(newer.sequence - older.sequence)
        .map_err(|_| MnemeError::RootInconsistent)?;
    if proof.appended_checkpoints.len() != expected_len {
        return Err(MnemeError::RootInconsistent);
    }

    let computed = root_history_peak_state_digest(&replay_peak_delta(
        older,
        operator_keys,
        &proof.appended_checkpoints,
    )?)?;
    if &computed != newer {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

pub fn verify_root_history_peak_frontier(
    older: &RootHistoryPeakState,
    newer: &RootHistoryPeakDigest,
    proof: &RootHistoryPeakFrontierProof,
) -> Result<(), MnemeError> {
    let older_digest = root_history_peak_state_digest(older)?;
    if proof.from_sequence != older.sequence
        || proof.to_sequence != newer.sequence
        || proof.from_peak_bag_root != older.peak_bag_root
        || proof.to_peak_bag_root != newer.peak_bag_root
        || older.sequence > newer.sequence
        || newer.checkpoint_count != newer.sequence
        || newer.peak_count != u64::from(newer.sequence.count_ones())
    {
        return Err(MnemeError::RootInconsistent);
    }

    if older.sequence == newer.sequence {
        if proof.appended_subtrees.is_empty() && &older_digest == newer {
            return Ok(());
        }
        return Err(MnemeError::RootInconsistent);
    }

    let mut sequence = older.sequence;
    let mut peaks = older.peaks.clone();
    for subtree in &proof.appended_subtrees {
        let width = checked_peak_width(subtree.height)?;
        let start = sequence
            .checked_add(1)
            .ok_or(MnemeError::RootInconsistent)?;
        if (start - 1) % width != 0 {
            return Err(MnemeError::RootInconsistent);
        }
        sequence = sequence
            .checked_add(width)
            .ok_or(MnemeError::RootInconsistent)?;
        if sequence > newer.sequence {
            return Err(MnemeError::RootInconsistent);
        }
        peaks = append_peak(peaks, subtree.clone())?;
    }

    if sequence != newer.sequence
        || !peaks_are_strictly_descending(&peaks)
        || !peaks_cover_sequence(newer.sequence, &peaks)
        || u64::try_from(peaks.len()).map_err(|_| MnemeError::RootInconsistent)? != newer.peak_count
        || peak_bag_root(newer.sequence, &newer.head_preimage_hash, &peaks) != newer.peak_bag_root
    {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

fn read_contiguous_verified_checkpoints(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
) -> Result<Vec<StoredRoot>, MnemeError> {
    if head.sequence == 0 {
        return Err(MnemeError::RootInconsistent);
    }
    let capacity = usize::try_from(head.sequence).map_err(|_| MnemeError::RootInconsistent)?;
    let mut checkpoints = Vec::with_capacity(capacity);
    let mut expected_prev = [0u8; 32];
    for sequence in 1..=head.sequence {
        let stored = CheckpointLog::read_checkpoint(store, sequence)?;
        if stored.sequence != sequence {
            return Err(MnemeError::RootInconsistent);
        }
        if !checkpoint_signature_valid(&stored, operator_keys) {
            return Err(MnemeError::RootSigInvalid);
        }
        if stored.prev_root != expected_prev {
            return Err(MnemeError::RootInconsistent);
        }
        expected_prev = stored.preimage_hash;
        checkpoints.push(stored);
    }
    if checkpoints.last() != Some(head) {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(checkpoints)
}

fn read_verified_checkpoint_delta(
    store: &Path,
    operator_keys: &[[u8; 32]],
    mut expected_prev: [u8; 32],
    first_sequence: u64,
    head: &StoredRoot,
) -> Result<Vec<StoredRoot>, MnemeError> {
    if first_sequence == 0 || first_sequence > head.sequence {
        return Err(MnemeError::RootInconsistent);
    }
    let count = head
        .sequence
        .checked_sub(first_sequence)
        .and_then(|delta| delta.checked_add(1))
        .ok_or(MnemeError::RootInconsistent)?;
    let capacity = usize::try_from(count).map_err(|_| MnemeError::RootInconsistent)?;
    let mut checkpoints = Vec::with_capacity(capacity);
    for sequence in first_sequence..=head.sequence {
        let stored = CheckpointLog::read_checkpoint(store, sequence)?;
        if stored.sequence != sequence
            || stored.prev_root != expected_prev
            || !checkpoint_signature_valid(&stored, operator_keys)
        {
            return Err(MnemeError::RootInconsistent);
        }
        expected_prev = stored.preimage_hash;
        checkpoints.push(stored);
    }
    if checkpoints.last() != Some(head) {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(checkpoints)
}

fn recompute_peak_state_from_verified_checkpoints(
    store: &Path,
    operator_keys: &[[u8; 32]],
    head: &StoredRoot,
) -> Result<RootHistoryPeakState, MnemeError> {
    let checkpoints = read_contiguous_verified_checkpoints(store, operator_keys, head)?;
    let mut state = None;
    for checkpoint in checkpoints {
        let peaks = state
            .map(|state: RootHistoryPeakState| state.peaks)
            .unwrap_or_default();
        state = Some(append_peak_state(peaks, &checkpoint)?);
    }
    state.ok_or(MnemeError::RootInconsistent)
}

fn appended_subtree_roots(
    checkpoints: &[StoredRoot],
    from_sequence: u64,
    to_sequence: u64,
) -> Result<Vec<RootHistoryPeak>, MnemeError> {
    if from_sequence > to_sequence {
        return Err(MnemeError::RootInconsistent);
    }
    let mut sequence = from_sequence
        .checked_add(1)
        .ok_or(MnemeError::RootInconsistent)?;
    let mut subtrees = Vec::new();
    while sequence <= to_sequence {
        let remaining = to_sequence
            .checked_sub(sequence)
            .and_then(|remaining| remaining.checked_add(1))
            .ok_or(MnemeError::RootInconsistent)?;
        let height = aligned_subtree_height(sequence, remaining)?;
        let width = checked_peak_width(height)?;
        let start = usize::try_from(sequence - 1).map_err(|_| MnemeError::RootInconsistent)?;
        let end = usize::try_from(
            sequence
                .checked_add(width)
                .and_then(|next| next.checked_sub(1))
                .ok_or(MnemeError::RootInconsistent)?,
        )
        .map_err(|_| MnemeError::RootInconsistent)?;
        let leaves = checkpoints
            .get(start..end)
            .ok_or(MnemeError::RootInconsistent)?
            .iter()
            .map(root_history_leaf)
            .collect::<Result<Vec<_>, _>>()?;
        subtrees.push(RootHistoryPeak {
            height,
            hash: merkle_root(&leaves),
        });
        sequence = sequence
            .checked_add(width)
            .ok_or(MnemeError::RootInconsistent)?;
    }
    Ok(subtrees)
}

fn aligned_subtree_height(sequence: u64, remaining: u64) -> Result<u32, MnemeError> {
    if sequence == 0 || remaining == 0 {
        return Err(MnemeError::RootInconsistent);
    }
    let max_height = 63 - remaining.leading_zeros();
    for height in (0..=max_height).rev() {
        let width = checked_peak_width(height)?;
        if (sequence - 1) % width == 0 {
            return Ok(height);
        }
    }
    Err(MnemeError::RootInconsistent)
}

fn replay_peak_delta(
    from_state: &RootHistoryPeakState,
    operator_keys: &[[u8; 32]],
    appended_checkpoints: &[StoredRoot],
) -> Result<RootHistoryPeakState, MnemeError> {
    validate_peak_state(from_state)?;
    let mut state = from_state.clone();
    let mut expected_prev = state.head_preimage_hash;
    for (idx, checkpoint) in appended_checkpoints.iter().enumerate() {
        let offset = u64::try_from(idx).map_err(|_| MnemeError::RootInconsistent)?;
        let expected_sequence = from_state
            .sequence
            .checked_add(offset)
            .and_then(|sequence| sequence.checked_add(1))
            .ok_or(MnemeError::RootInconsistent)?;
        if checkpoint.sequence != expected_sequence
            || checkpoint.prev_root != expected_prev
            || !checkpoint_signature_valid(checkpoint, operator_keys)
        {
            return Err(MnemeError::RootInconsistent);
        }
        state = append_peak_state(state.peaks, checkpoint)?;
        expected_prev = checkpoint.preimage_hash;
    }
    Ok(state)
}

fn root_history_leaf(root: &StoredRoot) -> Result<[u8; 32], MnemeError> {
    let bytes = root.to_bytes()?;
    let len = u64::try_from(bytes.len()).map_err(|_| MnemeError::RootInconsistent)?;
    let mut payload = Vec::with_capacity(30 + 8 + 8 + bytes.len());
    payload.extend_from_slice(b"root-history-leaf-v1\x00");
    payload.extend_from_slice(&root.sequence.to_le_bytes());
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&bytes);
    Ok(hash_ckpt(&payload))
}

fn inclusion_path(leaves: &[[u8; 32]], index: usize) -> Vec<RootHistoryProofStep> {
    match leaves.len() {
        0 | 1 => Vec::new(),
        len => {
            let split = largest_power_of_two_less_than(len);
            if index < split {
                let mut path = inclusion_path(&leaves[..split], index);
                path.push(RootHistoryProofStep {
                    direction: RootHistoryProofDirection::Right,
                    sibling_hash: merkle_root(&leaves[split..]),
                });
                path
            } else {
                let mut path = inclusion_path(&leaves[split..], index - split);
                path.push(RootHistoryProofStep {
                    direction: RootHistoryProofDirection::Left,
                    sibling_hash: merkle_root(&leaves[..split]),
                });
                path
            }
        }
    }
}

/// SUBPROOF(m, D[n], b) from RFC6962-style append-only Merkle consistency.
fn consistency_subproof(
    leaves: &[[u8; 32]],
    prefix_len: usize,
    prefix_root_known: bool,
) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if prefix_len == n {
        if prefix_root_known {
            return Vec::new();
        }
        return vec![merkle_root(leaves)];
    }
    let split = largest_power_of_two_less_than(n);
    if prefix_len <= split {
        let mut proof = consistency_subproof(&leaves[..split], prefix_len, prefix_root_known);
        proof.push(merkle_root(&leaves[split..]));
        proof
    } else {
        let mut proof = consistency_subproof(&leaves[split..], prefix_len - split, false);
        proof.push(merkle_root(&leaves[..split]));
        proof
    }
}

fn verify_consistency_subproof<'a, I>(
    prefix_len: usize,
    full_len: usize,
    prefix_root_known: bool,
    known_prefix_root: [u8; 32],
    proof_nodes: &mut I,
) -> Result<([u8; 32], [u8; 32]), MnemeError>
where
    I: Iterator<Item = &'a [u8; 32]>,
{
    if prefix_len == 0 || prefix_len > full_len {
        return Err(MnemeError::RootInconsistent);
    }
    if prefix_len == full_len {
        if prefix_root_known {
            return Ok((known_prefix_root, known_prefix_root));
        }
        let subtree = *proof_nodes.next().ok_or(MnemeError::RootInconsistent)?;
        return Ok((subtree, subtree));
    }

    let split = largest_power_of_two_less_than(full_len);
    if prefix_len <= split {
        let (old_left, new_left) = verify_consistency_subproof(
            prefix_len,
            split,
            prefix_root_known,
            known_prefix_root,
            proof_nodes,
        )?;
        let right = *proof_nodes.next().ok_or(MnemeError::RootInconsistent)?;
        Ok((old_left, root_history_node(&new_left, &right)))
    } else {
        let (old_right, new_right) = verify_consistency_subproof(
            prefix_len - split,
            full_len - split,
            false,
            [0u8; 32],
            proof_nodes,
        )?;
        let left = *proof_nodes.next().ok_or(MnemeError::RootInconsistent)?;
        Ok((
            root_history_node(&left, &old_right),
            root_history_node(&left, &new_right),
        ))
    }
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => hash_ckpt(b"root-history-empty-v1\x00"),
        1 => leaves[0],
        len => {
            let split = largest_power_of_two_less_than(len);
            let left = merkle_root(&leaves[..split]);
            let right = merkle_root(&leaves[split..]);
            root_history_node(&left, &right)
        }
    }
}

fn root_history_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(23 + 64);
    payload.extend_from_slice(b"root-history-node-v1\x00");
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);
    hash_ckpt(&payload)
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut power = 1usize;
    while power.saturating_mul(2) < n {
        power *= 2;
    }
    power
}

fn append_peak_state(
    peaks: Vec<RootHistoryPeak>,
    root: &StoredRoot,
) -> Result<RootHistoryPeakState, MnemeError> {
    let carry = RootHistoryPeak {
        height: 0,
        hash: root_history_leaf(root)?,
    };
    let peaks = append_peak(peaks, carry)?;
    let peak_bag_root = peak_bag_root(root.sequence, &root.preimage_hash, &peaks);
    Ok(RootHistoryPeakState {
        version: PEAKS_VERSION,
        sequence: root.sequence,
        head_preimage_hash: root.preimage_hash,
        peaks,
        peak_bag_root,
    })
}

fn append_peak(
    mut peaks: Vec<RootHistoryPeak>,
    mut carry: RootHistoryPeak,
) -> Result<Vec<RootHistoryPeak>, MnemeError> {
    while let Some(last) = peaks.last() {
        if last.height != carry.height {
            break;
        }
        let left = peaks.pop().ok_or(MnemeError::RootInconsistent)?;
        carry = RootHistoryPeak {
            height: left
                .height
                .checked_add(1)
                .ok_or(MnemeError::RootInconsistent)?,
            hash: root_history_node(&left.hash, &carry.hash),
        };
    }
    peaks.push(carry);
    if !peaks_are_strictly_descending(&peaks) {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(peaks)
}

fn peaks_are_strictly_descending(peaks: &[RootHistoryPeak]) -> bool {
    peaks
        .windows(2)
        .all(|window| window[0].height > window[1].height)
}

fn peak_bag_root(
    sequence: u64,
    head_preimage_hash: &[u8; 32],
    peaks: &[RootHistoryPeak],
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

fn validate_peak_state(state: &RootHistoryPeakState) -> Result<(), MnemeError> {
    if state.version != PEAKS_VERSION
        || state.sequence == 0
        || state.head_preimage_hash == [0u8; 32]
        || state.peaks.is_empty()
        || !peaks_are_strictly_descending(&state.peaks)
        || !peaks_cover_sequence(state.sequence, &state.peaks)
        || state.peak_bag_root
            != peak_bag_root(state.sequence, &state.head_preimage_hash, &state.peaks)
    {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

fn peaks_cover_sequence(sequence: u64, peaks: &[RootHistoryPeak]) -> bool {
    if peaks.len() != usize::try_from(sequence.count_ones()).unwrap_or(usize::MAX) {
        return false;
    }
    let mut covered = 0u64;
    for peak in peaks {
        let Some(width) = 1u64.checked_shl(peak.height) else {
            return false;
        };
        let Some(next) = covered.checked_add(width) else {
            return false;
        };
        covered = next;
    }
    covered == sequence
}

fn checked_peak_width(height: u32) -> Result<u64, MnemeError> {
    1u64.checked_shl(height).ok_or(MnemeError::RootInconsistent)
}

fn peak_range_for_sequence(
    peaks: &[RootHistoryPeak],
    sequence: u64,
) -> Result<(usize, u64, u64), MnemeError> {
    let mut start = 1u64;
    for (index, peak) in peaks.iter().enumerate() {
        let width = 1u64
            .checked_shl(peak.height)
            .ok_or(MnemeError::RootInconsistent)?;
        let end = start
            .checked_add(width)
            .and_then(|next_start| next_start.checked_sub(1))
            .ok_or(MnemeError::RootInconsistent)?;
        if sequence >= start && sequence <= end {
            return Ok((index, start, end));
        }
        start = end.checked_add(1).ok_or(MnemeError::RootInconsistent)?;
    }
    Err(MnemeError::RootInconsistent)
}

fn root_history_peaks_path(store: &Path) -> std::path::PathBuf {
    store.join("roots/HISTORY_PEAKS.cbor")
}

fn io_err(path: &Path, e: std::io::Error) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: e.to_string(),
    }
}

impl DcborEncode for RootHistoryPeakState {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        validate_peak_state(self)?;
        enc.begin_map(5)?;
        enc.encode_unsigned(F_PEAKS_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_PEAKS_SEQUENCE)?;
        enc.encode_unsigned(self.sequence)?;
        enc.encode_unsigned(F_PEAKS_HEAD)?;
        enc.encode_bytes(&self.head_preimage_hash)?;
        enc.encode_unsigned(F_PEAKS)?;
        enc.begin_array(self.peaks.len() as u64)?;
        for peak in &self.peaks {
            enc.begin_map(2)?;
            enc.encode_unsigned(F_PEAK_HEIGHT)?;
            enc.encode_unsigned(u64::from(peak.height))?;
            enc.encode_unsigned(F_PEAK_HASH)?;
            enc.encode_bytes(&peak.hash)?;
        }
        enc.encode_unsigned(F_PEAKS_BAG_ROOT)?;
        enc.encode_bytes(&self.peak_bag_root)?;
        Ok(())
    }
}

impl DcborDecode for RootHistoryPeakState {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut sequence = None;
        let mut head_preimage_hash = None;
        let mut peaks = None;
        let mut peak_bag_root = None;

        for (key, value) in map {
            let field = parse_field_key(&key)?;
            match field {
                F_PEAKS_VERSION => version = Some(parse_u16(&value)?),
                F_PEAKS_SEQUENCE => sequence = Some(parse_u64(&value)?),
                F_PEAKS_HEAD => head_preimage_hash = Some(parse_fixed32(&value)?),
                F_PEAKS => peaks = Some(parse_peaks(&value)?),
                F_PEAKS_BAG_ROOT => peak_bag_root = Some(parse_fixed32(&value)?),
                _ => return Err(unknown_field(field)),
            }
        }

        let state = Self {
            version: version.ok_or(MnemeError::SchemaDrift)?,
            sequence: sequence.ok_or(MnemeError::SchemaDrift)?,
            head_preimage_hash: head_preimage_hash.ok_or(MnemeError::SchemaDrift)?,
            peaks: peaks.ok_or(MnemeError::SchemaDrift)?,
            peak_bag_root: peak_bag_root.ok_or(MnemeError::SchemaDrift)?,
        };
        validate_peak_state(&state)?;
        Ok(state)
    }
}

fn parse_peaks(value: &CborValue) -> Result<Vec<RootHistoryPeak>, MnemeError> {
    let items = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    items.iter().map(parse_peak).collect()
}

fn parse_peak(value: &CborValue) -> Result<RootHistoryPeak, MnemeError> {
    let map = value.as_map().ok_or(MnemeError::SchemaDrift)?;
    let mut by_field = BTreeMap::new();
    for (key, value) in map {
        let field = parse_field_key(key)?;
        if by_field.insert(field, value).is_some() {
            return Err(MnemeError::SerializationNonCanonical);
        }
    }
    if let Some((&field, _)) = by_field
        .iter()
        .find(|(field, _)| **field != F_PEAK_HEIGHT && **field != F_PEAK_HASH)
    {
        return Err(unknown_field(field));
    }
    Ok(RootHistoryPeak {
        height: parse_u32(
            by_field
                .get(&F_PEAK_HEIGHT)
                .ok_or(MnemeError::SchemaDrift)?,
        )?,
        hash: parse_fixed32(by_field.get(&F_PEAK_HASH).ok_or(MnemeError::SchemaDrift)?)?,
    })
}

fn unknown_field(field: u64) -> MnemeError {
    MnemeError::UnknownField {
        field: u16::try_from(field).unwrap_or(u16::MAX),
    }
}

fn parse_field_key(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_u32(value: &CborValue) -> Result<u32, MnemeError> {
    let value = parse_u64(value)?;
    u32::try_from(value).map_err(|_| MnemeError::SchemaDrift)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let value = parse_u64(value)?;
    u16::try_from(value).map_err(|_| MnemeError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or(MnemeError::SchemaDrift)?;
    let mut out = [0u8; 32];
    if bytes.len() != out.len() {
        return Err(MnemeError::SchemaDrift);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}
