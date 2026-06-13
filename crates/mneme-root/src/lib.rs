//! Signed root assembly, checkpoint log, HEAD pointer (§5.7, INV-4, INV-6).

#![deny(warnings)]

mod atomic;
mod checkpoint;
mod history;
mod wire;

pub use checkpoint::{CheckpointLog, max_signed_checkpoint, verify_checkpoint_chain};
pub use history::{
    RootHistoryConsistencyProof, RootHistoryDigest, RootHistoryInclusionProof, RootHistoryPeak,
    RootHistoryPeakConsistencyProof, RootHistoryPeakDigest, RootHistoryPeakFrontierProof,
    RootHistoryPeakInclusionProof, RootHistoryPeakState, RootHistoryProofDirection,
    RootHistoryProofStep, read_root_history_peak_state, root_history_consistency_proof,
    root_history_digest, root_history_inclusion_proof, root_history_peak_consistency_proof,
    root_history_peak_digest, root_history_peak_frontier_proof, root_history_peak_inclusion_proof,
    root_history_peak_state_digest, update_root_history_peaks, verify_root_history_consistency,
    verify_root_history_digest, verify_root_history_inclusion,
    verify_root_history_peak_consistency, verify_root_history_peak_frontier,
    verify_root_history_peak_inclusion, verify_root_history_peak_state,
};

use mneme_core::{MnemeError, Root, RootPreimage, cmp_wire, from_bytes_strict, to_bytes_canonical};
use mneme_crypto::{KeyPair, verify_signature_bytes};
use std::path::Path;

pub const ROOT_VERSION: u16 = 1;

/// Persisted signed root checkpoint (`roots/<seq>.root.cbor`, `roots/HEAD`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRoot {
    pub version: u16,
    pub dag_head_root: [u8; 32],
    pub key_index_root: [u8; 32],
    pub semantic_commit: [u8; 32],
    pub hlc_max: [u8; 14],
    pub prev_root: [u8; 32],
    pub preimage_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub sequence: u64,
}

impl StoredRoot {
    /// Assemble preimage, hash, and Ed25519-sign (§5.7, INV-4).
    pub fn assemble(
        dag_head_root: [u8; 32],
        key_index_root: [u8; 32],
        semantic_commit: [u8; 32],
        hlc_max: [u8; 14],
        prev_root: [u8; 32],
        sequence: u64,
        operator: &KeyPair,
    ) -> Result<Self, MnemeError> {
        let preimage = RootPreimage {
            version: ROOT_VERSION,
            dag_head_root,
            key_index_root,
            semantic_commit,
            hlc_max,
            prev_root,
        };
        let preimage_hash = preimage.hash();
        let signature = operator.sign(&preimage_hash).to_vec();
        Ok(Self {
            version: ROOT_VERSION,
            dag_head_root,
            key_index_root,
            semantic_commit,
            hlc_max,
            prev_root,
            preimage_hash,
            signature,
            sequence,
        })
    }

    pub fn preimage(&self) -> RootPreimage {
        RootPreimage {
            version: self.version,
            dag_head_root: self.dag_head_root,
            key_index_root: self.key_index_root,
            semantic_commit: self.semantic_commit,
            hlc_max: self.hlc_max,
            prev_root: self.prev_root,
        }
    }

    pub fn to_root(&self) -> Root {
        Root {
            version: self.version,
            preimage_hash: self.preimage_hash,
            dag_head_root: self.dag_head_root,
            key_index_root: self.key_index_root,
            semantic_commit: self.semantic_commit,
            hlc_max: self.hlc_max,
            prev_root: self.prev_root,
            signature: self.signature.clone(),
            sequence: self.sequence,
        }
    }

    /// Recompute preimage hash and verify Ed25519 signature (INV-4).
    pub fn verify(&self, operator_pk: &ed25519_dalek::VerifyingKey) -> Result<(), MnemeError> {
        if self.preimage().hash() != self.preimage_hash {
            return Err(MnemeError::RootSigInvalid);
        }
        verify_signature_bytes(operator_pk, &self.preimage_hash, &self.signature)
    }

    pub fn verify_signature(
        &self,
        operator_pk: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), MnemeError> {
        self.verify(operator_pk)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MnemeError> {
        to_bytes_canonical(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MnemeError> {
        from_bytes_strict(bytes)
    }
}

/// Verify hash-chain link and monotonic sequence (INV-4 succession).
pub fn verify_root_chain(current: &Root, previous: Option<&Root>) -> Result<(), MnemeError> {
    if let Some(prev) = previous {
        if current.prev_root != prev.preimage_hash {
            return Err(MnemeError::RootInconsistent);
        }
        if current.sequence <= prev.sequence {
            return Err(MnemeError::RootInconsistent);
        }
    }
    Ok(())
}

/// Reject roots whose HLC high-water mark regresses (INV-6 / A-REPLAY).
pub fn check_replay(current: &Root, last_seen_hlc: Option<[u8; 14]>) -> Result<(), MnemeError> {
    if let Some(last) = last_seen_hlc {
        if cmp_wire(&current.hlc_max, &last) == std::cmp::Ordering::Less {
            return Err(MnemeError::RootReplayed);
        }
    }
    Ok(())
}

/// Check whether a root/store-owned path has a directory entry without
/// following aliases.
///
/// Verifier callers use this to reject present symlinks, including dangling
/// symlinks, without adding direct filesystem traversal to the verifier TCB.
pub fn path_entry_exists_no_follow(path: &Path) -> Result<bool, MnemeError> {
    atomic::entry_exists(path)
}
