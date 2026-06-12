//! Signed root assembly, checkpoint log, HEAD pointer (§5.7, INV-4, INV-6).

#![deny(warnings)]

mod atomic;
mod checkpoint;
mod wire;

pub use checkpoint::{CheckpointLog, max_signed_checkpoint, verify_checkpoint_chain};

use mneme_core::{MnemeError, Root, RootPreimage, cmp_wire, from_bytes_strict, to_bytes_canonical};
use mneme_crypto::{KeyPair, verify_signature_bytes};

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
    pub vdf_proof: Option<Vec<u8>>,
    pub vdf_difficulty: Option<u64>,
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
        Self::assemble_with_vdf(
            dag_head_root,
            key_index_root,
            semantic_commit,
            hlc_max,
            prev_root,
            sequence,
            operator,
            None,
            None,
        )
    }

    /// Assemble preimage with VDF anchoring fields.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_with_vdf(
        dag_head_root: [u8; 32],
        key_index_root: [u8; 32],
        semantic_commit: [u8; 32],
        hlc_max: [u8; 14],
        prev_root: [u8; 32],
        sequence: u64,
        operator: &KeyPair,
        vdf_proof: Option<Vec<u8>>,
        vdf_difficulty: Option<u64>,
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
            vdf_proof,
            vdf_difficulty,
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
            vdf_proof: self.vdf_proof.clone(),
            vdf_difficulty: self.vdf_difficulty,
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

/// Wesolowski VDF verification.
///
/// Honesty Label (H3-VDF):
/// "VDF time anchoring proves that a minimum amount of sequential CPU/ASIC work has elapsed
/// between epoch checkpoints, but does NOT prove absolute wall-clock time unless bound to a
/// verified external trust anchor."
pub fn verify_vdf_wesolowski(
    x_hash: &[u8; 32],
    vdf_proof_bytes: &[u8],
    difficulty: u64,
) -> Result<(), MnemeError> {
    if difficulty == 0 {
        return Err(MnemeError::RootInconsistent);
    }
    if vdf_proof_bytes.len() != 512 {
        return Err(MnemeError::RootInconsistent);
    }
    let (y, proof) = vdf_proof_bytes.split_at(256);
    if mneme_vdf::VdfVerifier::verify(x_hash, y, proof, difficulty) {
        Ok(())
    } else {
        Err(MnemeError::RootInconsistent)
    }
}

/// Verify hash-chain link and monotonic sequence (INV-4 succession).
pub fn verify_root_chain(current: &Root, previous: Option<&Root>) -> Result<(), MnemeError> {
    let mut prev_hash = [0u8; 32];
    if let Some(prev) = previous {
        if current.prev_root != prev.preimage_hash {
            return Err(MnemeError::RootInconsistent);
        }
        if current.sequence <= prev.sequence {
            return Err(MnemeError::RootInconsistent);
        }
        prev_hash = prev.preimage_hash;
    }
    if let Some(proof) = &current.vdf_proof {
        let difficulty = current.vdf_difficulty.unwrap_or(0);
        verify_vdf_wesolowski(&prev_hash, proof, difficulty)?;
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
