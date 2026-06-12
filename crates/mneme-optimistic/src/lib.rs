//! Optimistic top-k verifier layer for MNEME (Task A).
//!
//! # Trust Model
//! This module implements a refereed delegation / optimistic rollup trust model:
//! 1. **1-of-N Honest Watcher**: We assume that at least one watcher is online, honest,
//!    and has access to the full dataset to verify the prover's claim and submit a fraud proof.
//! 2. **Data Availability (DA)**: Watchers must be able to read all committed vectors to
//!    identify a missing closer vector and generate the Merkle membership proof for it.
//! 3. **Liveness / Censorship Resistance**: We assume that watchers can broadcast valid fraud
//!    proofs to the verifier (e.g. blockchain, consensus layer, or audit engine) within the
//!    challenge window without being censored or blocked.
//!
//! If these assumptions hold, the verifier achieves complete soundness with O(1) verify time
//! and minimal proof size on the happy path.

use mneme_core::{FixedPointEmbedding, MnemeError, ObjectId};
use mneme_index::{SemanticMerkleTree, hash_sem_leaf};
use serde::{Deserialize, Serialize};

/// A claim posted by a prover asserting that a set of results is the exact top-k set
/// under the committed quantized metric.
#[derive(Debug, Clone)]
pub struct TopKClaim {
    /// The query vector.
    pub query: FixedPointEmbedding,
    /// The claimed k-th boundary distance.
    pub d_k: i64,
    /// The ObjectIds returned in the top-k set.
    pub returned_ids: Vec<ObjectId>,
    /// The signed semantic root committing to all vectors in the dataset.
    pub semantic_commit: [u8; 32],
}

/// A fraud proof submitted by a watcher challenging a prover's claim.
#[derive(Debug, Clone)]
pub struct WatcherChallenge {
    /// The index of the counterexample in the sorted semantic Merkle tree.
    pub leaf_index: usize,
    /// The counterexample vector.
    pub counterexample_vector: FixedPointEmbedding,
    /// The Merkle membership proof in the balanced semantic Merkle tree.
    pub merkle_path: Vec<[u8; 32]>,
    /// The ObjectId of the counterexample.
    pub object_id: ObjectId,
}

impl TopKClaim {
    /// Verifies a watcher's challenge.
    ///
    /// Returns:
    /// - `Ok(true)` if the challenge is VALID (the prover cheated, slash/reject the claim!).
    /// - `Ok(false)` if the challenge is INVALID (the challenge is false/unfounded, reject the challenge).
    /// - `Err(MnemeError)` if verification encountered a structural/internal error.
    pub fn verify_challenge(&self, challenge: &WatcherChallenge) -> Result<bool, MnemeError> {
        // 1. Verify that the counterexample is NOT already in the claimed top-k set.
        if self.returned_ids.contains(&challenge.object_id) {
            return Ok(false);
        }

        // 2. Verify that the Merkle path matches the counterexample vector.
        let expected_commit = challenge.counterexample_vector.commit();
        let leaf_commit = hash_sem_leaf(challenge.object_id.as_bytes(), &expected_commit);

        if SemanticMerkleTree::verify_path_with_index(
            challenge.leaf_index,
            &leaf_commit,
            &challenge.merkle_path,
            &self.semantic_commit,
        )
        .is_err()
        {
            return Ok(false);
        }

        // 3. Recompute the quantized distance between the query and the counterexample vector.
        let dist = self
            .query
            .squared_l2_distance(&challenge.counterexample_vector)?;

        // 4. Compare with the claimed boundary distance d_k.
        // If dist < d_k, the counterexample is strictly closer than the k-th returned item,
        // proving the prover omitted a closer vector.
        if dist < self.d_k {
            Ok(true) // Prover lied!
        } else {
            Ok(false) // False challenge
        }
    }
}

// --- Wire Representations for Serde ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TopKClaimWire {
    pub query_dim: u32,
    pub query_scale: i8,
    pub query_components: Vec<i16>,
    pub d_k: i64,
    pub returned_ids: Vec<[u8; 32]>,
    pub semantic_commit: [u8; 32],
}

impl From<TopKClaim> for TopKClaimWire {
    fn from(claim: TopKClaim) -> Self {
        Self {
            query_dim: claim.query.dim,
            query_scale: claim.query.scale,
            query_components: claim.query.components,
            d_k: claim.d_k,
            returned_ids: claim.returned_ids.iter().map(|id| *id.as_bytes()).collect(),
            semantic_commit: claim.semantic_commit,
        }
    }
}

impl TryFrom<TopKClaimWire> for TopKClaim {
    type Error = MnemeError;

    fn try_from(wire: TopKClaimWire) -> Result<Self, Self::Error> {
        let query =
            FixedPointEmbedding::new(wire.query_dim, wire.query_scale, wire.query_components)?;
        let returned_ids = wire.returned_ids.into_iter().map(ObjectId).collect();
        Ok(Self {
            query,
            d_k: wire.d_k,
            returned_ids,
            semantic_commit: wire.semantic_commit,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WatcherChallengeWire {
    pub leaf_index: usize,
    pub vector_dim: u32,
    pub vector_scale: i8,
    pub vector_components: Vec<i16>,
    pub merkle_path: Vec<[u8; 32]>,
    pub object_id: [u8; 32],
}

impl From<WatcherChallenge> for WatcherChallengeWire {
    fn from(challenge: WatcherChallenge) -> Self {
        Self {
            leaf_index: challenge.leaf_index,
            vector_dim: challenge.counterexample_vector.dim,
            vector_scale: challenge.counterexample_vector.scale,
            vector_components: challenge.counterexample_vector.components,
            merkle_path: challenge.merkle_path,
            object_id: *challenge.object_id.as_bytes(),
        }
    }
}

impl TryFrom<WatcherChallengeWire> for WatcherChallenge {
    type Error = MnemeError;

    fn try_from(wire: WatcherChallengeWire) -> Result<Self, Self::Error> {
        let counterexample_vector =
            FixedPointEmbedding::new(wire.vector_dim, wire.vector_scale, wire.vector_components)?;
        Ok(Self {
            leaf_index: wire.leaf_index,
            counterexample_vector,
            merkle_path: wire.merkle_path,
            object_id: ObjectId(wire.object_id),
        })
    }
}
