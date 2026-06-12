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
use mneme_smt::{MembershipProof, SparseMerkleTree};

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
    /// The signed SMT root committing to all vectors in the dataset.
    pub smt_root: [u8; 32],
}

/// A fraud proof submitted by a watcher challenging a prover's claim.
#[derive(Debug, Clone)]
pub struct WatcherChallenge {
    /// The key of the counterexample vector in the SMT.
    pub counterexample_key: [u8; 32],
    /// The counterexample vector.
    pub counterexample_vector: FixedPointEmbedding,
    /// The SMT membership proof showing the counterexample vector's commit is committed.
    pub merkle_proof: MembershipProof,
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
        let counter_id = ObjectId(challenge.counterexample_key);
        if self.returned_ids.contains(&counter_id) {
            return Ok(false);
        }

        // 2. Verify that the Merkle proof matches the counterexample vector.
        let expected_commit = challenge.counterexample_vector.commit();
        if challenge.merkle_proof.value != expected_commit {
            return Ok(false);
        }
        if challenge.merkle_proof.root != self.smt_root {
            return Ok(false);
        }
        if challenge.merkle_proof.key != challenge.counterexample_key {
            return Ok(false);
        }

        // Verify the SMT membership proof.
        if SparseMerkleTree::verify_membership(&challenge.merkle_proof).is_err() {
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
