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

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_smt::SparseMerkleTree;

    // Deterministic xorshift — generative coverage without a rand dependency in unit tests.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    struct Fixture {
        tree: SparseMerkleTree,
        vectors: Vec<FixedPointEmbedding>,
        keys: Vec<[u8; 32]>,
        order: Vec<usize>, // indices sorted by ascending distance to query
        query: FixedPointEmbedding,
    }

    fn build(seed: u64, n: usize, dim: u32) -> Fixture {
        let mut st = seed;
        let query = FixedPointEmbedding::new(dim, 0, vec![0; dim as usize]).unwrap();
        let mut tree = SparseMerkleTree::new();
        let mut vectors = Vec::with_capacity(n);
        let mut keys = Vec::with_capacity(n);
        for i in 0..n {
            let components: Vec<i16> = (0..dim)
                .map(|_| (xorshift(&mut st) % 200) as i16 - 100)
                .collect();
            let v = FixedPointEmbedding::new(dim, 0, components).unwrap();
            let mut key = [0u8; 32];
            key[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            tree.upsert(key, v.commit());
            vectors.push(v);
            keys.push(key);
        }
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| query.squared_l2_distance(&vectors[i]).unwrap());
        Fixture {
            tree,
            vectors,
            keys,
            order,
            query,
        }
    }

    /// Soundness + completeness: an honest top-k claim is NEVER slashed by a
    /// non-closer challenge, and a claim that omits a genuinely-closer vector is
    /// ALWAYS caught. 120 randomized datasets.
    #[test]
    fn generative_watcher_soundness_and_completeness() {
        let k = 5;
        let mut st: u64 = 0x1234_5678_9abc_def1;
        for case in 0..120 {
            let n = 40 + (xorshift(&mut st) % 60) as usize;
            let f = build(xorshift(&mut st), n, 8);
            let smt_root = f.tree.root();
            let returned_ids: Vec<ObjectId> = f
                .order
                .iter()
                .take(k)
                .map(|&i| ObjectId(f.keys[i]))
                .collect();
            let d_k = f
                .query
                .squared_l2_distance(&f.vectors[f.order[k - 1]])
                .unwrap();
            let honest = TopKClaim {
                query: f.query.clone(),
                d_k,
                returned_ids: returned_ids.clone(),
                smt_root,
            };

            // (a) Honest claim: any vector OUTSIDE the returned set is not closer than
            // d_k by construction, so no challenge is ever accepted.
            for &i in f.order.iter().skip(k) {
                let proof = f.tree.prove_membership(f.keys[i]).unwrap();
                let ch = WatcherChallenge {
                    counterexample_key: f.keys[i],
                    counterexample_vector: f.vectors[i].clone(),
                    merkle_proof: proof,
                };
                assert!(
                    !honest.verify_challenge(&ch).unwrap(),
                    "case {case}: honest claim must not be slashed by a non-closer vector"
                );
            }

            // (b) Cheating claim: drop the closest entry. A watcher submitting the
            // omitted closest vector must slash it.
            if n > k + 1 {
                let omitted = f.order[0];
                let mut cheated_ids = returned_ids.clone();
                cheated_ids[0] = ObjectId(f.keys[f.order[k]]);
                let cheated = TopKClaim {
                    query: f.query.clone(),
                    d_k: f.query.squared_l2_distance(&f.vectors[f.order[k]]).unwrap(),
                    returned_ids: cheated_ids,
                    smt_root,
                };
                let proof = f.tree.prove_membership(f.keys[omitted]).unwrap();
                let ch = WatcherChallenge {
                    counterexample_key: f.keys[omitted],
                    counterexample_vector: f.vectors[omitted].clone(),
                    merkle_proof: proof,
                };
                assert!(
                    cheated.verify_challenge(&ch).unwrap(),
                    "case {case}: omission of the closest vector must be caught and slashed"
                );
            }
        }
    }

    /// A challenge whose carried vector does not match the committed Merkle leaf is
    /// rejected — a watcher cannot fabricate a closer vector that isn't in the set.
    #[test]
    fn forged_counterexample_not_in_commitment_is_rejected() {
        let f = build(0xabcd, 50, 8);
        let smt_root = f.tree.root();
        let returned_ids: Vec<ObjectId> = f
            .order
            .iter()
            .take(5)
            .map(|&i| ObjectId(f.keys[i]))
            .collect();
        let d_k = f.query.squared_l2_distance(&f.vectors[f.order[4]]).unwrap();
        let claim = TopKClaim {
            query: f.query.clone(),
            d_k,
            returned_ids,
            smt_root,
        };
        // Real membership proof for a far key, but swap in a forged vector equal to the
        // query (distance 0). value != commit ⇒ rejected before the distance check.
        let victim = f.order[10];
        let proof = f.tree.prove_membership(f.keys[victim]).unwrap();
        let forged = FixedPointEmbedding::new(8, 0, vec![0; 8]).unwrap();
        let ch = WatcherChallenge {
            counterexample_key: f.keys[victim],
            counterexample_vector: forged,
            merkle_proof: proof,
        };
        assert!(
            !claim.verify_challenge(&ch).unwrap(),
            "a counterexample whose vector is not the committed leaf must be rejected"
        );
    }
}
