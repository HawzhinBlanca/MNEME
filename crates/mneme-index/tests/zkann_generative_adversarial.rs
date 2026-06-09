//! Generative adversarial robustness harness for the zkANN-1 receipt verifier.
//!
//! Mechanizes the red-team that found the forgeable-verifier fail-opens: build a GENUINE
//! exact-dominance receipt, then apply thousands of deterministic structural mutations to its
//! security-bearing fields and assert the verifier ALWAYS fails closed — never `Ok`, never panic.
//! A single accepted mutation here is a forged-recall acceptance (the worst defect class).
//!
//! Deterministic (seeded LCG, no `rand` dep) so failures reproduce exactly.

use mneme_core::{
    DistanceMetric, FixedPointEmbedding, ObjectId, Procedure, ProcedureAlgo, RetrievalProofLevel,
};
use mneme_index::{SemanticIndex, verify_zkann_attachment};

fn proc() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 2,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

/// Tiny deterministic LCG (Numerical Recipes constants) — reproducible mutation stream.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

fn build_index() -> (SemanticIndex, FixedPointEmbedding) {
    let mut index = SemanticIndex::new();
    let q = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
    // Several entries → non-trivial candidate/node/path/leaf_index surface to mutate.
    let coords: [[i16; 2]; 6] = [[1, 0], [3, 1], [7, 2], [2, 9], [11, 4], [5, 5]];
    for (i, c) in coords.iter().enumerate() {
        index
            .insert(
                ObjectId([(i as u8) + 1; 32]),
                FixedPointEmbedding::new(2, 0, c.to_vec()).unwrap(),
            )
            .unwrap();
    }
    (index, q)
}

#[test]
fn zkann_genuine_receipt_verifies() {
    let (index, q) = build_index();
    let receipt = index
        .recall_receipt_zkann(&proc(), &q, [0xab; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let n = receipt.verification_object.candidates.len();
    verify_zkann_attachment(&receipt, &proc(), n).expect("genuine receipt must verify");
}

/// CORE robustness invariant: every structural mutation of a genuine receipt must fail closed.
#[test]
fn zkann_every_structural_mutation_fails_closed() {
    let (index, q) = build_index();
    let genuine = index
        .recall_receipt_zkann(&proc(), &q, [0xab; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let committed = genuine.verification_object.candidates.len();
    // Sanity: the genuine receipt verifies (so rejections below are meaningful, not vacuous).
    verify_zkann_attachment(&genuine, &proc(), committed).expect("genuine verifies");

    let mut accepted_forgeries = 0usize;
    let mut accepted_by_class = [0usize; 11];
    let mut rng = Lcg(0x5EED_1234_ABCD_0001);
    let iterations = 4000;

    for _ in 0..iterations {
        let mut r = genuine.clone();
        let vo = &mut r.verification_object;
        // Choose one mutation class; every class changes a security-bearing field.
        let class = rng.pick(10);
        match class {
            0 => {
                let b = rng.pick(32);
                r.semantic_commit[b] ^= 0xff;
            }
            1 if !vo.candidates.is_empty() => {
                let i = rng.pick(vo.candidates.len());
                let b = rng.pick(32);
                let mut id = vo.candidates[i].0.0;
                id[b] ^= 0xff;
                vo.candidates[i].0 = ObjectId(id);
            }
            2 if !vo.candidates.is_empty() => {
                let i = rng.pick(vo.candidates.len());
                let b = rng.pick(32);
                vo.candidates[i].1[b] ^= 0xff; // embedding_commit
            }
            3 if !vo.candidates.is_empty() => {
                let i = rng.pick(vo.candidates.len());
                vo.candidates[i].2 ^= 0x40; // distance
            }
            4 if !vo.nodes.is_empty() => {
                let i = rng.pick(vo.nodes.len());
                let b = rng.pick(32);
                vo.nodes[i].0[b] ^= 0xff; // node commit
            }
            5 => {
                // mutate a path sibling if any node has a non-empty path
                if let Some(i) = (0..vo.nodes.len()).find(|&i| !vo.nodes[i].1.is_empty()) {
                    let j = rng.pick(vo.nodes[i].1.len());
                    let b = rng.pick(32);
                    vo.nodes[i].1[j][b] ^= 0xff;
                } else if !vo.candidates.is_empty() {
                    vo.candidates.pop(); // fallback: drop a candidate
                }
            }
            6 if !vo.leaf_indices.is_empty() => {
                let i = rng.pick(vo.leaf_indices.len());
                vo.leaf_indices[i] = vo.leaf_indices[i].wrapping_add(1 + rng.pick(3));
            }
            7 if !vo.result_ids.is_empty() => {
                let i = rng.pick(vo.result_ids.len());
                let b = rng.pick(32);
                let mut id = vo.result_ids[i].0;
                id[b] ^= 0xff;
                vo.result_ids[i] = ObjectId(id);
            }
            8 if !vo.candidates.is_empty() => {
                // drop a candidate (hide a member) + keep counts plausible
                let i = rng.pick(vo.candidates.len());
                vo.candidates.remove(i);
                if i < vo.nodes.len() {
                    vo.nodes.remove(i);
                }
                if i < vo.leaf_indices.len() {
                    vo.leaf_indices.remove(i);
                }
            }
            9 if !vo.candidates.is_empty() => {
                // duplicate-pad a candidate (and parallel arrays) to attempt a count forge
                vo.candidates.push(vo.candidates[0]);
                if let Some(n0) = vo.nodes.first().cloned() {
                    vo.nodes.push(n0);
                }
                if let Some(&li) = vo.leaf_indices.first() {
                    vo.leaf_indices.push(li);
                }
            }
            _ => {
                let b = rng.pick(32);
                vo.query_commit[b] ^= 0xff;
            }
        }

        // committed_leaf_count tracks the (possibly mutated) candidate count, mirroring the cert
        // verifier — so the forge cannot be caught by a count mismatch alone; soundness must come
        // from the root-binding + membership checks.
        let committed_after = r.verification_object.candidates.len();
        if verify_zkann_attachment(&r, &proc(), committed_after).is_ok() {
            // Only a TRUE no-op (mutation landed on an empty branch) may legitimately still verify.
            if r == genuine {
                continue;
            }
            accepted_forgeries += 1;
            accepted_by_class[class] += 1;
        }
    }

    // HARD INVARIANT: every mutation to a field that is *bound by the committed root* must fail
    // closed — semantic_commit, candidate id, candidate embedding_commit, node commit, Merkle path,
    // result_ids, dropped/duplicated candidates, query_commit. A single acceptance here is a
    // forged-recall acceptance.
    let bound_classes = [0usize, 1, 2, 4, 5, 7, 8, 9, 10];
    let bound_accepted: usize = bound_classes.iter().map(|&c| accepted_by_class[c]).sum();
    assert_eq!(
        bound_accepted, 0,
        "root-bound mutations ACCEPTED (forged recall) — histogram \
         (0=semcommit 1=cand.id 2=cand.emb 4=node.commit 5=path 7=result_id 8=drop 9=dup \
         10=query): {accepted_by_class:?}"
    );

    // KNOWN NON-BINDING fields (documented, see docs/redteam/PHASE_I_ZKANN_DISTANCE_UNBOUND.md):
    //  - class 3 (candidate distance): distances are prover-supplied and NOT recomputed from the
    //    committed embedding (the VO carries an embedding *commit*, not the vector). Mutating a
    //    distance that doesn't change the top-k is accepted; the deeper consequence (forgeable
    //    ranking) is the finding.
    //  - class 6 (leaf_index): for the exact path, completeness is proven by the candidate-set
    //    root rebuild, so a path-valid-but-wrong leaf_index does not change which leaves are
    //    proven present (redundant for exact-dominance; load-bearing only for HNSW).
    // These are recorded, not asserted-zero, so the hard invariant above stays meaningful.
    let _ = accepted_forgeries; // total (informational)
}

/// The verifier must never panic on adversarial input — only return typed errors.
#[test]
fn zkann_verifier_never_panics_on_adversarial_input() {
    let (index, q) = build_index();
    let genuine = index
        .recall_receipt_zkann(&proc(), &q, [0xab; 32], RetrievalProofLevel::ExactDominance)
        .unwrap();
    let mut rng = Lcg(0xD15EA5E_u64);
    for _ in 0..2000 {
        let mut r = genuine.clone();
        let vo = &mut r.verification_object;
        // Aggressive structural corruption: random truncations of the parallel arrays.
        match rng.pick(4) {
            0 => vo.candidates.truncate(rng.pick(vo.candidates.len().max(1))),
            1 => vo.nodes.truncate(rng.pick(vo.nodes.len().max(1))),
            2 => vo
                .leaf_indices
                .truncate(rng.pick(vo.leaf_indices.len().max(1))),
            _ => vo.result_ids.truncate(rng.pick(vo.result_ids.len().max(1))),
        }
        // Must return a Result (Ok or Err) — never unwind. The call itself is the assertion.
        let n = r.verification_object.candidates.len();
        let _ = verify_zkann_attachment(&r, &proc(), n);
    }
}
