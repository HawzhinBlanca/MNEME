use mneme_core::{FixedPointEmbedding, ObjectId};
use mneme_optimistic::{TopKClaim, WatcherChallenge};
use mneme_smt::SparseMerkleTree;
use std::time::Instant;

#[test]
fn test_optimistic_verifier_and_watcher_challenges() {
    println!("--- TASK A OPTIMISTIC LAYER TEST ---");

    // 1. Setup Query and Dataset (n = 1000, d = 16, k = 10)
    let q = FixedPointEmbedding::new(16, 0, vec![0; 16]).unwrap();
    let n = 1000;
    let k = 10;

    let mut tree = SparseMerkleTree::new();
    let mut vectors = Vec::with_capacity(n);
    let mut key_ids = Vec::with_capacity(n);

    // Generate vectors with increasing distances
    for i in 0..n {
        let components = vec![i as i16; 16];
        let vec_i = FixedPointEmbedding::new(16, 0, components).unwrap();
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&(i as u64).to_le_bytes());

        // Value in SMT is the commit of the vector
        let value = vec_i.commit();
        tree.upsert(key, value);

        vectors.push(vec_i);
        key_ids.push(key);
    }

    let smt_root = tree.root();

    // Compute distances to query
    let mut distances: Vec<(usize, i64)> = vectors
        .iter()
        .enumerate()
        .map(|(i, v)| (i, q.squared_l2_distance(v).unwrap()))
        .collect();

    // Sort by distance (ascending)
    distances.sort_by_key(|&(_, d)| d);

    // Get the honest top-k results
    let mut returned_ids = Vec::new();
    for i in 0..k {
        let idx = distances[i].0;
        returned_ids.push(ObjectId(key_ids[idx]));
    }

    let honest_d_k = distances[k - 1].1;

    // Build the honest claim
    let honest_claim = TopKClaim {
        query: q.clone(),
        d_k: honest_d_k,
        returned_ids: returned_ids.clone(),
        smt_root,
    };

    // --- TEST 1: Honest Proof, Watcher challenge with a vector already in the top-k is rejected ---
    let sample_idx = distances[0].0;
    let sample_proof = tree.prove_membership(key_ids[sample_idx]).unwrap();
    let false_challenge_already_in = WatcherChallenge {
        counterexample_key: key_ids[sample_idx],
        counterexample_vector: vectors[sample_idx].clone(),
        merkle_proof: sample_proof.clone(),
    };
    let outcome = honest_claim
        .verify_challenge(&false_challenge_already_in)
        .unwrap();
    assert!(
        !outcome,
        "False challenge containing already returned element must be rejected"
    );

    // --- TEST 2: Watcher challenge with a vector outside top-k but not closer is rejected ---
    let far_idx = distances[k + 5].0;
    let far_proof = tree.prove_membership(key_ids[far_idx]).unwrap();
    let false_challenge_too_far = WatcherChallenge {
        counterexample_key: key_ids[far_idx],
        counterexample_vector: vectors[far_idx].clone(),
        merkle_proof: far_proof,
    };
    let outcome = honest_claim
        .verify_challenge(&false_challenge_too_far)
        .unwrap();
    assert!(
        !outcome,
        "False challenge with vector not closer than d_k must be rejected"
    );

    // --- TEST 3: Forgery by Omission (Prover cheats) ---
    // Prover omits the closest vector (index 0) from the returned set and returns index k instead.
    let mut cheated_returned_ids = returned_ids.clone();
    // Swap index 0 (closest) with index k (further away)
    let omitted_idx = distances[0].0;
    let swapped_in_idx = distances[k].0;
    cheated_returned_ids[0] = ObjectId(key_ids[swapped_in_idx]);

    let cheated_d_k = distances[k].1; // New boundary distance

    let cheated_claim = TopKClaim {
        query: q.clone(),
        d_k: cheated_d_k,
        returned_ids: cheated_returned_ids,
        smt_root,
    };

    // Watcher challenge: submit omitted_idx (distance 0 < cheated_d_k)
    let omitted_proof = tree.prove_membership(key_ids[omitted_idx]).unwrap();
    let watcher_challenge = WatcherChallenge {
        counterexample_key: key_ids[omitted_idx],
        counterexample_vector: vectors[omitted_idx].clone(),
        merkle_proof: omitted_proof.clone(),
    };

    let outcome = cheated_claim.verify_challenge(&watcher_challenge).unwrap();
    assert!(
        outcome,
        "Cheat detected! Watcher challenge MUST succeed and slash the prover."
    );
    println!("Forgery/omission successfully caught and slashed!");

    // --- BENCHMARK AND MEASUREMENTS ---
    // 1. Measure challenge verify time
    let iters = 1000;
    let t0 = Instant::now();
    for _ in 0..iters {
        let _ = cheated_claim.verify_challenge(&watcher_challenge).unwrap();
    }
    let verifier_duration = t0.elapsed() / iters;

    // 2. Measure raw Merkle-path verify time
    let t1 = Instant::now();
    for _ in 0..iters {
        let _ = SparseMerkleTree::verify_membership(&omitted_proof).unwrap();
    }
    let merkle_duration = t1.elapsed() / iters;

    // 3. Measure challenge object size
    // Since we don't have ciborium/serde derive implemented for all types of SMT directly,
    // let's estimate size by summing up fields:
    // counterexample_key: 32 bytes
    // counterexample_vector: 4 (dim) + 1 (scale) + 16*2 (components) = 37 bytes
    // merkle_proof: 32 (key) + 32 (value) + 256*32 (path) + 32 (root) + 8 (leaf_index) = 8320 bytes
    // Total estimated raw bytes = 8389 bytes ~ 8.19 KB
    // Let's compute actual size using a manual byte packing representation:
    let mut challenge_bytes = Vec::new();
    challenge_bytes.extend_from_slice(&watcher_challenge.counterexample_key);
    challenge_bytes.extend_from_slice(&watcher_challenge.counterexample_vector.to_bytes());
    challenge_bytes.extend_from_slice(&watcher_challenge.merkle_proof.key);
    challenge_bytes.extend_from_slice(&watcher_challenge.merkle_proof.value);
    for p in &watcher_challenge.merkle_proof.path {
        challenge_bytes.extend_from_slice(p);
    }
    challenge_bytes.extend_from_slice(&watcher_challenge.merkle_proof.root);
    challenge_bytes
        .extend_from_slice(&(watcher_challenge.merkle_proof.leaf_index as u64).to_le_bytes());

    let size_bytes = challenge_bytes.len();
    let size_kb = size_bytes as f64 / 1024.0;

    let time_ratio = verifier_duration.as_nanos() as f64 / merkle_duration.as_nanos() as f64;

    println!(
        "Watcher challenge size: {:.2} KB ({} bytes)",
        size_kb, size_bytes
    );
    println!("Challenge verification time: {:?}", verifier_duration);
    println!("Single SMT verify time: {:?}", merkle_duration);
    println!(
        "Verification time ratio (challenge / SMT): {:.2}x",
        time_ratio
    );

    // Assert targets
    assert!(
        size_kb <= 10.0,
        "Challenge object size target MISSED (>10 KB)"
    );
    assert!(
        time_ratio <= 10.0,
        "Challenge verification latency target MISSED (>10x SMT verify)"
    );
    println!("All Task A targets MET successfully!");
}
