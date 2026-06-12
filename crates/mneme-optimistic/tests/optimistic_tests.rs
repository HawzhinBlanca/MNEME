use mneme_core::{FixedPointEmbedding, ObjectId};
use mneme_index::SemanticMerkleTree;
use mneme_optimistic::{TopKClaim, WatcherChallenge};
use std::time::Instant;

#[test]
fn test_optimistic_verifier_and_watcher_challenges() {
    println!("--- TASK A OPTIMISTIC LAYER TEST ---");

    // 1. Setup Query and Dataset (n = 1000, d = 16, k = 10)
    let q = FixedPointEmbedding::new(16, 0, vec![0; 16]).unwrap();
    let n = 1000;
    let k = 10;

    let mut vectors = Vec::with_capacity(n);
    let mut key_ids = Vec::with_capacity(n);
    let mut entries = Vec::with_capacity(n);

    // Generate vectors with increasing distances
    for i in 0..n {
        let components = vec![i as i16; 16];
        let vec_i = FixedPointEmbedding::new(16, 0, components).unwrap();
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let object_id = ObjectId(key);

        let value = vec_i.commit();
        entries.push((object_id, value));

        vectors.push(vec_i);
        key_ids.push(object_id);
    }

    // Sort entries by ObjectId to match SemanticMerkleTree creation logic
    let mut sorted_entries = entries.clone();
    sorted_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let tree = SemanticMerkleTree::from_entries(&entries);
    let semantic_commit = tree.root();

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
        returned_ids.push(key_ids[idx]);
    }

    let honest_d_k = distances[k - 1].1;

    // Build the honest claim
    let honest_claim = TopKClaim {
        query: q.clone(),
        d_k: honest_d_k,
        returned_ids: returned_ids.clone(),
        semantic_commit,
    };

    // Find the leaf index of a sample in the sorted tree
    let sample_idx = distances[0].0;
    let sample_id = key_ids[sample_idx];
    let leaf_index = sorted_entries
        .iter()
        .position(|e| e.0 == sample_id)
        .unwrap();
    let merkle_path = tree.merkle_path(leaf_index).unwrap();

    // --- TEST 1: Honest Proof, Watcher challenge with a vector already in the top-k is rejected ---
    let false_challenge_already_in = WatcherChallenge {
        leaf_index,
        counterexample_vector: vectors[sample_idx].clone(),
        merkle_path: merkle_path.clone(),
        object_id: sample_id,
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
    let far_id = key_ids[far_idx];
    let far_leaf_index = sorted_entries.iter().position(|e| e.0 == far_id).unwrap();
    let far_merkle_path = tree.merkle_path(far_leaf_index).unwrap();

    let false_challenge_too_far = WatcherChallenge {
        leaf_index: far_leaf_index,
        counterexample_vector: vectors[far_idx].clone(),
        merkle_path: far_merkle_path,
        object_id: far_id,
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
    let omitted_idx = distances[0].0;
    let swapped_in_idx = distances[k].0;
    cheated_returned_ids[0] = key_ids[swapped_in_idx];

    let cheated_d_k = distances[k].1; // New boundary distance

    let cheated_claim = TopKClaim {
        query: q.clone(),
        d_k: cheated_d_k,
        returned_ids: cheated_returned_ids,
        semantic_commit,
    };

    // Watcher challenge: submit omitted_idx (distance 0 < cheated_d_k)
    let omitted_id = key_ids[omitted_idx];
    let omitted_leaf_index = sorted_entries
        .iter()
        .position(|e| e.0 == omitted_id)
        .unwrap();
    let omitted_merkle_path = tree.merkle_path(omitted_leaf_index).unwrap();

    let watcher_challenge = WatcherChallenge {
        leaf_index: omitted_leaf_index,
        counterexample_vector: vectors[omitted_idx].clone(),
        merkle_path: omitted_merkle_path.clone(),
        object_id: omitted_id,
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
    let expected_commit = vectors[omitted_idx].commit();
    let leaf_commit = mneme_index::hash_sem_leaf(omitted_id.as_bytes(), &expected_commit);
    let t1 = Instant::now();
    for _ in 0..iters {
        let _ = SemanticMerkleTree::verify_path_with_index(
            omitted_leaf_index,
            &leaf_commit,
            &omitted_merkle_path,
            &semantic_commit,
        )
        .unwrap();
    }
    let merkle_duration = t1.elapsed() / iters;

    // 3. Measure challenge object size
    let challenge_wire = mneme_optimistic::WatcherChallengeWire::from(watcher_challenge.clone());
    let challenge_bytes = serde_json::to_vec(&challenge_wire).unwrap();
    let size_bytes = challenge_bytes.len();
    let size_kb = size_bytes as f64 / 1024.0;

    let time_ratio = verifier_duration.as_nanos() as f64 / merkle_duration.as_nanos() as f64;

    println!(
        "Watcher challenge size: {:.2} KB ({} bytes)",
        size_kb, size_bytes
    );
    println!("Challenge verification time: {:?}", verifier_duration);
    println!("Single Merkle verify time: {:?}", merkle_duration);
    println!(
        "Verification time ratio (challenge / Merkle): {:.2}x",
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
