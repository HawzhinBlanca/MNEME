#![allow(non_snake_case)]
use mneme_topk_proof::{P, TopKProofError, TopKProver, TopKVerifier, add, mul, sub};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn quantize_vector(v_float: &[f64], scale: f64) -> Vec<u64> {
    v_float
        .iter()
        .map(|&x| (x * scale).round() as i64)
        .map(|x| {
            if x < 0 {
                sub(0, (-x) as u64)
            } else {
                x as u64 % P
            }
        })
        .collect()
}

#[test]
fn test_cryptographic_topk_proof_system() {
    let mut rng = StdRng::seed_from_u64(42);

    let n = 1024;
    let d = 16;
    let k = 10;
    let b = 30; // 30-bit range checking

    println!(
        "Generating honest test dataset: n={}, d={}, k={}...",
        n, d, k
    );
    let mut V_floats = vec![vec![0.0f64; d]; n];
    for i in 0..n {
        for j in 0..d {
            V_floats[i][j] = rng.gen_range(-1.0..1.0);
        }
    }

    let mut q_float = vec![0.0f64; d];
    for j in 0..d {
        q_float[j] = rng.gen_range(-1.0..1.0);
    }

    let scale = 1000.0;
    let V: Vec<Vec<u64>> = V_floats.iter().map(|v| quantize_vector(v, scale)).collect();
    let q = quantize_vector(&q_float, scale);

    let mut N = Vec::with_capacity(n);
    for i in 0..n {
        let mut sum_v = 0u64;
        for &x in &V[i] {
            sum_v = add(sum_v, mul(x, x));
        }
        N.push(sum_v);
    }

    let prover = TopKProver::new(V.clone(), q.clone(), k, b);
    let verifier = TopKVerifier::new(q.clone(), k, V.clone(), N.clone(), b);

    println!("Generating proof for honest run...");
    let proof = prover.generate_proof();

    println!("Verifying honest proof...");
    let verify_result = verifier.verify(&proof);
    assert!(
        verify_result.is_ok(),
        "Honest verification should have succeeded"
    );
    println!("Honest verification passed successfully!");

    // --- FORGERY TEST 1: Forgery by Omission ---
    println!("\n--- FORGERY TEST 1: Forgery by Omission ---");
    let mut V_forged = V.clone();

    let mut forged_index = 99;
    while proof.S_indices.contains(&forged_index) {
        forged_index += 1;
    }

    V_forged[forged_index] = q.clone(); // distance to query is exactly 0
    let mut N_forged = N.clone();
    let mut sum_v = 0u64;
    for &x in &V_forged[forged_index] {
        sum_v = add(sum_v, mul(x, x));
    }
    N_forged[forged_index] = sum_v;

    println!(
        "Planted forged closer vector at index {} (distance 0).",
        forged_index
    );
    println!("Verifying the original top-k proof against the modified dataset...");

    let forged_verifier = TopKVerifier::new(q.clone(), k, V_forged, N_forged, b);
    let forged_result = forged_verifier.verify(&proof);
    assert_eq!(
        forged_result.unwrap_err(),
        TopKProofError::NormsMismatch,
        "Verifier accepted a forged proof that omitted a closer vector!"
    );
    println!("Forgery 1 successfully caught and rejected!");

    // --- FORGERY TEST 2: Tie-Breaking Violation ---
    println!("\n--- FORGERY TEST 2: Tie-Breaking Violation ---");
    let mut V_tie = V.clone();

    // Force distance for indices 500 and 600 to be exactly 200^2 = 40000
    for &idx in &[500, 600] {
        V_tie[idx] = q.clone();
        V_tie[idx][0] = add(q[0], 200);
    }

    // Make the first k-1 vectors closer (distance < 40000)
    for i in 0..(k - 1) {
        V_tie[i] = q.clone();
        V_tie[i][0] = add(q[0], i as u64);
    }

    let mut N_tie = Vec::with_capacity(n);
    for i in 0..n {
        let mut sum_v = 0u64;
        for &x in &V_tie[i] {
            sum_v = add(sum_v, mul(x, x));
        }
        N_tie.push(sum_v);
    }

    let tie_prover = TopKProver::new(V_tie.clone(), q.clone(), k, b);
    let tie_proof_honest = tie_prover.generate_proof();
    assert!(tie_proof_honest.S_indices.contains(&500));
    assert!(!tie_proof_honest.S_indices.contains(&600));

    // Cheat: create a proof where S_indices contains 600 instead of 500
    println!(
        "Attempting to cheat by returning index 600 (larger index) instead of 500 (smaller index)..."
    );
    let mut fake_S_indices = tie_proof_honest.S_indices.clone();
    fake_S_indices.retain(|&x| x != 500);
    fake_S_indices.push(600);

    // Fabricate proof components corresponding to this cheat
    let mut fake_B = vec![0u64; n];
    for &idx in &fake_S_indices {
        fake_B[idx] = 1;
    }

    let mut D_tie = Vec::with_capacity(n);
    for i in 0..n {
        let mut dist_val = 0u64;
        for j in 0..d {
            let diff = sub(q[j], V_tie[i][j]);
            dist_val = add(dist_val, mul(diff, diff));
        }
        D_tie.push(dist_val);
    }

    let mut fake_slacks = Vec::with_capacity(n);
    let mut fake_bit_matrices = vec![vec![0u64; n]; b];
    for i in 0..n {
        let sl = if fake_B[i] == 1 {
            sub(40000, D_tie[i])
        } else {
            sub(sub(D_tie[i], 40000), 1)
        };
        fake_slacks.push(sl);

        let mut temp = sl;
        for j in 0..b {
            fake_bit_matrices[j][i] = temp & 1;
            temp >>= 1;
        }
    }

    let mut fake_P_vec = Vec::with_capacity(n);
    for i in 0..n {
        fake_P_vec.push(mul(fake_B[i], D_tie[i]));
    }

    let mut tr = mneme_topk_proof::Transcript::new("MNEME Top-K Proof");
    tr.absorb("dataset_n", &[n as u64]);
    tr.absorb("dataset_d", &[d as u64]);
    tr.absorb("k", &[k as u64]);
    tr.absorb("d_k", &[40000]);

    let fake_s_indices_u64: Vec<u64> = fake_S_indices.iter().map(|&x| x as u64).collect();
    tr.absorb("S_indices", &fake_s_indices_u64);

    let (proof_count, r_challenges) = mneme_topk_proof::prove_count_sumcheck(&fake_B, &mut tr);

    let alpha = tr.squeeze_challenge("batch_alpha");
    let mut v = 0;
    while (1 << v) < n {
        v += 1;
    }
    let mut z = Vec::with_capacity(v);
    for idx in 0..v {
        z.push(tr.squeeze_challenge(&format!("eq_z_{}", idx)));
    }

    let (proof_binary, bin_r_challenges) = mneme_topk_proof::prove_binary_check(
        &fake_bit_matrices,
        &fake_B,
        &D_tie,
        &fake_P_vec,
        alpha,
        &z,
        &mut tr,
    );

    let evals_r = mneme_topk_proof::EvalsAtR {
        B_r: mneme_topk_proof::evaluate_mle(&fake_B, &r_challenges),
        S_r: fake_bit_matrices
            .iter()
            .map(|m| mneme_topk_proof::evaluate_mle(m, &r_challenges))
            .collect(),
        N_r: mneme_topk_proof::evaluate_mle(&N_tie, &r_challenges),
        V_r: (0..d)
            .map(|j| {
                let col: Vec<u64> = (0..n).map(|i| V_tie[i][j]).collect();
                mneme_topk_proof::evaluate_mle(&col, &r_challenges)
            })
            .collect(),
        P_r: mneme_topk_proof::evaluate_mle(&fake_P_vec, &r_challenges),
    };

    let evals_r_prime = mneme_topk_proof::EvalsAtRPrime {
        S_r_prime: fake_bit_matrices
            .iter()
            .map(|m| mneme_topk_proof::evaluate_mle(m, &bin_r_challenges))
            .collect(),
        B_r_prime: mneme_topk_proof::evaluate_mle(&fake_B, &bin_r_challenges),
        D_r_prime: mneme_topk_proof::evaluate_mle(&D_tie, &bin_r_challenges),
        P_r_prime: mneme_topk_proof::evaluate_mle(&fake_P_vec, &bin_r_challenges),
    };

    let cheat_proof = mneme_topk_proof::TopKProof {
        d_k: 40000,
        S_indices: fake_S_indices,
        proof_count,
        proof_binary,
        evals_r,
        evals_r_prime,
    };

    let tie_verifier = TopKVerifier::new(q.clone(), k, V_tie, N_tie, b);
    let cheat_result = tie_verifier.verify(&cheat_proof);

    assert_eq!(
        cheat_result.unwrap_err(),
        TopKProofError::SlackCheckFailed,
        "Verifier accepted a proof violating index-order tie-breaking!"
    );
    println!("Forgery 2 successfully caught and rejected!");
    println!("--- ALL TESTS PASSED SUCCESSFULLY ---");
}
