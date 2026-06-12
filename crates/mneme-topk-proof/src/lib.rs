#![allow(non_snake_case)]
//! Count-sum-check cryptographic layer top-k proof system for MNEME (Task B Rust translation).

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Goldilocks Prime p = 2^64 - 2^32 + 1
pub const P: u64 = 0xffffffff00000001;

/// Closed error enum for the cryptographic top-k proof system
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TopKProofError {
    #[error("count sumcheck verification failed")]
    CountSumcheckFailed,
    #[error("binary check sumcheck verification failed")]
    BinaryCheckFailed,
    #[error("evaluation mismatch for B_r")]
    EvaluationMismatchBr,
    #[error("evaluation mismatch for sum_check_final")]
    EvaluationMismatchFinal,
    #[error("simulated PCS evaluation check of committed Norms at r failed")]
    NormsMismatch,
    #[error("simulated PCS evaluation check of committed Vector dataset at r failed")]
    VectorMismatch,
    #[error("slack relation check failed at point r")]
    SlackCheckFailed,
    #[error("invalid index set size")]
    InvalidIndexSetSize,
}

// --- Field Arithmetic ---

#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % P as u128) as u64
}

#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    ((P as u128 + a as u128 - b as u128) % P as u128) as u64
}

#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P as u128) as u64
}

pub fn exp(base: u64, exponent: u64) -> u64 {
    let mut res = 1u64;
    let mut base = base % P;
    let mut exp = exponent;
    while exp > 0 {
        if exp % 2 == 1 {
            res = mul(res, base);
        }
        base = mul(base, base);
        exp /= 2;
    }
    res
}

pub fn inv(a: u64) -> u64 {
    assert!(a != 0, "division by zero");
    exp(a, P - 2)
}

// --- Fiat-Shamir Transcript ---

pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    pub fn new(label: &str) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(label.as_bytes());
        Self {
            state: hasher.finalize().into(),
        }
    }

    pub fn absorb(&mut self, label: &str, data: &[u64]) {
        let mut hasher = Hasher::new();
        hasher.update(&self.state);
        hasher.update(label.as_bytes());
        for &val in data {
            hasher.update(&val.to_le_bytes());
        }
        self.state = hasher.finalize().into();
    }

    pub fn squeeze_challenge(&mut self, label: &str) -> u64 {
        let mut hasher = Hasher::new();
        hasher.update(&self.state);
        hasher.update(label.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        self.state = digest;
        let val = u64::from_le_bytes(digest[0..8].try_into().unwrap());
        val % P
    }
}

// --- Multilinear Extension (MLE) Evaluation ---

pub fn evaluate_mle(evals: &[u64], r: &[u64]) -> u64 {
    let v = r.len();
    assert_eq!(evals.len(), 1 << v);
    let mut current = evals.to_vec();
    for &r_j in r {
        let next_len = current.len() / 2;
        let mut next_vec = vec![0u64; next_len];
        for i in 0..next_len {
            next_vec[i] = add(
                mul(sub(1, r_j), current[2 * i]),
                mul(r_j, current[2 * i + 1]),
            );
        }
        current = next_vec;
    }
    current[0]
}

pub fn evaluate_eq_generator(y: &[u64]) -> Vec<u64> {
    let mut evals = vec![1u64];
    for &y_j in y {
        let mut next_evals = Vec::with_capacity(evals.len() * 2);
        for &val in &evals {
            next_evals.push(mul(val, sub(1, y_j)));
            next_evals.push(mul(val, y_j));
        }
        evals = next_evals;
    }
    evals
}

pub fn interpolate_deg3(evals_at_0123: &[u64; 4], r: u64) -> u64 {
    let y0 = evals_at_0123[0];
    let y1 = evals_at_0123[1];
    let y2 = evals_at_0123[2];
    let y3 = evals_at_0123[3];

    let r_sub_1 = sub(r, 1);
    let r_sub_2 = sub(r, 2);
    let r_sub_3 = sub(r, 3);

    let inv_6 = inv(6);
    let inv_2 = inv(2);

    let l0 = mul(sub(0, inv_6), mul(r_sub_1, mul(r_sub_2, r_sub_3)));
    let l1 = mul(inv_2, mul(r, mul(r_sub_2, r_sub_3)));
    let l2 = mul(sub(0, inv_2), mul(r, mul(r_sub_1, r_sub_3)));
    let l3 = mul(inv_6, mul(r, mul(r_sub_1, r_sub_2)));

    let mut ans = add(mul(y0, l0), mul(y1, l1));
    ans = add(ans, mul(y2, l2));
    ans = add(ans, mul(y3, l3));
    ans
}

// --- Sum-Check Transcriptions ---

pub fn prove_count_sumcheck(
    evals: &[u64],
    transcript: &mut Transcript,
) -> (Vec<(u64, u64)>, Vec<u64>) {
    let mut v = 0;
    while (1 << v) < evals.len() {
        v += 1;
    }
    assert_eq!(evals.len(), 1 << v);

    let mut current = evals.to_vec();
    let mut proof_rounds = Vec::new();
    let mut r_challenges = Vec::new();

    for round_idx in 0..v {
        let next_len = current.len() / 2;
        let mut g_0 = 0;
        for i in 0..next_len {
            g_0 = add(g_0, current[2 * i]);
        }
        let mut g_1 = 0;
        for i in 0..next_len {
            g_1 = add(g_1, current[2 * i + 1]);
        }

        proof_rounds.push((g_0, g_1));
        transcript.absorb(&format!("round_{}", round_idx), &[g_0, g_1]);

        let r_j = transcript.squeeze_challenge(&format!("challenge_{}", round_idx));
        r_challenges.push(r_j);

        let mut next_vec = vec![0u64; next_len];
        for i in 0..next_len {
            next_vec[i] = add(
                mul(sub(1, r_j), current[2 * i]),
                mul(r_j, current[2 * i + 1]),
            );
        }
        current = next_vec;
    }

    (proof_rounds, r_challenges)
}

pub fn verify_count_sumcheck(
    claimed_sum: u64,
    proof_rounds: &[(u64, u64)],
    r_challenges: &[u64],
) -> Result<u64, TopKProofError> {
    let v = proof_rounds.len();
    if r_challenges.len() != v {
        return Err(TopKProofError::CountSumcheckFailed);
    }

    let mut expected_sum = claimed_sum;
    for round_idx in 0..v {
        let (g_0, g_1) = proof_rounds[round_idx];
        if add(g_0, g_1) != expected_sum {
            return Err(TopKProofError::CountSumcheckFailed);
        }
        let r_j = r_challenges[round_idx];
        expected_sum = add(mul(sub(1, r_j), g_0), mul(r_j, g_1));
    }
    Ok(expected_sum)
}

pub fn prove_binary_check(
    bit_matrices: &[Vec<u64>],
    B: &[u64],
    D: &[u64],
    P_vec: &[u64],
    alpha: u64,
    z: &[u64],
    transcript: &mut Transcript,
) -> (Vec<[u64; 4]>, Vec<u64>) {
    let b_bits = bit_matrices.len();
    let v = z.len();

    let eq_evals = evaluate_eq_generator(z);

    let mut proof_rounds = Vec::new();
    let mut r_challenges = Vec::new();

    let mut current_S = bit_matrices.to_vec();
    let mut current_B = B.to_vec();
    let mut current_D = D.to_vec();
    let mut current_P = P_vec.to_vec();
    let mut current_eq = eq_evals;

    for round_idx in 0..v {
        let next_len = 1 << (v - 1 - round_idx);
        let mut g_evals = [0u64; 4];

        for t_idx in 0..4 {
            let t = t_idx as u64;
            let mut sum_t = 0u64;

            for i in 0..next_len {
                let eq_val = add(
                    mul(sub(1, t), current_eq[2 * i]),
                    mul(t, current_eq[2 * i + 1]),
                );

                let mut term = 0u64;
                for j in 0..b_bits {
                    let s_0 = current_S[j][2 * i];
                    let s_1 = current_S[j][2 * i + 1];
                    let s_t = add(mul(sub(1, t), s_0), mul(t, s_1));
                    let s_t_sq_minus_s = mul(s_t, sub(s_t, 1));
                    let alpha_pow = exp(alpha, j as u64);
                    term = add(term, mul(alpha_pow, s_t_sq_minus_s));
                }

                let b_0 = current_B[2 * i];
                let b_1 = current_B[2 * i + 1];
                let b_t = add(mul(sub(1, t), b_0), mul(t, b_1));

                let d_0 = current_D[2 * i];
                let d_1 = current_D[2 * i + 1];
                let d_t = add(mul(sub(1, t), d_0), mul(t, d_1));

                let p_0 = current_P[2 * i];
                let p_1 = current_P[2 * i + 1];
                let p_t = add(mul(sub(1, t), p_0), mul(t, p_1));

                let prod_term = sub(p_t, mul(b_t, d_t));
                let alpha_pow_b = exp(alpha, b_bits as u64);
                term = add(term, mul(alpha_pow_b, prod_term));

                sum_t = add(sum_t, mul(term, eq_val));
            }
            g_evals[t_idx] = sum_t;
        }

        proof_rounds.push(g_evals);
        transcript.absorb(&format!("bin_round_{}", round_idx), &g_evals);

        let r_j = transcript.squeeze_challenge(&format!("bin_challenge_{}", round_idx));
        r_challenges.push(r_j);

        let mut next_eq = vec![0u64; next_len];
        for i in 0..next_len {
            next_eq[i] = add(
                mul(sub(1, r_j), current_eq[2 * i]),
                mul(r_j, current_eq[2 * i + 1]),
            );
        }
        current_eq = next_eq;

        for j in 0..b_bits {
            let mut next_S_j = vec![0u64; next_len];
            for i in 0..next_len {
                next_S_j[i] = add(
                    mul(sub(1, r_j), current_S[j][2 * i]),
                    mul(r_j, current_S[j][2 * i + 1]),
                );
            }
            current_S[j] = next_S_j;
        }

        let mut next_B = vec![0u64; next_len];
        for i in 0..next_len {
            next_B[i] = add(
                mul(sub(1, r_j), current_B[2 * i]),
                mul(r_j, current_B[2 * i + 1]),
            );
        }
        current_B = next_B;

        let mut next_D = vec![0u64; next_len];
        for i in 0..next_len {
            next_D[i] = add(
                mul(sub(1, r_j), current_D[2 * i]),
                mul(r_j, current_D[2 * i + 1]),
            );
        }
        current_D = next_D;

        let mut next_P = vec![0u64; next_len];
        for i in 0..next_len {
            next_P[i] = add(
                mul(sub(1, r_j), current_P[2 * i]),
                mul(r_j, current_P[2 * i + 1]),
            );
        }
        current_P = next_P;
    }

    (proof_rounds, r_challenges)
}

pub fn verify_binary_check(
    proof_rounds: &[[u64; 4]],
    r_challenges: &[u64],
) -> Result<u64, TopKProofError> {
    let v = proof_rounds.len();
    if r_challenges.len() != v {
        return Err(TopKProofError::BinaryCheckFailed);
    }

    let mut expected_sum = 0u64;
    for round_idx in 0..v {
        let g_evals = &proof_rounds[round_idx];
        if add(g_evals[0], g_evals[1]) != expected_sum {
            return Err(TopKProofError::BinaryCheckFailed);
        }
        let r_j = r_challenges[round_idx];
        expected_sum = interpolate_deg3(g_evals, r_j);
    }
    Ok(expected_sum)
}

// --- Serialized Structures ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvalsAtR {
    pub B_r: u64,
    pub S_r: Vec<u64>,
    pub N_r: u64,
    pub V_r: Vec<u64>,
    pub P_r: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvalsAtRPrime {
    pub S_r_prime: Vec<u64>,
    pub B_r_prime: u64,
    pub D_r_prime: u64,
    pub P_r_prime: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TopKProof {
    pub d_k: u64,
    pub S_indices: Vec<usize>,
    pub proof_count: Vec<(u64, u64)>,
    pub proof_binary: Vec<[u64; 4]>,
    pub evals_r: EvalsAtR,
    pub evals_r_prime: EvalsAtRPrime,
}

// --- Prover and Verifier Drivers ---

pub struct TopKProver {
    pub V: Vec<Vec<u64>>,
    pub q: Vec<u64>,
    pub k: usize,
    pub b: usize,
}

impl TopKProver {
    pub fn new(V: Vec<Vec<u64>>, q: Vec<u64>, k: usize, b: usize) -> Self {
        Self { V, q, k, b }
    }

    pub fn generate_proof(&self) -> TopKProof {
        let n = self.V.len();
        let d = self.q.len();
        let mut v = 0;
        while (1 << v) < n {
            v += 1;
        }
        assert_eq!(n, 1 << v);

        let mut N = Vec::with_capacity(n);
        for i in 0..n {
            let mut sum_v = 0u64;
            for &x in &self.V[i] {
                sum_v = add(sum_v, mul(x, x));
            }
            N.push(sum_v);
        }

        let mut D = Vec::with_capacity(n);
        for i in 0..n {
            let mut dist_val = 0u64;
            for j in 0..d {
                let diff = sub(self.q[j], self.V[i][j]);
                dist_val = add(dist_val, mul(diff, diff));
            }
            D.push(dist_val);
        }

        let mut indexed_distances: Vec<(usize, u64)> = D.iter().copied().enumerate().collect();
        indexed_distances.sort_by(|x, y| match x.1.cmp(&y.1) {
            std::cmp::Ordering::Equal => x.0.cmp(&y.0),
            other => other,
        });

        let S_indices: Vec<usize> = indexed_distances.iter().take(self.k).map(|x| x.0).collect();
        let d_k = indexed_distances[self.k - 1].1;

        let mut B = vec![0u64; n];
        for &idx in &S_indices {
            B[idx] = 1;
        }

        let mut slacks = Vec::with_capacity(n);
        let mut bit_matrices = vec![vec![0u64; n]; self.b];
        for i in 0..n {
            let sl = if B[i] == 1 {
                sub(d_k, D[i])
            } else {
                sub(sub(D[i], d_k), 1)
            };
            slacks.push(sl);

            let mut temp = sl;
            for j in 0..self.b {
                bit_matrices[j][i] = temp & 1;
                temp >>= 1;
            }
        }

        let mut P_vec = Vec::with_capacity(n);
        for i in 0..n {
            P_vec.push(mul(B[i], D[i]));
        }

        let mut tr = Transcript::new("MNEME Top-K Proof");
        tr.absorb("dataset_n", &[n as u64]);
        tr.absorb("dataset_d", &[d as u64]);
        tr.absorb("k", &[self.k as u64]);
        tr.absorb("d_k", &[d_k]);

        let s_indices_u64: Vec<u64> = S_indices.iter().map(|&x| x as u64).collect();
        tr.absorb("S_indices", &s_indices_u64);

        let (proof_count, r_challenges) = prove_count_sumcheck(&B, &mut tr);

        let alpha = tr.squeeze_challenge("batch_alpha");
        let mut z = Vec::with_capacity(v);
        for idx in 0..v {
            z.push(tr.squeeze_challenge(&format!("eq_z_{}", idx)));
        }

        let (proof_binary, bin_r_challenges) =
            prove_binary_check(&bit_matrices, &B, &D, &P_vec, alpha, &z, &mut tr);

        let evals_r = EvalsAtR {
            B_r: evaluate_mle(&B, &r_challenges),
            S_r: bit_matrices
                .iter()
                .map(|m| evaluate_mle(m, &r_challenges))
                .collect(),
            N_r: evaluate_mle(&N, &r_challenges),
            V_r: (0..d)
                .map(|j| {
                    let col: Vec<u64> = (0..n).map(|i| self.V[i][j]).collect();
                    evaluate_mle(&col, &r_challenges)
                })
                .collect(),
            P_r: evaluate_mle(&P_vec, &r_challenges),
        };

        let evals_r_prime = EvalsAtRPrime {
            S_r_prime: bit_matrices
                .iter()
                .map(|m| evaluate_mle(m, &bin_r_challenges))
                .collect(),
            B_r_prime: evaluate_mle(&B, &bin_r_challenges),
            D_r_prime: evaluate_mle(&D, &bin_r_challenges),
            P_r_prime: evaluate_mle(&P_vec, &bin_r_challenges),
        };

        TopKProof {
            d_k,
            S_indices,
            proof_count,
            proof_binary,
            evals_r,
            evals_r_prime,
        }
    }
}

pub struct TopKVerifier {
    pub q: Vec<u64>,
    pub k: usize,
    pub committed_V: Vec<Vec<u64>>,
    pub committed_N: Vec<u64>,
    pub b: usize,
}

impl TopKVerifier {
    pub fn new(
        q: Vec<u64>,
        k: usize,
        committed_V: Vec<Vec<u64>>,
        committed_N: Vec<u64>,
        b: usize,
    ) -> Self {
        Self {
            q,
            k,
            committed_V,
            committed_N,
            b,
        }
    }

    pub fn verify(&self, proof: &TopKProof) -> Result<(), TopKProofError> {
        let n = self.committed_V.len();
        let d = self.q.len();
        let mut v = 0;
        while (1 << v) < n {
            v += 1;
        }

        if proof.S_indices.len() != self.k {
            return Err(TopKProofError::InvalidIndexSetSize);
        }

        let mut tr = Transcript::new("MNEME Top-K Proof");
        tr.absorb("dataset_n", &[n as u64]);
        tr.absorb("dataset_d", &[d as u64]);
        tr.absorb("k", &[self.k as u64]);
        tr.absorb("d_k", &[proof.d_k]);

        let s_indices_u64: Vec<u64> = proof.S_indices.iter().map(|&x| x as u64).collect();
        tr.absorb("S_indices", &s_indices_u64);

        let mut r_challenges = Vec::new();
        for round_idx in 0..v {
            let (g_0, g_1) = proof.proof_count[round_idx];
            tr.absorb(&format!("round_{}", round_idx), &[g_0, g_1]);
            let r_j = tr.squeeze_challenge(&format!("challenge_{}", round_idx));
            r_challenges.push(r_j);
        }

        let expected_B_r = verify_count_sumcheck(self.k as u64, &proof.proof_count, &r_challenges)?;
        if proof.evals_r.B_r != expected_B_r {
            return Err(TopKProofError::EvaluationMismatchBr);
        }

        let alpha = tr.squeeze_challenge("batch_alpha");
        let mut z = Vec::with_capacity(v);
        for idx in 0..v {
            z.push(tr.squeeze_challenge(&format!("eq_z_{}", idx)));
        }

        let mut bin_r_challenges = Vec::new();
        for round_idx in 0..v {
            let g_evals = &proof.proof_binary[round_idx];
            tr.absorb(&format!("bin_round_{}", round_idx), g_evals);
            let r_j = tr.squeeze_challenge(&format!("bin_challenge_{}", round_idx));
            bin_r_challenges.push(r_j);
        }

        let expected_sum_r_prime = verify_binary_check(&proof.proof_binary, &bin_r_challenges)?;

        let eq_r_prime = evaluate_mle(&evaluate_eq_generator(&z), &bin_r_challenges);

        let mut term_r_prime = 0u64;
        for j in 0..self.b {
            let s_val = proof.evals_r_prime.S_r_prime[j];
            let s_term = mul(s_val, sub(s_val, 1));
            let alpha_pow = exp(alpha, j as u64);
            term_r_prime = add(term_r_prime, mul(alpha_pow, s_term));
        }

        let prod_term_r_prime = sub(
            proof.evals_r_prime.P_r_prime,
            mul(proof.evals_r_prime.B_r_prime, proof.evals_r_prime.D_r_prime),
        );
        let alpha_pow_b = exp(alpha, self.b as u64);
        term_r_prime = add(term_r_prime, mul(alpha_pow_b, prod_term_r_prime));

        let expected_sum_check_final = mul(term_r_prime, eq_r_prime);
        if expected_sum_r_prime != expected_sum_check_final {
            return Err(TopKProofError::EvaluationMismatchFinal);
        }

        let q_norm = self.q.iter().map(|&x| mul(x, x)).fold(0u64, add);

        let expected_N_r = evaluate_mle(&self.committed_N, &r_challenges);
        if proof.evals_r.N_r != expected_N_r {
            return Err(TopKProofError::NormsMismatch);
        }

        for j in 0..d {
            let col: Vec<u64> = (0..n).map(|i| self.committed_V[i][j]).collect();
            let expected_V_r_j = evaluate_mle(&col, &r_challenges);
            if proof.evals_r.V_r[j] != expected_V_r_j {
                return Err(TopKProofError::VectorMismatch);
            }
        }

        let mut IP_r = 0u64;
        for j in 0..d {
            IP_r = add(IP_r, mul(self.q[j], proof.evals_r.V_r[j]));
        }
        let D_r = add(q_norm, sub(proof.evals_r.N_r, mul(2, IP_r)));

        let mut Slack_r = 0u64;
        for j in 0..self.b {
            Slack_r = add(Slack_r, mul(proof.evals_r.S_r[j], exp(2, j as u64)));
        }

        let expected_Slack_r = sub(
            add(mul(add(mul(2, proof.d_k), 1), proof.evals_r.B_r), D_r),
            add(mul(2, proof.evals_r.P_r), add(proof.d_k, 1)),
        );

        if Slack_r != expected_Slack_r {
            return Err(TopKProofError::SlackCheckFailed);
        }

        Ok(())
    }
}
