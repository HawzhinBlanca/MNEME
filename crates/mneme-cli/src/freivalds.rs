//! ROBR-3 — Freivalds spot-check for logged matmuls.
//!
//! For a claimed matrix product `C = A·B`, Freivalds' algorithm verifies the claim in
//! O(n²) instead of recomputing in O(mnk): pick a random 0/1 vector `r` and check
//! `A·(B·r) == C·r`. If `C ≠ A·B`, a single round accepts with probability ≤ ½, so
//! `t` independent rounds bound the false-accept probability by `2^-t`.
//!
//! The challenge vectors are derived by Fiat–Shamir from a commitment to `(shape, A,
//! B, C)`, so the check is non-interactive and reproducible, and a prover cannot pick
//! `r` to pass a wrong product. All arithmetic is exact integer math (i128 accumulator)
//! — no floating point, so the result is deterministic and host-independent.
//!
//! HONESTY BOUNDARY: this PROBABILISTICALLY verifies that a *logged* matmul equals
//! `A·B` (false-accept ≤ 2^-rounds); it is a spot-check, not a proof, and it says
//! nothing about whether the logged matrices are a real model's layers (same
//! deterministic-stand-in caveat as ROBR-2). Never semantic truth.

use mneme_core::MnemeError;

const FREIVALDS_DOMAIN: &[u8] = b"MNEME-robr-freivalds-v1";
/// Default rounds → false-accept probability ≤ 2^-64.
pub const DEFAULT_FREIVALDS_ROUNDS: usize = 64;

/// A claimed integer matrix product `C (m×n) = A (m×k) · B (k×n)`, row-major.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatMulClaim {
    pub m: usize,
    pub k: usize,
    pub n: usize,
    pub a: Vec<i32>,
    pub b: Vec<i32>,
    pub c: Vec<i32>,
}

impl MatMulClaim {
    /// Validate the declared shape against the data lengths. Fail-closed on mismatch.
    fn check_shape(&self) -> Result<(), MnemeError> {
        let ok = self
            .m
            .checked_mul(self.k)
            .is_some_and(|mk| mk == self.a.len())
            && self
                .k
                .checked_mul(self.n)
                .is_some_and(|kn| kn == self.b.len())
            && self
                .m
                .checked_mul(self.n)
                .is_some_and(|mn| mn == self.c.len())
            && self.m > 0
            && self.k > 0
            && self.n > 0;
        if ok {
            Ok(())
        } else {
            Err(MnemeError::SchemaDrift)
        }
    }

    /// Commitment binding the FS challenge to the exact claimed matrices and shape.
    fn commit(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(FREIVALDS_DOMAIN);
        for d in [self.m, self.k, self.n] {
            h.update(&(d as u64).to_le_bytes());
        }
        for mat in [&self.a, &self.b, &self.c] {
            h.update(&(mat.len() as u64).to_le_bytes());
            for v in mat {
                h.update(&v.to_le_bytes());
            }
        }
        *h.finalize().as_bytes()
    }
}

/// Derive the round-`round` 0/1 challenge vector of length `n` from the commitment.
fn challenge_vector(commit: &[u8; 32], round: usize, n: usize) -> Vec<i128> {
    let mut h = blake3::Hasher::new();
    h.update(FREIVALDS_DOMAIN);
    h.update(commit);
    h.update(&(round as u64).to_le_bytes());
    let mut reader = h.finalize_xof();
    let mut bytes = vec![0u8; n.div_ceil(8)];
    reader.fill(&mut bytes);
    (0..n)
        .map(|i| i128::from((bytes[i / 8] >> (i % 8)) & 1))
        .collect()
}

/// Multiply row-major `mat` (rows×cols, i32) by column vector `v` (len cols) → len rows.
fn mat_vec(mat: &[i32], rows: usize, cols: usize, v: &[i128]) -> Vec<i128> {
    (0..rows)
        .map(|i| {
            let base = i * cols;
            (0..cols)
                .map(|j| i128::from(mat[base + j]) * v[j])
                .sum::<i128>()
        })
        .collect()
}

/// Freivalds verification of `C == A·B` over `rounds` Fiat–Shamir challenges.
/// Returns `Ok(true)` if every round's `A·(B·r) == C·r`, `Ok(false)` if any round
/// detects a discrepancy, and `Err` on a malformed/inconsistent shape.
pub fn freivalds_verify(claim: &MatMulClaim, rounds: usize) -> Result<bool, MnemeError> {
    claim.check_shape()?;
    let commit = claim.commit();
    for round in 0..rounds {
        let r = challenge_vector(&commit, round, claim.n);
        // A·(B·r)
        let br = mat_vec(&claim.b, claim.k, claim.n, &r);
        let abr = mat_vec(&claim.a, claim.m, claim.k, &br);
        // C·r
        let cr = mat_vec(&claim.c, claim.m, claim.n, &r);
        if abr != cr {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Honest reference product `C = A·B` (used by the demo/tests to build valid claims).
pub fn reference_product(a: &[i32], b: &[i32], m: usize, k: usize, n: usize) -> Vec<i32> {
    let mut c = vec![0i32; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut acc: i64 = 0;
            for p in 0..k {
                acc += i64::from(a[i * k + p]) * i64::from(b[p * n + j]);
            }
            c[i * n + j] = acc as i32;
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn rand_mat(state: &mut u64, len: usize) -> Vec<i32> {
        (0..len)
            .map(|_| (xorshift(state) % 41) as i32 - 20) // [-20, 20]
            .collect()
    }

    fn honest_claim(state: &mut u64, m: usize, k: usize, n: usize) -> MatMulClaim {
        let a = rand_mat(state, m * k);
        let b = rand_mat(state, k * n);
        let c = reference_product(&a, &b, m, k, n);
        MatMulClaim { m, k, n, a, b, c }
    }

    #[test]
    fn honest_product_always_accepts() {
        let mut st = 0xC0FFEE;
        for _ in 0..50 {
            let m = 1 + (xorshift(&mut st) % 6) as usize;
            let k = 1 + (xorshift(&mut st) % 6) as usize;
            let n = 1 + (xorshift(&mut st) % 6) as usize;
            let claim = honest_claim(&mut st, m, k, n);
            assert!(
                freivalds_verify(&claim, 32).unwrap(),
                "honest C=A·B must always pass Freivalds"
            );
        }
    }

    #[test]
    fn single_entry_tamper_is_caught() {
        // Across many random products, flipping ONE entry of C must be detected.
        let mut st = 0x1234_ABCD;
        for case in 0..100 {
            let m = 2 + (xorshift(&mut st) % 5) as usize;
            let k = 2 + (xorshift(&mut st) % 5) as usize;
            let n = 2 + (xorshift(&mut st) % 5) as usize;
            let mut claim = honest_claim(&mut st, m, k, n);
            let idx = (xorshift(&mut st) as usize) % claim.c.len();
            claim.c[idx] = claim.c[idx].wrapping_add(1); // off by one
            assert!(
                !freivalds_verify(&claim, DEFAULT_FREIVALDS_ROUNDS).unwrap(),
                "case {case}: a tampered product entry must be rejected"
            );
        }
    }

    #[test]
    fn challenge_binds_to_matrices_and_is_deterministic() {
        let mut st = 7;
        let claim = honest_claim(&mut st, 3, 3, 3);
        // Deterministic: same claim → same challenge.
        assert_eq!(
            claim.commit(),
            claim.commit(),
            "commitment must be deterministic"
        );
        // Sensitive: changing a matrix entry changes the challenge derivation.
        let mut other = claim.clone();
        other.a[0] = other.a[0].wrapping_add(1);
        assert_ne!(claim.commit(), other.commit());
    }

    #[test]
    fn malformed_shape_fails_closed() {
        let bad = MatMulClaim {
            m: 2,
            k: 2,
            n: 2,
            a: vec![1, 2, 3], // should be 4
            b: vec![1, 2, 3, 4],
            c: vec![1, 2, 3, 4],
        };
        assert!(matches!(
            freivalds_verify(&bad, 8),
            Err(MnemeError::SchemaDrift)
        ));
    }

    #[test]
    fn wrong_product_rejected_even_if_self_consistent_shape() {
        // C is the right shape but entirely wrong (all zeros vs real product).
        let mut st = 99;
        let mut claim = honest_claim(&mut st, 4, 4, 4);
        claim.c = vec![0i32; claim.m * claim.n];
        assert!(!freivalds_verify(&claim, DEFAULT_FREIVALDS_ROUNDS).unwrap());
    }
}
