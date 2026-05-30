//! RFC 9162 / RFC 6962 Merkle consistency proofs over dag-head-root checkpoints (§5.7).

use mneme_core::{MnemeError, hash_ckpt, hash_smt_internal};

/// Empty checkpoint-tree root (MTH of zero leaves).
pub(crate) fn empty_tree_hash() -> [u8; 32] {
    hash_ckpt(&[])
}

fn leaf_hash(dag_head_root: &[u8; 32]) -> [u8; 32] {
    hash_ckpt(dag_head_root)
}

fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_smt_internal(left, right)
}

/// Largest power of two strictly less than `n`, or 0 when `n <= 1`.
fn down_pow2(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    1usize << ((n - 1).ilog2())
}

/// Merkle root over the first `size` checkpoint leaves (RFC 6962 MTH).
pub fn root_at_size(checkpoints: &[[u8; 32]], size: usize) -> [u8; 32] {
    mth(checkpoints, 0, size)
}

fn mth(checkpoints: &[[u8; 32]], start: usize, count: usize) -> [u8; 32] {
    if count == 0 {
        return empty_tree_hash();
    }
    if count == 1 {
        return leaf_hash(&checkpoints[start]);
    }
    let split = down_pow2(count);
    let left = mth(checkpoints, start, split);
    let right = mth(checkpoints, start + split, count - split);
    internal_hash(&left, &right)
}

/// Generate an RFC 6962 consistency proof between checkpoint sequences `from` and `to`.
pub fn consistency_proof(
    checkpoints: &[[u8; 32]],
    from: u64,
    to: u64,
) -> Result<Vec<[u8; 32]>, MnemeError> {
    let from = usize_from_u64(from)?;
    let to = usize_from_u64(to)?;
    if from > to {
        return Err(MnemeError::RootInconsistent);
    }
    if to > checkpoints.len() {
        return Err(MnemeError::RootInconsistent);
    }
    if from == to || from == 0 {
        return Ok(Vec::new());
    }
    Ok(subproof(checkpoints, from, to, true))
}

/// SUBPROOF(m, D[n], b) from RFC 6962 §2.1.2.
fn subproof(checkpoints: &[[u8; 32]], m: usize, n: usize, known: bool) -> Vec<[u8; 32]> {
    if m == n {
        if known {
            return Vec::new();
        }
        return vec![mth(checkpoints, 0, n)];
    }
    if n == 0 {
        return Vec::new();
    }
    let k = down_pow2(n);
    if m <= k {
        let mut proof = subproof(checkpoints, m, k, known);
        proof.push(mth(checkpoints, k, n - k));
        proof
    } else {
        let mut proof = subproof(checkpoints, m - k, n - k, false);
        proof.push(mth(checkpoints, 0, k));
        proof
    }
}

/// Verify that the checkpoint tree at `to` is a consistent extension of `from`.
pub fn verify_consistency(
    checkpoints: &[[u8; 32]],
    from: u64,
    to: u64,
    path: &[[u8; 32]],
) -> Result<(), MnemeError> {
    let from = usize_from_u64(from)?;
    let to = usize_from_u64(to)?;
    if from > to {
        return Err(MnemeError::RootInconsistent);
    }
    if to > checkpoints.len() {
        return Err(MnemeError::RootInconsistent);
    }

    let expected = consistency_proof(checkpoints, from as u64, to as u64)?;
    if expected != path {
        return Err(MnemeError::RootInconsistent);
    }
    Ok(())
}

fn usize_from_u64(v: u64) -> Result<usize, MnemeError> {
    usize::try_from(v).map_err(|_| MnemeError::RootInconsistent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq_roots(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                b
            })
            .collect()
    }

    #[test]
    fn consistency_proof_roundtrip_various_sizes() {
        let checkpoints = seq_roots(16);
        for from in 0..=16 {
            for to in from..=16 {
                let proof = consistency_proof(&checkpoints, from as u64, to as u64).unwrap();
                verify_consistency(&checkpoints, from as u64, to as u64, &proof).unwrap();
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_tampered_path() {
        let checkpoints = seq_roots(8);
        let mut proof = consistency_proof(&checkpoints, 2, 8).unwrap();
        assert!(!proof.is_empty());
        proof[0][0] ^= 0xff;
        let err = verify_consistency(&checkpoints, 2, 8, &proof).unwrap_err();
        assert_eq!(err, MnemeError::RootInconsistent);
    }

    #[test]
    fn equal_sequences_require_empty_proof() {
        let checkpoints = seq_roots(4);
        let proof = consistency_proof(&checkpoints, 2, 2).unwrap();
        assert!(proof.is_empty());
        verify_consistency(&checkpoints, 2, 2, &proof).unwrap();
    }

    #[test]
    fn genesis_to_full_tree_empty_proof() {
        let checkpoints = seq_roots(5);
        let proof = consistency_proof(&checkpoints, 0, 5).unwrap();
        assert!(proof.is_empty());
        verify_consistency(&checkpoints, 0, 5, &proof).unwrap();
    }
}
