//! Merkle proof verification — every path element checked (immudb GHSA-672p lesson).

use mneme_core::MnemeError;
use mneme_smt::{MembershipProof, TOMBSTONE, TREE_DEPTH, hash_up, key_bit, membership_leaf_hash};

/// Verify SMT membership by validating **each** auth-path sibling (not just endpoints).
pub fn verify_membership_proof(proof: &MembershipProof) -> Result<(), MnemeError> {
    if proof.leaf_index != 0 {
        return Err(MnemeError::IndexPathInvalid);
    }
    if proof.value == TOMBSTONE {
        return Err(MnemeError::Forgotten);
    }
    if !membership_path_has_tree_depth(&proof.path) {
        return Err(MnemeError::IndexPathInvalid);
    }

    let leaf = membership_leaf_hash(&proof.key, &proof.value);
    let mut current = leaf;
    for depth in (0..TREE_DEPTH).rev() {
        // Bounds already enforced by the named path-depth guard above;
        // use `.get()` so the TCB carries no slice-index panic vector (§10, §17.6).
        let sibling = proof.path.get(depth).ok_or(MnemeError::IndexPathInvalid)?;
        current = hash_up(current, *sibling, key_bit(&proof.key, depth));
    }
    if current != proof.root {
        return Err(MnemeError::IndexPathInvalid);
    }
    Ok(())
}

fn membership_path_has_tree_depth(path: &[[u8; 32]]) -> bool {
    path.len() == TREE_DEPTH
}
