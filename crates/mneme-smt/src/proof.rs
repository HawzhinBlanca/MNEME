use crate::defaults::{TREE_DEPTH, default_hashes, fold_auth_path, key_bit};
use crate::tree::{SparseMerkleTree, TOMBSTONE};
use mneme_core::{MnemeError, hash_smt_leaf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    /// SMT proofs use key bits for direction; must be zero (legacy Receipt field).
    pub leaf_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipProof {
    pub key: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    /// Present when the key maps to a tombstone or a divergent leaf.
    pub conflicting_leaf: Option<([u8; 32], [u8; 32])>,
}

impl SparseMerkleTree {
    pub fn prove_membership(&self, key: [u8; 32]) -> Result<MembershipProof, MnemeError> {
        let value = self
            .leaves
            .get(&key)
            .copied()
            .ok_or(MnemeError::IndexPathInvalid)?;
        if value == TOMBSTONE {
            return Err(MnemeError::Forgotten);
        }
        let path = self.auth_path(&key);
        let root = self.root();
        Ok(MembershipProof {
            key,
            value,
            path,
            root,
            leaf_index: 0,
        })
    }

    pub fn prove_non_membership(&self, key: [u8; 32]) -> Result<NonMembershipProof, MnemeError> {
        if self.contains_live(&key) {
            return Err(MnemeError::TombstoneConflict);
        }
        let conflicting_leaf = self.leaves.get(&key).copied().map(|v| (key, v));
        let path = self.auth_path(&key);
        Ok(NonMembershipProof {
            key,
            path,
            root: self.root(),
            conflicting_leaf,
        })
    }

    pub fn verify_membership(proof: &MembershipProof) -> Result<(), MnemeError> {
        if proof.value == TOMBSTONE {
            return Err(MnemeError::Forgotten);
        }
        if proof.leaf_index != 0 {
            return Err(MnemeError::IndexPathInvalid);
        }
        let leaf = hash_smt_leaf(&proof.key, &proof.value);
        let computed = fold_auth_path(leaf, &proof.key, &proof.path)
            .map_err(|_| MnemeError::IndexPathInvalid)?;
        if computed != proof.root {
            return Err(MnemeError::IndexPathInvalid);
        }
        Ok(())
    }

    pub fn verify_non_membership(proof: &NonMembershipProof) -> Result<(), MnemeError> {
        if proof.path.len() != TREE_DEPTH {
            return Err(MnemeError::IndexPathInvalid);
        }
        let defaults = default_hashes();
        let leaf = match proof.conflicting_leaf {
            Some((k, v)) => {
                if k != proof.key {
                    return Err(MnemeError::IndexPathInvalid);
                }
                if v != TOMBSTONE {
                    return Err(MnemeError::IndexPathInvalid);
                }
                hash_smt_leaf(&k, &v)
            }
            None => defaults[0],
        };
        let computed = fold_auth_path(leaf, &proof.key, &proof.path)
            .map_err(|_| MnemeError::IndexPathInvalid)?;
        if computed != proof.root {
            return Err(MnemeError::IndexPathInvalid);
        }
        Ok(())
    }
}

/// Exposed for vector generation and tests.
pub fn membership_leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    hash_smt_leaf(key, value)
}

/// Exposed for vector generation and tests.
pub fn direction_bit(key: &[u8; 32], depth: usize) -> bool {
    key_bit(key, depth)
}
