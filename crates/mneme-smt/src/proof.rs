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

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = n;
        v
    }
    fn val(n: u8) -> [u8; 32] {
        let mut v = [0xFFu8; 32];
        v[0] = n;
        v
    }

    /// SMT-PROOF-1: Membership proof roundtrip — prove then verify succeeds.
    #[test]
    fn membership_proof_roundtrip() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(1), val(1));
        let proof = smt
            .prove_membership(k(1))
            .expect("membership proof must succeed");
        assert_eq!(
            proof.path.len(),
            TREE_DEPTH,
            "auth path must be TREE_DEPTH long"
        );
        assert_eq!(proof.leaf_index, 0, "leaf_index must be 0");
        SparseMerkleTree::verify_membership(&proof).expect("fresh proof must verify");
    }

    /// SMT-PROOF-2: Tampered value in membership proof is rejected.
    #[test]
    fn membership_proof_tampered_value_rejected() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(2), val(2));
        let mut proof = smt.prove_membership(k(2)).unwrap();
        proof.value[0] ^= 0xFF; // tamper the value
        assert!(
            SparseMerkleTree::verify_membership(&proof).is_err(),
            "tampered value must be rejected"
        );
    }

    /// SMT-PROOF-3: Tampered root in membership proof is rejected.
    #[test]
    fn membership_proof_tampered_root_rejected() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(3), val(3));
        let mut proof = smt.prove_membership(k(3)).unwrap();
        proof.root[0] ^= 0x01; // tamper root
        assert!(
            SparseMerkleTree::verify_membership(&proof).is_err(),
            "tampered root must be rejected"
        );
    }

    /// SMT-PROOF-4: verify_membership rejects non-zero leaf_index (legacy guard).
    #[test]
    fn membership_proof_nonzero_leaf_index_rejected() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(4), val(4));
        let mut proof = smt.prove_membership(k(4)).unwrap();
        proof.leaf_index = 1;
        assert!(
            SparseMerkleTree::verify_membership(&proof).is_err(),
            "non-zero leaf_index must be rejected"
        );
    }

    /// SMT-PROOF-5: prove_membership returns Forgotten for tombstoned key (fail-closed).
    #[test]
    fn prove_membership_returns_forgotten_for_tombstoned_key() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(5), val(5));
        smt.tombstone(k(5));
        let err = smt.prove_membership(k(5)).unwrap_err();
        assert_eq!(
            err,
            MnemeError::Forgotten,
            "tombstoned key must yield Forgotten"
        );
    }

    /// SMT-PROOF-6: prove_non_membership fails with TombstoneConflict for a live key (fail-closed).
    #[test]
    fn prove_non_membership_fails_for_live_key() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(6), val(6));
        let err = smt.prove_non_membership(k(6)).unwrap_err();
        assert_eq!(
            err,
            MnemeError::TombstoneConflict,
            "live key must yield TombstoneConflict"
        );
    }

    /// SMT-PROOF-7: Non-membership proof roundtrip for a key never inserted.
    #[test]
    fn non_membership_proof_roundtrip_absent_key() {
        let mut smt = SparseMerkleTree::new();
        smt.upsert(k(10), val(10)); // different key present
        let proof = smt
            .prove_non_membership(k(99))
            .expect("absent key must produce non-membership proof");
        SparseMerkleTree::verify_non_membership(&proof).expect("non-membership proof must verify");
    }

    /// SMT-PROOF-8: direction_bit and membership_leaf_hash are deterministic.
    #[test]
    fn direction_bit_and_leaf_hash_deterministic() {
        let key = k(0xAB);
        assert_eq!(direction_bit(&key, 0), direction_bit(&key, 0));
        let h1 = membership_leaf_hash(&key, &val(1));
        let h2 = membership_leaf_hash(&key, &val(1));
        assert_eq!(h1, h2, "membership_leaf_hash must be deterministic");
        let h_diff = membership_leaf_hash(&key, &val(2));
        assert_ne!(
            h1, h_diff,
            "different values must produce different leaf hashes"
        );
    }
}
