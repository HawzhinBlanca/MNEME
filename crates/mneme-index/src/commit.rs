//! Merkle-committed semantic index nodes (blueprint §5.6, SEM domain).

use blake3::Hasher;
use mneme_core::{DomainTag, MnemeError, ObjectId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticCommitFailure {
    VerifyPathAtIndexRootMismatch,
    VerifyPathWithIndexRootMismatch,
}

fn semantic_commit_failure_to_mneme(failure: SemanticCommitFailure) -> MnemeError {
    match failure {
        SemanticCommitFailure::VerifyPathAtIndexRootMismatch
        | SemanticCommitFailure::VerifyPathWithIndexRootMismatch => MnemeError::IndexPathInvalid,
    }
}

fn semantic_commit_error(failure: SemanticCommitFailure) -> MnemeError {
    semantic_commit_failure_to_mneme(failure)
}

fn hash_sem_domain(payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DomainTag::Sem.bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

/// Leaf node tag — distinct from embedding-commit preimages (§5.3).
const LEAF_TAG: u8 = 0x10;
/// Internal node tag.
const INT_TAG: u8 = 0x11;
/// Empty subtree / empty index root.
const EMPTY_TAG: u8 = 0x12;

/// `BLAKE3(SEM ‖ 0x10 ‖ object_id ‖ embedding_commit)`.
pub fn hash_sem_leaf(object_id: &[u8; 32], embedding_commit: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 65];
    payload[0] = LEAF_TAG; // tcb-index-ok fixed 65-byte semantic leaf payload layout
    payload[1..33].copy_from_slice(object_id); // tcb-index-ok fixed 65-byte semantic leaf payload layout
    payload[33..65].copy_from_slice(embedding_commit); // tcb-index-ok fixed 65-byte semantic leaf payload layout
    hash_sem_domain(&payload)
}

/// `BLAKE3(SEM ‖ 0x11 ‖ left ‖ right)`.
pub fn hash_sem_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 65];
    payload[0] = INT_TAG; // tcb-index-ok fixed 65-byte semantic internal-node payload layout
    payload[1..33].copy_from_slice(left); // tcb-index-ok fixed 65-byte semantic internal-node payload layout
    payload[33..65].copy_from_slice(right); // tcb-index-ok fixed 65-byte semantic internal-node payload layout
    hash_sem_domain(&payload)
}

/// Root of an empty semantic index.
pub fn empty_semantic_root() -> [u8; 32] {
    hash_sem_domain(&[EMPTY_TAG])
}

/// Balanced Merkle tree over semantic leaves (sorted by `ObjectId` asc).
#[derive(Clone, Debug)]
pub struct SemanticMerkleTree {
    leaves: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl SemanticMerkleTree {
    pub fn from_entries(entries: &[(ObjectId, [u8; 32])]) -> Self {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let leaves: Vec<[u8; 32]> = sorted
            .iter()
            .map(|(id, commit)| hash_sem_leaf(id.as_bytes(), commit))
            .collect();
        Self::from_leaf_hashes(leaves)
    }

    fn from_leaf_hashes(leaves: Vec<[u8; 32]>) -> Self {
        let mut levels = Vec::new();
        if leaves.is_empty() {
            levels.push(vec![empty_semantic_root()]);
            return Self { leaves, levels };
        }
        levels.push(leaves.clone());
        let mut current = leaves.clone();
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut idx = 0;
            while idx < current.len() {
                let Some(left) = current.get(idx).copied() else {
                    break;
                };
                let right = match current.get(idx + 1).copied() {
                    Some(right) => right,
                    None => left,
                };
                next.push(hash_sem_internal(&left, &right));
                idx += 2;
            }
            levels.push(next.clone());
            current = next;
        }
        Self { leaves, levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|lvl| lvl.first().copied())
            .unwrap_or_else(empty_semantic_root)
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn leaf_hash(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).copied()
    }

    /// Merkle authentication path from leaf `index` to `root`.
    pub fn merkle_path(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = index;
        for level in 0..self.levels.len().saturating_sub(1) {
            let lvl = self.levels.get(level)?;
            let sibling = if idx % 2 == 0 {
                match lvl.get(idx + 1).copied() {
                    Some(right) => right,
                    None => *lvl.get(idx)?,
                }
            } else {
                *lvl.get(idx - 1)?
            };
            path.push(sibling);
            idx /= 2;
        }
        Some(path)
    }

    /// Verify a leaf at `index` resolves to `root`.
    pub fn verify_path_at_index(
        &self,
        index: usize,
        leaf_commit: &[u8; 32],
        path: &[[u8; 32]],
        root: &[u8; 32],
    ) -> Result<(), MnemeError> {
        let mut current = *leaf_commit;
        let mut idx = index;
        for sibling in path {
            current = if idx % 2 == 0 {
                hash_sem_internal(&current, sibling)
            } else {
                hash_sem_internal(sibling, &current)
            };
            idx /= 2;
        }
        if current != *root {
            return Err(semantic_commit_error(
                SemanticCommitFailure::VerifyPathAtIndexRootMismatch,
            ));
        }
        Ok(())
    }

    /// Verify a leaf commitment resolves to `root` when `index` is known.
    pub fn verify_path_with_index(
        index: usize,
        leaf_commit: &[u8; 32],
        path: &[[u8; 32]],
        root: &[u8; 32],
    ) -> Result<(), MnemeError> {
        let mut current = *leaf_commit;
        let mut idx = index;
        for sibling in path {
            current = if idx % 2 == 0 {
                hash_sem_internal(&current, sibling)
            } else {
                hash_sem_internal(sibling, &current)
            };
            idx /= 2;
        }
        if current != *root {
            return Err(semantic_commit_error(
                SemanticCommitFailure::VerifyPathWithIndexRootMismatch,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    #[test]
    fn semantic_commit_failures_are_classified_not_error_collapsed() {
        let production = include_str!("commit.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("commit.rs should keep tests after production code");

        let forbidden = "return Err(MnemeError::IndexPathInvalid";
        assert!(
            !production.contains(forbidden),
            "semantic commit production code still collapses directly through {forbidden}"
        );

        for required in [
            "enum SemanticCommitFailure",
            "VerifyPathAtIndexRootMismatch",
            "VerifyPathWithIndexRootMismatch",
            "fn semantic_commit_failure_to_mneme(",
            "fn semantic_commit_error(",
        ] {
            assert!(
                production.contains(required),
                "semantic commit production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn semantic_commit_failure_classifier_preserves_public_error() {
        for failure in [
            SemanticCommitFailure::VerifyPathAtIndexRootMismatch,
            SemanticCommitFailure::VerifyPathWithIndexRootMismatch,
        ] {
            assert_eq!(
                semantic_commit_failure_to_mneme(failure),
                MnemeError::IndexPathInvalid
            );
            assert_eq!(semantic_commit_error(failure), MnemeError::IndexPathInvalid);
        }
    }

    #[test]
    fn empty_tree_root_is_not_zero() {
        let tree = SemanticMerkleTree::from_entries(&[]);
        assert_ne!(tree.root(), [0u8; 32]);
        assert_eq!(tree.root(), empty_semantic_root());
    }

    #[test]
    fn merkle_path_roundtrip() {
        let entries = vec![
            (oid(0x01), [0xaa; 32]),
            (oid(0x02), [0xbb; 32]),
            (oid(0x03), [0xcc; 32]),
        ];
        let tree = SemanticMerkleTree::from_entries(&entries);
        let root = tree.root();
        for i in 0..entries.len() {
            let leaf = tree.leaf_hash(i).unwrap();
            let path = tree.merkle_path(i).unwrap();
            tree.verify_path_at_index(i, &leaf, &path, &root).unwrap();
        }
    }
}
