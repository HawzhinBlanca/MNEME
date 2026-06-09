//! Logical key index: `namespace + name → ObjectId` via SMT (blueprint §5.6).

use mneme_core::{LogicalKey, MnemeError, ObjectId, Receipt};
use mneme_smt::{MembershipProof, NonMembershipProof, SparseMerkleTree};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyIndexFailure {
    ResolveMissingLiveValue,
    ResolveTombstonedKey,
    RecallReceiptRootMismatch,
}

fn key_index_failure_to_mneme(failure: KeyIndexFailure) -> MnemeError {
    match failure {
        KeyIndexFailure::ResolveMissingLiveValue => MnemeError::IndexPathInvalid,
        KeyIndexFailure::ResolveTombstonedKey => MnemeError::Forgotten,
        KeyIndexFailure::RecallReceiptRootMismatch => MnemeError::ReceiptRootMismatch,
    }
}

fn key_index_error(failure: KeyIndexFailure) -> MnemeError {
    key_index_failure_to_mneme(failure)
}

/// Authenticated key index backed by a sparse Merkle tree.
#[derive(Clone, Debug, Default)]
pub struct KeyIndex {
    smt: SparseMerkleTree,
}

impl KeyIndex {
    pub fn new() -> Self {
        Self {
            smt: SparseMerkleTree::new(),
        }
    }

    pub fn from_tree(smt: SparseMerkleTree) -> Self {
        Self { smt }
    }

    pub fn root(&self) -> [u8; 32] {
        self.smt.root()
    }

    pub fn tree(&self) -> &SparseMerkleTree {
        &self.smt
    }

    pub fn tree_mut(&mut self) -> &mut SparseMerkleTree {
        &mut self.smt
    }

    pub fn upsert(&mut self, key: &LogicalKey, id: ObjectId) {
        self.smt.upsert(key.hash(), *id.as_bytes());
    }

    pub fn tombstone(&mut self, key: &LogicalKey) {
        self.smt.tombstone(key.hash());
    }

    pub fn contains_live(&self, key: &LogicalKey) -> bool {
        self.smt.contains_live(&key.hash())
    }

    pub fn resolve(&self, key: &LogicalKey) -> Result<ObjectId, MnemeError> {
        let key_hash = key.hash();
        let value = self
            .smt
            .get(&key_hash)
            .ok_or_else(|| key_index_error(KeyIndexFailure::ResolveMissingLiveValue))?;
        if self.smt.is_tombstoned(&key_hash) {
            return Err(key_index_error(KeyIndexFailure::ResolveTombstonedKey));
        }
        Ok(ObjectId(value))
    }

    pub fn prove_membership(&self, key: &LogicalKey) -> Result<MembershipProof, MnemeError> {
        self.smt.prove_membership(key.hash())
    }

    pub fn prove_non_membership(&self, key: &LogicalKey) -> Result<NonMembershipProof, MnemeError> {
        self.smt.prove_non_membership(key.hash())
    }

    /// Build a key-index receipt bound to a signed root (§9.2 key path, v0).
    pub fn recall_receipt(
        &self,
        key: &LogicalKey,
        root_bound: [u8; 32],
        key_index_root: [u8; 32],
    ) -> Result<Receipt, MnemeError> {
        let proof = self.prove_membership(key)?;
        if proof.root != key_index_root {
            return Err(key_index_error(KeyIndexFailure::RecallReceiptRootMismatch));
        }
        Ok(Receipt {
            root_bound,
            logical_key: key.hash(),
            object_id: proof.value,
            membership_proof: proof.path,
            key_index_root,
            leaf_index: proof.leaf_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_index_failures_are_classified_not_error_collapsed() {
        let production = include_str!("key_index.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("key_index.rs should keep tests after production code");

        for forbidden in [
            ".ok_or(MnemeError::IndexPathInvalid",
            "return Err(MnemeError::Forgotten",
            "return Err(MnemeError::ReceiptRootMismatch",
        ] {
            assert!(
                !production.contains(forbidden),
                "key-index production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum KeyIndexFailure",
            "ResolveMissingLiveValue",
            "ResolveTombstonedKey",
            "RecallReceiptRootMismatch",
            "fn key_index_failure_to_mneme(",
            "fn key_index_error(",
        ] {
            assert!(
                production.contains(required),
                "key-index production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn key_index_failure_classifier_preserves_public_errors() {
        for (failure, expected) in [
            (
                KeyIndexFailure::ResolveMissingLiveValue,
                MnemeError::IndexPathInvalid,
            ),
            (KeyIndexFailure::ResolveTombstonedKey, MnemeError::Forgotten),
            (
                KeyIndexFailure::RecallReceiptRootMismatch,
                MnemeError::ReceiptRootMismatch,
            ),
        ] {
            assert_eq!(key_index_failure_to_mneme(failure), expected);
            assert_eq!(key_index_error(failure), expected);
        }
    }
}
