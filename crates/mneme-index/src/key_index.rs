//! Logical key index: `namespace + name → ObjectId` via SMT (blueprint §5.6).

use mneme_core::{LogicalKey, MnemeError, ObjectId, Receipt};
use mneme_smt::{MembershipProof, NonMembershipProof, SparseMerkleTree};

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
            .ok_or(MnemeError::IndexPathInvalid)?;
        if self.smt.is_tombstoned(&key_hash) {
            return Err(MnemeError::Forgotten);
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
            return Err(MnemeError::ReceiptRootMismatch);
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
