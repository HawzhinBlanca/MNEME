//! Sparse Merkle tree: deterministic root, membership and non-membership proofs (blueprint §5.6).

#![deny(warnings)]

mod defaults;
mod proof;
mod tree;
mod wire;

pub use defaults::{TREE_DEPTH, default_hashes, empty_root, hash_up, key_bit};
pub use proof::{MembershipProof, NonMembershipProof, direction_bit, membership_leaf_hash};
pub use tree::{
    ChameleonLeafConfig, SparseMerkleTree, TOMBSTONE, root_from_leaves, verify_root_matches,
};
pub use wire::{
    ParsedProof, encode_membership_wire, encode_non_membership_wire, fuzz_parse_and_verify,
    parse_proof_blob,
};
