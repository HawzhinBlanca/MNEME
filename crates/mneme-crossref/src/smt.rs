//! Sparse Merkle tree — independent reference (blueprint §5.6).

use crate::domain::{hash_smt_internal, hash_smt_leaf};
use crate::error::CrossrefError;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const TREE_DEPTH: usize = 256;
pub const TOMBSTONE: [u8; 32] = [0xff; 32];

type Leaf = ([u8; 32], [u8; 32]);

pub fn default_hashes() -> [[u8; 32]; TREE_DEPTH + 1] {
    static DEFAULTS: OnceLock<[[u8; 32]; TREE_DEPTH + 1]> = OnceLock::new();
    *DEFAULTS.get_or_init(|| {
        let mut d = [[0u8; 32]; TREE_DEPTH + 1];
        d[0] = hash_smt_leaf(&[0u8; 32], &[0u8; 32]);
        for h in 1..=TREE_DEPTH {
            d[h] = hash_smt_internal(&d[h - 1], &d[h - 1]);
        }
        d
    })
}

pub fn empty_root() -> [u8; 32] {
    default_hashes()[TREE_DEPTH]
}

pub fn key_bit(key: &[u8; 32], depth: usize) -> bool {
    let byte = depth / 8;
    let bit = 7 - (depth % 8);
    (key[byte] >> bit) & 1 == 1
}

pub fn hash_up(current: [u8; 32], sibling: [u8; 32], go_right: bool) -> [u8; 32] {
    if go_right {
        hash_smt_internal(&sibling, &current)
    } else {
        hash_smt_internal(&current, &sibling)
    }
}

pub fn fold_auth_path(
    leaf: [u8; 32],
    key: &[u8; 32],
    path: &[[u8; 32]],
) -> Result<[u8; 32], usize> {
    if path.len() != TREE_DEPTH {
        return Err(path.len());
    }
    let mut current = leaf;
    for depth in (0..TREE_DEPTH).rev() {
        current = hash_up(current, path[depth], key_bit(key, depth));
    }
    Ok(current)
}

#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTree {
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
    cached_root: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipProof {
    pub key: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub conflicting_leaf: Option<([u8; 32], [u8; 32])>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
            cached_root: Some(empty_root()),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.cached_root.unwrap_or_else(|| self.compute_root())
    }

    pub fn upsert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
        self.cached_root = None;
    }

    pub fn rebuild_root_cache(&mut self) {
        self.cached_root = Some(self.compute_root());
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.leaves.get(key).copied()
    }

    pub fn contains_live(&self, key: &[u8; 32]) -> bool {
        matches!(self.leaves.get(key), Some(v) if *v != TOMBSTONE)
    }

    pub fn iter_leaves(&self) -> impl Iterator<Item = ([u8; 32], [u8; 32])> + '_ {
        self.leaves.iter().map(|(k, v)| (*k, *v))
    }

    fn compute_root(&self) -> [u8; 32] {
        hash_subtree(collect_leaves(&self.leaves), 0)
    }

    fn auth_path(&self, key: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut current = collect_leaves(&self.leaves);
        for depth in 0..TREE_DEPTH {
            let (left, right) = partition(&current, depth);
            if key_bit(key, depth) {
                path.push(hash_subtree(left, depth + 1));
                current = right;
            } else {
                path.push(hash_subtree(right, depth + 1));
                current = left;
            }
        }
        path
    }

    pub fn prove_membership(&self, key: [u8; 32]) -> Result<MembershipProof, CrossrefError> {
        let value = self
            .leaves
            .get(&key)
            .copied()
            .ok_or(CrossrefError::PathInvalid)?;
        if value == TOMBSTONE {
            return Err(CrossrefError::PathInvalid);
        }
        Ok(MembershipProof {
            key,
            value,
            path: self.auth_path(&key),
            root: self.root(),
        })
    }

    pub fn prove_non_membership(&self, key: [u8; 32]) -> Result<NonMembershipProof, CrossrefError> {
        if self.contains_live(&key) {
            return Err(CrossrefError::PathInvalid);
        }
        let conflicting_leaf = self.leaves.get(&key).copied().map(|v| (key, v));
        Ok(NonMembershipProof {
            key,
            path: self.auth_path(&key),
            root: self.root(),
            conflicting_leaf,
        })
    }

    pub fn verify_membership(proof: &MembershipProof) -> Result<(), CrossrefError> {
        if proof.value == TOMBSTONE {
            return Err(CrossrefError::PathInvalid);
        }
        let leaf = hash_smt_leaf(&proof.key, &proof.value);
        let computed = fold_auth_path(leaf, &proof.key, &proof.path)
            .map_err(|_| CrossrefError::PathInvalid)?;
        if computed != proof.root {
            return Err(CrossrefError::PathInvalid);
        }
        Ok(())
    }

    pub fn verify_non_membership(proof: &NonMembershipProof) -> Result<(), CrossrefError> {
        if proof.path.len() != TREE_DEPTH {
            return Err(CrossrefError::PathInvalid);
        }
        let defaults = default_hashes();
        let leaf = match proof.conflicting_leaf {
            Some((k, v)) => {
                if k != proof.key || v != TOMBSTONE {
                    return Err(CrossrefError::PathInvalid);
                }
                hash_smt_leaf(&k, &v)
            }
            None => defaults[0],
        };
        let computed = fold_auth_path(leaf, &proof.key, &proof.path)
            .map_err(|_| CrossrefError::PathInvalid)?;
        if computed != proof.root {
            return Err(CrossrefError::PathInvalid);
        }
        Ok(())
    }
}

fn collect_leaves(map: &BTreeMap<[u8; 32], [u8; 32]>) -> Vec<Leaf> {
    map.iter().map(|(k, v)| (*k, *v)).collect()
}

fn partition(entries: &[Leaf], depth: usize) -> (Vec<Leaf>, Vec<Leaf>) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for (key, value) in entries {
        if key_bit(key, depth) {
            right.push((*key, *value));
        } else {
            left.push((*key, *value));
        }
    }
    (left, right)
}

enum Work {
    Eval { depth: usize, entries: Vec<Leaf> },
    Merge,
}

fn hash_subtree(entries: Vec<Leaf>, start_depth: usize) -> [u8; 32] {
    let defaults = default_hashes();
    let mut stack = vec![Work::Eval {
        depth: start_depth,
        entries,
    }];
    let mut out: Vec<[u8; 32]> = Vec::new();

    while let Some(job) = stack.pop() {
        match job {
            Work::Eval { depth, entries } => {
                if entries.is_empty() {
                    out.push(defaults[TREE_DEPTH - depth]);
                    continue;
                }
                if depth == TREE_DEPTH {
                    out.push(hash_smt_leaf(&entries[0].0, &entries[0].1));
                    continue;
                }
                let (left, right) = partition(&entries, depth);
                stack.push(Work::Merge);
                stack.push(Work::Eval {
                    depth: depth + 1,
                    entries: right,
                });
                stack.push(Work::Eval {
                    depth: depth + 1,
                    entries: left,
                });
            }
            Work::Merge => {
                let right = out.pop().expect("merge right");
                let left = out.pop().expect("merge left");
                out.push(hash_smt_internal(&left, &right));
            }
        }
    }
    out.pop().expect("root hash")
}

pub fn root_from_entries(entries: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let map: BTreeMap<_, _> = entries.iter().copied().collect();
    hash_subtree(collect_leaves(&map), 0)
}
