use crate::defaults::{TREE_DEPTH, default_hashes, empty_root, hash_up, key_bit};
use mneme_core::{MnemeError, hash_smt_internal, hash_smt_leaf};
use mneme_crypto::chameleon_leaf_hash;
use std::cell::RefCell;
use std::collections::BTreeMap;

pub const TOMBSTONE: [u8; 32] = [0xff; 32];

type Leaf = ([u8; 32], [u8; 32]);
type NodeKey = (usize, [u8; 32]);

/// Chameleon-randomness per key for root-stable redaction (§13.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChameleonLeafConfig {
    pub trapdoor_pk: [u8; 32],
    pub slots: BTreeMap<[u8; 32], [u8; 32]>,
}

/// Lazily-built proof caches. Interior mutability lets read paths (`root`,
/// membership `auth_path`) warm the cache on first use and reuse it thereafter,
/// while any write clears it. This makes the production recall path O(TREE_DEPTH)
/// without forcing an O(n) rebuild on every write.
#[derive(Clone, Debug, Default)]
struct TreeCache {
    root: Option<[u8; 32]>,
    nodes: Option<BTreeMap<NodeKey, [u8; 32]>>,
}

#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTree {
    pub(crate) leaves: BTreeMap<[u8; 32], [u8; 32]>,
    pub chameleon: Option<ChameleonLeafConfig>,
    cache: RefCell<TreeCache>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
            chameleon: None,
            cache: RefCell::new(TreeCache {
                root: Some(empty_root()),
                nodes: Some(BTreeMap::new()),
            }),
        }
    }

    /// Drop the lazily-built proof caches; called after any mutation.
    fn invalidate(&self) {
        let mut cache = self.cache.borrow_mut();
        cache.root = None;
        cache.nodes = None;
    }

    /// Build the node cache + root from the current leaf set if cold.
    ///
    /// Single pass, O(n·depth), shared by every read path. Single-leaf subtrees
    /// are folded directly to a single cached node — this is sufficient for
    /// membership proofs and `root`, but **not** for non-membership of keys that
    /// share a prefix with an existing leaf (see `auth_path`).
    fn ensure_cache(&self) {
        if self.cache.borrow().nodes.is_some() {
            return;
        }
        let leaves = collect_leaves(&self.leaves);
        let mut nodes = BTreeMap::new();
        let defaults = default_hashes();
        let root = hash_subtree_cached(&leaves, 0, self.chameleon.as_ref(), &defaults, &mut nodes);
        let mut cache = self.cache.borrow_mut();
        cache.root = Some(root);
        cache.nodes = Some(nodes);
    }

    pub fn enable_chameleon(&mut self, trapdoor_pk: [u8; 32]) {
        self.chameleon = Some(ChameleonLeafConfig {
            trapdoor_pk,
            slots: BTreeMap::new(),
        });
        self.invalidate();
    }

    pub fn register_chameleon_slot(
        &mut self,
        key: [u8; 32],
        randomness: [u8; 32],
    ) -> Result<(), MnemeError> {
        let cfg = self.chameleon.as_mut().ok_or(MnemeError::CapDenied)?;
        cfg.slots.insert(key, randomness);
        self.invalidate();
        Ok(())
    }

    pub fn chameleon_slot(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.chameleon
            .as_ref()
            .and_then(|c| c.slots.get(key).copied())
    }

    /// Replace leaf value + chameleon randomness (root unchanged when collision valid).
    pub fn redact_chameleon(
        &mut self,
        key: [u8; 32],
        new_value: [u8; 32],
        new_randomness: [u8; 32],
        trapdoor_pk: [u8; 32],
    ) {
        self.leaves.insert(key, new_value);
        if let Some(cfg) = self.chameleon.as_mut() {
            cfg.trapdoor_pk = trapdoor_pk;
            cfg.slots.insert(key, new_randomness);
        }
        self.invalidate();
    }

    pub fn root(&self) -> [u8; 32] {
        self.ensure_cache();
        self.cache.borrow().root.unwrap_or_else(empty_root)
    }

    pub fn upsert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
        self.invalidate();
    }

    pub fn tombstone(&mut self, key: [u8; 32]) {
        self.leaves.insert(key, TOMBSTONE);
        self.invalidate();
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.leaves.get(key).copied()
    }

    pub fn is_tombstoned(&self, key: &[u8; 32]) -> bool {
        self.leaves.get(key) == Some(&TOMBSTONE)
    }

    pub fn tombstone_keys(&self) -> Vec<[u8; 32]> {
        self.leaves
            .iter()
            .filter(|(_, v)| **v == TOMBSTONE)
            .map(|(k, _)| *k)
            .collect()
    }

    pub fn contains_live(&self, key: &[u8; 32]) -> bool {
        matches!(self.leaves.get(key), Some(v) if *v != TOMBSTONE)
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Iterate live SMT leaves for MST diff (§9.4).
    pub fn iter_leaves(&self) -> impl Iterator<Item = ([u8; 32], [u8; 32])> + '_ {
        self.leaves.iter().map(|(k, v)| (*k, *v))
    }

    pub fn rebuild_root_cache(&mut self) {
        self.invalidate();
        self.ensure_cache();
    }

    pub fn upsert_and_root(&mut self, key: [u8; 32], value: [u8; 32]) -> [u8; 32] {
        self.leaves.insert(key, value);
        self.invalidate();
        self.root()
    }

    pub(crate) fn auth_path(&self, key: &[u8; 32]) -> Vec<[u8; 32]> {
        // Membership: the cached node map is exact (the proven key descends to its
        // own leaf, so every deeper sibling on its path is empty/default). Warm the
        // cache lazily so the production recall path is O(TREE_DEPTH), not O(n·depth).
        if self.leaves.contains_key(key) {
            self.ensure_cache();
            let cache = self.cache.borrow();
            let defaults = default_hashes();
            if let Some(nodes) = cache.nodes.as_ref() {
                return (0..TREE_DEPTH)
                    .map(|depth| {
                        let child_depth = depth + 1;
                        let sibling = sibling_prefix(key, child_depth);
                        nodes
                            .get(&(child_depth, sibling))
                            .copied()
                            .unwrap_or(defaults[TREE_DEPTH - child_depth])
                    })
                    .collect();
            }
            drop(cache);
        }

        // Non-membership: keys that share a prefix with an existing leaf need the
        // intermediate single-leaf subtree hashes that the cache folds away, so we
        // recompute from the leaf set. This path is not on the recall hot budget.
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut current = collect_leaves(&self.leaves);
        for depth in 0..TREE_DEPTH {
            let (left, right) = partition(&current, depth);
            if key_bit(key, depth) {
                path.push(hash_subtree(left, depth + 1, self.chameleon.as_ref()));
                current = right;
            } else {
                path.push(hash_subtree(right, depth + 1, self.chameleon.as_ref()));
                current = left;
            }
        }
        path
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

fn partition_index(entries: &[Leaf], depth: usize) -> usize {
    entries.partition_point(|(key, _)| !key_bit(key, depth))
}

fn prefix_key(key: &[u8; 32], depth: usize) -> [u8; 32] {
    debug_assert!(depth <= TREE_DEPTH);
    let mut prefix = [0u8; 32];
    let whole_bytes = depth / 8;
    let rem_bits = depth % 8;

    if whole_bytes > 0 {
        prefix[..whole_bytes].copy_from_slice(&key[..whole_bytes]);
    }
    if rem_bits > 0 {
        prefix[whole_bytes] = key[whole_bytes] & (0xff << (8 - rem_bits));
    }
    prefix
}

fn sibling_prefix(key: &[u8; 32], child_depth: usize) -> [u8; 32] {
    debug_assert!((1..=TREE_DEPTH).contains(&child_depth));
    let mut sibling = prefix_key(key, child_depth);
    let bit_depth = child_depth - 1;
    sibling[bit_depth / 8] ^= 1 << (7 - (bit_depth % 8));
    sibling
}

fn hash_subtree_cached(
    entries: &[Leaf],
    depth: usize,
    chameleon: Option<&ChameleonLeafConfig>,
    defaults: &[[u8; 32]; TREE_DEPTH + 1],
    nodes: &mut BTreeMap<NodeKey, [u8; 32]>,
) -> [u8; 32] {
    if entries.is_empty() {
        return defaults[TREE_DEPTH - depth];
    }

    let hash = if entries.len() == 1 {
        hash_single_leaf_subtree(&entries[0], depth, chameleon, defaults)
    } else {
        let split = partition_index(entries, depth);
        let left = hash_subtree_cached(&entries[..split], depth + 1, chameleon, defaults, nodes);
        let right = hash_subtree_cached(&entries[split..], depth + 1, chameleon, defaults, nodes);
        hash_smt_internal(&left, &right)
    };

    nodes.insert((depth, prefix_key(&entries[0].0, depth)), hash);
    hash
}

fn hash_single_leaf_subtree(
    leaf: &Leaf,
    start_depth: usize,
    chameleon: Option<&ChameleonLeafConfig>,
    defaults: &[[u8; 32]; TREE_DEPTH + 1],
) -> [u8; 32] {
    let mut current = leaf_hash(&leaf.0, &leaf.1, chameleon);
    for depth in (start_depth..TREE_DEPTH).rev() {
        let sibling = defaults[TREE_DEPTH - (depth + 1)];
        current = hash_up(current, sibling, key_bit(&leaf.0, depth));
    }
    current
}

enum Work {
    Eval { depth: usize, entries: Vec<Leaf> },
    Merge,
}

fn leaf_hash(
    key: &[u8; 32],
    value: &[u8; 32],
    chameleon: Option<&ChameleonLeafConfig>,
) -> [u8; 32] {
    if let Some(cfg) = chameleon {
        if let Some(r) = cfg.slots.get(key) {
            return chameleon_leaf_hash(key, value, r, &cfg.trapdoor_pk);
        }
    }
    hash_smt_leaf(key, value)
}

/// Post-order heap stack — no 256-frame call-stack recursion.
fn hash_subtree(
    entries: Vec<Leaf>,
    start_depth: usize,
    chameleon: Option<&ChameleonLeafConfig>,
) -> [u8; 32] {
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
                    out.push(leaf_hash(&entries[0].0, &entries[0].1, chameleon));
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
                let Some(right) = out.pop() else {
                    return empty_root();
                };
                let Some(left) = out.pop() else {
                    return empty_root();
                };
                out.push(hash_smt_internal(&left, &right));
            }
        }
    }
    out.pop().unwrap_or_else(empty_root)
}

pub fn root_from_leaves(leaves: &BTreeMap<[u8; 32], [u8; 32]>) -> [u8; 32] {
    hash_subtree(collect_leaves(leaves), 0, None)
}

pub fn verify_root_matches(
    leaves: &BTreeMap<[u8; 32], [u8; 32]>,
    root: &[u8; 32],
) -> Result<(), MnemeError> {
    if root_from_leaves(leaves) != *root {
        return Err(MnemeError::IndexPathInvalid);
    }
    Ok(())
}
