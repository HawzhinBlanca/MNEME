use crate::defaults::{TREE_DEPTH, default_hashes, empty_root, hash_up, key_bit};
use mneme_core::{MnemeError, hash_smt_internal, hash_smt_leaf};
#[cfg(feature = "experimental_redaction")]
use mneme_crypto::chameleon_leaf_hash;
use std::cell::RefCell;
use std::collections::BTreeMap;

pub const TOMBSTONE: [u8; 32] = [0xff; 32];

type Leaf = ([u8; 32], [u8; 32]);
type NodeKey = (usize, [u8; 32]);

/// Chameleon-randomness per key for root-stable redaction (§13.3).
#[cfg(feature = "experimental_redaction")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChameleonLeafConfig {
    pub trapdoor_pk: [u8; 32],
    pub slots: BTreeMap<[u8; 32], [u8; 32]>,
}

#[cfg(not(feature = "experimental_redaction"))]
struct ChameleonLeafConfig;

/// Largest dirty-key batch still updated incrementally; beyond this a single full
/// rebuild is cheaper than recomputing many independent paths (bulk seed / load).
const INCREMENTAL_DIRTY_MAX: usize = 64;

/// Lazily-built proof caches. Interior mutability lets read paths (`root`,
/// membership `auth_path`) warm the cache on first use and reuse it thereafter.
///
/// Writes record only the *changed keys* in `dirty` rather than discarding the
/// whole cache, so a single `upsert`/`tombstone` followed by `root()` recomputes
/// just that key's O(TREE_DEPTH) root-to-leaf path instead of re-folding all
/// leaves (the O(n·TREE_DEPTH) cost that dominated every `remember`/`forget`/
/// `merge` commit — §22 K5/K6). The node map stays byte-identical to a full
/// rebuild (validated against `root_from_leaves`), so membership `auth_path`
/// proofs are unaffected.
#[derive(Clone, Debug, Default)]
struct TreeCache {
    root: Option<[u8; 32]>,
    nodes: Option<BTreeMap<NodeKey, [u8; 32]>>,
    dirty: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTree {
    pub(crate) leaves: BTreeMap<[u8; 32], [u8; 32]>,
    #[cfg(feature = "experimental_redaction")]
    pub chameleon: Option<ChameleonLeafConfig>,
    cache: RefCell<TreeCache>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
            #[cfg(feature = "experimental_redaction")]
            chameleon: None,
            cache: RefCell::new(TreeCache {
                root: Some(empty_root()),
                nodes: Some(BTreeMap::new()),
                dirty: Vec::new(),
            }),
        }
    }

    /// Fully drop the proof caches; used when the hashing basis changes (chameleon
    /// config / redaction) so no incremental path update is valid.
    fn invalidate(&self) {
        let mut cache = self.cache.borrow_mut();
        cache.root = None;
        cache.nodes = None;
        cache.dirty.clear();
    }

    /// Record that `key`'s root-to-leaf path must be recomputed on the next read.
    /// Keeps the node cache warm so the recompute can be incremental.
    fn mark_dirty(&self, key: [u8; 32]) {
        let mut cache = self.cache.borrow_mut();
        if cache.nodes.is_some() {
            cache.dirty.push(key);
        }
        cache.root = None;
    }

    /// Bring the cache up to date with the current leaf set (idempotent). Performs
    /// an incremental path recompute for a small dirty batch, else a full rebuild.
    fn sync_cache(&self) {
        {
            let cache = self.cache.borrow();
            if cache.nodes.is_some() && cache.dirty.is_empty() && cache.root.is_some() {
                return;
            }
        }
        let do_full = {
            let cache = self.cache.borrow();
            cache.nodes.is_none() || cache.dirty.len() > INCREMENTAL_DIRTY_MAX
        };
        if do_full {
            self.full_rebuild();
            return;
        }
        let defaults = default_hashes();
        let mut cache = self.cache.borrow_mut();
        let dirty = std::mem::take(&mut cache.dirty);
        let Some(nodes) = cache.nodes.as_mut() else {
            // Lost the warm map between borrows; fall back to a full rebuild.
            drop(cache);
            self.full_rebuild();
            return;
        };
        for key in &dirty {
            for depth in 0..=TREE_DEPTH {
                nodes.remove(&(depth, prefix_key(key, depth)));
            }
        }
        let root = node_hash_lazy(
            &self.leaves,
            0,
            [0u8; 32],
            nodes,
            &defaults,
            self.chameleon_config(),
        );
        cache.root = Some(root);
    }

    /// Build the node cache + root from the current leaf set in a single pass,
    /// O(n·depth). Single-leaf subtrees are folded to a single cached node — this
    /// is sufficient for membership proofs and `root`, but **not** for
    /// non-membership of keys that share a prefix with an existing leaf (see
    /// `auth_path`).
    fn full_rebuild(&self) {
        let leaves = collect_leaves(&self.leaves);
        let mut nodes = BTreeMap::new();
        let defaults = default_hashes();
        let root = hash_subtree_cached(&leaves, 0, self.chameleon_config(), &defaults, &mut nodes);
        let mut cache = self.cache.borrow_mut();
        cache.root = Some(root);
        cache.nodes = Some(nodes);
        cache.dirty.clear();
    }

    #[cfg(feature = "experimental_redaction")]
    fn chameleon_config(&self) -> Option<&ChameleonLeafConfig> {
        self.chameleon.as_ref()
    }

    #[cfg(not(feature = "experimental_redaction"))]
    fn chameleon_config(&self) -> Option<&ChameleonLeafConfig> {
        None
    }

    #[cfg(feature = "experimental_redaction")]
    pub fn enable_chameleon(&mut self, trapdoor_pk: [u8; 32]) {
        self.chameleon = Some(ChameleonLeafConfig {
            trapdoor_pk,
            slots: BTreeMap::new(),
        });
        self.invalidate();
    }

    #[cfg(feature = "experimental_redaction")]
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

    #[cfg(feature = "experimental_redaction")]
    pub fn chameleon_slot(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.chameleon
            .as_ref()
            .and_then(|c| c.slots.get(key).copied())
    }

    /// Replace leaf value + chameleon randomness (root unchanged when collision valid).
    #[cfg(feature = "experimental_redaction")]
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
        self.sync_cache();
        self.cache.borrow().root.unwrap_or_else(empty_root)
    }

    pub fn upsert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
        self.mark_dirty(key);
    }

    pub fn tombstone(&mut self, key: [u8; 32]) {
        self.leaves.insert(key, TOMBSTONE);
        self.mark_dirty(key);
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
        self.sync_cache();
    }

    pub fn upsert_and_root(&mut self, key: [u8; 32], value: [u8; 32]) -> [u8; 32] {
        self.leaves.insert(key, value);
        self.mark_dirty(key);
        self.root()
    }

    pub(crate) fn auth_path(&self, key: &[u8; 32]) -> Vec<[u8; 32]> {
        // Membership: the cached node map is exact (the proven key descends to its
        // own leaf, so every deeper sibling on its path is empty/default). Warm the
        // cache lazily so the production recall path is O(TREE_DEPTH), not O(n·depth).
        if self.leaves.contains_key(key) {
            self.sync_cache();
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
                path.push(hash_subtree(left, depth + 1, self.chameleon_config()));
                current = right;
            } else {
                path.push(hash_subtree(right, depth + 1, self.chameleon_config()));
                current = left;
            }
        }
        path
    }
}

fn collect_leaves(map: &BTreeMap<[u8; 32], [u8; 32]>) -> Vec<Leaf> {
    map.iter().map(|(k, v)| (*k, *v)).collect()
}

/// Inclusive key range covering every leaf under `prefix` at `depth` (the keys
/// whose first `depth` bits equal `prefix`). Used to drive incremental recompute
/// from a sorted leaf map without materializing the full leaf vector.
fn prefix_range(prefix: &[u8; 32], depth: usize) -> ([u8; 32], [u8; 32]) {
    let mut hi = *prefix;
    let whole = depth / 8;
    let rem = depth % 8;
    let mut start = whole;
    if rem != 0 {
        hi[whole] |= 0xffu8 >> rem;
        start = whole + 1;
    }
    for byte in hi.iter_mut().skip(start) {
        *byte = 0xff;
    }
    (*prefix, hi)
}

fn set_prefix_bit(prefix: &mut [u8; 32], depth: usize) {
    prefix[depth / 8] |= 1 << (7 - (depth % 8));
}

/// Compute (and memoize) the subtree hash at `(depth, prefix)` over the current
/// leaves, reusing any already-cached node. Identical in value and cache keying
/// to `hash_subtree_cached`, but only descends/recomputes the subtrees that are
/// missing from `nodes` — i.e. the dirty key's path plus any newly split sibling.
fn node_hash_lazy(
    leaves: &BTreeMap<[u8; 32], [u8; 32]>,
    depth: usize,
    prefix: [u8; 32],
    nodes: &mut BTreeMap<NodeKey, [u8; 32]>,
    defaults: &[[u8; 32]; TREE_DEPTH + 1],
    chameleon: Option<&ChameleonLeafConfig>,
) -> [u8; 32] {
    if let Some(h) = nodes.get(&(depth, prefix)) {
        return *h;
    }
    let (lo, hi) = prefix_range(&prefix, depth);
    let mut iter = leaves.range(lo..=hi);
    let Some((&k0, &v0)) = iter.next() else {
        // Empty subtree folds to the default for its height; not cached.
        return defaults[TREE_DEPTH - depth];
    };
    let hash = if iter.next().is_none() {
        hash_single_leaf_subtree(&(k0, v0), depth, chameleon, defaults)
    } else {
        let left_prefix = prefix;
        let mut right_prefix = prefix;
        set_prefix_bit(&mut right_prefix, depth);
        let left = node_hash_lazy(leaves, depth + 1, left_prefix, nodes, defaults, chameleon);
        let right = node_hash_lazy(leaves, depth + 1, right_prefix, nodes, defaults, chameleon);
        hash_smt_internal(&left, &right)
    };
    nodes.insert((depth, prefix), hash);
    hash
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
    #[cfg(feature = "experimental_redaction")]
    if let Some(cfg) = chameleon {
        if let Some(r) = cfg.slots.get(key) {
            return chameleon_leaf_hash(key, value, r, &cfg.trapdoor_pk);
        }
    }
    #[cfg(not(feature = "experimental_redaction"))]
    let _ = chameleon;
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

#[cfg(test)]
mod incremental_tests {
    use super::*;

    // Deterministic LCG so the property test is reproducible without extra deps.
    fn next_key(state: &mut u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        out
    }

    /// The incrementally-maintained root must equal a from-scratch fold of the
    /// leaf set after every mutation — including re-upserts, tombstones, and new
    /// keys that split existing single-leaf subtrees.
    #[test]
    fn incremental_root_matches_full_rebuild() {
        let mut tree = SparseMerkleTree::new();
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for i in 0..400u32 {
            let key = next_key(&mut state);
            tree.upsert(key, [i as u8; 32]);
            keys.push(key);
            assert_eq!(
                tree.root(),
                root_from_leaves(&tree.leaves),
                "after insert {i}"
            );

            // Re-upsert (value change) and tombstone an earlier key to exercise
            // the in-place path recompute on warm caches.
            if i % 5 == 4 {
                let victim = keys[(i as usize) / 2];
                tree.upsert(victim, [0xAB; 32]);
                assert_eq!(
                    tree.root(),
                    root_from_leaves(&tree.leaves),
                    "after re-upsert {i}"
                );
                tree.tombstone(keys[(i as usize) / 3]);
                assert_eq!(
                    tree.root(),
                    root_from_leaves(&tree.leaves),
                    "after tombstone {i}"
                );
            }
        }
    }

    /// Two keys sharing a long prefix force a deep split; the incremental update
    /// must still match the full fold and keep membership proofs valid.
    #[test]
    fn incremental_handles_deep_prefix_split() {
        let mut tree = SparseMerkleTree::new();
        let mut a = [0u8; 32];
        a[0] = 0xFF;
        let mut b = a;
        b[31] = 0x01; // shares all but the last bit with `a`
        tree.upsert(a, [1u8; 32]);
        let root_a = tree.root();
        tree.upsert(b, [2u8; 32]);
        assert_eq!(tree.root(), root_from_leaves(&tree.leaves));
        assert_ne!(tree.root(), root_a);
        // Membership proofs over the split subtree must still verify (fold back to root).
        let proof_a = tree.prove_membership(a).expect("membership a");
        let proof_b = tree.prove_membership(b).expect("membership b");
        SparseMerkleTree::verify_membership(&proof_a).expect("verify a");
        SparseMerkleTree::verify_membership(&proof_b).expect("verify b");
        assert_eq!(proof_a.root, tree.root());
    }
}
