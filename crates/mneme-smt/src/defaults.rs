use mneme_core::{hash_smt_internal, hash_smt_leaf};

/// SMT depth: 256-bit logical keys (blueprint §5.6).
pub const TREE_DEPTH: usize = 256;

/// Precomputed empty-subtree hashes `default[height]` (blueprint §5.6).
pub fn default_hashes() -> [[u8; 32]; TREE_DEPTH + 1] {
    static DEFAULTS: std::sync::OnceLock<[[u8; 32]; TREE_DEPTH + 1]> = std::sync::OnceLock::new();
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
    debug_assert!(depth < TREE_DEPTH);
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
