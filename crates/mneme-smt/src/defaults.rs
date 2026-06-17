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

#[cfg(test)]
mod tests {
    use super::*;

    /// DEFAULTS-1: empty_root is deterministic and non-zero.
    #[test]
    fn empty_root_deterministic_and_nonzero() {
        let r1 = empty_root();
        let r2 = empty_root();
        assert_eq!(r1, r2, "empty_root must be deterministic");
        assert_ne!(r1, [0u8; 32], "empty_root must not be all-zeros");
    }

    /// DEFAULTS-2: default_hashes returns an array of TREE_DEPTH+1 entries.
    #[test]
    fn default_hashes_has_correct_length() {
        let d = default_hashes();
        assert_eq!(
            d.len(),
            TREE_DEPTH + 1,
            "default_hashes must have TREE_DEPTH+1 entries"
        );
    }

    /// DEFAULTS-3: Each default hash level is distinct (no collisions between levels).
    /// A collision would mean the empty-subtree commitment is ambiguous.
    #[test]
    fn default_hashes_levels_are_distinct() {
        let d = default_hashes();
        // Spot check: first, middle, and last are all distinct.
        assert_ne!(d[0], d[1], "level 0 and level 1 defaults must be distinct");
        assert_ne!(
            d[0], d[128],
            "level 0 and level 128 defaults must be distinct"
        );
        assert_ne!(
            d[0], d[256],
            "level 0 and level 256 (root) must be distinct"
        );
        assert_ne!(d[128], d[256]);
    }

    /// DEFAULTS-4: key_bit extracts the correct bit for known patterns.
    /// Depth 0 is the MSB of byte 0.
    #[test]
    fn key_bit_extracts_correct_bit() {
        // Key with MSB set: 0x80 = 0b10000000
        let mut key = [0u8; 32];
        key[0] = 0x80;
        assert!(key_bit(&key, 0), "depth 0 = MSB of byte 0 = 1 for 0x80");
        assert!(
            !key_bit(&key, 1),
            "depth 1 = second bit of byte 0 = 0 for 0x80"
        );

        // Key with LSB of byte 0 set: 0x01 = 0b00000001
        let mut key2 = [0u8; 32];
        key2[0] = 0x01;
        assert!(!key_bit(&key2, 0), "depth 0 = MSB of 0x01 = 0");
        assert!(key_bit(&key2, 7), "depth 7 = LSB of byte 0 = 1 for 0x01");
    }

    /// DEFAULTS-5: hash_up is NOT commutative — left vs right must matter.
    /// If left==right the hash is the same for both directions (trivially).
    /// Use distinct values to ensure direction changes the output.
    #[test]
    fn hash_up_direction_matters() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let go_left = hash_up(a, b, false);
        let go_right = hash_up(a, b, true);
        assert_ne!(
            go_left, go_right,
            "hash_up must produce different results for left vs right"
        );
    }

    /// DEFAULTS-6: fold_auth_path rejects a wrong-length path.
    #[test]
    fn fold_auth_path_rejects_wrong_length() {
        let leaf = [0u8; 32];
        let key = [0u8; 32];
        let short = vec![[0u8; 32]; TREE_DEPTH - 1];
        assert!(
            fold_auth_path(leaf, &key, &short).is_err(),
            "short path must be rejected"
        );
        let long = vec![[0u8; 32]; TREE_DEPTH + 1];
        assert!(
            fold_auth_path(leaf, &key, &long).is_err(),
            "long path must be rejected"
        );
    }
}
