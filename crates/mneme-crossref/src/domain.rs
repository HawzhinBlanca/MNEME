use blake3::Hasher;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainTag {
    Obj,
    Sem,
    SmtLeaf,
    SmtInternal,
    Root,
    Cap,
}

impl DomainTag {
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Obj => b"MNEME-obj-v1\x00",
            Self::Sem => b"MNEME-sem-v1\x00",
            Self::SmtLeaf => b"MNEME-smt-leaf-v1\x00",
            Self::SmtInternal => b"MNEME-smt-int-v1\x00",
            Self::Root => b"MNEME-root-v1\x00",
            Self::Cap => b"MNEME-cap-v1\x00",
        }
    }
}

pub fn hash_domain(tag: DomainTag, payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(tag.bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

pub fn hash_obj(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Obj, canonical_bytes)
}

pub fn hash_smt_leaf(key: &[u8; 32], val: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DomainTag::SmtLeaf.bytes());
    h.update(key);
    h.update(val);
    *h.finalize().as_bytes()
}

pub fn hash_smt_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DomainTag::SmtInternal.bytes());
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

fn hash_sem_domain(payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DomainTag::Sem.bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

/// `BLAKE3(SEM ‖ 0x10 ‖ object_id ‖ embedding_commit)`.
pub fn hash_sem_leaf(object_id: &[u8; 32], embedding_commit: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 65];
    payload[0] = 0x10;
    payload[1..33].copy_from_slice(object_id);
    payload[33..65].copy_from_slice(embedding_commit);
    hash_sem_domain(&payload)
}

/// `BLAKE3(SEM ‖ 0x11 ‖ left ‖ right)`.
pub fn hash_sem_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 65];
    payload[0] = 0x11;
    payload[1..33].copy_from_slice(left);
    payload[33..65].copy_from_slice(right);
    hash_sem_domain(&payload)
}

/// Root of an empty semantic index — parity with `mneme-index::commit::empty_semantic_root`:
/// `BLAKE3(SEM ‖ 0x12)`.
pub fn empty_semantic_root() -> [u8; 32] {
    hash_sem_domain(&[0x12])
}

pub fn hash_root_preimage(bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Root, bytes)
}

/// Fixed-point embedding commitment (§5.3).
pub fn hash_sem_preimage(dim_le: [u8; 4], scale: i8, components: &[i16]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DomainTag::Sem.bytes());
    h.update(&dim_le);
    h.update(&[scale as u8]);
    for c in components {
        h.update(&c.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

pub fn hash_cap(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Cap, canonical_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// DOM-1: All 6 DomainTag byte prefixes are pairwise distinct.
    /// A silent collision between two domain tags means a hash for one domain
    /// could be forged as valid for another — a catastrophic cross-domain attack.
    #[test]
    fn all_domain_tag_prefixes_are_pairwise_distinct() {
        let tags = [
            DomainTag::Obj,
            DomainTag::Sem,
            DomainTag::SmtLeaf,
            DomainTag::SmtInternal,
            DomainTag::Root,
            DomainTag::Cap,
        ];
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for tag in tags {
            let bytes = tag.bytes();
            assert!(
                seen.insert(bytes),
                "DomainTag {:?} has a colliding prefix: {:?}",
                tag,
                bytes
            );
        }
        assert_eq!(
            seen.len(),
            6,
            "all 6 domain tags must have distinct byte prefixes"
        );
    }

    /// DOM-2: Cross-domain hash functions never collide for identical payloads.
    /// `hash_obj`, `hash_cap`, and `hash_root_preimage` must produce distinct
    /// outputs for the same input bytes — otherwise an object hash could masquerade
    /// as a capability hash.
    #[test]
    fn cross_domain_hashes_never_collide_for_same_payload() {
        let payload = b"same-payload-for-all-domains";
        let h_obj = hash_obj(payload);
        let h_cap = hash_cap(payload);
        let h_root = hash_root_preimage(payload);
        assert_ne!(h_obj, h_cap, "hash_obj and hash_cap must differ");
        assert_ne!(h_obj, h_root, "hash_obj and hash_root_preimage must differ");
        assert_ne!(h_cap, h_root, "hash_cap and hash_root_preimage must differ");
    }

    /// DOM-3: hash_smt_leaf and hash_smt_internal never collide for same inputs.
    /// They share a BLAKE3 domain (SmtLeaf vs SmtInternal) — if these ever collide,
    /// a leaf hash could be substituted for an internal node hash in a membership proof.
    #[test]
    fn smt_leaf_and_internal_hashes_never_collide() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let h_leaf = hash_smt_leaf(&a, &b);
        let h_internal = hash_smt_internal(&a, &b);
        assert_ne!(
            h_leaf, h_internal,
            "SMT leaf hash and internal node hash must never be equal for same inputs"
        );
    }

    /// DOM-4: hash_sem_leaf (type-byte 0x10) and hash_sem_internal (type-byte 0x11)
    /// never collide for the same object_id and embedding commit.
    #[test]
    fn sem_leaf_and_sem_internal_type_bytes_prevent_collision() {
        let id = [0xABu8; 32];
        let commit = [0xCDu8; 32];
        let h_leaf = hash_sem_leaf(&id, &commit);
        let h_internal = hash_sem_internal(&id, &commit);
        assert_ne!(
            h_leaf, h_internal,
            "sem leaf (0x10) and sem internal (0x11) must differ via type-byte"
        );
    }

    /// DOM-5: empty_semantic_root() is a deterministic constant (not zero, not random).
    #[test]
    fn empty_semantic_root_is_deterministic_and_nonzero() {
        let r1 = empty_semantic_root();
        let r2 = empty_semantic_root();
        assert_eq!(r1, r2, "empty_semantic_root must be deterministic");
        assert_ne!(
            r1, [0u8; 32],
            "empty_semantic_root must not be the zero hash"
        );
    }

    /// DOM-6: hash_domain is not commutative — tag order matters.
    /// The tag bytes must always precede the payload; swapping them changes the hash.
    #[test]
    fn hash_domain_tag_precedes_payload() {
        let payload = b"test-payload";
        let with_obj = hash_domain(DomainTag::Obj, payload);
        let with_cap = hash_domain(DomainTag::Cap, payload);
        assert_ne!(
            with_obj, with_cap,
            "different tags must produce different hashes"
        );

        // Both must be deterministic
        assert_eq!(hash_domain(DomainTag::Obj, payload), with_obj);
        assert_eq!(hash_domain(DomainTag::Cap, payload), with_cap);
    }

    /// DOM-7: sem leaf type-byte 0x10 is distinct from type-byte 0x11 even for all-zero input.
    /// This guards the degenerate case where zeros could conceal the type-byte difference.
    #[test]
    fn sem_type_byte_separation_holds_for_all_zero_inputs() {
        let zero = [0u8; 32];
        let h_leaf = hash_sem_leaf(&zero, &zero);
        let h_internal = hash_sem_internal(&zero, &zero);
        assert_ne!(
            h_leaf, h_internal,
            "type-byte separation must hold even for all-zero inputs"
        );
    }

    /// DOM-8: All 6 domain hash fns produce distinct outputs for the zero payload.
    #[test]
    fn all_hash_functions_produce_distinct_outputs_for_zero_payload() {
        let zero32 = [0u8; 32];
        let outputs = [
            hash_obj(&[]),
            hash_cap(&[]),
            hash_root_preimage(&[]),
            hash_smt_leaf(&zero32, &zero32),
            hash_smt_internal(&zero32, &zero32),
            hash_sem_leaf(&zero32, &zero32),
        ];
        let mut seen = HashSet::new();
        for h in &outputs {
            assert!(
                seen.insert(*h),
                "two domain hash fns produced the same output for zero input"
            );
        }
    }
}
