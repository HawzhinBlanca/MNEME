use blake3::Hasher;

/// Domain-separation tags (blueprint §5.2). ASCII, NUL-terminated, frozen at v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainTag {
    Obj,
    Dag,
    SmtLeaf,
    SmtInternal,
    Sem,
    Root,
    Cap,
    Ckpt,
    Rcpt,
    ContextAssembled,
    CertifiedMemorySet,
}

impl DomainTag {
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Obj => b"MNEME-obj-v1\x00",
            Self::Dag => b"MNEME-dag-v1\x00",
            Self::SmtLeaf => b"MNEME-smt-leaf-v1\x00",
            Self::SmtInternal => b"MNEME-smt-int-v1\x00",
            Self::Sem => b"MNEME-sem-v1\x00",
            Self::Root => b"MNEME-root-v1\x00",
            Self::Cap => b"MNEME-cap-v1\x00",
            Self::Ckpt => b"MNEME-ckpt-v1\x00",
            Self::Rcpt => b"MNEME-receipt-v1\x00",
            Self::ContextAssembled => b"MNEME-ctx-assembled-v1\x00",
            Self::CertifiedMemorySet => b"MNEME-cms-v1\x00",
        }
    }
}

pub fn hash_domain(tag: DomainTag, payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(tag.bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

/// INV-1: object identity = BLAKE3(OBJ ‖ canonical_cbor(object_without_id)).
pub fn hash_obj(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Obj, canonical_bytes)
}

/// DAG node commitment (§6.2: == OBJ id for object nodes).
pub fn hash_dag(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Dag, canonical_bytes)
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

pub fn hash_root_preimage(bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Root, bytes)
}

pub fn hash_cap(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Cap, canonical_bytes)
}

pub fn hash_ckpt(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Ckpt, canonical_bytes)
}

pub fn hash_receipt_preimage(bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Rcpt, bytes)
}

/// Deterministic assembled-context digest (Phase II P2-3/4).
pub fn hash_context_assembled(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Certified memory-set digest (order-only on object ids).
pub fn hash_certified_memory_set(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_are_nul_terminated_ascii() {
        for tag in [
            DomainTag::Obj,
            DomainTag::Dag,
            DomainTag::SmtLeaf,
            DomainTag::SmtInternal,
            DomainTag::Sem,
            DomainTag::Root,
            DomainTag::Cap,
            DomainTag::Ckpt,
            DomainTag::Rcpt,
            DomainTag::ContextAssembled,
            DomainTag::CertifiedMemorySet,
        ] {
            let b = tag.bytes();
            assert!(b.starts_with(b"MNEME-"));
            assert_eq!(b.last(), Some(&0));
        }
    }
}
