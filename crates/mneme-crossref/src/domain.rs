use blake3::Hasher;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainTag {
    Obj,
    SmtLeaf,
    SmtInternal,
    Root,
    Cap,
}

impl DomainTag {
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Obj => b"MNEME-obj-v1\x00",
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

pub fn hash_root_preimage(bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Root, bytes)
}

pub fn hash_cap(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Cap, canonical_bytes)
}
