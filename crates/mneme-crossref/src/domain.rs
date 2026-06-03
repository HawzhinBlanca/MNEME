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

pub fn hash_cap(canonical_bytes: &[u8]) -> [u8; 32] {
    hash_domain(DomainTag::Cap, canonical_bytes)
}
