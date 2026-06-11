//! Additive multiset hash (MuHash / LtHash) over Ristretto for object-set convergence.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

pub const MSET_COMMIT_LEN: usize = 32;
const MSET_HASH_DOMAIN: &[u8] = b"MNEME/vcp/convergence-mset/v1";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectMultiset { sum: RistrettoPoint }

impl ObjectMultiset {
    pub fn empty() -> Self { Self::default() }
    pub fn from_object_ids<'a>(ids: impl IntoIterator<Item = &'a [u8; 32]>) -> Self {
        let mut mset = Self::empty(); for id in ids { mset.insert(id); } mset
    }
    pub fn insert(&mut self, object_id: &[u8; 32]) { self.sum += hash_object_to_group(object_id); }
    pub fn remove(&mut self, object_id: &[u8; 32]) { self.sum -= hash_object_to_group(object_id); }
    pub fn merge(&mut self, other: &Self) { self.sum += other.sum; }
    pub fn commitment(&self) -> [u8; 32] {
        let mut out = [0u8; MSET_COMMIT_LEN]; out.copy_from_slice(self.sum.compress().as_bytes()); out
    }
    pub fn commitments_equal(a: &[u8; 32], b: &[u8; 32]) -> bool { a == b }
}

pub fn hash_object_to_group(object_id: &[u8; 32]) -> RistrettoPoint {
    let mut reader = blake3::Hasher::new().update(MSET_HASH_DOMAIN).update(object_id).finalize_xof();
    let mut wide = [0u8; 64]; reader.fill(&mut wide); RistrettoPoint::from_uniform_bytes(&wide)
}

pub fn decompress_commitment(commit: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(commit).ok().and_then(|c| c.decompress())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn mset_insert_order_independent() {
        let ids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let forward = ObjectMultiset::from_object_ids(ids.iter());
        let mut reverse = ObjectMultiset::empty(); for id in ids.iter().rev() { reverse.insert(id); }
        assert_eq!(forward.commitment(), reverse.commitment());
    }
    #[test] fn mset_lthash_insert_remove_roundtrip() {
        let id = [0x42u8; 32]; let mut mset = ObjectMultiset::empty(); mset.insert(&id); mset.remove(&id);
        assert_eq!(mset.commitment(), ObjectMultiset::empty().commitment());
    }
    #[test] fn mset_merge_commutative() {
        let a = [[0x01u8; 32], [0x02u8; 32]]; let b = [[0x03u8; 32], [0x04u8; 32]];
        let mut ab = ObjectMultiset::from_object_ids(a.iter()); ab.merge(&ObjectMultiset::from_object_ids(b.iter()));
        let mut ba = ObjectMultiset::from_object_ids(b.iter()); ba.merge(&ObjectMultiset::from_object_ids(a.iter()));
        assert_eq!(ab.commitment(), ba.commitment());
    }
}
