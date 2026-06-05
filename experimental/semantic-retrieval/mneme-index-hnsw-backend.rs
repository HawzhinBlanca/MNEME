//! Wrapped `fast-hnsw` graph — storage only; procedure P uses integer replay (§1.2, §15.3).

use fast_hnsw::Config;
use fast_hnsw::distance::SquaredEuclidean;
use fast_hnsw::labeled::LabeledIndex;
use fast_hnsw::payload::{DecodeError, Payload};
use mneme_core::{FixedPointEmbedding, ObjectId};

use crate::error::IndexError;

/// Payload stored alongside each HNSW vector.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObjectIdPayload([u8; 32]);

impl Payload for ObjectIdPayload {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.len() < 32 {
            return Err(DecodeError("ObjectIdPayload: too short"));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[..32]);
        Ok((Self(id), 32))
    }

    fn fixed_stride() -> Option<usize> {
        Some(32)
    }
}

/// External ANN engine wrapper (blueprint §1.2: no custom ANN).
pub struct HnswBackend {
    index: LabeledIndex<SquaredEuclidean, ObjectIdPayload>,
}

impl std::fmt::Debug for HnswBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HnswBackend")
            .field("len", &self.len())
            .finish()
    }
}

impl Default for HnswBackend {
    fn default() -> Self {
        Self::new(16)
    }
}

impl HnswBackend {
    pub fn new(max_elements: usize) -> Self {
        let cap = max_elements.max(16);
        let config = Config {
            m: 16,
            m0: Some(32),
            ef_construction: 200,
            use_heuristic: true,
            extend_candidates: false,
            keep_pruned: false,
            prune_strategy: fast_hnsw::PruneStrategy::Simple,
            capacity: cap,
        };
        Self {
            index: LabeledIndex::new(config, SquaredEuclidean),
        }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Insert into wrapped HNSW; call site should use ascending `ObjectId` order for determinism.
    pub fn insert(
        &mut self,
        object_id: ObjectId,
        embedding: &FixedPointEmbedding,
    ) -> Result<(), IndexError> {
        for i in 0..self.index.len() {
            if self.index.get_payload(i).0 == *object_id.as_bytes() {
                return Err(IndexError::DuplicateObject);
            }
        }
        let vec = embedding_to_f32(embedding);
        self.index
            .insert(vec, ObjectIdPayload(*object_id.as_bytes()));
        Ok(())
    }

    /// Approximate search (not receipt-bearing — §3 honesty boundary).
    pub fn approximate_search(
        &self,
        query: &FixedPointEmbedding,
        k: usize,
        ef: usize,
    ) -> Vec<ObjectId> {
        if self.is_empty() {
            return Vec::new();
        }
        let vec = embedding_to_f32(query);
        let ef = ef.max(k).max(1);
        self.index
            .search(&vec, k, ef)
            .into_iter()
            .map(|r| ObjectId(r.payload.0))
            .collect()
    }
}

fn embedding_to_f32(embedding: &FixedPointEmbedding) -> Vec<f32> {
    let factor = 2f32.powi(i32::from(embedding.scale));
    embedding
        .components
        .iter()
        .map(|c| f32::from(*c) * factor)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_hnsw_accepts_inserts() {
        let mut backend = HnswBackend::new(8);
        let emb = FixedPointEmbedding::new(2, 0, vec![1, 2]).unwrap();
        backend.insert(ObjectId([1; 32]), &emb).unwrap();
        assert_eq!(backend.len(), 1);
    }
}
