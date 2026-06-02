//! Authenticated semantic index: Merkle-committed entries + wrapped HNSW (§5.6, §9.2).

use crate::commit::SemanticMerkleTree;
use crate::error::IndexError;
use crate::hnsw_backend::HnswBackend;
use crate::procedure::{IndexedEntry, execute_procedure_p, procedure_id};
use crate::receipt::SemanticRecallReceipt;
use mneme_core::{FixedPointEmbedding, ObjectId, Procedure, VerificationObject};
use std::collections::BTreeMap;

/// Committed ANN index with ADS verification-object prover (§9.2).
pub struct SemanticIndex {
    entries: BTreeMap<[u8; 32], IndexedEntry>,
    merkle: SemanticMerkleTree,
    hnsw: HnswBackend,
}

impl Default for SemanticIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticIndex {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            merkle: SemanticMerkleTree::from_entries(&[]),
            hnsw: HnswBackend::new(16),
        }
    }

    /// Merkle root over authenticated semantic layout (§5.7 `semantic_commit`).
    pub fn semantic_commit(&self) -> [u8; 32] {
        self.merkle.root()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert object embedding; maintains wrapped HNSW graph + Merkle commitment.
    pub fn insert(
        &mut self,
        object_id: ObjectId,
        embedding: FixedPointEmbedding,
    ) -> Result<(), IndexError> {
        let commit = embedding.commit();
        if self.entries.contains_key(object_id.as_bytes()) {
            return Err(IndexError::DuplicateObject);
        }
        self.hnsw.insert(object_id, &embedding)?;
        self.entries.insert(
            *object_id.as_bytes(),
            IndexedEntry {
                object_id,
                embedding_commit: commit,
                embedding,
            },
        );
        self.rebuild_merkle();
        Ok(())
    }

    fn rebuild_merkle(&mut self) {
        let pairs: Vec<(ObjectId, [u8; 32])> = self
            .entries
            .values()
            .map(|e| (e.object_id, e.embedding_commit))
            .collect();
        self.merkle = SemanticMerkleTree::from_entries(&pairs);
    }

    /// Remove one indexed object (merge tombstone / forget path).
    pub fn remove(&mut self, object_id: &ObjectId) -> Result<(), IndexError> {
        if self.entries.remove(object_id.as_bytes()).is_none() {
            return Err(IndexError::ObjectNotIndexed);
        }
        self.rebuild_hnsw_from_entries()?;
        self.rebuild_merkle();
        Ok(())
    }

    /// Incremental merge update: insert new embeddings; full rebuild only when removals occur.
    pub fn apply_merge_delta(
        &mut self,
        added: &[(ObjectId, FixedPointEmbedding)],
        removed: &[[u8; 32]],
    ) -> Result<(), IndexError> {
        if removed.is_empty() {
            for (id, emb) in added {
                if self.entries.contains_key(id.as_bytes()) {
                    continue;
                }
                self.insert(*id, emb.clone())?;
            }
            return Ok(());
        }
        for id in removed {
            self.entries.remove(id);
        }
        self.rebuild_hnsw_from_entries()?;
        self.rebuild_merkle();
        for (id, emb) in added {
            if !self.entries.contains_key(id.as_bytes()) {
                self.insert(*id, emb.clone())?;
            }
        }
        Ok(())
    }

    fn rebuild_hnsw_from_entries(&mut self) -> Result<(), IndexError> {
        let cap = self.entries.len().max(16);
        let mut hnsw = HnswBackend::new(cap);
        let mut ids: Vec<ObjectId> = self.entries.values().map(|e| e.object_id).collect();
        ids.sort();
        for id in ids {
            let emb = &self.entries[id.as_bytes()].embedding;
            hnsw.insert(id, emb)?;
        }
        self.hnsw = hnsw;
        Ok(())
    }

    fn sorted_entries(&self) -> Vec<IndexedEntry> {
        self.entries.values().cloned().collect()
    }

    /// Deterministic semantic search (§9.2, INV-10): integer distances, ObjectId tie-break.
    pub fn search_deterministic(
        &self,
        proc: &Procedure,
        query: &FixedPointEmbedding,
    ) -> Result<(Vec<ObjectId>, VerificationObject), IndexError> {
        let entries = self.sorted_entries();
        let (result_ids, candidates) = execute_procedure_p(proc, query, &entries);

        let nodes: Vec<([u8; 32], Vec<[u8; 32]>)> = (0..self.merkle.leaf_count())
            .map(|i| {
                let commit = self
                    .merkle
                    .leaf_hash(i)
                    .ok_or(IndexError::ObjectNotIndexed)?;
                let path = self
                    .merkle
                    .merkle_path(i)
                    .ok_or(IndexError::ObjectNotIndexed)?;
                Ok((commit, path))
            })
            .collect::<Result<_, IndexError>>()?;

        let vo = VerificationObject {
            nodes,
            candidates,
            procedure_id: procedure_id(proc),
            query_commit: query.commit(),
            result_ids,
        };
        Ok((vo.result_ids.clone(), vo))
    }

    /// Build receipt bound to signed root + `semantic_commit`.
    pub fn recall_receipt(
        &self,
        proc: &Procedure,
        query: &FixedPointEmbedding,
        root_bound: [u8; 32],
    ) -> Result<SemanticRecallReceipt, IndexError> {
        let (_, vo) = self.search_deterministic(proc, query)?;
        #[cfg(feature = "plonky2_prover")]
        {
            let mut receipt = SemanticRecallReceipt::new(root_bound, self.semantic_commit(), vo);
            crate::semantic_zk::try_attach_zk_retrieval(&mut receipt, query);
            return Ok(receipt);
        }
        #[cfg(not(feature = "plonky2_prover"))]
        {
            Ok(SemanticRecallReceipt::new(
                root_bound,
                self.semantic_commit(),
                vo,
            ))
        }
    }

    /// Wrapped ANN approximate search (not receipt-bearing — §3 honesty boundary).
    pub fn approximate_search(
        &self,
        proc: &Procedure,
        query: &FixedPointEmbedding,
    ) -> Vec<ObjectId> {
        self.hnsw
            .approximate_search(query, proc.k as usize, proc.ef_search as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verify_ads_vo;
    use mneme_core::{DistanceMetric, MnemeError, ProcedureAlgo};

    fn oid(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    fn proc() -> Procedure {
        Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 2,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        }
    }

    #[test]
    fn semantic_search_is_deterministic() {
        let mut index = SemanticIndex::new();
        index
            .insert(
                oid(0x02),
                FixedPointEmbedding::new(2, 0, vec![3, 4]).unwrap(),
            )
            .unwrap();
        index
            .insert(
                oid(0x01),
                FixedPointEmbedding::new(2, 0, vec![3, 4]).unwrap(),
            )
            .unwrap();
        index
            .insert(
                oid(0x03),
                FixedPointEmbedding::new(2, 0, vec![10, 0]).unwrap(),
            )
            .unwrap();

        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let p = proc();
        let (a, vo_a) = index.search_deterministic(&p, &query).unwrap();
        let (b, vo_b) = index.search_deterministic(&p, &query).unwrap();
        assert_eq!(a, b);
        assert_eq!(vo_a, vo_b);
    }

    #[test]
    fn receipt_binds_to_semantic_commit() {
        let mut index = SemanticIndex::new();
        index
            .insert(
                oid(0x01),
                FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
            )
            .unwrap();
        let commit = index.semantic_commit();
        let receipt = index
            .recall_receipt(
                &proc(),
                &FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap(),
                [0xab; 32],
            )
            .unwrap();
        assert!(receipt.binds_to_semantic_commit(&commit));
        verify_ads_vo(&receipt.verification_object, &commit, &proc()).unwrap();
    }

    #[test]
    fn tampered_semantic_commit_fails_verification() {
        let mut index = SemanticIndex::new();
        index
            .insert(
                oid(0x01),
                FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap(),
            )
            .unwrap();
        let receipt = index
            .recall_receipt(
                &proc(),
                &FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap(),
                [0xab; 32],
            )
            .unwrap();
        let err = verify_ads_vo(&receipt.verification_object, &[0xff; 32], &proc()).unwrap_err();
        assert_eq!(err, MnemeError::IndexPathInvalid);
    }

    #[test]
    fn apply_merge_delta_inserts_incrementally() {
        let mut index = SemanticIndex::new();
        let emb_a = FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap();
        index.insert(oid(0x01), emb_a.clone()).unwrap();
        let emb_b = FixedPointEmbedding::new(2, 0, vec![2, 0]).unwrap();
        index.apply_merge_delta(&[(oid(0x02), emb_b)], &[]).unwrap();
        assert_eq!(index.len(), 2);
        let commit_before = index.semantic_commit();
        index
            .apply_merge_delta(
                &[(
                    oid(0x03),
                    FixedPointEmbedding::new(2, 0, vec![3, 0]).unwrap(),
                )],
                &[],
            )
            .unwrap();
        assert_eq!(index.len(), 3);
        assert_ne!(index.semantic_commit(), commit_before);
    }

    #[test]
    fn approximate_may_differ_from_deterministic_procedure() {
        let mut index = SemanticIndex::new();
        for b in 1u8..=8 {
            index
                .insert(
                    oid(b),
                    FixedPointEmbedding::new(2, 0, vec![i16::from(b), 0]).unwrap(),
                )
                .unwrap();
        }
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let p = proc();
        let (det, _) = index.search_deterministic(&p, &query).unwrap();
        let _approx = index.approximate_search(&p, &query);
        // Honesty: deterministic procedure is authoritative for receipts.
        assert!(!det.is_empty());
    }
}
