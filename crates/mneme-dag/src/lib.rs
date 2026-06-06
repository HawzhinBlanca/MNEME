//! Provenance DAG head-set Merkle root, acyclicity-by-construction (INV-3),
//! and RFC 9162-style consistency proofs between dag-head checkpoints (§5.6, §9.3).

#![deny(warnings)]

mod checkpoint;

use checkpoint::{consistency_proof, root_at_size, verify_consistency};
use mneme_core::{ConsistencyProof, MnemeError, ObjectId};
use mneme_smt::SparseMerkleTree;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Live provenance index: head-set SMT root + known-object set + checkpoint log.
#[derive(Clone, Debug)]
pub struct DagIndex {
    heads: SparseMerkleTree,
    known: BTreeSet<[u8; 32]>,
    checkpoints: Vec<[u8; 32]>,
}

impl Default for DagIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl DagIndex {
    pub fn new() -> Self {
        let heads = SparseMerkleTree::new();
        let initial_root = heads.root();
        Self {
            heads,
            known: BTreeSet::new(),
            checkpoints: vec![initial_root],
        }
    }

    /// Current dag-head-set Merkle root (SMT over live head ids).
    pub fn root(&self) -> [u8; 32] {
        self.heads.root()
    }

    /// Latest checkpoint sequence (matches store root sequence semantics).
    pub fn sequence(&self) -> u64 {
        u64::try_from(self.checkpoints.len().saturating_sub(1))
            .expect("checkpoint sequence fits in u64")
    }

    /// Whether `id` was ever inserted into the provenance DAG (head or internal).
    pub fn has(&self, id: &[u8; 32]) -> bool {
        self.known.contains(id)
    }

    /// Replace a known object id (e.g. trust-tier promotion changes content hash).
    /// Tombstones the old head if live, inserts `new_id` with unchanged parents, appends checkpoint.
    pub fn rekey_object(
        &mut self,
        old_id: [u8; 32],
        new_id: [u8; 32],
        parent_ids: &[[u8; 32]],
    ) -> Result<(), MnemeError> {
        if !self.known.contains(&old_id) {
            return Err(MnemeError::ProvenanceBroken);
        }
        validate_insert(&self.known, new_id, parent_ids)?;
        if self.heads.contains_live(&old_id) {
            self.heads.tombstone(old_id);
        }
        self.known.insert(new_id);
        self.heads.upsert(new_id, new_id);
        self.checkpoints.push(self.heads.root());
        Ok(())
    }

    /// Batch-insert parentless heads with a single checkpoint (bulk seed / perf bench).
    pub fn seed_independent_heads(&mut self, ids: &[ObjectId]) -> Result<(), MnemeError> {
        for id in ids {
            let id_bytes = *id.as_bytes();
            validate_insert(&self.known, id_bytes, &[])?;
            self.known.insert(id_bytes);
            self.heads.upsert(id_bytes, id_bytes);
        }
        self.heads.rebuild_root_cache();
        self.checkpoints.push(self.heads.root());
        Ok(())
    }

    /// Insert `id`, retire parent heads, append checkpoint. Enforces INV-3.
    pub fn update_heads(
        &mut self,
        id: ObjectId,
        parent_ids: &[[u8; 32]],
    ) -> Result<(), MnemeError> {
        let id_bytes = *id.as_bytes();
        validate_insert(&self.known, id_bytes, parent_ids)?;

        self.known.insert(id_bytes);
        self.heads.upsert(id_bytes, id_bytes);
        for parent in parent_ids {
            if self.heads.contains_live(parent) {
                self.heads.tombstone(*parent);
            }
        }

        self.checkpoints.push(self.heads.root());
        Ok(())
    }

    /// Rebuild the index from persisted objects in topological order.
    pub fn rebuild_from(
        &mut self,
        entries: &[(ObjectId, Vec<[u8; 32]>)],
    ) -> Result<(), MnemeError> {
        *self = Self::new();
        for (id, parents) in topo_sort(entries)? {
            self.update_heads(id, &parents)?;
        }
        Ok(())
    }

    /// Membership proof that `head_id` is a current dag head under `self.root()`.
    pub fn prove_head_membership(
        &self,
        head_id: [u8; 32],
    ) -> Result<mneme_core::MerkleProof, MnemeError> {
        let proof = self.heads.prove_membership(head_id)?;
        Ok(mneme_core::MerkleProof {
            key: proof.key,
            value: proof.value,
            path: proof.path,
            root: proof.root,
            leaf_index: proof.leaf_index,
        })
    }

    /// RFC 9162 consistency proof between two checkpoint sequences.
    pub fn prove_consistency(
        &self,
        from_sequence: u64,
        to_sequence: u64,
    ) -> Result<ConsistencyProof, MnemeError> {
        let path = consistency_proof(&self.checkpoints, from_sequence, to_sequence)?;
        Ok(ConsistencyProof {
            from_sequence,
            to_sequence,
            path,
        })
    }

    /// Verify a consistency proof against this index's checkpoint log.
    pub fn verify_consistency_proof(&self, proof: &ConsistencyProof) -> Result<(), MnemeError> {
        verify_consistency(
            &self.checkpoints,
            proof.from_sequence,
            proof.to_sequence,
            &proof.path,
        )
    }

    /// Merkle root over the checkpoint log at `sequence` (for cross-checking).
    pub fn checkpoint_tree_root(&self, sequence: u64) -> Result<[u8; 32], MnemeError> {
        let size = usize_from_u64(sequence)? + 1;
        if size > self.checkpoints.len() {
            return Err(MnemeError::RootInconsistent);
        }
        Ok(root_at_size(&self.checkpoints, size))
    }

    /// Dag head root recorded at `sequence`.
    pub fn checkpoint_at(&self, sequence: u64) -> Result<[u8; 32], MnemeError> {
        self.checkpoints
            .get(usize_from_u64(sequence)?)
            .copied()
            .ok_or(MnemeError::RootInconsistent)
    }
}

fn validate_insert(
    known: &BTreeSet<[u8; 32]>,
    id: [u8; 32],
    parent_ids: &[[u8; 32]],
) -> Result<(), MnemeError> {
    if known.contains(&id) {
        return Err(MnemeError::ProvenanceBroken);
    }
    let mut seen = HashSet::with_capacity(parent_ids.len());
    for parent in parent_ids {
        if *parent == id {
            return Err(MnemeError::ProvenanceBroken);
        }
        if !known.contains(parent) {
            return Err(MnemeError::ProvenanceBroken);
        }
        if !seen.insert(*parent) {
            return Err(MnemeError::ProvenanceBroken);
        }
    }
    Ok(())
}

type DagEntry = (ObjectId, Vec<[u8; 32]>);
type DagEntries = Vec<DagEntry>;

fn topo_sort(entries: &[(ObjectId, Vec<[u8; 32]>)]) -> Result<DagEntries, MnemeError> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut ids: HashMap<[u8; 32], ObjectId> = HashMap::with_capacity(entries.len());
    let mut parents: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::with_capacity(entries.len());
    let mut indegree: HashMap<[u8; 32], usize> = HashMap::with_capacity(entries.len());
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

    for (id, ps) in entries {
        let id_bytes = *id.as_bytes();
        if ids.insert(id_bytes, *id).is_some() {
            return Err(MnemeError::ProvenanceBroken);
        }
        parents.insert(id_bytes, ps.clone());
        indegree.insert(id_bytes, ps.len());
        for parent in ps {
            children.entry(*parent).or_default().push(id_bytes);
        }
    }

    for ps in parents.values() {
        for p in ps {
            if !ids.contains_key(p) {
                return Err(MnemeError::ProvenanceBroken);
            }
        }
    }

    let mut queue: VecDeque<[u8; 32]> = indegree
        .iter()
        .filter_map(|(id, &deg)| if deg == 0 { Some(*id) } else { None })
        .collect();
    queue.make_contiguous().sort();

    let mut ordered = Vec::with_capacity(entries.len());
    while let Some(id_bytes) = queue.pop_front() {
        // Fail closed rather than panic if a kernel invariant is ever violated
        // (id already drained, untracked child, or indegree underflow). These
        // are unreachable for inputs that pass the validation above, but the
        // provenance path must never panic — INV fail-closed default.
        let id = ids.remove(&id_bytes).ok_or(MnemeError::ProvenanceBroken)?;
        ordered.push((id, parents.remove(&id_bytes).unwrap_or_default()));
        if let Some(kids) = children.get(&id_bytes) {
            for child in kids {
                let deg = indegree
                    .get_mut(child)
                    .ok_or(MnemeError::ProvenanceBroken)?;
                *deg = deg.checked_sub(1).ok_or(MnemeError::ProvenanceBroken)?;
                if *deg == 0 {
                    queue.push_back(*child);
                }
            }
        }
    }

    if ordered.len() != entries.len() {
        return Err(MnemeError::ProvenanceBroken);
    }
    Ok(ordered)
}

fn usize_from_u64(v: u64) -> Result<usize, MnemeError> {
    usize::try_from(v).map_err(|_| MnemeError::RootInconsistent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_smt::empty_root;

    fn oid(byte: u8) -> ObjectId {
        ObjectId::from_bytes([byte; 32])
    }

    fn chain_updates(dag: &mut DagIndex, ids: &[ObjectId]) {
        let mut prev: Vec<[u8; 32]> = Vec::new();
        for id in ids {
            dag.update_heads(*id, &prev).expect("valid chain");
            prev = vec![*id.as_bytes()];
        }
    }

    #[test]
    fn dag_rejects_missing_parent_inv3() {
        let mut dag = DagIndex::new();
        let child = oid(0x01);
        let missing = [0x99; 32];
        let err = dag.update_heads(child, &[missing]).unwrap_err();
        assert_eq!(err, MnemeError::ProvenanceBroken);
    }

    #[test]
    fn dag_rejects_self_parent_inv3() {
        let mut dag = DagIndex::new();
        let id = oid(0x02);
        let err = dag.update_heads(id, &[*id.as_bytes()]).unwrap_err();
        assert_eq!(err, MnemeError::ProvenanceBroken);
    }

    #[test]
    fn dag_rejects_duplicate_insert_inv3() {
        let mut dag = DagIndex::new();
        let id = oid(0x03);
        dag.update_heads(id, &[]).unwrap();
        let err = dag.update_heads(id, &[]).unwrap_err();
        assert_eq!(err, MnemeError::ProvenanceBroken);
    }

    #[test]
    fn dag_rejects_duplicate_parents_inv3() {
        let mut dag = DagIndex::new();
        let parent = oid(0x10);
        dag.update_heads(parent, &[]).unwrap();
        let child = oid(0x11);
        let p = *parent.as_bytes();
        let err = dag.update_heads(child, &[p, p]).unwrap_err();
        assert_eq!(err, MnemeError::ProvenanceBroken);
    }

    #[test]
    fn dag_head_root_tracks_live_heads() {
        let mut dag = DagIndex::new();
        assert_eq!(dag.root(), empty_root());

        let a = oid(0x20);
        let b = oid(0x21);
        dag.update_heads(a, &[]).unwrap();
        let root_a = dag.root();

        dag.update_heads(b, &[]).unwrap();
        let root_ab = dag.root();
        assert_ne!(root_a, root_ab);

        let c = oid(0x22);
        dag.update_heads(c, &[*a.as_bytes()]).unwrap();
        assert_ne!(root_ab, dag.root());
        assert!(dag.prove_head_membership(*c.as_bytes()).is_ok());
        assert!(dag.prove_head_membership(*b.as_bytes()).is_ok());
        assert!(dag.prove_head_membership(*a.as_bytes()).is_err());
    }

    #[test]
    fn dag_has_tracks_known_not_only_heads() {
        let mut dag = DagIndex::new();
        let parent = oid(0x30);
        let child = oid(0x31);
        dag.update_heads(parent, &[]).unwrap();
        dag.update_heads(child, &[*parent.as_bytes()]).unwrap();

        assert!(dag.has(parent.as_bytes()));
        assert!(!dag.heads.contains_live(parent.as_bytes()));
        assert!(dag.has(child.as_bytes()));
    }

    #[test]
    fn dag_acyclic_by_construction_inv3() {
        let mut dag = DagIndex::new();
        chain_updates(&mut dag, &[oid(0x40), oid(0x41), oid(0x42)]);
        assert_eq!(dag.sequence(), 3);
    }

    #[test]
    fn dag_consistency_proof_between_checkpoints() {
        let mut dag = DagIndex::new();
        chain_updates(&mut dag, &[oid(0x50), oid(0x51), oid(0x52), oid(0x53)]);

        let proof = dag.prove_consistency(1, 4).unwrap();
        assert_eq!(proof.from_sequence, 1);
        assert_eq!(proof.to_sequence, 4);
        dag.verify_consistency_proof(&proof).unwrap();

        let same = dag.prove_consistency(2, 2).unwrap();
        assert!(same.path.is_empty());
        dag.verify_consistency_proof(&same).unwrap();
    }

    #[test]
    fn dag_consistency_proof_rejects_tampered_path() {
        let mut dag = DagIndex::new();
        chain_updates(&mut dag, &[oid(0x60), oid(0x61), oid(0x62)]);

        let mut proof = dag.prove_consistency(0, 3).unwrap();
        if proof.path.is_empty() {
            proof.path.push([0xff; 32]);
        } else {
            proof.path[0][0] ^= 0xff;
        }
        let err = dag.verify_consistency_proof(&proof).unwrap_err();
        assert_eq!(err, MnemeError::RootInconsistent);
    }

    #[test]
    fn dag_rebuild_from_out_of_order_entries() {
        let a = oid(0x70);
        let b = oid(0x71);
        let c = oid(0x72);
        let entries = vec![
            (c, vec![*b.as_bytes()]),
            (a, vec![]),
            (b, vec![*a.as_bytes()]),
        ];
        let mut dag = DagIndex::new();
        dag.rebuild_from(&entries).unwrap();
        assert!(dag.has(a.as_bytes()));
        assert!(dag.has(b.as_bytes()));
        assert!(dag.has(c.as_bytes()));
        assert_eq!(dag.sequence(), 3);
    }

    #[test]
    fn dag_rebuild_rejects_cycle_inv3() {
        let a = oid(0x80);
        let b = oid(0x81);
        let entries = vec![(a, vec![*b.as_bytes()]), (b, vec![*a.as_bytes()])];
        let mut dag = DagIndex::new();
        let err = dag.rebuild_from(&entries).unwrap_err();
        assert_eq!(err, MnemeError::ProvenanceBroken);
    }
}
