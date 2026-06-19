//! Deterministic procedure P identity + replay (mirrors mneme-index `procedure.rs`).
//!
//! Independent reimplementation — no `mneme-*` deps. Field-byte layout and the
//! distance-asc / ObjectId-asc replay ordering must match the implementation crate.

use blake3::Hasher;

/// Domain tag for procedure hashing (§6.1).
pub const PROC_DOMAIN: &[u8] = b"MNEME-proc-v1\x00";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcedureAlgo {
    Hnsw,
    Ivf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DistanceMetric {
    SquaredL2I64,
    CosineI64,
}

/// Retrieval procedure parameters (§6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Procedure {
    pub algo: ProcedureAlgo,
    pub ef_search: u32,
    pub k: u32,
    pub distance: DistanceMetric,
    pub seed: u64,
}

/// One VO candidate row: `(object_id, embedding_commit, integer_distance)`.
pub type CandidateRow = ([u8; 32], [u8; 32], i64);

fn algo_tag(algo: ProcedureAlgo) -> u8 {
    match algo {
        ProcedureAlgo::Hnsw => 0,
        ProcedureAlgo::Ivf => 1,
    }
}

fn distance_tag(dist: DistanceMetric) -> u8 {
    match dist {
        DistanceMetric::SquaredL2I64 => 0,
        DistanceMetric::CosineI64 => 1,
    }
}

/// `P_id = BLAKE3("MNEME-proc-v1\x00" ‖ canonical_field_bytes(P))`.
pub fn procedure_id(proc: &Procedure) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROC_DOMAIN);
    h.update(&[algo_tag(proc.algo)]);
    h.update(&proc.ef_search.to_le_bytes());
    h.update(&proc.k.to_le_bytes());
    h.update(&[distance_tag(proc.distance)]);
    h.update(&proc.seed.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Replay procedure over VO candidates — must reproduce `result_ids`.
pub fn replay_from_candidates(proc: &Procedure, candidates: &[CandidateRow]) -> Vec<[u8; 32]> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    let beam = proc.ef_search.max(proc.k).max(1) as usize;
    if sorted.len() > beam {
        sorted.truncate(beam);
    }
    sorted.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    let k = proc.k.max(1) as usize;
    if sorted.len() > k {
        sorted.truncate(k);
    }
    sorted.iter().map(|(id, _, _)| *id).collect()
}

/// Quantized fixed-point embedding: `value = component * 2^scale`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPointEmbedding {
    pub dim: u32,
    pub scale: i8,
    pub components: Vec<i16>,
}

impl FixedPointEmbedding {
    pub fn new(dim: u32, scale: i8, components: Vec<i16>) -> Result<Self, crate::CrossrefError> {
        let declared_dim = usize::try_from(dim).map_err(|_| crate::CrossrefError::SchemaDrift)?;
        if declared_dim == 0 || components.len() != declared_dim {
            return Err(crate::CrossrefError::SchemaDrift);
        }
        Ok(Self {
            dim,
            scale,
            components,
        })
    }

    /// `embedding_commit = BLAKE3(SEM ‖ dim_le ‖ scale ‖ concat(components_le_i16))`.
    pub fn commit(&self) -> [u8; 32] {
        crate::domain::hash_sem_preimage(self.dim.to_le_bytes(), self.scale, &self.components)
    }

    pub fn validate_shape(&self) -> Result<(), crate::CrossrefError> {
        let declared_dim =
            usize::try_from(self.dim).map_err(|_| crate::CrossrefError::SchemaDrift)?;
        if declared_dim == 0 || self.components.len() != declared_dim {
            return Err(crate::CrossrefError::SchemaDrift);
        }
        Ok(())
    }

    fn ensure_compatible_pair(&self, other: &Self) -> Result<(), crate::CrossrefError> {
        self.validate_shape()?;
        other.validate_shape()?;
        if self.dim != other.dim || self.scale != other.scale {
            return Err(crate::CrossrefError::SchemaDrift);
        }
        Ok(())
    }

    /// Integer squared-L2 distance in the quantized domain (procedure-pinned).
    pub fn squared_l2_distance(&self, other: &Self) -> Result<i64, crate::CrossrefError> {
        self.ensure_compatible_pair(other)?;
        let mut sum: i64 = 0;
        for (a, b) in self.components.iter().zip(&other.components) {
            let diff = i64::from(*a) - i64::from(*b);
            sum = sum
                .checked_add(
                    diff.checked_mul(diff)
                        .ok_or(crate::CrossrefError::SchemaDrift)?,
                )
                .ok_or(crate::CrossrefError::SchemaDrift)?;
        }
        Ok(sum)
    }

    /// Integer dot product for cosine-style procedures.
    pub fn dot_product(&self, other: &Self) -> Result<i64, crate::CrossrefError> {
        self.ensure_compatible_pair(other)?;
        let mut sum: i64 = 0;
        for (a, b) in self.components.iter().zip(&other.components) {
            sum = sum
                .checked_add(
                    i64::from(*a)
                        .checked_mul(i64::from(*b))
                        .ok_or(crate::CrossrefError::SchemaDrift)?,
                )
                .ok_or(crate::CrossrefError::SchemaDrift)?;
        }
        Ok(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn procedure_id_is_deterministic() {
        assert_eq!(procedure_id(&proc()), procedure_id(&proc()));
    }

    #[test]
    fn procedure_id_changes_when_seed_changes() {
        let mut other = proc();
        other.seed = 1;
        assert_ne!(procedure_id(&proc()), procedure_id(&other));
    }

    #[test]
    fn replay_tie_breaks_by_object_id() {
        let cands = vec![
            ([0x02; 32], [0u8; 32], 5),
            ([0x01; 32], [0u8; 32], 5),
            ([0x03; 32], [0u8; 32], 9),
        ];
        let out = replay_from_candidates(&proc(), &cands);
        assert_eq!(out, vec![[0x01; 32], [0x02; 32]]);
    }
}
