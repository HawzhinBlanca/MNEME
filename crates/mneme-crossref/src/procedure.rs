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
