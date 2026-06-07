//! Deterministic procedure P execution and replay (blueprint §6.1, INV-10).

use crate::distance::integer_distance;
use blake3::Hasher;
use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
};

/// Domain tag for procedure hashing (§6.1).
pub const PROC_DOMAIN: &[u8] = b"MNEME-proc-v1\x00";

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

pub fn default_key_procedure() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 0,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

/// Default semantic ANN procedure (90-day; ef_search > 0 distinguishes key-index P).
pub fn default_semantic_procedure() -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}

/// True when `proc` is the v0 exact key-index procedure (not semantic recall).
pub fn is_key_index_procedure(proc: &Procedure) -> bool {
    procedure_id(proc) == procedure_id(&default_key_procedure())
}

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

/// One indexed semantic entry used during procedure replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEntry {
    pub object_id: ObjectId,
    pub embedding_commit: [u8; 32],
    pub embedding: FixedPointEmbedding,
}

/// Deterministic top-k selection: distance asc, tie-break by ascending `ObjectId`.
///
pub type CandidateRow = (ObjectId, [u8; 32], i64);

/// Returns `(result_ids, all_candidates)` where `all_candidates` lists every indexed
/// entry examined (ObjectId asc traversal order) with integer distances.
pub fn execute_procedure_p(
    proc: &Procedure,
    query: &FixedPointEmbedding,
    entries: &[IndexedEntry],
) -> Result<(Vec<ObjectId>, Vec<CandidateRow>), MnemeError> {
    let _ = proc.algo;
    let all_candidates: Vec<CandidateRow> = entries
        .iter()
        .map(|entry| {
            integer_distance(proc.distance, query, &entry.embedding)
                .map(|dist| (entry.object_id, entry.embedding_commit, dist))
        })
        .collect::<Result<_, _>>()?;

    let mut ranked = all_candidates.clone();
    ranked.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));

    let beam = proc.ef_search.max(proc.k).max(1) as usize;
    if ranked.len() > beam {
        ranked.truncate(beam);
    }
    ranked.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));

    let k = proc.k.max(1) as usize;
    if ranked.len() > k {
        ranked.truncate(k);
    }

    let result_ids: Vec<ObjectId> = ranked.iter().map(|(id, _, _)| *id).collect();
    Ok((result_ids, all_candidates))
}

/// Replay procedure over VO candidates — must reproduce `result_ids`.
pub fn replay_from_candidates(
    proc: &Procedure,
    candidates: &[(ObjectId, [u8; 32], i64)],
) -> Vec<ObjectId> {
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
    use crate::procedure::procedure_id;

    fn entry(byte: u8, components: Vec<i16>) -> IndexedEntry {
        let embedding = FixedPointEmbedding::new(2, 0, components).unwrap();
        IndexedEntry {
            object_id: ObjectId([byte; 32]),
            embedding_commit: embedding.commit(),
            embedding,
        }
    }

    #[test]
    fn procedure_tie_breaks_by_object_id() {
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 2,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let entries = vec![
            entry(0x02, vec![3, 4]),
            entry(0x01, vec![3, 4]),
            entry(0x03, vec![10, 0]),
        ];
        let (results, _) = execute_procedure_p(&proc, &query, &entries).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], ObjectId([0x01; 32]));
        assert_eq!(results[1], ObjectId([0x02; 32]));
    }

    #[test]
    fn procedure_execution_does_not_silently_filter_malformed_entries() {
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 2,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let malformed = FixedPointEmbedding {
            dim: 2,
            scale: 0,
            components: vec![1],
        };
        let entries = vec![
            entry(0x01, vec![1, 0]),
            IndexedEntry {
                object_id: ObjectId([0x02; 32]),
                embedding_commit: malformed.commit(),
                embedding: malformed,
            },
        ];

        assert_eq!(
            execute_procedure_p(&proc, &query, &entries),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn procedure_id_is_deterministic() {
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 10,
            distance: DistanceMetric::CosineI64,
            seed: 42,
        };
        assert_eq!(procedure_id(&proc), procedure_id(&proc));
    }

    #[test]
    fn procedure_id_changes_when_params_change() {
        let base = default_key_procedure();
        let mut changed = base.clone();
        changed.seed = 1;
        assert_ne!(procedure_id(&base), procedure_id(&changed));
    }
}
