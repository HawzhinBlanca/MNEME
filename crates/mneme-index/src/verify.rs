//! ADS verification-object checks (§9.2 prover-side helpers; verifier TCB in `mneme-verify`).

use crate::commit::{SemanticMerkleTree, hash_sem_leaf};
use crate::procedure::replay_from_candidates;
use crate::receipt::SemanticRecallReceipt;
use mneme_core::{MnemeError, ObjectId, Procedure, VerificationObject};

/// Verify ADS backend VO: Merkle paths + deterministic procedure replay.
pub fn verify_ads_vo(
    vo: &VerificationObject,
    semantic_commit: &[u8; 32],
    proc: &Procedure,
) -> Result<(), MnemeError> {
    if vo.procedure_id != crate::procedure::procedure_id(proc) {
        return Err(MnemeError::ProcedureMismatch);
    }

    let mut sorted_ids: Vec<ObjectId> = vo.candidates.iter().map(|(id, _, _)| *id).collect();
    sorted_ids.sort();

    for (commit, path) in &vo.nodes {
        let leaf_index = sorted_ids
            .iter()
            .position(|id| {
                vo.candidates
                    .iter()
                    .any(|(cid, emb, _)| cid == id && hash_sem_leaf(id.as_bytes(), emb) == *commit)
            })
            .ok_or(MnemeError::IndexPathInvalid)?;
        SemanticMerkleTree::verify_path_with_index(leaf_index, commit, path, semantic_commit)?;
    }

    let replayed = replay_from_candidates(proc, &vo.candidates);
    if replayed != vo.result_ids {
        return Err(MnemeError::ProcedureMismatch);
    }

    Ok(())
}

/// Verify ADS VO plus optional ZK retrieval attachment on a semantic recall receipt.
pub fn verify_semantic_receipt_vo(
    receipt: &SemanticRecallReceipt,
    proc: &Procedure,
) -> Result<(), MnemeError> {
    verify_ads_vo(&receipt.verification_object, &receipt.semantic_commit, proc)?;
    if let Some(zk) = &receipt.zk_retrieval {
        #[cfg(feature = "plonky2_prover")]
        {
            crate::semantic_zk::verify_zk_retrieval_attachment(zk, &receipt.verification_object)?;
        }
        #[cfg(not(feature = "plonky2_prover"))]
        {
            let _ = zk;
            return Err(MnemeError::ZkProofInvalid);
        }
    }
    Ok(())
}

/// Honesty guard: VO proves procedure-faithfulness, not exact-NN optimality (§3).
pub const HONESTY_NOT_EXACT_NN: &str = "receipt proves faithful execution of procedure P over committed data, not true nearest neighbors";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::SemanticMerkleTree;
    use crate::procedure::{execute_procedure_p, procedure_id};
    use mneme_core::{
        DistanceMetric, FixedPointEmbedding, ObjectId, Procedure, ProcedureAlgo, VerificationObject,
    };

    fn sample_vo() -> (VerificationObject, [u8; 32], Procedure) {
        let proc = Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 2,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let e1 = FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap();
        let e2 = FixedPointEmbedding::new(2, 0, vec![2, 0]).unwrap();
        let id1 = ObjectId([0x01; 32]);
        let id2 = ObjectId([0x02; 32]);
        let c1 = e1.commit();
        let c2 = e2.commit();
        let tree = SemanticMerkleTree::from_entries(&[(id1, c1), (id2, c2)]);
        let root = tree.root();
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let entries = vec![
            crate::procedure::IndexedEntry {
                object_id: id1,
                embedding_commit: c1,
                embedding: e1,
            },
            crate::procedure::IndexedEntry {
                object_id: id2,
                embedding_commit: c2,
                embedding: e2,
            },
        ];
        let (result_ids, candidates) = execute_procedure_p(&proc, &query, &entries);
        let nodes = (0..tree.leaf_count())
            .map(|i| {
                let commit = tree.leaf_hash(i).unwrap();
                let path = tree.merkle_path(i).unwrap();
                (commit, path)
            })
            .collect();
        let vo = VerificationObject {
            nodes,
            candidates,
            procedure_id: procedure_id(&proc),
            query_commit: query.commit(),
            result_ids,
        };
        (vo, root, proc)
    }

    #[test]
    fn ads_vo_verifies_against_semantic_commit() {
        let (vo, root, proc) = sample_vo();
        verify_ads_vo(&vo, &root, &proc).unwrap();
    }

    #[test]
    fn ads_vo_rejects_wrong_semantic_commit() {
        let (vo, _, proc) = sample_vo();
        let err = verify_ads_vo(&vo, &[0xee; 32], &proc).unwrap_err();
        assert_eq!(err, MnemeError::IndexPathInvalid);
    }

    #[test]
    fn ads_vo_rejects_tampered_candidate_distance() {
        let (mut vo, root, proc) = sample_vo();
        if let Some((_, _, dist)) = vo.candidates.first_mut() {
            *dist = i64::MAX;
        }
        let err = verify_ads_vo(&vo, &root, &proc).unwrap_err();
        assert_eq!(err, MnemeError::ProcedureMismatch);
    }

    #[test]
    fn honesty_message_is_non_empty() {
        assert!(HONESTY_NOT_EXACT_NN.contains("not true nearest"));
    }
}
