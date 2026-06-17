use mneme_core::cognition_bounds::PROCEDURE_FAITHFUL_TOPK_FLOOR_HONESTY;
use mneme_core::{
    DistanceMetric, FixedPointEmbedding, MnemeError, ObjectId, Procedure, ProcedureAlgo,
    VerificationObject,
};
use mneme_index::{
    IndexedEntry, SemanticMerkleTree, execute_procedure_p, procedure_id, replay_from_candidates,
    verify_ads_vo, verify_ads_vo_membership,
};
fn proc(k: u32) -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}
fn vo(n: usize, k: u32) -> (VerificationObject, [u8; 32], Procedure) {
    let p = proc(k);
    let mut es = Vec::new();
    let mut me = Vec::new();
    for i in 0..n {
        let mut b = [0u8; 32];
        b[0] = i as u8;
        let id = ObjectId(b);
        let e = FixedPointEmbedding::new(2, 0, vec![i as i16, 0]).unwrap();
        let c = e.commit();
        es.push(IndexedEntry {
            object_id: id,
            embedding_commit: c,
            embedding: e,
        });
        me.push((id, c));
    }
    let t = SemanticMerkleTree::from_entries(&me);
    let r = t.root();
    let q = FixedPointEmbedding::new(2, 0, vec![0i16, 0]).unwrap();
    let (rid, cand) = execute_procedure_p(&p, &q, &es).unwrap();
    let nodes = (0..t.leaf_count())
        .map(|i| (t.leaf_hash(i).unwrap(), t.merkle_path(i).unwrap()))
        .collect();
    (
        VerificationObject {
            nodes,
            candidates: cand,
            leaf_indices: (0..t.leaf_count()).collect(),
            procedure_id: procedure_id(&p),
            query_commit: q.commit(),
            result_ids: rid,
            candidates_embeddings: None,
        },
        r,
        p,
    )
}
#[test]
fn linear() {
    for n in [1, 4, 16] {
        let (v, r, p) = vo(n, n.min(4) as u32);
        assert_eq!(v.candidates.len(), n);
        verify_ads_vo_membership(&v, &r, &p).unwrap();
        verify_ads_vo(&v, &r, &p).unwrap();
    }
}
#[test]
fn replay() {
    let (v, _, p) = vo(12, 4);
    assert_eq!(v.candidates.len(), 12);
    assert_eq!(replay_from_candidates(&p, &v.candidates).unwrap().len(), 4);
}
#[test]
fn shape_mismatch_rejected() {
    let (mut v, r, p) = vo(4, 2);
    v.candidates.pop();
    assert_eq!(
        verify_ads_vo_membership(&v, &r, &p),
        Err(MnemeError::IndexPathInvalid)
    );
}
#[test]
fn honesty() {
    assert!(PROCEDURE_FAITHFUL_TOPK_FLOOR_HONESTY.contains("Θ(n)"));
    assert!(PROCEDURE_FAITHFUL_TOPK_FLOOR_HONESTY.contains("transparent non-succinct"));
}
