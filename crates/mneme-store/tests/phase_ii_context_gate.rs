use mneme_cap::{Capability, Permissions};
use mneme_context::{
    ASSEMBLY_PROFILE_V1, assemble_verified_context, consumption_attestation_from_assembly,
};
use mneme_core::{
    DistanceMetric, Draft, FixedPointEmbedding, LogicalKey, MemoryKind, MnemeError, Procedure,
    ProcedureAlgo, Query, TrustTier, hash_context_assembled,
};
use mneme_crypto::KeyPair;
use mneme_gate::PHASE_II_GATE_OPEN;
use mneme_store::{ContextGateRecallOpts, Store};
use tempfile::TempDir;

#[test]
fn gate_open_when_context_gate_feature_enabled() {
    assert!(std::hint::black_box(PHASE_II_GATE_OPEN));
}

#[test]
fn injection_fails_on_gated_recall() {
    let dir = TempDir::new().unwrap();
    let op = KeyPair::generate();
    let mut store = Store::create(dir.path(), op.clone()).unwrap();
    let cap = Capability::issue(
        &op,
        op.public_key_bytes(),
        vec!["d".into()],
        vec![MemoryKind::Episodic],
        TrustTier::Identity,
        TrustTier::Working,
        Permissions::all(),
        vec![],
    )
    .unwrap();
    let proc = Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search: 64,
        k: 1,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    };
    let q = Query {
        logical_key: LogicalKey {
            namespace: "d".into(),
            name: "k".into(),
        },
        min_tier: TrustTier::Working,
        embedding: Some(FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap()),
    };
    store
        .remember(
            Draft {
                namespace: "d".into(),
                logical_name: "k".into(),
                kind: MemoryKind::Episodic,
                body: b"x".into(),
                parent_ids: vec![],
                session: [1; 16],
                trust_tier: None,
                embedding: Some(FixedPointEmbedding::new(2, 0, vec![1, 0]).unwrap()),
                valid_time_ms: None,
            },
            &cap,
        )
        .unwrap();
    let entries = store.recall_verified(&q, &proc, &cap).unwrap();
    let mut att = consumption_attestation_from_assembly(
        &assemble_verified_context(&[entries[0].id], &entries, ASSEMBLY_PROFILE_V1).unwrap(),
    );
    att.context_hash = hash_context_assembled(b"MNEME-CTX-ASM-v1\nINJECTED");
    let opts = ContextGateRecallOpts {
        attestation: &att,
        output_binding: None,
        model_output: None,
        model_identity: None,
    };
    assert!(matches!(
        store.recall_verified_context_gated(&q, &proc, &cap, &opts),
        Err(MnemeError::ProvenanceBroken)
    ));
}
