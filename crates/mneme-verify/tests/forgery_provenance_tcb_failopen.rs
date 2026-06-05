#![cfg(feature = "experimental_semantic")]

//! Adversarial gate: provenance-bearing semantic receipts must not skip VO membership
//! or filtered dominance (red-team PHASE_I_TCB_FAILOPEN_PROVENANCE).

mod helpers;

use helpers::{build_valid_semantic_recall, sample_procedure, sample_query_embedding, theme_key};
use mneme_core::{MnemeError, ProvenanceFilter, Query, TrustTier};
use mneme_index::build_provenance_attestation;
use mneme_verify::{
    RecallContext, SemanticRecallInput, verify_semantic_recall, verify_semantic_receipt,
};

#[test]
fn forgery_provenance_bearing_non_topk_result_rejected() {
    let mut f = build_valid_semantic_recall();
    let filter = ProvenanceFilter {
        written_by: None,
        since: None,
        min_tier: TrustTier::Working,
    };
    f.receipt.provenance =
        Some(build_provenance_attestation(&f.receipt, &filter, &f.objects).expect("attestation"));
    assert!(
        run_semantic_receipt(&f).is_ok(),
        "honest provenance receipt"
    );

    let farthest = f
        .receipt
        .verification_object
        .candidates
        .last()
        .expect("candidates")
        .0;
    f.receipt.verification_object.result_ids = vec![farthest];
    assert_eq!(
        run_semantic_receipt(&f).unwrap_err(),
        MnemeError::ProvenanceFilterViolation,
    );

    let query = Query {
        logical_key: theme_key("semantic", "query"),
        min_tier: TrustTier::Working,
        embedding: Some(sample_query_embedding()),
    };
    let ctx = RecallContext {
        key_index: &f.key_index,
        dag: &f.dag,
        objects: &f.objects,
        previous_root: f.previous_root.as_ref(),
    };
    assert_eq!(
        verify_semantic_recall(
            &SemanticRecallInput {
                receipt: f.receipt.clone(),
                root: f.root.clone(),
            },
            &sample_procedure(),
            &query,
            &f.trust,
            &ctx,
        )
        .unwrap_err(),
        MnemeError::ProvenanceFilterViolation,
    );
}

#[test]
fn forgery_provenance_without_object_set_fails_closed() {
    let mut f = build_valid_semantic_recall();
    f.receipt.provenance = Some(
        build_provenance_attestation(
            &f.receipt,
            &ProvenanceFilter {
                written_by: None,
                since: None,
                min_tier: TrustTier::Working,
            },
            &f.objects,
        )
        .expect("attestation"),
    );
    assert_eq!(
        verify_semantic_receipt(
            &f.receipt,
            &f.root,
            &f.procedure,
            &f.trust,
            f.previous_root.as_ref(),
            None,
        )
        .unwrap_err(),
        MnemeError::ProvenanceFilterViolation,
    );
}

fn run_semantic_receipt(f: &helpers::SemanticFixture) -> Result<(), MnemeError> {
    verify_semantic_receipt(
        &f.receipt,
        &f.root,
        &f.procedure,
        &f.trust,
        f.previous_root.as_ref(),
        Some(&f.objects),
    )
}
