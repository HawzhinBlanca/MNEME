#![forbid(unsafe_code)]

use mneme_accum::{
    CognitionTimeline, JEWEL_C_HONESTY, JEWEL_C_STATUS, T8_COUNTEREXAMPLE_HONESTY,
    accumulate_commit, element_prime_from_commit, prove_membership, prove_non_membership,
    prove_nonuse_after_forget, t8_sigma_max_gap_unbounded, test_accumulator_params,
    test_accumulator_prover, verify_membership, verify_non_membership, verify_nonuse_after_forget,
};

#[test]
fn jewel_c_honesty_strings_are_load_bearing() {
    assert!(
        JEWEL_C_STATUS.contains("certified-cognition") || JEWEL_C_STATUS.contains("certified"),
        "JEWEL_C_STATUS must scope to certified cognition"
    );
    assert!(
        JEWEL_C_HONESTY.contains("NOT semantic truth"),
        "JEWEL_C_HONESTY must preserve honesty boundary"
    );
    assert!(
        T8_COUNTEREXAMPLE_HONESTY.contains("Operator equivocation"),
        "T8 honesty must mention operator equivocation"
    );
    assert!(
        JEWEL_C_HONESTY.contains("σ_max") || JEWEL_C_HONESTY.contains("wall-clock"),
        "Jewel C honesty must document σ_max / wall-clock ceiling"
    );
}

#[test]
fn accumulate_membership_and_non_membership_round_trip() {
    let params = test_accumulator_params();
    let mut prover = test_accumulator_prover().expect("prover");

    let used_a = [1u8; 32];
    let used_b = [2u8; 32];
    let forgotten = [3u8; 32];

    accumulate_commit(&mut prover, &used_a).expect("accumulate a");
    accumulate_commit(&mut prover, &used_b).expect("accumulate b");
    let acc = mneme_accum::accumulator_value(&prover);

    let prime_a = element_prime_from_commit(&used_a);
    let mem = prove_membership(&prover, &prime_a).expect("membership witness");
    verify_membership(&params, &acc, &prime_a, &mem).expect("membership verifies");

    let prime_forgotten = element_prime_from_commit(&forgotten);
    let non_mem = prove_non_membership(&prover, &prime_forgotten).expect("non-membership");
    verify_non_membership(&params, &acc, &prime_forgotten, &non_mem)
        .expect("non-membership verifies");

    let nonuse = prove_nonuse_after_forget(&prover, &forgotten).expect("non-use");
    verify_nonuse_after_forget(&params, &acc, &forgotten, &nonuse).expect("non-use verifies");
}

#[test]
fn membership_forgery_rejects() {
    let params = test_accumulator_params();
    let mut prover = test_accumulator_prover().expect("prover");
    let used = [9u8; 32];
    accumulate_commit(&mut prover, &used).expect("accumulate");
    let acc = mneme_accum::accumulator_value(&prover);

    let prime = element_prime_from_commit(&used);
    let mut bad = prove_membership(&prover, &prime).expect("witness");
    if !bad.witness.is_empty() {
        bad.witness[0] ^= 0x01;
    }
    assert!(verify_membership(&params, &acc, &prime, &bad).is_err());
}

#[test]
fn t8_counterexample_same_witness_unbounded_gap() {
    let params = test_accumulator_params();
    let forgotten = [4u8; 32];
    let used_a = [5u8; 32];
    let used_b = [6u8; 32];
    let fast = CognitionTimeline {
        first_cert_unix: 1_700_000_000,
        second_cert_unix: 1_700_000_060,
    };
    let slow = CognitionTimeline {
        first_cert_unix: 1_700_000_000,
        second_cert_unix: 1_700_864_000,
    };
    let (acc, proof) = t8_sigma_max_gap_unbounded(&params, forgotten, used_a, used_b, fast, slow)
        .expect("counterexample");
    assert!(slow.gap_secs() > fast.gap_secs());
    verify_nonuse_after_forget(&params, &acc, &forgotten, &proof)
        .expect("witness still verifies under slow timeline");
}
