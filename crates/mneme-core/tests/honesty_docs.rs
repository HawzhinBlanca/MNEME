fn assert_distance_caveat(surface: &str, text: &str) {
    for phrase in [
        "procedure-faithfulness",
        "not exact",
        "membership/completeness",
        "top-k over prover-asserted distances",
        "top-k ranking is not proven",
        "not top-k by true query-to-embedding distance",
    ] {
        assert!(
            text.contains(phrase),
            "{surface} missing required honesty phrase `{phrase}`: {text}"
        );
    }
}

fn assert_phrases_in_order(surface: &str, text: &str, phrases: &[&str]) {
    let mut offset = 0;
    for phrase in phrases {
        let remaining = &text[offset..];
        let relative = remaining
            .find(phrase)
            .unwrap_or_else(|| panic!("{surface} missing ordered phrase `{phrase}`"));
        offset += relative + phrase.len();
    }
}

#[test]
fn standing_honesty_docs_preserve_exact_dominance_distance_caveat() {
    assert_distance_caveat(
        "HSM/KMS adapter doc",
        include_str!("../../../docs/HSM_KMS_ADAPTER.md"),
    );
    assert_distance_caveat(
        "cross-host determinism proof doc",
        include_str!("../../../docs/benchmarks/XHOST_DETERMINISM_PROOF.md"),
    );
}

#[test]
fn validation_lane_tamper_is_wired_to_in_repo_tamper_suites() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let validate_reliability = include_str!("../../../scripts/validate_reliability.sh");

    assert!(
        validation_lane.contains("exec scripts/validate_reliability.sh tamper"),
        "validation-lane tamper must delegate to the in-repo reliability wrapper"
    );

    for phrase in [
        "cargo test -p mneme-store --test tamper_suite tamper_suite_generative -- --nocapture",
        "cargo test -p mneme-verify --test tamper_suite -- --nocapture",
        "cargo test -p mneme-verify --test tamper_semantic -- --nocapture",
        "cargo test -p mneme-verify --test tamper_cap -- --nocapture",
        "cargo test -p mneme-verify --test tamper_checkpoint -- --nocapture",
        "cargo test -p mneme-verify --test tamper_tombstone -- --nocapture",
    ] {
        assert!(
            validate_reliability.contains(phrase),
            "validate_reliability tamper must invoke `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_full_runs_required_sublanes_and_preserves_honesty_boundary() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let full_lane = validation_lane
        .split("\n  full)")
        .nth(1)
        .and_then(|tail| tail.split("\n  *)").next())
        .expect("validation-lane must define a full lane");

    assert_phrases_in_order(
        "validation-lane full sublane source",
        validation_lane,
        &[
            "FULL_SUBLANES=(quick crypto tamper merge determinism)",
            "run_full_sublanes()",
            "for sublane in \"${FULL_SUBLANES[@]}\"",
            "bash \"$0\" \"$sublane\"",
            "run_full_sublanes",
        ],
    );

    for phrase in [
        "print_local_cross_host_honesty_boundary",
        "cross-host two-machine determinism is NOT proven by this lane (single host)",
        "set MNEME_SECOND_HOST",
        "distinct physical host",
        "bash scripts/ci/determinism-two-machine.sh",
    ] {
        assert!(
            full_lane.contains(phrase) || validation_lane.contains(phrase),
            "validation-lane full must preserve local-only honesty phrase `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_full_preflight_is_lightweight_and_preserves_plan() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let preflight_lane = validation_lane
        .split("\n  full-preflight)")
        .nth(1)
        .and_then(|tail| tail.split("\n  full)").next())
        .expect("validation-lane must define a full-preflight lane");

    assert!(
        preflight_lane.contains("print_full_preflight_plan"),
        "full-preflight must use the shared full-lane plan printer"
    );

    for forbidden in ["cargo ", "bash ", "fuzz", "bench", "ssh ", "docker"] {
        assert!(
            !preflight_lane.contains(forbidden),
            "full-preflight must stay lightweight and not contain `{forbidden}`"
        );
    }

    for phrase in [
        "validation-lane (full-preflight): planned sublanes: ${FULL_SUBLANES[*]}",
        "validation-lane (full-preflight): heavy checks are NOT executed by this lane.",
        "cross-host two-machine determinism is NOT proven by this lane (single host)",
        "set MNEME_SECOND_HOST",
        "distinct physical host",
        "expected quick|crypto|tamper|merge|determinism|full-preflight|full",
    ] {
        assert!(
            validation_lane.contains(phrase),
            "validation-lane full-preflight must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_full_and_preflight_share_one_sublane_source() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");

    for phrase in [
        "FULL_SUBLANES=(quick crypto tamper merge determinism)",
        "${FULL_SUBLANES[*]}",
        "run_full_sublanes()",
        "for sublane in \"${FULL_SUBLANES[@]}\"",
        "bash \"$0\" \"$sublane\"",
    ] {
        assert!(
            validation_lane.contains(phrase),
            "validation-lane must preserve shared full-lane source `{phrase}`"
        );
    }

    for phrase in [
        "bash \"$0\" quick",
        "bash \"$0\" crypto",
        "bash \"$0\" tamper",
        "bash \"$0\" merge",
        "bash \"$0\" determinism",
        "planned sublanes: quick crypto tamper merge determinism",
    ] {
        assert!(
            !validation_lane.contains(phrase),
            "validation-lane must not duplicate full-lane plan as `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_full_and_preflight_share_cross_host_honesty_printer() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let preflight_lane = validation_lane
        .split("\n  full-preflight)")
        .nth(1)
        .and_then(|tail| tail.split("\n  full)").next())
        .expect("validation-lane must define a full-preflight lane");
    let full_lane = validation_lane
        .split("\n  full)")
        .nth(1)
        .and_then(|tail| tail.split("\n  *)").next())
        .expect("validation-lane must define a full lane");
    let preflight_plan = validation_lane
        .split("print_full_preflight_plan() {")
        .nth(1)
        .and_then(|tail| tail.split("\n}").next())
        .expect("validation-lane must define a full-preflight plan printer");

    for phrase in [
        "print_local_cross_host_honesty_boundary()",
        "validation-lane ($LANE): Section 17.7 cross-host two-machine determinism is NOT proven by this lane (single host).",
        "validation-lane ($LANE): to prove it, set MNEME_SECOND_HOST and run scripts/ci/determinism-two-machine.sh on a distinct physical host.",
    ] {
        assert!(
            validation_lane.contains(phrase),
            "validation-lane must preserve shared cross-host honesty source `{phrase}`"
        );
    }

    assert!(
        preflight_lane.contains("print_full_preflight_plan"),
        "full-preflight must call the full-preflight plan printer"
    );
    assert!(
        preflight_plan.contains("print_local_cross_host_honesty_boundary"),
        "full-preflight plan printer must call the shared cross-host honesty printer"
    );
    assert!(
        full_lane.contains("print_local_cross_host_honesty_boundary"),
        "full must call the shared cross-host honesty printer"
    );

    for phrase in [
        "validation-lane (full-preflight): cross-host two-machine determinism is NOT proven",
        "validation-lane (full-preflight): to prove it, set MNEME_SECOND_HOST",
        "validation-lane (full): Section 17.7 cross-host two-machine determinism is NOT proven",
        "validation-lane (full): to prove it, set MNEME_SECOND_HOST",
    ] {
        assert!(
            !validation_lane.contains(phrase),
            "validation-lane must not duplicate cross-host honesty text as `{phrase}`"
        );
    }
}

#[test]
fn full_preflight_smoke_preserves_executable_contract() {
    let smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/full-preflight-smoke.sh"
    );
    let smoke =
        std::fs::read_to_string(smoke_path).expect("full-preflight smoke script must exist");

    for phrase in [
        "bash scripts/ci/validation-lane.sh full-preflight",
        "validation-lane (full-preflight): planned sublanes: quick crypto tamper merge determinism",
        "validation-lane (full-preflight): heavy checks are NOT executed by this lane.",
        "validation-lane (full-preflight): Section 17.7 cross-host two-machine determinism is NOT proven by this lane (single host).",
        "validation-lane (full-preflight): to prove it, set MNEME_SECOND_HOST and run scripts/ci/determinism-two-machine.sh on a distinct physical host.",
        "validation-lane (full-preflight): OK",
        "full-preflight-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "full-preflight smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn unknown_lane_smoke_preserves_executable_contract() {
    let smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/validation-lane-unknown-smoke.sh"
    );
    let smoke = std::fs::read_to_string(smoke_path).expect("unknown-lane smoke script must exist");

    for phrase in [
        "bash scripts/ci/validation-lane.sh __mneme_unknown_lane__",
        "status=$?",
        "require_exit_status \"$label\" \"$status\" \"2\" \"$output\"",
        "Unknown lane: __mneme_unknown_lane__ (expected quick|crypto|tamper|merge|determinism|full-preflight|full)",
        "validation-lane-unknown-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "unknown-lane smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_smoke_scripts_share_assertion_helpers() {
    let full_preflight_smoke = include_str!("../../../scripts/ci/full-preflight-smoke.sh");
    let unknown_lane_smoke = include_str!("../../../scripts/ci/validation-lane-unknown-smoke.sh");

    for (name, smoke) in [
        ("full-preflight-smoke", full_preflight_smoke),
        ("validation-lane-unknown-smoke", unknown_lane_smoke),
    ] {
        assert!(
            smoke.contains("source scripts/ci/smoke-assertions.sh"),
            "{name} must source the shared smoke assertion helper"
        );

        for local_assertion in ["require_line()", "require_absent()", "line_count=\"$(wc -l"] {
            assert!(
                !smoke.contains(local_assertion),
                "{name} must not carry local assertion helper `{local_assertion}`"
            );
        }
    }

    let helper_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/smoke-assertions.sh"
    );
    let helper =
        std::fs::read_to_string(helper_path).expect("shared smoke assertion helper must exist");

    for function in [
        "require_exact_line()",
        "require_absent_substring()",
        "require_line_count()",
        "require_exit_status()",
    ] {
        assert!(
            helper.contains(function),
            "shared smoke assertion helper must define `{function}`"
        );
    }
}

#[test]
fn smoke_assertion_helper_has_executable_self_smoke() {
    let validation_contract_smoke =
        include_str!("../../../scripts/ci/validation-contract-smoke.sh");
    assert!(
        validation_contract_smoke.contains("bash scripts/ci/smoke-assertions-smoke.sh"),
        "validation contract smoke must run the shared assertion helper self-smoke"
    );

    let smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/smoke-assertions-smoke.sh"
    );
    let smoke =
        std::fs::read_to_string(smoke_path).expect("smoke assertion helper self-smoke must exist");

    for phrase in [
        "source scripts/ci/smoke-assertions.sh",
        "require_exact_line \"$label\" \"$sample_output\" \"alpha\"",
        "require_absent_substring \"$label\" \"$sample_output\" \"gamma\"",
        "require_line_count \"$label\" \"$sample_output\" \"2\"",
        "require_exit_status \"$label\" \"2\" \"2\" \"$sample_output\"",
        "expect_failure \"missing exact line\"",
        "expect_failure \"forbidden substring\"",
        "expect_failure \"line count mismatch\"",
        "expect_failure \"exit status mismatch\"",
        "smoke-assertions-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "smoke assertion helper self-smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_quick_runs_aggregate_validation_contract_smoke() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let quick_lane = validation_lane
        .split("\n  quick)")
        .nth(1)
        .and_then(|tail| tail.split("\n  crypto)").next())
        .expect("validation-lane must define a quick lane");

    assert!(
        quick_lane.contains("bash scripts/ci/validation-contract-smoke.sh"),
        "quick lane must run the aggregate validation contract smoke"
    );

    for direct_smoke in [
        "bash scripts/ci/full-preflight-smoke.sh",
        "bash scripts/ci/validation-lane-unknown-smoke.sh",
    ] {
        assert!(
            !quick_lane.contains(direct_smoke),
            "quick lane must delegate `{direct_smoke}` through validation-contract-smoke.sh"
        );
    }

    let smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/validation-contract-smoke.sh"
    );
    let smoke =
        std::fs::read_to_string(smoke_path).expect("validation contract smoke script must exist");

    for phrase in [
        "bash scripts/ci/full-preflight-smoke.sh",
        "bash scripts/ci/validation-lane-unknown-smoke.sh",
        "validation-contract-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "validation contract smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_merge_delegates_to_reliability_wrapper() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let validate_reliability = include_str!("../../../scripts/validate_reliability.sh");

    assert!(
        validation_lane.contains("exec scripts/validate_reliability.sh merge"),
        "validation-lane merge must delegate to the in-repo reliability wrapper"
    );

    for phrase in [
        "cargo test -p mneme-crdt -- merge_convergence 2>/dev/null",
        "cargo test -p mneme-crdt -- merge_convergence -- --nocapture",
        "fail_closed \"CRDT merge_convergence tests not wired (§18 merge)\"",
    ] {
        assert!(
            validate_reliability.contains(phrase),
            "validate_reliability merge must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_determinism_delegates_to_reliability_wrapper() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let validate_reliability = include_str!("../../../scripts/validate_reliability.sh");

    assert!(
        validation_lane.contains("exec scripts/validate_reliability.sh determinism"),
        "validation-lane determinism must delegate to the in-repo reliability wrapper"
    );

    for phrase in [
        "cargo run -p mneme-cli -- determinism foundation-gate --help &>/dev/null",
        "cargo run -p mneme-cli -- determinism foundation-gate",
        "--timestamp \"1970-01-01T00:00:00Z\"",
        "cargo run -p mneme-cli -- determinism foundation-verify",
        "fail_closed \"mneme-cli determinism foundation-gate not available\"",
        "==> determinism foundation-gate run ${run}/2",
    ] {
        assert!(
            validate_reliability.contains(phrase),
            "validate_reliability determinism must preserve `{phrase}`"
        );
    }
}

#[test]
fn reliability_wrapper_uses_shared_ci_initialization() {
    let validate_reliability = include_str!("../../../scripts/validate_reliability.sh");

    for phrase in [
        "# shellcheck source=scripts/ci/lib.sh",
        "source \"$ROOT/scripts/ci/lib.sh\"",
        "mneme_ci_init \"$ROOT\" \"$LANE\"",
    ] {
        assert!(
            validate_reliability.contains(phrase),
            "validate_reliability must preserve shared CI setup `{phrase}`"
        );
    }
}
