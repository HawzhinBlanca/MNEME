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

fn bash_array_values<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let marker = format!("{name}=(");
    source
        .split(&marker)
        .nth(1)
        .and_then(|tail| tail.split(')').next())
        .unwrap_or_else(|| panic!("missing bash array `{name}`"))
        .split_whitespace()
        .collect()
}

fn validation_lane_usage_values(source: &str) -> Vec<&str> {
    source
        .split("# Usage: scripts/ci/validation-lane.sh <")
        .nth(1)
        .and_then(|tail| tail.split('>').next())
        .expect("validation-lane usage comment must declare valid lanes")
        .split('|')
        .collect()
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
    assert_distance_caveat("OSS threat model", include_str!("../../../THREAT_MODEL.md"));
    assert_distance_caveat(
        "OSS positioning doc",
        include_str!("../../../POSITIONING.md"),
    );
}

#[test]
fn oss_release_docs_exist_with_security_and_contributing_guides() {
    for (surface, text) in [
        ("SECURITY.md", include_str!("../../../SECURITY.md")),
        ("CONTRIBUTING.md", include_str!("../../../CONTRIBUTING.md")),
    ] {
        assert!(
            text.contains("authenticated ≠ true") || text.contains("Authenticated ≠ true"),
            "{surface} must preserve authenticated-not-true honesty boundary"
        );
        assert!(
            text.contains("validation-lane.sh quick"),
            "{surface} must point contributors at validation-lane quick"
        );
    }

    assert!(
        include_str!("../../../SECURITY.md").contains("GitHub Security Advisories"),
        "SECURITY.md must use GitHub private advisory reporting (no fabricated contact endpoints)"
    );
}

#[test]
fn p3_local_scaffold_docs_honest_about_scope() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let work_order = include_str!("../../../docs/WORK_ORDER_DEEP_INSPECTION_2026-06-08.md");
    let human_tasks = include_str!("../../../docs/HUMAN_TASKS.md");
    let p3_doc = include_str!("../../../docs/P3_LOCAL_SCAFFOLDS.md");

    assert!(
        validation_lane.contains("p3-local"),
        "validation-lane must wire the p3-local aggregate gate"
    );
    assert!(
        human_tasks.contains("| `validation-lane.sh p3-local` | **Landed** |"),
        "HUMAN_TASKS must record p3-local scaffold as landed"
    );
    assert!(
        work_order.contains("| P3 local scaffolds (aggregate) | SCAFFOLD-LANDED |"),
        "work order must record p3-local scaffolds as scaffold-landed"
    );
    assert!(
        p3_doc.contains("not shipped external proof"),
        "P3_LOCAL_SCAFFOLDS must preserve not-external-proof honesty boundary"
    );
    assert!(
        p3_doc.contains("AcceptedReportPolicy"),
        "P3_LOCAL_SCAFFOLDS must document AcceptedReportPolicy placeholder"
    );

    for forbidden in [
        "`scripts/ci/p3-local-watch-history-summary.sh` validates",
        "`scripts/ci/p3-local-hourly-report.sh` reruns",
        "`scripts/ci/p3-local-hourly-report-verify.sh` verifies",
        "verify_accepted_report_policy",
        "run_key_vault_conformance",
    ] {
        assert!(
            !work_order.contains(forbidden),
            "work order must not claim unshipped p3-local artifact `{forbidden}`"
        );
    }
}

#[test]
fn validation_lane_bounds_runs_floor_audit_tests() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let bounds_lane = validation_lane
        .split("\n  bounds)")
        .nth(1)
        .and_then(|t| t.split("\n  full-preflight)").next())
        .expect("bounds lane");
    for phrase in [
        "Pillar B floor audit",
        "Ω(log n / log log n)",
        "docs/theory/PRICE_OF_VERIFIABLE_COGNITION.md",
        "cargo test -p mneme-core --test cognition_floor_audit",
        "cargo test -p mneme-smt --test recall_floor",
        "cargo test -p mneme-index --test exact_dominance_floor",
    ] {
        assert!(bounds_lane.contains(phrase));
    }
}

#[test]
fn validation_lane_p3_local_runs_scaffold_scripts() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let p3_lane = validation_lane
        .split("\n  p3-local)")
        .nth(1)
        .and_then(|tail| tail.split("\n  crypto)").next())
        .expect("validation-lane must define a p3-local lane");

    for phrase in [
        "NOT external KMS/TEE/SSH proof",
        "bash scripts/ci/convergence-two-host.sh --local-smoke",
        "bash scripts/kms/conformance-local.sh",
        "bash scripts/ci/attestation-policy-local.sh",
        "bash scripts/ci/formal-obligations-local.sh",
    ] {
        assert!(
            p3_lane.contains(phrase),
            "p3-local lane must invoke scaffold `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_choices_are_single_source_and_match_claude_ladder() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let claude = include_str!("../../../CLAUDE.md");
    let expected_lanes = vec![
        "quick",
        "crypto",
        "tamper",
        "merge",
        "determinism",
        "bounds",
        "p3-local",
        "full-preflight",
        "full",
    ];

    let validation_lanes = bash_array_values(validation_lane, "VALIDATION_LANES");
    assert_eq!(
        validation_lanes, expected_lanes,
        "validation-lane must keep one ordered source for accepted lanes"
    );

    assert_eq!(
        validation_lane_usage_values(validation_lane),
        validation_lanes,
        "validation-lane usage comment must match VALIDATION_LANES"
    );

    let claude_lanes: Vec<&str> = claude
        .lines()
        .filter_map(|line| line.strip_prefix("scripts/ci/validation-lane.sh "))
        .filter(|tail| !tail.starts_with("--"))
        .map(|tail| {
            tail.split_whitespace()
                .next()
                .expect("CLAUDE validation-lane line must include a lane")
        })
        .collect();
    assert_eq!(
        claude_lanes, validation_lanes,
        "CLAUDE validation ladder must match VALIDATION_LANES"
    );

    for phrase in [
        "validation_lane_choices()",
        "validation_lane_usage()",
        "local IFS='|'",
        "echo \"${VALIDATION_LANES[*]}\"",
        "if [[ \"${1:-}\" == \"--list\" ]]",
        "validation_lane_choices",
        "exit 0",
        "if [[ \"${1:-}\" == \"--help\" || \"${1:-}\" == \"-h\" ]]",
        "validation_lane_usage",
        "validation_lane_is_known()",
        "if [[ \"$LANE\" != \"full-preflight\" ]]",
        "echo \"Unknown lane: $LANE (expected $(validation_lane_choices))\" >&2",
    ] {
        assert!(
            validation_lane.contains(phrase),
            "validation-lane must preserve shared lane-list phrase `{phrase}`"
        );
    }

    assert_phrases_in_order(
        "validation-lane --list must not initialize a lane",
        validation_lane,
        &[
            "if [[ \"${1:-}\" == \"--list\" ]]",
            "exit 0",
            "if [[ \"${1:-}\" == \"--help\" || \"${1:-}\" == \"-h\" ]]",
            "validation_lane_usage",
            "exit 0",
            "LANE=\"${1:-quick}\"",
            "if ! validation_lane_is_known \"$LANE\"",
            "exit 2",
            "if [[ \"$LANE\" != \"full-preflight\" ]]",
            "mneme_ci_init \"$ROOT\" \"$LANE\"",
        ],
    );

    assert!(
        claude.contains("scripts/ci/validation-lane.sh --list"),
        "CLAUDE validation ladder must document the non-executing lane list mode"
    );
    assert!(
        claude.contains("scripts/ci/validation-lane.sh --help"),
        "CLAUDE validation ladder must document the non-executing lane help mode"
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
        "cargo test -p mneme-index --test complete_knn_tamper -- --nocapture",
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
        "expected $(validation_lane_choices)",
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
        "scratch=\"$(mktemp -d \"${TMPDIR:-/tmp}/mneme-full-preflight.XXXXXX\")\"",
        "sentinel_target=\"$scratch/cargo-target\"",
        "output=\"$(CARGO_TARGET_DIR=\"$sentinel_target\" bash scripts/ci/validation-lane.sh full-preflight)\"",
        "validation-lane (full-preflight): planned sublanes: quick crypto tamper merge determinism",
        "validation-lane (full-preflight): heavy checks are NOT executed by this lane.",
        "validation-lane (full-preflight): Section 17.7 cross-host two-machine determinism is NOT proven by this lane (single host).",
        "validation-lane (full-preflight): to prove it, set MNEME_SECOND_HOST and run scripts/ci/determinism-two-machine.sh on a distinct physical host.",
        "validation-lane (full-preflight): OK",
        "if [[ -e \"$sentinel_target\" ]]",
        "full-preflight-smoke: full-preflight created target dir",
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
        "scratch=\"$(mktemp -d \"${TMPDIR:-/tmp}/mneme-validation-lane-unknown.XXXXXX\")\"",
        "sentinel_target=\"$scratch/cargo-target\"",
        "CARGO_TARGET_DIR=\"$sentinel_target\" bash scripts/ci/validation-lane.sh __mneme_unknown_lane__",
        "status=$?",
        "require_exit_status \"$label\" \"$status\" \"2\" \"$output\"",
        "Unknown lane: __mneme_unknown_lane__ (expected quick|crypto|tamper|merge|determinism|bounds|p3-local|full-preflight|full)",
        "if [[ -e \"$sentinel_target\" ]]",
        "validation-lane-unknown-smoke: unknown lane created target dir",
        "validation-lane-unknown-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "unknown-lane smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_help_smoke_preserves_executable_contract() {
    let validation_contract_smoke =
        include_str!("../../../scripts/ci/validation-contract-smoke.sh");
    assert!(
        validation_contract_smoke.contains("bash scripts/ci/validation-lane-help-smoke.sh"),
        "validation contract smoke must run the validation-lane --help smoke"
    );

    let smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/validation-lane-help-smoke.sh"
    );
    let smoke = std::fs::read_to_string(smoke_path).expect("validation-lane help smoke must exist");

    for phrase in [
        "source scripts/ci/smoke-assertions.sh",
        "scratch=\"$(mktemp -d \"${TMPDIR:-/tmp}/mneme-validation-lane-help.XXXXXX\")\"",
        "sentinel_target=\"$scratch/cargo-target\"",
        "short_sentinel_target=\"$scratch/short-cargo-target\"",
        "output=\"$(CARGO_TARGET_DIR=\"$sentinel_target\" bash scripts/ci/validation-lane.sh --help)\"",
        "short_output=\"$(CARGO_TARGET_DIR=\"$short_sentinel_target\" bash scripts/ci/validation-lane.sh -h)\"",
        "Usage: scripts/ci/validation-lane.sh <quick|crypto|tamper|merge|determinism|bounds|p3-local|full-preflight|full>",
        "       scripts/ci/validation-lane.sh --list",
        "       scripts/ci/validation-lane.sh --help",
        "require_exact_output \"$label\" \"$output\" \"$expected_output\"",
        "require_exact_output \"$label\" \"$short_output\" \"$expected_output\"",
        "require_line_count \"$label\" \"$output\" \"3\"",
        "require_line_count \"$label\" \"$short_output\" \"3\"",
        "if [[ -e \"$sentinel_target\" ]]",
        "if [[ -e \"$short_sentinel_target\" ]]",
        "validation-lane-help-smoke: --help created target dir",
        "validation-lane-help-smoke: -h created target dir",
        "validation-lane-help-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "validation-lane help smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_list_smoke_preserves_executable_contract() {
    let validation_contract_smoke =
        include_str!("../../../scripts/ci/validation-contract-smoke.sh");
    assert!(
        validation_contract_smoke.contains("bash scripts/ci/validation-lane-list-smoke.sh"),
        "validation contract smoke must run the validation-lane --list smoke"
    );

    let smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/validation-lane-list-smoke.sh"
    );
    let smoke = std::fs::read_to_string(smoke_path).expect("validation-lane list smoke must exist");

    for phrase in [
        "source scripts/ci/smoke-assertions.sh",
        "scratch=\"$(mktemp -d \"${TMPDIR:-/tmp}/mneme-validation-lane-list.XXXXXX\")\"",
        "sentinel_target=\"$scratch/cargo-target\"",
        "output=\"$(CARGO_TARGET_DIR=\"$sentinel_target\" bash scripts/ci/validation-lane.sh --list)\"",
        "expected_output=\"quick|crypto|tamper|merge|determinism|bounds|p3-local|full-preflight|full\"",
        "require_exact_output \"$label\" \"$output\" \"$expected_output\"",
        "require_line_count \"$label\" \"$output\" \"1\"",
        "if [[ -e \"$sentinel_target\" ]]",
        "validation-lane-list-smoke: --list created target dir",
        "validation-lane-list-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "validation-lane list smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_smoke_scripts_share_assertion_helpers() {
    let full_preflight_smoke = include_str!("../../../scripts/ci/full-preflight-smoke.sh");
    let unknown_lane_smoke = include_str!("../../../scripts/ci/validation-lane-unknown-smoke.sh");
    let help_smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/validation-lane-help-smoke.sh"
    );
    let help_smoke =
        std::fs::read_to_string(help_smoke_path).expect("validation-lane help smoke must exist");
    let list_smoke_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/ci/validation-lane-list-smoke.sh"
    );
    let list_smoke =
        std::fs::read_to_string(list_smoke_path).expect("validation-lane list smoke must exist");

    for (name, smoke) in [
        ("full-preflight-smoke", full_preflight_smoke),
        ("validation-lane-unknown-smoke", unknown_lane_smoke),
        ("validation-lane-help-smoke", help_smoke.as_str()),
        ("validation-lane-list-smoke", list_smoke.as_str()),
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
        "require_exact_output()",
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
        "require_exact_output \"$label\" \"$sample_output\" \"$sample_output\"",
        "require_absent_substring \"$label\" \"$sample_output\" \"gamma\"",
        "require_line_count \"$label\" \"$sample_output\" \"2\"",
        "require_exit_status \"$label\" \"2\" \"2\" \"$sample_output\"",
        "expect_failure \"missing exact line\"",
        "expect_failure \"output mismatch\"",
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
fn validation_contract_smoke_enforces_exact_component_output() {
    let smoke = include_str!("../../../scripts/ci/validation-contract-smoke.sh");

    for phrase in [
        "source scripts/ci/smoke-assertions.sh",
        "expected_output=\"$(cat <<'EOF'",
        "smoke-assertions-smoke: OK",
        "validation-lane-list-smoke: OK",
        "validation-lane-help-smoke: OK",
        "full-preflight-smoke: OK",
        "validation-lane-unknown-smoke: OK",
        "require_exact_output \"$label\" \"$output\" \"$expected_output\"",
        "printf '%s\\n' \"$output\"",
        "validation-contract-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "validation contract smoke must preserve `{phrase}`"
        );
    }
}

#[test]
fn validation_lane_quick_runs_vcp_integration_smoke() {
    let validation_lane = include_str!("../../../scripts/ci/validation-lane.sh");
    let quick_lane = validation_lane
        .split("\n  quick)")
        .nth(1)
        .and_then(|tail| tail.split("\n  crypto)").next())
        .expect("validation-lane must define a quick lane");

    assert!(
        quick_lane.contains("bash scripts/ci/vcp-integration-smoke.sh"),
        "quick lane must run VCP integration smoke after validation contract"
    );

    let smoke = include_str!("../../../scripts/ci/vcp-integration-smoke.sh");
    for phrase in [
        "cargo test -p mneme-index --test beacon_spot_check",
        "cargo test -p mneme-index --test complete_knn_cert_v1",
        "crossref_",
        "cargo test -p mneme-cli verify_cert",
        "vcp-integration-smoke: OK",
    ] {
        assert!(
            smoke.contains(phrase),
            "vcp-integration-smoke must preserve `{phrase}`"
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
        "bash scripts/ci/validation-lane-list-smoke.sh",
        "bash scripts/ci/validation-lane-help-smoke.sh",
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
