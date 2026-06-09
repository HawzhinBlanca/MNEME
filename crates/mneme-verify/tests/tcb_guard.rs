//! TCB guard: production source must not contain forbidden patterns (§10).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

#[test]
fn tcb_guard_no_forbidden_patterns() {
    let output = run_tcb_guard(&[]);
    assert_guard_success("TCB guard", &output);
}

#[test]
fn tcb_guard_verifier_length_calls_stay_in_named_helpers() {
    let src = workspace_root().join("crates/mneme-verify/src");
    let mut violations = Vec::new();

    for file in [
        "lib.rs",
        "proof.rs",
        "recall.rs",
        "root.rs",
        "semantic.rs",
        "store.rs",
    ] {
        let path = src.join(file);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read verifier source {}: {err}", path.display()));
        for (line_no, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if !trimmed.contains(".len()") {
                continue;
            }
            let is_named_helper_len =
                trimmed == "path.len() == TREE_DEPTH" || trimmed == "objects.len()";
            if !is_named_helper_len {
                violations.push(format!("{file}:{}: {trimmed}", line_no + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "mneme-verify direct .len() calls must stay behind named helpers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn tcb_guard_script_self_test_covers_masking_semantics() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
}

#[test]
fn tcb_guard_script_self_test_covers_trusted_parser_test_boundary() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) boundary OK"),
        "TCB guard self-test must cover the trusted parser #[cfg(test)] boundary\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_code_aware_cfg_test_cutoff() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) cutoff ignores comments/strings OK"),
        "TCB guard self-test must prove cfg(test) cutoff is based on code, not comments or strings\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_byte_raw_and_nested_block_masks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner masks byte raw strings and nested block comments OK"),
        "TCB guard self-test must prove byte raw strings and nested block comments are masked\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_escaped_and_multiline_string_masks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner masks escaped quotes and multiline normal strings OK"),
        "TCB guard self-test must prove escaped quotes and multiline normal strings are masked\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_char_and_byte_char_masks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner handles char and byte char literals without hiding code OK"),
        "TCB guard self-test must prove char and byte char literals cannot hide following code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_lifetime_syntax_near_forbidden_code() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner keeps lifetime syntax from masking production code OK"),
        "TCB guard self-test must prove lifetime syntax cannot be mistaken for char literals\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_marker_scope() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner only honors opt-out markers in line comments OK"),
        "TCB guard self-test must prove opt-out markers inside strings cannot suppress real code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_unsafe_code() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects unsafe code OK"),
        "TCB guard self-test must prove unsafe code is rejected in the trusted scanning surface\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_production_assert_macros() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects production assert macros OK"),
        "TCB guard self-test must prove assert macros are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_whitespace_macro_invocations() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects whitespace macro invocations OK"),
        "TCB guard self-test must prove whitespace before forbidden macro bangs cannot evade trusted production scanning\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_result_error_unwraps() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects Result unwrap_err/expect_err OK"),
        "TCB guard self-test must prove panic-capable Result error helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_fallback_default_helpers() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects fallback default helpers OK"),
        "TCB guard self-test must prove fallback default helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_implicit_default_constructors() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects implicit default constructors OK"),
        "TCB guard self-test must prove implicit default construction is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_result_option_conversions() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects Result-to-Option conversions OK"),
        "TCB guard self-test must prove Result::ok/err conversions are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_result_option_predicate_collapse() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects Result/Option predicate collapse OK"),
        "TCB guard self-test must prove Result/Option predicate collapse is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_collection_membership_predicates() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects collection membership predicates OK"),
        "TCB guard self-test must prove collection membership predicates are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_iterator_elision_helpers() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects iterator elision helpers OK"),
        "TCB guard self-test must prove iterator helpers that can silently drop evidence are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_iterator_terminal_selection_helpers() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects iterator terminal selection helpers OK"),
        "TCB guard self-test must prove iterator terminal selection helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_iterator_aggregate_predicates() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects iterator aggregate predicates OK"),
        "TCB guard self-test must prove iterator aggregate predicates are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_retain_based_silent_filtering() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects retain-based silent filtering OK"),
        "TCB guard self-test must prove retain-style collection filtering is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_bulk_collection_mutation() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects bulk collection mutation OK"),
        "TCB guard self-test must prove bulk collection mutation helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_collection_reorder_and_dedup_helpers() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects collection reorder/dedup helpers OK"),
        "TCB guard self-test must prove collection reorder and dedup helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_collection_remove_and_pop_helpers() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects collection remove/pop helpers OK"),
        "TCB guard self-test must prove collection remove and pop helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_floating_point_hazards() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects floating-point hazards OK"),
        "TCB guard self-test must prove floating-point types, literals, and NaN-sensitive helpers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_whitespace_panic_calls() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects whitespace panic calls OK"),
        "TCB guard self-test must prove whitespace before panic-capable call parens cannot evade trusted production scanning\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_panic_any() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects panic_any OK"),
        "TCB guard self-test must prove panic_any is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_resume_unwind() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects resume_unwind OK"),
        "TCB guard self-test must prove resume_unwind is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_catch_unwind() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects catch_unwind OK"),
        "TCB guard self-test must prove catch_unwind is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_process_termination() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects process termination OK"),
        "TCB guard self-test must prove process exit/abort calls are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_ambient_time() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects ambient time OK"),
        "TCB guard self-test must prove ambient time reads are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_ambient_process_state() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects ambient process state OK"),
        "TCB guard self-test must prove ambient process-state reads are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_ambient_runtime_probes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects ambient runtime probes OK"),
        "TCB guard self-test must prove stdio, process/thread identity, and backtrace probes are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_process_spawning() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects process spawning OK"),
        "TCB guard self-test must prove external process spawning is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_network_io() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects network I/O OK"),
        "TCB guard self-test must prove network I/O is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_filesystem_mutation() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects filesystem mutation OK"),
        "TCB guard self-test must prove filesystem mutation is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_filesystem_probe_traversal() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects filesystem probe/traversal OK"),
        "TCB guard self-test must prove filesystem metadata, directory traversal, symlink reads, and File::open are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_concurrency_spawning() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects concurrency spawning OK"),
        "TCB guard self-test must prove thread/task spawning is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_entropy_use() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects entropy use OK"),
        "TCB guard self-test must prove entropy/randomness is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_global_mutable_state() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects global mutable state OK"),
        "TCB guard self-test must prove global/interior mutable state is rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_randomized_hash_collections() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects randomized hash collections OK"),
        "TCB guard self-test must prove randomized hash collections/hashers are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_path_exists_probes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects path exists probes OK"),
        "TCB guard self-test must prove Path::exists probes are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_manual_memory_primitives() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects manual memory primitives OK"),
        "TCB guard self-test must prove manual memory/raw-pointer primitives are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_compile_time_ambient_inputs() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects compile-time ambient inputs OK"),
        "TCB guard self-test must prove compile-time file/env inputs are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_catches_diagnostics_and_native_hooks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner rejects diagnostics and native hooks OK"),
        "TCB guard self-test must prove diagnostic side effects and native hooks are rejected in trusted production code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_trusted_parser_index_and_cast_guards() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser index and cast guards OK"),
        "TCB guard self-test must prove trusted parser production code gets index/cast checks\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_index_expression_shapes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner catches spaced and expression-result indexes OK"),
        "TCB guard self-test must prove slice-index panic vectors cannot hide behind whitespace or call results\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_try_result_indexing() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scanner catches try-result indexes OK"),
        "TCB guard self-test must prove postfix ? cannot hide slice-index panic vectors\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_scanning_after_trusted_parser_tests() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser resumes scanning after cfg(test) items OK"),
        "TCB guard self-test must prove production code after a cfg(test) item is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_inline_cfg_test_items() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser inline cfg(test) items resume scanning OK"),
        "TCB guard self-test must prove same-line production after inline cfg(test) items is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_cfg_test_attribute_stacks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) attribute stacks resume scanning OK"),
        "TCB guard self-test must prove production after stacked cfg(test) attributes is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_cfg_test_after_other_attributes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) after other attributes OK"),
        "TCB guard self-test must prove cfg(test) is honored anywhere in a leading attribute stack without skipping non-test cfgs\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_multiline_attributes_before_cfg_test() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser multiline attributes before cfg(test) OK"),
        "TCB guard self-test must prove cfg(test) is honored after a preceding multiline attribute closes on the same line\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_spaced_cfg_test_attributes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser spaced cfg(test) attributes OK"),
        "TCB guard self-test must prove whitespace-equivalent cfg(test) attributes are handled without matching non-test cfgs\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_compound_cfg_test_attributes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser compound cfg(test) attributes OK"),
        "TCB guard self-test must prove cfg(all(test, ...)) is skipped without treating cfg(any(test, ...)) as test-only\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_logical_cfg_test_attributes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser logical cfg(test) attributes OK"),
        "TCB guard self-test must prove cfg(not(not(test))) is treated as test-only without skipping cfg(not(test)) code\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_multiline_cfg_test_attributes() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser multiline cfg(test) attributes OK"),
        "TCB guard self-test must prove multiline cfg(test) expressions are handled without skipping non-test multiline cfgs\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_cfg_test_semicolon_and_macro_items() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) semicolon and macro items resume scanning OK"),
        "TCB guard self-test must prove production after cfg(test) semicolon and macro items is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_cfg_test_multiline_signatures() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) multiline signatures resume scanning OK"),
        "TCB guard self-test must prove production after cfg(test) multiline signatures is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_cfg_test_impl_blocks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) impl blocks resume scanning OK"),
        "TCB guard self-test must prove production after cfg(test) impl blocks is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_script_self_test_covers_cfg_test_trait_enum_extern_blocks() {
    let output = run_tcb_guard(&["--self-test"]);
    assert_guard_success("TCB guard self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trusted parser cfg(test) trait/enum/extern blocks resume scanning OK"),
        "TCB guard self-test must prove production after cfg(test) trait, enum, and extern blocks is still scanned\nstdout:\n{stdout}"
    );
}

#[test]
fn tcb_guard_masking_logic_lives_in_ci_guard_script() {
    let source = include_str!("tcb_guard.rs");
    let local_mask_type = ["Source", "Code", "Mask"].concat();
    let local_mask_helper = ["masked", "_code", "_lines"].concat();
    let local_raw_string_helper = ["raw", "_string", "_starts", "_at"].concat();

    assert!(
        !source.contains(&local_mask_type)
            && !source.contains(&local_mask_helper)
            && !source.contains(&local_raw_string_helper),
        "Rust TCB guard tests must exercise scripts/ci/verify-tcb-guard.sh instead of carrying duplicate masking logic"
    );
}

#[test]
fn tcb_guard_script_self_test_centralizes_fixture_reset() {
    let script = include_str!("../../../scripts/ci/verify-tcb-guard.sh");

    assert!(
        script.contains("reset_tcb_self_test_fixture()"),
        "TCB guard self-test should centralize temp verifier fixture resets"
    );
    assert!(
        script.contains("run_self_test_guard()"),
        "TCB guard self-test should centralize guard invocation wiring"
    );
    assert_eq!(
        script
            .matches("rm -rf \"$tmp/crates/mneme-verify/src\"")
            .count(),
        0,
        "TCB guard self-test should not duplicate hard-coded verifier fixture resets"
    );
    assert_eq!(
        script
            .matches("MNEME_TCB_DIR=\"$tmp/crates/mneme-verify/src\"")
            .count(),
        0,
        "TCB guard self-test should not duplicate hard-coded guard environment wiring"
    );
}

fn run_tcb_guard(args: &[&str]) -> Output {
    let root = workspace_root();
    let mut command = Command::new("bash");
    command
        .arg(root.join("scripts/ci/verify-tcb-guard.sh"))
        .args(args)
        .current_dir(&root);
    command
        .output()
        .unwrap_or_else(|err| panic!("run TCB guard script: {err}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_guard_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
