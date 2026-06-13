fn normalized_source(source: &str) -> String {
    source.split_whitespace().collect()
}

fn helper_directly_returns_raw_timeout_result(helper_body: &str, raw_timeout_call: &str) -> bool {
    let normalized_helper = normalized_source(helper_body);
    let direct_raw_return = format!("{}}}", normalized_source(raw_timeout_call));

    normalized_helper.ends_with(&direct_raw_return)
}

fn contains_normalized_source(source: &str, expected: &str) -> bool {
    normalized_source(source).contains(&normalized_source(expected))
}

fn count_normalized_source(source: &str, expected: &str) -> usize {
    normalized_source(source)
        .matches(&normalized_source(expected))
        .count()
}

fn source_between_markers<'a>(
    source: &'a str,
    start_marker: &str,
    end_marker: &str,
    context: &str,
) -> &'a str {
    let (_, after_start) = source
        .split_once(start_marker)
        .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
    let (section, _) = after_start
        .split_once(end_marker)
        .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));

    section
}

fn source_top_level_item_after_marker<'a>(
    source: &'a str,
    start_marker: &str,
    context: &str,
) -> &'a str {
    let (_, after_start) = source
        .split_once(start_marker)
        .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
    let top_level_end = after_start
        .find("\n}")
        .unwrap_or_else(|| panic!("{context} should contain top-level closing brace"));

    &after_start[..top_level_end]
}

#[test]
fn sync_client_reuses_server_sync_frame_limit() {
    let sync_client = include_str!("../src/sync_client.rs");

    assert!(
        !sync_client.contains("SYNC_CLIENT_MAX_FRAME"),
        "sync client must reuse sync::SYNC_MAX_FRAME instead of defining its own frame cap"
    );
    assert!(
        sync_client.contains("sync::SYNC_MAX_FRAME"),
        "sync client WebSocket config must reference the server sync frame cap"
    );
}

#[test]
fn sync_peer_drop_audit_hook_is_wired_to_client_and_server() {
    let daemon_audit = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/audit.rs"),
    )
    .unwrap_or_else(|err| panic!("daemon audit module should exist: {err}"));
    let sync_client = include_str!("../src/sync_client.rs");
    let sync_server = include_str!("../src/sync.rs");
    let store_audit = include_str!("../../mneme-store/src/audit.rs");

    assert!(
        daemon_audit.contains("target: AUDIT_TARGET")
            || daemon_audit.contains("target: \"mneme.audit\""),
        "daemon audit module should emit on the shared mneme.audit target"
    );
    assert!(
        daemon_audit.contains("event = \"sync.peer_dropped\""),
        "daemon audit module should name the sync peer drop event"
    );
    assert!(
        daemon_audit.contains("peer,") && daemon_audit.contains("reason,"),
        "sync peer drop audit events should carry peer and reason fields"
    );
    assert!(
        sync_client.contains("audit::emit_sync_peer_dropped("),
        "production sync client should emit a sync peer drop audit event when it drops a peer"
    );
    assert!(
        sync_server.contains("audit::emit_sync_peer_dropped("),
        "sync websocket server should emit a sync peer drop audit event when it suppresses/drops a peer frame"
    );
    assert!(
        !store_audit.contains("emit_sync_peer_dropped"),
        "sync peer drop audit hook belongs in mnemed, not as a dead store-kernel stub"
    );
}

#[test]
fn audit_observability_exports_otlp_when_configured() {
    let observability = include_str!("../src/observability.rs");
    let store_audit = include_str!("../../mneme-store/src/audit.rs");
    let main_rs = include_str!("../src/main.rs");

    assert!(
        observability.contains("pub use mneme_store::AUDIT_TARGET"),
        "observability module should re-export the shared audit target"
    );
    assert!(
        observability.contains("OTEL_EXPORTER_OTLP_ENDPOINT")
            && observability.contains("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
        "observability should honor standard OTLP endpoint env vars"
    );
    assert!(
        observability.contains("tracing_opentelemetry::layer()"),
        "observability should bridge audit events to OpenTelemetry when OTLP is configured"
    );
    assert!(
        store_audit.contains("pub const AUDIT_TARGET: &str = \"mneme.audit\""),
        "store audit emitters should share the mneme.audit target constant"
    );
    assert!(
        store_audit.contains("tracing::event!"),
        "store audit emitters should use explicit tracing events for OTel export"
    );
    assert!(
        main_rs.contains("init_observability()"),
        "mnemed main should install the observability subscriber"
    );
}

#[test]
fn source_invariant_async_outcome_signature_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let quoted_async_fn = ["\"", "async fn "].concat();
    let escaped_newline = ["\\", "n"].concat();
    let outcome_token = ["Out", "come"].concat();
    let brittle_signature_line = source_invariants.lines().find(|line| {
        line.contains(&quoted_async_fn)
            && line.contains(&escaped_newline)
            && line.contains(&outcome_token)
    });

    assert!(
        brittle_signature_line.is_none(),
        "source invariants should not depend on exact multiline async Outcome signature formatting: {brittle_signature_line:?}"
    );
}

#[test]
fn source_invariant_timeout_return_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let brittle_return_suffix = [".await", "\\n}"].concat();

    assert!(
        !source_invariants.contains(&brittle_return_suffix),
        "source invariants should not depend on exact timeout-return line endings"
    );
}

#[test]
fn source_invariant_direct_read_body_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let direct_read_token = ["stream", ".read", "_exact"].concat();
    let brittle_direct_read_line = source_invariants
        .lines()
        .find(|line| line.contains(&escaped_newline) && line.contains(&direct_read_token));

    assert!(
        brittle_direct_read_line.is_none(),
        "source invariants should not depend on exact multiline direct-read body formatting: {brittle_direct_read_line:?}"
    );
}

#[test]
fn source_invariant_accept_await_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let await_token = [".a", "wait"].concat();
    let listener_accept_token = [".ac", "cept()"].concat();
    let websocket_accept_token = ["accept", "_async"].concat();
    let brittle_accept_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && line.contains(&await_token)
            && (line.contains(&listener_accept_token) || line.contains(&websocket_accept_token))
    });

    assert!(
        brittle_accept_line.is_none(),
        "source invariants should not depend on exact multiline accept/handshake await formatting: {brittle_accept_line:?}"
    );
}

#[test]
fn source_invariant_timeout_await_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let await_token = [".a", "wait"].concat();
    let brittle_timeout_await_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && line.contains(&await_token)
            && (line.contains("tokio::time::timeout")
                || line.contains("Duration::")
                || line.contains("_TIMEOUT"))
    });

    assert!(
        brittle_timeout_await_line.is_none(),
        "source invariants should not depend on exact multiline timeout await formatting: {brittle_timeout_await_line:?}"
    );
}

#[test]
fn source_invariant_await_chain_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let await_token = [".a", "wait"].concat();
    let brittle_await_chain_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && line.contains(&await_token)
            && (line.contains(".ok") || line.contains(".is_ok"))
    });

    assert!(
        brittle_await_chain_line.is_none(),
        "source invariants should not depend on exact multiline await-chain formatting: {brittle_await_chain_line:?}"
    );
}

#[test]
fn source_invariant_yield_loop_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let yield_token = ["yield", "_now"].concat();
    let brittle_yield_loop_line = source_invariants
        .lines()
        .find(|line| line.contains(&escaped_newline) && line.contains(&yield_token));

    assert!(
        brittle_yield_loop_line.is_none(),
        "source invariants should not depend on exact multiline yield-loop formatting: {brittle_yield_loop_line:?}"
    );
}

#[test]
fn source_invariant_timeout_argument_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let timeout_token = ["tokio::time::", "timeout"].concat();
    let shutdown_helper_token = ["wait_for_running_server_", "shutdown"].concat();
    let brittle_timeout_argument_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && (line.contains(&timeout_token)
                || line.contains("RUNNING_SERVER_SHUTDOWN_HELPER_TIMEOUT")
                || line.contains(&shutdown_helper_token))
    });

    assert!(
        brittle_timeout_argument_line.is_none(),
        "source invariants should not depend on exact multiline timeout/helper argument formatting: {brittle_timeout_argument_line:?}"
    );
}

#[test]
fn source_invariant_classifier_call_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let classifier_token = ["classify_", "two_peer_ws_binary_read"].concat();
    let brittle_classifier_call_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && line.contains("match ")
            && line.contains(&classifier_token)
    });

    assert!(
        brittle_classifier_call_line.is_none(),
        "source invariants should not depend on exact multiline classifier-call formatting: {brittle_classifier_call_line:?}"
    );
}

#[test]
fn source_invariant_fixture_loop_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let subject_index_token = ["subject", "_index"].concat();
    let brittle_fixture_loop_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && line.contains("for ")
            && line.contains(&subject_index_token)
    });

    assert!(
        brittle_fixture_loop_line.is_none(),
        "source invariants should not depend on exact multiline fixture-loop formatting: {brittle_fixture_loop_line:?}"
    );
}

#[test]
fn source_invariant_constructor_argument_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let constructor_token = ["Rate", "Limiter::new"].concat();
    let brittle_constructor_line = source_invariants
        .lines()
        .find(|line| line.contains(&escaped_newline) && line.contains(&constructor_token));

    assert!(
        brittle_constructor_line.is_none(),
        "source invariants should not depend on exact multiline constructor argument formatting: {brittle_constructor_line:?}"
    );
}

#[test]
fn source_invariant_function_signature_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let observer_token = ["observe", "_connection_result"].concat();
    let joined_type_token = ["joined: Option", "<Result"].concat();
    let brittle_signature_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && (line.contains(&observer_token) || line.contains(&joined_type_token))
    });

    assert!(
        brittle_signature_line.is_none(),
        "source invariants should not depend on exact multiline function signature formatting: {brittle_signature_line:?}"
    );
}

#[test]
fn source_invariant_raw_match_arm_checks_are_not_whitespace_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_newline = ["\\", "n"].concat();
    let raw_result_arm_line = source_invariants.lines().find(|line| {
        line.contains(&escaped_newline)
            && (line.contains("Ok(") || line.contains("Err("))
            && line.contains("=>")
    });

    assert!(
        raw_result_arm_line.is_none(),
        "source invariants should not depend on exact multiline raw match-arm formatting: {raw_result_arm_line:?}"
    );
}

#[test]
fn source_invariant_sync_client_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let recv_binary_token = ["recv", "_binary"].concat();
    let send_binary_token = ["send", "_binary"].concat();
    let sync_client_token = ["sync", "_client"].concat();
    let brittle_sync_client_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&sync_client_token)
                || line.contains(&recv_binary_token)
                || line.contains(&send_binary_token))
    });

    assert!(
        brittle_sync_client_section_line.is_none(),
        "sync-client source invariant sections should not depend on exact blank-line formatting: {brittle_sync_client_section_line:?}"
    );
}

#[test]
fn source_invariant_v11_fake_peer_close_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let recorded_binary_token = ["recv", "_recorded_binary_result"].concat();
    let stalled_peer_token = ["stalled", "_websocket_peer"].concat();
    let close_classifier_token = ["classify", "_v11_fake_peer_close_read"].concat();
    let brittle_v11_close_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&recorded_binary_token)
                || line.contains(&stalled_peer_token)
                || line.contains(&close_classifier_token))
    });

    assert!(
        brittle_v11_close_section_line.is_none(),
        "v11 fake-peer close source invariant sections should not depend on exact blank-line formatting: {brittle_v11_close_section_line:?}"
    );
}

#[test]
fn source_invariant_v11_fake_peer_accept_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let tcp_accept_token = ["accept", "_fake_peer_tcp_stream_with_timeout"].concat();
    let tcp_classifier_token = ["classify", "_v11_fake_peer_tcp_accept"].concat();
    let websocket_accept_token = ["accept", "_fake_peer_websocket_with_timeout"].concat();
    let websocket_classifier_token = ["classify", "_v11_fake_peer_websocket_accept"].concat();
    let oversized_send_token = ["send", "_oversized_fake_peer_frame"].concat();
    let brittle_v11_accept_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&tcp_accept_token)
                || line.contains(&tcp_classifier_token)
                || line.contains(&websocket_accept_token)
                || line.contains(&websocket_classifier_token)
                || line.contains(&oversized_send_token))
    });

    assert!(
        brittle_v11_accept_section_line.is_none(),
        "v11 fake-peer accept source invariant sections should not depend on exact blank-line formatting: {brittle_v11_accept_section_line:?}"
    );
}

#[test]
fn source_invariant_v11_binary_read_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let binary_classifier_token = ["classify", "_v11_binary_read"].concat();
    let remember_token = ["fn ", "remember("].concat();
    let brittle_v11_binary_read_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&binary_classifier_token) || line.contains(&remember_token))
    });

    assert!(
        brittle_v11_binary_read_section_line.is_none(),
        "v11 binary-read source invariant sections should not depend on exact blank-line formatting: {brittle_v11_binary_read_section_line:?}"
    );
}

#[test]
fn source_invariant_sync_ws_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let binary_classifier_token = ["classify", "_sync_ws_binary_read"].concat();
    let close_classifier_token = ["classify", "_sync_ws_close_read"].concat();
    let binary_frame_token = ["recv", "_sync_ws_binary_frame"].concat();
    let close_message_token = ["recv", "_sync_ws_close_message_with_timeout"].concat();
    let authed_request_token = ["authed", "_ws_request"].concat();
    let brittle_sync_ws_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&binary_classifier_token)
                || line.contains(&close_classifier_token)
                || line.contains(&binary_frame_token)
                || line.contains(&close_message_token)
                || line.contains(&authed_request_token))
    });

    assert!(
        brittle_sync_ws_section_line.is_none(),
        "sync WebSocket source invariant sections should not depend on exact blank-line formatting: {brittle_sync_ws_section_line:?}"
    );
}

#[test]
fn source_invariant_two_peer_ws_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let binary_classifier_token = ["classify", "_two_peer_ws_binary_read"].concat();
    let binary_frame_token = ["recv", "_ws_binary_frame"].concat();
    let brittle_two_peer_ws_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&binary_classifier_token) || line.contains(&binary_frame_token))
    });

    assert!(
        brittle_two_peer_ws_section_line.is_none(),
        "two-peer WebSocket source invariant sections should not depend on exact blank-line formatting: {brittle_two_peer_ws_section_line:?}"
    );
}

#[test]
fn source_invariant_unix_fake_peer_request_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let accept_timeout_token = ["accept", "_fake_unix_peer_stream_with_timeout"].concat();
    let request_timeout_token = ["read", "_fake_unix_request_exact_with_timeout"].concat();
    let accept_classifier_token = ["classify", "_fake_unix_peer_accept"].concat();
    let request_classifier_token = ["classify", "_fake_unix_request_exact_read"].concat();
    let brittle_unix_fake_peer_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&accept_timeout_token)
                || line.contains(&request_timeout_token)
                || line.contains(&accept_classifier_token)
                || line.contains(&request_classifier_token))
    });

    assert!(
        brittle_unix_fake_peer_section_line.is_none(),
        "Unix fake-peer request source invariant sections should not depend on exact blank-line formatting: {brittle_unix_fake_peer_section_line:?}"
    );
}

#[test]
fn source_invariant_unix_fake_peer_client_close_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let client_close_classifier_token = ["classify", "_fake_unix_peer_client_close"].concat();
    let client_close_timeout_token = ["read", "_fake_unix_peer_client_close_with_timeout"].concat();
    let zero_timeout_test_token = ["request", "_json_zero_timeout_uses_default_deadline"].concat();
    let brittle_unix_client_close_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&client_close_classifier_token)
                || line.contains(&client_close_timeout_token)
                || line.contains(&zero_timeout_test_token))
    });

    assert!(
        brittle_unix_client_close_section_line.is_none(),
        "Unix fake-peer client-close source invariant sections should not depend on exact blank-line formatting: {brittle_unix_client_close_section_line:?}"
    );
}

#[test]
fn source_invariant_unix_post_shutdown_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let post_shutdown_read_token = ["read", "_after_shutdown"].concat();
    let fake_peer_token = ["expect", "_fake_unix_peer"].concat();
    let brittle_unix_post_shutdown_section_line = source_invariants.lines().find(|line| {
        line.contains(".split(")
            && line.contains(&escaped_blank_line)
            && (line.contains(&post_shutdown_read_token) || line.contains(&fake_peer_token))
    });

    assert!(
        brittle_unix_post_shutdown_section_line.is_none(),
        "Unix post-shutdown source invariant sections should not depend on exact blank-line formatting: {brittle_unix_post_shutdown_section_line:?}"
    );
}

#[test]
fn source_invariant_unix_silent_client_close_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let silent_timeout_token = ["read", "_silent_client_close_with_timeout"].concat();
    let silent_classifier_token = ["classify", "_silent_client_close_read"].concat();
    let oversized_request_token =
        ["request", "_json_rejects_oversized_request_before_connect"].concat();
    let source_lines: Vec<_> = source_invariants.lines().collect();
    let brittle_unix_silent_client_close_section = source_lines.windows(4).find(|window| {
        let section_window = window.join("\n");
        window[0].contains(".split(")
            && section_window.contains(&escaped_blank_line)
            && (section_window.contains(&silent_timeout_token)
                || section_window.contains(&silent_classifier_token)
                || section_window.contains(&oversized_request_token))
    });

    assert!(
        brittle_unix_silent_client_close_section.is_none(),
        "Unix silent-client close source invariant sections should not depend on exact blank-line formatting: {brittle_unix_silent_client_close_section:?}"
    );
}

#[test]
fn source_invariant_unix_client_io_sections_are_not_blank_line_brittle() {
    let source_invariants = include_str!("source_invariants.rs");
    let escaped_blank_line = ["\\n", "\\n"].concat();
    let connect_timeout_token = ["connect", "_unix_stream_with_timeout"].concat();
    let connect_classifier_token = ["classify", "_unix_connect"].concat();
    let read_classifier_token = ["classify", "_unix_read_exact"].concat();
    let write_classifier_token = ["classify", "_unix_write_all"].concat();
    let source_lines: Vec<_> = source_invariants.lines().collect();
    let brittle_unix_client_io_section = source_lines.windows(4).find(|window| {
        let section_window = window.join("\n");
        window[0].contains(".split(")
            && section_window.contains(&escaped_blank_line)
            && (section_window.contains(&connect_timeout_token)
                || section_window.contains(&connect_classifier_token)
                || section_window.contains(&read_classifier_token)
                || section_window.contains(&write_classifier_token))
    });

    assert!(
        brittle_unix_client_io_section.is_none(),
        "Unix client I/O source invariant sections should not depend on exact blank-line formatting: {brittle_unix_client_io_section:?}"
    );
}

#[test]
fn source_invariant_unix_readiness_section_uses_bounded_extraction() {
    let source_invariants = include_str!("source_invariants.rs");
    let readiness_helper_token = ["wait_for", "_unix_socket_accepting"].concat();
    let unbounded_readiness_section_line = source_invariants
        .lines()
        .find(|line| line.contains(".split(") && line.contains(&readiness_helper_token));

    assert!(
        unbounded_readiness_section_line.is_none(),
        "Unix readiness source invariant sections should use bounded extraction: {unbounded_readiness_section_line:?}"
    );
}

#[test]
fn sync_client_receive_timeout_uses_named_read_helper() {
    let sync_client = include_str!("../src/sync_client.rs");
    let binary_reader = source_between_markers(
        sync_client,
        "async fn recv_binary(",
        "async fn recv_sync_client_message_with_timeout(",
        "recv_binary body",
    );

    assert!(
        !binary_reader.contains("tokio::time::timeout(io_timeout, ws.next()).await"),
        "sync client binary receive classifier should route timed reads through a named helper"
    );
    assert!(
        sync_client.contains("async fn recv_sync_client_message_with_timeout("),
        "sync client receive timeout policy should have a named helper"
    );
    assert!(
        binary_reader.contains("recv_sync_client_message_with_timeout(ws, io_timeout).await"),
        "sync client binary receive classifier should call the named timeout helper"
    );
}

#[test]
fn sync_client_receive_timeout_outcomes_are_classified() {
    let sync_client = include_str!("../src/sync_client.rs");
    let binary_reader = source_between_markers(
        sync_client,
        "async fn recv_binary(",
        "fn classify_sync_client_frame(",
        "recv_binary body",
    );
    let timeout_helper = source_between_markers(
        sync_client,
        "async fn recv_sync_client_message_with_timeout(",
        "fn classify_sync_client_timed_message(",
        "recv_sync_client_message_with_timeout body",
    );

    for inline_pattern in [
        "Ok(Some(Ok(frame)))",
        "Ok(Some(Err(e)))",
        "Ok(None)",
        "Err(_)",
    ] {
        assert!(
            !binary_reader.contains(inline_pattern),
            "sync client binary receive loop should classify timed receive outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        sync_client.contains("enum SyncClientTimedMessageOutcome"),
        "sync client timed receives should expose a typed outcome enum"
    );
    assert!(
        sync_client.contains("fn classify_sync_client_timed_message("),
        "sync client timed receives should classify timeout results through a named helper"
    );
    assert!(
        timeout_helper.contains("classify_sync_client_timed_message("),
        "sync client receive timeout helper should return classified outcomes"
    );
    assert!(
        !helper_directly_returns_raw_timeout_result(
            timeout_helper,
            "tokio::time::timeout(io_timeout, ws.next()).await"
        ),
        "sync client receive timeout helper should not return the raw timeout result directly"
    );
    assert!(
        binary_reader.contains("SyncClientTimedMessageOutcome::Received(frame) => frame"),
        "sync client timed receive success should preserve the received frame"
    );
    assert!(
        binary_reader.contains("SyncClientTimedMessageOutcome::ReadFailed(e) =>"),
        "sync client timed receive read failures should remain explicit"
    );
    assert!(
        binary_reader.contains("SyncClientTimedMessageOutcome::Closed =>"),
        "sync client timed receive EOF should remain explicit"
    );
    assert!(
        binary_reader.contains("SyncClientTimedMessageOutcome::TimedOut =>"),
        "sync client timed receive timeouts should remain explicit"
    );
}

#[test]
fn sync_client_classifier_preservation_tests_use_named_helpers() {
    let sync_client = include_str!("../src/sync_client.rs");
    let received_frame_test = source_top_level_item_after_marker(
        sync_client,
        "fn sync_client_timed_message_classifier_preserves_received_frame()",
        "sync_client_timed_message_classifier_preserves_received_frame body",
    );
    let io_timeout_test = source_top_level_item_after_marker(
        sync_client,
        "fn sync_client_io_timeout_classifier_preserves_completed_and_failed_operations()",
        "sync_client_io_timeout_classifier_preserves_completed_and_failed_operations body",
    );
    let frame_payload_test = source_top_level_item_after_marker(
        sync_client,
        "fn sync_client_frame_classifier_preserves_binary_payload()",
        "sync_client_frame_classifier_preserves_binary_payload body",
    );

    for (test_body, context, helper_call) in [
        (
            received_frame_test,
            "timed-message received-frame preservation",
            "assert_sync_client_received_binary_frame(",
        ),
        (
            io_timeout_test,
            "generic I/O timeout preservation",
            "assert_sync_client_completed_io_timeout_value(",
        ),
        (
            frame_payload_test,
            "frame binary-payload preservation",
            "assert_sync_client_binary_frame_payload(",
        ),
    ] {
        assert!(
            !test_body.contains("=> panic!("),
            "sync client {context} test should route classifier preservation reporting through named helpers"
        );
        assert!(
            test_body.contains(helper_call),
            "sync client {context} test should call `{helper_call}`"
        );
    }
    assert!(
        io_timeout_test.contains("assert_sync_client_failed_io_timeout_error("),
        "sync client generic I/O timeout preservation test should call the named failed-operation helper"
    );
    assert!(
        sync_client.contains("type SyncClientClassifierCheck = Result<(), String>"),
        "sync client classifier preservation checks should name the validation result type"
    );
    for helper in [
        "fn assert_sync_client_received_binary_frame(",
        "fn expect_sync_client_received_binary_frame(",
        "fn assert_sync_client_completed_io_timeout_value(",
        "fn expect_sync_client_completed_io_timeout_value(",
        "fn assert_sync_client_failed_io_timeout_error(",
        "fn expect_sync_client_failed_io_timeout_error(",
        "fn assert_sync_client_binary_frame_payload(",
        "fn expect_sync_client_binary_frame_payload(",
        "fn assert_sync_client_classifier_check_passed(",
    ] {
        assert!(
            sync_client.contains(helper),
            "sync client classifier preservation checks should define `{helper}`"
        );
    }
}

#[test]
fn sync_client_generic_io_timeout_outcomes_are_classified() {
    let sync_client = include_str!("../src/sync_client.rs");
    let io_timeout_helper = source_between_markers(
        sync_client,
        "async fn with_io_timeout<T, E>(",
        "fn classify_sync_client_io_timeout",
        "with_io_timeout body",
    );

    for inline_pattern in ["Ok(Ok(value)) =>", "Ok(Err(e)) =>", "Err(_) =>"] {
        assert!(
            !contains_normalized_source(io_timeout_helper, inline_pattern),
            "sync client generic I/O timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    assert!(
        sync_client.contains("type TimedSyncClientOperation"),
        "sync client generic I/O timeout helper should name the timed operation result type"
    );
    assert!(
        sync_client.contains("enum SyncClientIoTimeoutOutcome"),
        "sync client generic I/O timeout helper should expose a typed outcome enum"
    );
    assert!(
        sync_client.contains("fn classify_sync_client_io_timeout"),
        "sync client generic I/O timeout helper should classify timeout results through a named helper"
    );
    assert!(
        io_timeout_helper.contains("match classify_sync_client_io_timeout("),
        "sync client generic I/O timeout helper should map classified outcomes"
    );
    assert!(
        io_timeout_helper.contains("SyncClientIoTimeoutOutcome::Completed(value) => Ok(value)"),
        "sync client generic I/O timeout helper should preserve completed operation values"
    );
    assert!(
        io_timeout_helper.contains("SyncClientIoTimeoutOutcome::Failed(e) => Err(sync_io_error("),
        "sync client generic I/O timeout helper should preserve operation errors"
    );
    assert!(
        io_timeout_helper.contains("SyncClientIoTimeoutOutcome::TimedOut =>"),
        "sync client generic I/O timeout helper should preserve timeout errors"
    );
    assert!(
        io_timeout_helper.contains("Err(sync_io_error(peer_ws_url,"),
        "sync client generic I/O timeout helper should route timeout errors through sync_io_error"
    );
    assert!(
        io_timeout_helper.contains("format!(\"{operation} timed out\")"),
        "sync client generic I/O timeout helper should preserve operation-specific timeout context"
    );
}

#[test]
fn sync_client_non_binary_frames_are_classified() {
    let sync_client = include_str!("../src/sync_client.rs");
    let binary_reader = source_between_markers(
        sync_client,
        "async fn recv_binary(",
        "async fn recv_sync_client_message_with_timeout(",
        "recv_binary body",
    );

    assert!(
        !binary_reader.contains("if let Message::Binary(data) = frame"),
        "sync client binary receive loop should not silently skip non-binary frames"
    );
    assert!(
        sync_client.contains("enum SyncClientFrameOutcome"),
        "sync client receive path should expose classified frame outcomes"
    );
    assert!(
        sync_client.contains("fn classify_sync_client_frame("),
        "sync client receive path should classify WebSocket frames through a named helper"
    );
    assert!(
        binary_reader.contains("match classify_sync_client_frame(frame)"),
        "sync client binary receive loop should branch on classified frame outcomes"
    );
    assert!(
        binary_reader.contains("SyncClientFrameOutcome::KeepAlive => continue"),
        "sync client binary receive loop should explicitly tolerate Ping/Pong keepalives"
    );
    assert!(
        binary_reader.contains("SyncClientFrameOutcome::Closed =>"),
        "sync client binary receive loop should explicitly reject Close before a binary frame"
    );
    assert!(
        binary_reader.contains("SyncClientFrameOutcome::Unexpected(kind) =>"),
        "sync client binary receive loop should explicitly reject unexpected non-binary frames"
    );
}

#[test]
fn sync_client_bye_send_outcomes_are_observed() {
    let sync_client = include_str!("../src/sync_client.rs");

    assert!(
        !contains_normalized_source(sync_client, ".await.ok();"),
        "sync client must not silently discard best-effort BYE send outcomes"
    );
    assert!(
        sync_client.contains("enum SyncClientByeSendOutcome"),
        "sync client BYE sends should expose sent/failed outcomes"
    );
    assert!(
        sync_client.contains("fn classify_sync_client_bye_send("),
        "sync client BYE sends should classify send results through a named helper"
    );
    assert!(
        sync_client.contains("fn observe_sync_client_bye_send("),
        "sync client BYE sends should observe failed best-effort outcomes explicitly"
    );
    assert_eq!(
        sync_client
            .matches("send_bye_best_effort(&mut ws, peer_ws_url, io_timeout).await;")
            .count(),
        2,
        "both sync client BYE paths should route through the named best-effort helper"
    );
}

#[test]
fn v11_object_sync_tests_do_not_abort_fake_peers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains(".abort()"),
        "v11 object sync fake peers should observe client close and join, not use abort-based cleanup"
    );
}

#[test]
fn v11_object_sync_fake_peers_assert_close_outcomes() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("let _ = ws.next().await"),
        "v11 object sync fake peers should assert close outcomes instead of discarding ws.next()"
    );
    assert!(
        !v11_object_sync.contains("while ws.next().await.is_some() {}"),
        "v11 object sync fake peers should bound and assert close drains"
    );
    assert!(
        v11_object_sync.contains("expect_fake_peer_close(&mut ws"),
        "v11 object sync fake peers should use the shared close/EOF assertion helper"
    );
    assert!(
        !v11_object_sync.contains("tokio::time::timeout(Duration::from_secs(1), ws.next()).await"),
        "v11 object sync fake-peer close observation should use a named close timeout"
    );
    assert!(
        v11_object_sync.contains("const FAKE_PEER_CLOSE_TIMEOUT: Duration"),
        "v11 object sync fake-peer close observation should share a bounded close timeout"
    );
    assert!(
        v11_object_sync.contains("recv_fake_peer_close_message_with_timeout(ws).await"),
        "v11 object sync fake-peer close observation should route ws.next through the named timeout helper"
    );
}

#[test]
fn v11_object_sync_fake_peer_close_timeout_uses_named_read_helper() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let close_observer = source_between_markers(
        v11_object_sync,
        "async fn expect_fake_peer_close(",
        "fn classify_v11_fake_peer_close_read(",
        "expect_fake_peer_close body",
    );

    assert!(
        !close_observer.contains("tokio::time::timeout(FAKE_PEER_CLOSE_TIMEOUT, ws.next()).await"),
        "v11 fake-peer close observer should route timed reads through a named helper"
    );
    assert!(
        v11_object_sync.contains("async fn recv_fake_peer_close_message_with_timeout("),
        "v11 fake-peer close read timeout policy should have a named helper"
    );
    assert!(
        close_observer.contains("recv_fake_peer_close_message_with_timeout(ws).await"),
        "v11 fake-peer close observer should call the named timeout helper"
    );
}

#[test]
fn v11_object_sync_fake_peer_close_timeout_helper_returns_classified_outcomes() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let close_timeout_helper = source_between_markers(
        v11_object_sync,
        "async fn recv_fake_peer_close_message_with_timeout(",
        "async fn stalled_websocket_peer(",
        "recv_fake_peer_close_message_with_timeout body",
    );
    let close_observer = source_between_markers(
        v11_object_sync,
        "async fn expect_fake_peer_close(",
        "fn classify_v11_fake_peer_close_read(",
        "expect_fake_peer_close body",
    );

    assert!(
        contains_normalized_source(
            v11_object_sync,
            "async fn recv_fake_peer_close_message_with_timeout(ws: &mut FakePeerWebSocket,) -> V11FakePeerCloseReadOutcome"
        ),
        "v11 fake-peer close timeout helper should return classified close outcomes"
    );
    assert!(
        close_timeout_helper.contains("classify_v11_fake_peer_close_read("),
        "v11 fake-peer close timeout helper should classify its raw timeout result"
    );
    assert!(
        !helper_directly_returns_raw_timeout_result(
            close_timeout_helper,
            "tokio::time::timeout(FAKE_PEER_CLOSE_TIMEOUT, ws.next()).await"
        ),
        "v11 fake-peer close timeout helper should not return the raw timeout result directly"
    );
    assert!(
        close_observer.contains("match recv_fake_peer_close_message_with_timeout(ws).await"),
        "v11 fake-peer close observer should branch on classified timeout helper outcomes"
    );
    assert!(
        !close_observer.contains(
            "match classify_v11_fake_peer_close_read(recv_fake_peer_close_message_with_timeout"
        ),
        "v11 fake-peer close observer should not classify timeout-helper output at the call site"
    );
}

#[test]
fn v11_object_sync_fake_peer_close_outcomes_are_classified() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let close_observer = source_between_markers(
        v11_object_sync,
        "async fn expect_fake_peer_close(",
        "fn classify_v11_fake_peer_close_read(",
        "expect_fake_peer_close body",
    );

    for inline_pattern in [
        "Ok(Some(Ok(Message::Close(_))))",
        "Ok(Some(Err(_)))",
        "Ok(None)",
        "Ok(Some(Ok(Message::Binary(data))))",
        "Ok(Some(Ok(other)))",
        "Err(_) if saw_bye",
        "Err(_) =>",
    ] {
        assert!(
            !close_observer.contains(inline_pattern),
            "v11 fake-peer close observer should classify timed read outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        v11_object_sync.contains("enum V11FakePeerCloseReadOutcome"),
        "v11 fake-peer close reads should expose a typed outcome enum"
    );
    assert!(
        v11_object_sync.contains("fn classify_v11_fake_peer_close_read("),
        "v11 fake-peer close reads should classify timed reads through a named helper"
    );
    assert!(
        close_observer.contains("match recv_fake_peer_close_message_with_timeout(ws).await"),
        "v11 fake-peer close observer should branch on classified timeout helper outcomes"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::CloseFrame"),
        "v11 fake-peer close observer should explicitly accept close frames"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::ReadFailed"),
        "v11 fake-peer close observer should explicitly accept read errors"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::Eof"),
        "v11 fake-peer close observer should explicitly accept EOF"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::ByeFrame"),
        "v11 fake-peer close observer should explicitly record the BYE frame before close"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::Unexpected(frame) =>"),
        "v11 fake-peer close observer should explicitly reject unexpected frames"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::TimedOut if saw_bye =>"),
        "v11 fake-peer close observer should preserve the after-BYE timeout branch"
    );
    assert!(
        close_observer.contains("V11FakePeerCloseReadOutcome::TimedOut =>"),
        "v11 fake-peer close observer should preserve the before-BYE timeout branch"
    );
}

#[test]
fn v11_object_sync_fake_peers_return_typed_results() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("JoinHandle<()>"),
        "v11 object sync fake peers should return typed task results instead of opaque unit joins"
    );
    assert!(
        v11_object_sync.contains("type FakePeerResult = Result<(), String>"),
        "v11 object sync fake peers should share a typed peer-result contract"
    );
}

#[test]
fn v11_object_sync_vector_fake_peers_return_typed_results() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("JoinHandle<Vec<[u8; 32]>>"),
        "v11 object sync fake peers that return wanted ids should preserve protocol failures as typed task results"
    );
    assert!(
        v11_object_sync.contains("type FakePeerWantedIds = Result<Vec<[u8; 32]>, String>"),
        "v11 object sync wanted-id fake peers should share a typed peer-result contract"
    );
    assert!(
        !v11_object_sync.contains("async fn recv_recorded_binary("),
        "v11 object sync fake peers should not use a panic-based binary frame receiver"
    );
}

#[test]
fn v11_object_sync_fake_peer_joins_use_shared_helpers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !contains_normalized_source(
            v11_object_sync,
            "tokio::time::timeout(Duration::from_secs(1), peer).await"
        ),
        "v11 object sync fake-peer joins should route timeout/join/result handling through shared helpers"
    );
    assert!(
        !v11_object_sync.contains(" peer joins\""),
        "v11 object sync fake-peer join messages should be centralized instead of repeated inline"
    );
    assert!(
        !v11_object_sync.contains(" peer completes\""),
        "v11 object sync fake-peer completion messages should be centralized instead of repeated inline"
    );
    assert!(
        v11_object_sync.contains("const FAKE_PEER_JOIN_TIMEOUT: Duration"),
        "v11 object sync fake-peer joins should share a bounded join timeout"
    );
    assert!(
        v11_object_sync.contains("async fn expect_fake_peer("),
        "v11 object sync unit fake peers should use a shared join helper"
    );
    assert!(
        v11_object_sync.contains("async fn expect_fake_peer_wanted_ids("),
        "v11 object sync wanted-id fake peers should use a shared join helper"
    );
    assert_eq!(
        v11_object_sync.matches("expect_fake_peer(peer,").count(),
        2,
        "both v11 unit fake-peer tests should route joins through the shared helper"
    );
    assert_eq!(
        v11_object_sync
            .matches("expect_fake_peer_wanted_ids(peer,")
            .count(),
        2,
        "both v11 wanted-id fake-peer tests should route joins through the shared helper"
    );
}

#[test]
fn v11_object_sync_fake_peer_join_reporting_uses_named_helpers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let join_helper = source_between_markers(
        v11_object_sync,
        "async fn join_fake_peer_result<T>(",
        "async fn expect_fake_peer(",
        "join_fake_peer_result body",
    );

    for inline_panic in ["unwrap_or_else(|_| panic!", "unwrap_or_else(|err| panic!"] {
        assert!(
            !join_helper.contains(inline_panic),
            "v11 fake-peer join helper should route `{inline_panic}` through named reporting helpers"
        );
    }
    assert!(
        v11_object_sync.contains("async fn observe_fake_peer_join"),
        "v11 fake-peer join timeout observation should be named"
    );
    assert!(
        v11_object_sync.contains("fn expect_observed_fake_peer_join"),
        "v11 fake-peer join timeout reporting should be named"
    );
    assert!(
        v11_object_sync.contains("fn expect_joined_fake_peer_task"),
        "v11 fake-peer JoinError reporting should be named"
    );
    assert!(
        v11_object_sync.contains("fn expect_successful_fake_peer_result"),
        "v11 fake-peer typed task-result reporting should be named"
    );
    assert!(
        join_helper.contains("observe_fake_peer_join(handle, context).await"),
        "v11 fake-peer join helper should call the named timeout observer"
    );
    assert!(
        join_helper.contains("expect_joined_fake_peer_task(joined, context)"),
        "v11 fake-peer join helper should call the named JoinError reporter"
    );
    assert!(
        join_helper.contains("expect_successful_fake_peer_result(task_result, context)"),
        "v11 fake-peer join helper should call the named task-result reporter"
    );
}

#[test]
fn v11_object_sync_pull_canonical_deadlines_use_named_parameters() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !contains_normalized_source(v11_object_sync, "Duration::from_secs(1),).await"),
        "v11 canonical sync tests should use a named normal pull deadline"
    );
    assert!(
        !contains_normalized_source(
            v11_object_sync,
            "Duration::from_millis(50),).await.expect_err(\"stalled peer must trip the sync client deadline\")"
        ),
        "v11 canonical stalled-peer test should use a named stalled pull deadline"
    );
    assert!(
        v11_object_sync.contains("const V11_PULL_CANONICAL_TEST_TIMEOUT: Duration"),
        "v11 canonical sync tests should share a normal pull deadline"
    );
    assert!(
        v11_object_sync.contains("const V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT: Duration"),
        "v11 canonical stalled-peer test should share a stalled pull deadline"
    );
    assert_eq!(
        count_normalized_source(v11_object_sync, "V11_PULL_CANONICAL_TEST_TIMEOUT,),"),
        3,
        "all three non-stalled v11 canonical pulls should route through the normal deadline"
    );
    assert_eq!(
        count_normalized_source(
            v11_object_sync,
            "expect_v11_pull_failure(mnemed::sync_client::pull_canonical_with_cap_and_timeout("
        ),
        3,
        "all three expected-failure v11 canonical pulls should route through the named pull-failure helper"
    );
    assert!(
        contains_normalized_source(
            v11_object_sync,
            "V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT,),"
        ),
        "v11 stalled canonical pull should route through the stalled deadline"
    );
}

#[test]
fn v11_object_sync_pull_canonical_io_failures_use_named_helpers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let frame_limit_failure_tests = [
        (
            source_top_level_item_after_marker(
                v11_object_sync,
                "async fn pull_canonical_rejects_oversized_peer_have_objects_response()",
                "pull_canonical_rejects_oversized_peer_have_objects_response body",
            ),
            "oversized HaveObjects response",
        ),
        (
            source_top_level_item_after_marker(
                v11_object_sync,
                "async fn pull_canonical_rejects_oversized_peer_diff_response()",
                "pull_canonical_rejects_oversized_peer_diff_response body",
            ),
            "oversized DiffResp response",
        ),
    ];
    let stalled_failure_test = source_top_level_item_after_marker(
        v11_object_sync,
        "async fn pull_canonical_times_out_when_peer_stalls_diff_response()",
        "pull_canonical_times_out_when_peer_stalls_diff_response body",
    );

    for (test_body, context) in frame_limit_failure_tests {
        for inline_report in [
            "MnemeError::IoFailed { path, kind }",
            "expected sync client I/O failure",
            "should be rejected by frame limit, not timeout",
        ] {
            assert!(
                !test_body.contains(inline_report),
                "v11 {context} test should route `{inline_report}` through named sync-client I/O failure helpers"
            );
        }
        assert!(
            test_body.contains("assert_pull_canonical_frame_limit_io_failure("),
            "v11 {context} test should call the named frame-limit I/O failure helper"
        );
    }
    for inline_report in [
        "MnemeError::IoFailed { path, kind }",
        "expected sync client timeout I/O error",
        "unexpected sync client I/O error",
    ] {
        assert!(
            !stalled_failure_test.contains(inline_report),
            "v11 stalled-peer test should route `{inline_report}` through named sync-client timeout helpers"
        );
    }
    assert!(
        stalled_failure_test.contains("assert_pull_canonical_timeout_io_failure("),
        "v11 stalled-peer test should call the named timeout I/O failure helper"
    );
    assert!(
        v11_object_sync.contains("type PullCanonicalIoFailureCheck = Result<String, String>"),
        "v11 pull-canonical I/O failure checks should name the validation result type"
    );
    assert!(
        v11_object_sync.contains("fn assert_pull_canonical_frame_limit_io_failure("),
        "v11 pull-canonical frame-limit tests should use a named assertion helper"
    );
    assert!(
        v11_object_sync.contains("fn assert_pull_canonical_timeout_io_failure("),
        "v11 pull-canonical timeout tests should use a named assertion helper"
    );
    assert!(
        v11_object_sync.contains("fn expect_pull_canonical_io_failure("),
        "v11 pull-canonical I/O failure checks should separate validation from reporting"
    );
    assert!(
        v11_object_sync.contains("fn assert_pull_canonical_io_failure_check_passed("),
        "v11 pull-canonical I/O failure checks should route failure reporting through a named helper"
    );
}

#[test]
fn v11_object_sync_direct_reads_use_typed_binary_frame_reader() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("async fn recv_binary("),
        "v11 object sync direct WebSocket reads should use a typed binary frame reader"
    );
    assert!(
        v11_object_sync.contains("async fn recv_client_binary_frame("),
        "v11 object sync direct WebSocket reads should share a typed client frame reader"
    );
}

#[test]
fn v11_object_sync_fake_peer_accepts_are_bounded() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !contains_normalized_source(v11_object_sync, "listener.accept().await"),
        "v11 fake WebSocket peers should not wait forever in bare listener.accept().await calls"
    );
    assert!(
        !contains_normalized_source(
            v11_object_sync,
            "tokio_tungstenite::accept_async(stream).await"
        ),
        "v11 fake WebSocket peers should not wait forever in bare websocket handshakes"
    );
    assert!(
        v11_object_sync.contains("const FAKE_PEER_ACCEPT_TIMEOUT: Duration"),
        "v11 fake WebSocket peers should share a bounded accept/handshake timeout"
    );
    assert!(
        v11_object_sync.contains("async fn accept_fake_websocket_peer("),
        "v11 fake WebSocket peers should share a named accept/handshake helper"
    );
    assert!(
        v11_object_sync.contains("accept_fake_peer_tcp_stream_with_timeout(listener)"),
        "v11 fake WebSocket peer accepts should route through the shared timeout helper"
    );
    assert_eq!(
        v11_object_sync
            .matches("accept_fake_websocket_peer(listener,")
            .count(),
        4,
        "all v11 fake WebSocket peers should route listener accepts through the shared helper"
    );
}

#[test]
fn v11_object_sync_fake_peer_accept_policy_uses_named_timeout_helpers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let accept_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_websocket_peer(",
        "async fn accept_fake_peer_tcp_stream_with_timeout(",
        "accept_fake_websocket_peer body",
    );

    assert!(
        !accept_helper
            .contains("tokio::time::timeout(FAKE_PEER_ACCEPT_TIMEOUT, listener.accept())"),
        "v11 fake-peer accept helper should route TCP accepts through a named timeout helper"
    );
    assert!(
        !contains_normalized_source(
            accept_helper,
            "tokio::time::timeout(FAKE_PEER_ACCEPT_TIMEOUT, tokio_tungstenite::accept_async(stream),)"
        ),
        "v11 fake-peer accept helper should route WebSocket handshakes through a named timeout helper"
    );
    assert!(
        v11_object_sync.contains("async fn accept_fake_peer_tcp_stream_with_timeout("),
        "v11 fake-peer TCP accept timeout policy should have a named helper"
    );
    assert!(
        v11_object_sync.contains("async fn accept_fake_peer_websocket_with_timeout("),
        "v11 fake-peer WebSocket handshake timeout policy should have a named helper"
    );
    assert!(
        accept_helper.contains("accept_fake_peer_tcp_stream_with_timeout(listener)"),
        "v11 fake-peer accept helper should call the named TCP accept timeout helper"
    );
    assert!(
        accept_helper.contains("accept_fake_peer_websocket_with_timeout(stream)"),
        "v11 fake-peer accept helper should call the named WebSocket handshake timeout helper"
    );
}

#[test]
fn v11_object_sync_fake_peer_accept_timeout_helpers_return_classified_outcomes() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let accept_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_websocket_peer(",
        "async fn accept_fake_peer_tcp_stream_with_timeout(",
        "accept_fake_websocket_peer body",
    );
    let tcp_accept_timeout_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_peer_tcp_stream_with_timeout(",
        "fn classify_v11_fake_peer_tcp_accept(",
        "accept_fake_peer_tcp_stream_with_timeout body",
    );
    let websocket_accept_timeout_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_peer_websocket_with_timeout(",
        "fn classify_v11_fake_peer_websocket_accept(",
        "accept_fake_peer_websocket_with_timeout body",
    );

    assert!(
        contains_normalized_source(
            v11_object_sync,
            "async fn accept_fake_peer_tcp_stream_with_timeout(listener: TcpListener,) -> V11FakePeerTcpAcceptOutcome"
        ),
        "v11 fake-peer TCP accept timeout helper should return classified accept outcomes"
    );
    assert!(
        contains_normalized_source(
            v11_object_sync,
            "async fn accept_fake_peer_websocket_with_timeout(stream: tokio::net::TcpStream,) -> V11FakePeerWebSocketAcceptOutcome"
        ),
        "v11 fake-peer WebSocket accept timeout helper should return classified accept outcomes"
    );
    assert!(
        tcp_accept_timeout_helper.contains("classify_v11_fake_peer_tcp_accept("),
        "v11 fake-peer TCP accept timeout helper should classify its raw timeout result"
    );
    assert!(
        websocket_accept_timeout_helper.contains("classify_v11_fake_peer_websocket_accept("),
        "v11 fake-peer WebSocket accept timeout helper should classify its raw timeout result"
    );
    for remapped_pattern in [
        "=> Ok(Ok((stream, addr)))",
        "=> Ok(Err(err))",
        "=> Err(err)",
    ] {
        assert!(
            !tcp_accept_timeout_helper.contains(remapped_pattern),
            "v11 fake-peer TCP accept timeout helper should not remap classified outcomes back into `{remapped_pattern}`"
        );
    }
    for remapped_pattern in ["=> Ok(Ok(ws))", "=> Ok(Err(err))", "=> Err(err)"] {
        assert!(
            !websocket_accept_timeout_helper.contains(remapped_pattern),
            "v11 fake-peer WebSocket accept timeout helper should not remap classified outcomes back into `{remapped_pattern}`"
        );
    }
    assert!(
        accept_helper.contains("match accept_fake_peer_tcp_stream_with_timeout(listener).await"),
        "v11 fake-peer accept helper should branch on classified TCP accept helper outcomes"
    );
    assert!(
        accept_helper.contains("match accept_fake_peer_websocket_with_timeout(stream).await"),
        "v11 fake-peer accept helper should branch on classified WebSocket accept helper outcomes"
    );
}

#[test]
fn v11_object_sync_fake_peer_accept_outcomes_are_classified() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let accept_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_websocket_peer(",
        "async fn accept_fake_peer_tcp_stream_with_timeout(",
        "accept_fake_websocket_peer body",
    );
    let tcp_accept_timeout_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_peer_tcp_stream_with_timeout(",
        "fn classify_v11_fake_peer_tcp_accept(",
        "accept_fake_peer_tcp_stream_with_timeout body",
    );
    let websocket_accept_timeout_helper = source_between_markers(
        v11_object_sync,
        "async fn accept_fake_peer_websocket_with_timeout(",
        "fn classify_v11_fake_peer_websocket_accept(",
        "accept_fake_peer_websocket_with_timeout body",
    );

    for inline_pattern in [
        "Ok(Ok((stream, addr))) =>",
        "Ok(Err(err)) =>",
        "Err(err) =>",
    ] {
        assert!(
            !contains_normalized_source(tcp_accept_timeout_helper, inline_pattern),
            "v11 fake-peer TCP accept timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    for inline_pattern in ["Ok(Ok(ws)) =>", "Ok(Err(err)) =>", "Err(err) =>"] {
        assert!(
            !contains_normalized_source(websocket_accept_timeout_helper, inline_pattern),
            "v11 fake-peer WebSocket accept timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    assert!(
        v11_object_sync.contains("enum V11FakePeerTcpAcceptOutcome"),
        "v11 fake-peer TCP accept timeout outcomes should have a named classifier enum"
    );
    assert!(
        v11_object_sync.contains("enum V11FakePeerWebSocketAcceptOutcome"),
        "v11 fake-peer WebSocket accept timeout outcomes should have a named classifier enum"
    );
    assert!(
        v11_object_sync.contains("fn classify_v11_fake_peer_tcp_accept("),
        "v11 fake-peer TCP accept timeout outcomes should route through a classifier"
    );
    assert!(
        v11_object_sync.contains("fn classify_v11_fake_peer_websocket_accept("),
        "v11 fake-peer WebSocket accept timeout outcomes should route through a classifier"
    );
    assert!(
        tcp_accept_timeout_helper.contains("classify_v11_fake_peer_tcp_accept("),
        "v11 fake-peer TCP accept timeout helper should return classified outcomes"
    );
    assert!(
        websocket_accept_timeout_helper.contains("classify_v11_fake_peer_websocket_accept("),
        "v11 fake-peer WebSocket accept timeout helper should return classified outcomes"
    );
    assert!(
        accept_helper.contains("match accept_fake_peer_tcp_stream_with_timeout(listener).await"),
        "v11 fake-peer accept helper should branch on classified TCP accept outcomes"
    );
    assert!(
        accept_helper.contains("V11FakePeerTcpAcceptOutcome::Accepted(stream) => stream"),
        "v11 fake-peer TCP accepted outcome should preserve the accepted stream"
    );
    assert!(
        accept_helper.contains("V11FakePeerTcpAcceptOutcome::Failed(err) =>"),
        "v11 fake-peer TCP accept failure should remain explicit"
    );
    assert!(
        accept_helper.contains("format!(\"{context} accept failed: {err}\")"),
        "v11 fake-peer TCP accept failure should preserve its error context"
    );
    assert!(
        accept_helper.contains("V11FakePeerTcpAcceptOutcome::TimedOut(_) =>"),
        "v11 fake-peer TCP accept timeout should remain explicit"
    );
    assert!(
        accept_helper.contains("format!(\"{context} timed out waiting for client connection\")"),
        "v11 fake-peer TCP accept timeout should preserve its timeout context"
    );
    assert!(
        accept_helper.contains("match accept_fake_peer_websocket_with_timeout(stream).await"),
        "v11 fake-peer accept helper should branch on classified WebSocket accept outcomes"
    );
    assert!(
        accept_helper.contains("V11FakePeerWebSocketAcceptOutcome::Accepted(ws) => Ok(ws)"),
        "v11 fake-peer WebSocket accepted outcome should preserve the accepted socket"
    );
    assert!(
        accept_helper.contains("V11FakePeerWebSocketAcceptOutcome::Failed(err) =>"),
        "v11 fake-peer WebSocket accept failure should remain explicit"
    );
    assert!(
        accept_helper.contains("format!(\"{context} websocket accept failed: {err}\")"),
        "v11 fake-peer WebSocket accept failure should preserve its error context"
    );
    assert!(
        accept_helper.contains("V11FakePeerWebSocketAcceptOutcome::TimedOut(_) =>"),
        "v11 fake-peer WebSocket accept timeout should remain explicit"
    );
    assert!(
        accept_helper.contains("{context} timed out waiting for websocket handshake"),
        "v11 fake-peer WebSocket accept timeout should preserve its timeout context"
    );
}

#[test]
fn v11_object_sync_binary_frame_reads_are_bounded() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("match ws.next().await"),
        "v11 WebSocket binary frame readers should not wait forever in raw ws.next().await loops"
    );
    assert!(
        v11_object_sync.contains("const V11_BINARY_FRAME_TIMEOUT: Duration"),
        "v11 WebSocket binary frame readers should share a bounded read timeout"
    );
    assert!(
        v11_object_sync.contains("async fn recv_ws_binary_frame_with_timeout"),
        "v11 WebSocket binary frame readers should share a timeout-wrapped frame reader"
    );
    assert!(
        v11_object_sync.contains("recv_v11_binary_message_with_timeout(ws).await"),
        "v11 WebSocket binary frame reads should route ws.next through the shared timeout helper"
    );
}

#[test]
fn v11_object_sync_binary_read_timeout_policy_uses_named_helper() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let binary_reader = source_between_markers(
        v11_object_sync,
        "async fn recv_ws_binary_frame_with_timeout",
        "fn classify_v11_binary_read",
        "recv_ws_binary_frame_with_timeout body",
    );

    assert!(
        !binary_reader.contains("tokio::time::timeout(V11_BINARY_FRAME_TIMEOUT, ws.next()).await"),
        "v11 WebSocket binary frame reader should route timed reads through a named helper"
    );
    assert!(
        v11_object_sync.contains("async fn recv_v11_binary_message_with_timeout"),
        "v11 WebSocket binary read timeout policy should have a named helper"
    );
    assert!(
        binary_reader.contains("recv_v11_binary_message_with_timeout(ws).await"),
        "v11 WebSocket binary frame reader should call the named timeout helper"
    );
}

#[test]
fn v11_object_sync_binary_timeout_helper_returns_classified_outcomes() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let binary_timeout_helper = source_between_markers(
        v11_object_sync,
        "async fn recv_v11_binary_message_with_timeout",
        "fn remember(",
        "recv_v11_binary_message_with_timeout body",
    );
    let binary_reader = source_between_markers(
        v11_object_sync,
        "async fn recv_ws_binary_frame_with_timeout",
        "fn classify_v11_binary_read",
        "recv_ws_binary_frame_with_timeout body",
    );

    assert!(
        v11_object_sync.contains(
            "async fn recv_v11_binary_message_with_timeout<S>(ws: &mut S) -> V11BinaryFrameOutcome"
        ),
        "v11 WebSocket binary timeout helper should return classified binary outcomes"
    );
    assert!(
        binary_timeout_helper.contains("classify_v11_binary_read("),
        "v11 WebSocket binary timeout helper should classify its raw timeout result"
    );
    assert!(
        !helper_directly_returns_raw_timeout_result(
            binary_timeout_helper,
            "tokio::time::timeout(V11_BINARY_FRAME_TIMEOUT, ws.next()).await"
        ),
        "v11 WebSocket binary timeout helper should not return the raw timeout result directly"
    );
    assert!(
        binary_reader.contains("match recv_v11_binary_message_with_timeout(ws).await"),
        "v11 WebSocket binary reader should branch on classified timeout helper outcomes"
    );
    assert!(
        !binary_reader
            .contains("match classify_v11_binary_read(recv_v11_binary_message_with_timeout"),
        "v11 WebSocket binary reader should not classify timeout-helper output at the call site"
    );
}

#[test]
fn v11_object_sync_binary_read_outcomes_are_classified() {
    let v11_object_sync = include_str!("v11_object_sync.rs");
    let binary_reader = source_between_markers(
        v11_object_sync,
        "async fn recv_ws_binary_frame_with_timeout",
        "fn classify_v11_binary_read",
        "recv_ws_binary_frame_with_timeout body",
    );

    for inline_pattern in [
        "Ok(Some(Ok(Message::Binary(data))))",
        "Ok(Some(Ok(Message::Ping(_))))",
        "Ok(Some(Ok(Message::Pong(_))))",
        "Ok(Some(Err(err)))",
        "Ok(None)",
        "Err(_)",
    ] {
        assert!(
            !binary_reader.contains(inline_pattern),
            "v11 binary frame reader should classify timed read outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        v11_object_sync.contains("enum V11BinaryFrameOutcome"),
        "v11 binary frame reads should expose a typed outcome enum"
    );
    assert!(
        v11_object_sync.contains("fn classify_v11_binary_read("),
        "v11 binary frame reads should classify timed reads through a named helper"
    );
    assert!(
        binary_reader.contains("match recv_v11_binary_message_with_timeout(ws).await"),
        "v11 binary frame reader should branch on classified timeout helper outcomes"
    );
    assert!(
        binary_reader.contains("V11BinaryFrameOutcome::Binary(data) => return Ok(data)"),
        "v11 binary frame reader should return classified binary payloads"
    );
    assert!(
        binary_reader.contains("V11BinaryFrameOutcome::KeepAlive => continue"),
        "v11 binary frame reader should explicitly tolerate Ping/Pong keepalives"
    );
    assert!(
        binary_reader.contains("V11BinaryFrameOutcome::Unexpected(frame) =>"),
        "v11 binary frame reader should explicitly reject unexpected frames"
    );
    assert!(
        binary_reader.contains("V11BinaryFrameOutcome::ReadFailed(err) =>"),
        "v11 binary frame reader should explicitly surface websocket read errors"
    );
    assert!(
        binary_reader.contains("V11BinaryFrameOutcome::Closed =>"),
        "v11 binary frame reader should explicitly surface EOF before a binary frame"
    );
    assert!(
        binary_reader.contains("V11BinaryFrameOutcome::TimedOut =>"),
        "v11 binary frame reader should explicitly surface read timeouts"
    );
}

#[test]
fn v11_object_sync_oversized_send_outcomes_are_classified() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !contains_normalized_source(v11_object_sync, ".await.is_ok()"),
        "v11 fake-peer oversized response sends should classify send outcomes instead of branching on is_ok inline"
    );
    assert!(
        v11_object_sync.contains("enum OversizedPeerSendOutcome"),
        "v11 fake-peer oversized response sends should expose sent/closed outcomes"
    );
    assert!(
        v11_object_sync.contains("async fn send_oversized_fake_peer_frame("),
        "v11 fake-peer oversized response sends should use a named helper"
    );
    assert_eq!(
        v11_object_sync
            .matches("match send_oversized_fake_peer_frame(&mut ws,")
            .count(),
        2,
        "both v11 fake-peer oversized response sends should branch on classified outcomes"
    );
}

#[test]
fn v11_object_sync_setup_uses_named_diagnostic_helpers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    for inline_expect in [".expect(", ".expect_err(", ".unwrap()"] {
        assert!(
            !v11_object_sync.contains(inline_expect),
            "v11 object sync tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "fn expect_v11_agent_cap(",
        "fn expect_v11_cap_b64(",
        "fn expect_v11_tempdir(",
        "fn expect_v11_store(",
        "fn expect_v11_remember",
        "async fn start_v11_server(",
        "async fn expect_v11_fake_peer_listener(",
        "fn expect_v11_fake_peer_url(",
        "fn expect_v11_snapshot_leaf(",
        "fn expect_v11_snapshot_logical_key(",
        "fn expect_v11_snapshot_object_bytes(",
        "fn expect_v11_have_objects_frame(",
        "fn expect_v11_ws_request(",
        "fn expect_v11_ws_header_value(",
        "async fn connect_v11_ws(",
        "async fn expect_v11_pull_success",
        "async fn expect_v11_pull_failure",
    ] {
        assert!(
            v11_object_sync.contains(helper),
            "v11 object sync setup should define `{helper}`"
        );
    }
    for (fallible_call, expected_count) in [
        ("agent_cap(operator, operator.public_key_bytes())", 1),
        ("tempfile::tempdir()", 1),
        ("mneme_store::Store::create(", 1),
        ("start_with_state(config, state).await", 1),
        ("TcpListener::bind(\"127.0.0.1:0\").await", 1),
        ("listener.local_addr()", 1),
        ("into_client_request()", 1),
        ("cap_to_b64(cap)", 1),
        ("HeaderValue::from_str(", 1),
        ("connect_async(", 1),
    ] {
        assert_eq!(
            count_normalized_source(v11_object_sync, fallible_call),
            expected_count,
            "v11 object sync setup should centralize `{fallible_call}` in named diagnostic helpers"
        );
    }
    for diagnostic in [
        "v11 capability creation failed",
        "v11 capability encoding failed",
        "v11 tempdir failed",
        "v11 store create failed",
        "v11 remember failed",
        "v11 server start failed",
        "v11 fake peer bind failed",
        "v11 fake peer local address failed",
        "v11 snapshot leaf missing",
        "v11 snapshot logical key missing",
        "v11 snapshot object bytes missing",
        "v11 HaveObjects frame encode failed",
        "v11 WebSocket request build failed",
        "v11 WebSocket header build failed",
        "v11 WebSocket connect failed",
        "v11 canonical pull failed",
        "expected v11 canonical pull failure",
    ] {
        assert!(
            v11_object_sync.contains(diagnostic),
            "v11 object sync setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn sync_ws_tests_do_not_discard_timeout_outcomes() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains("let _ = tokio::time::timeout("),
        "sync WebSocket tests must assert timeout outcomes instead of discarding them"
    );
}

#[test]
fn sync_ws_uses_typed_binary_response_reader() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains("ws.next().await.expect(\"response\").expect(\"ok msg\")"),
        "sync WebSocket tests should use a typed response reader instead of generic expect chains"
    );
    assert!(
        sync_ws.contains("async fn recv_sync_ws_binary_frame("),
        "sync WebSocket tests should share a typed binary response reader"
    );
}

#[test]
fn sync_ws_binary_response_reads_are_bounded() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains("match ws.next().await"),
        "sync WebSocket binary response reader should not wait forever in a raw ws.next().await"
    );
    assert!(
        sync_ws.contains("const SYNC_WS_BINARY_FRAME_TIMEOUT: std::time::Duration"),
        "sync WebSocket binary response reader should share a named timeout"
    );
    assert!(
        sync_ws.contains("recv_sync_ws_binary_message_with_timeout(ws).await"),
        "sync WebSocket binary response reader should route ws.next through the named timeout helper"
    );
}

#[test]
fn sync_ws_timeout_policies_use_named_read_helpers() {
    let sync_ws = include_str!("sync_ws.rs");
    let binary_reader = source_between_markers(
        sync_ws,
        "async fn recv_sync_ws_binary_frame(",
        "fn classify_sync_ws_binary_read(",
        "recv_sync_ws_binary_frame body",
    );
    let close_observer = source_between_markers(
        sync_ws,
        "async fn expect_sync_ws_close_or_eof(",
        "fn classify_sync_ws_close_read(",
        "expect_sync_ws_close_or_eof body",
    );

    assert!(
        !binary_reader
            .contains("tokio::time::timeout(SYNC_WS_BINARY_FRAME_TIMEOUT, ws.next()).await"),
        "sync WebSocket binary frame reader should route timed reads through a named helper"
    );
    assert!(
        !close_observer.contains("tokio::time::timeout(SYNC_WS_CLOSE_TIMEOUT, ws.next()).await"),
        "sync WebSocket close observer should route timed reads through a named helper"
    );
    assert!(
        sync_ws.contains("async fn recv_sync_ws_binary_message_with_timeout("),
        "sync WebSocket binary read timeout policy should have a named helper"
    );
    assert!(
        sync_ws.contains("async fn recv_sync_ws_close_message_with_timeout("),
        "sync WebSocket close read timeout policy should have a named helper"
    );
    assert!(
        binary_reader.contains("recv_sync_ws_binary_message_with_timeout(ws).await"),
        "sync WebSocket binary frame reader should call the named timeout helper"
    );
    assert!(
        close_observer.contains("recv_sync_ws_close_message_with_timeout(ws).await"),
        "sync WebSocket close observer should call the named timeout helper"
    );
}

#[test]
fn sync_ws_timeout_helpers_return_classified_outcomes() {
    let sync_ws = include_str!("sync_ws.rs");
    let binary_timeout_helper = source_between_markers(
        sync_ws,
        "async fn recv_sync_ws_binary_message_with_timeout(",
        "async fn recv_sync_ws_close_message_with_timeout(",
        "recv_sync_ws_binary_message_with_timeout body",
    );
    let close_timeout_helper = source_between_markers(
        sync_ws,
        "async fn recv_sync_ws_close_message_with_timeout(",
        "async fn recv_sync_ws_binary_frame(",
        "recv_sync_ws_close_message_with_timeout body",
    );
    let binary_reader = source_between_markers(
        sync_ws,
        "async fn recv_sync_ws_binary_frame(",
        "fn classify_sync_ws_binary_read(",
        "recv_sync_ws_binary_frame body",
    );
    let close_observer = source_between_markers(
        sync_ws,
        "async fn expect_sync_ws_close_or_eof(",
        "fn classify_sync_ws_close_read(",
        "expect_sync_ws_close_or_eof body",
    );

    assert!(
        contains_normalized_source(
            sync_ws,
            "async fn recv_sync_ws_binary_message_with_timeout(ws: &mut ClientWebSocket,) -> SyncWsBinaryFrameOutcome"
        ),
        "sync WebSocket binary timeout helper should return classified binary outcomes"
    );
    assert!(
        contains_normalized_source(
            sync_ws,
            "async fn recv_sync_ws_close_message_with_timeout(ws: &mut ClientWebSocket,) -> SyncWsCloseReadOutcome"
        ),
        "sync WebSocket close timeout helper should return classified close outcomes"
    );
    assert!(
        binary_timeout_helper.contains("classify_sync_ws_binary_read("),
        "sync WebSocket binary timeout helper should classify its raw timeout result"
    );
    assert!(
        close_timeout_helper.contains("classify_sync_ws_close_read("),
        "sync WebSocket close timeout helper should classify its raw timeout result"
    );
    assert!(
        !helper_directly_returns_raw_timeout_result(
            binary_timeout_helper,
            "tokio::time::timeout(SYNC_WS_BINARY_FRAME_TIMEOUT, ws.next()).await"
        ),
        "sync WebSocket binary timeout helper should not return the raw timeout result directly"
    );
    assert!(
        !helper_directly_returns_raw_timeout_result(
            close_timeout_helper,
            "tokio::time::timeout(SYNC_WS_CLOSE_TIMEOUT, ws.next()).await"
        ),
        "sync WebSocket close timeout helper should not return the raw timeout result directly"
    );
    assert!(
        binary_reader.contains("match recv_sync_ws_binary_message_with_timeout(ws).await"),
        "sync WebSocket binary reader should branch on classified timeout helper outcomes"
    );
    assert!(
        !binary_reader.contains(
            "match classify_sync_ws_binary_read(recv_sync_ws_binary_message_with_timeout"
        ),
        "sync WebSocket binary reader should not classify timeout-helper output at the call site"
    );
    assert!(
        close_observer.contains("match recv_sync_ws_close_message_with_timeout(ws).await"),
        "sync WebSocket close observer should branch on classified timeout helper outcomes"
    );
    assert!(
        !close_observer
            .contains("match classify_sync_ws_close_read(recv_sync_ws_close_message_with_timeout"),
        "sync WebSocket close observer should not classify timeout-helper output at the call site"
    );
}

#[test]
fn sync_ws_binary_read_outcomes_are_classified() {
    let sync_ws = include_str!("sync_ws.rs");
    let binary_reader = source_between_markers(
        sync_ws,
        "async fn recv_sync_ws_binary_frame(",
        "fn classify_sync_ws_binary_read(",
        "recv_sync_ws_binary_frame body",
    );

    for inline_pattern in [
        "Ok(Some(Ok(Message::Binary(data))))",
        "Ok(Some(Ok(other)))",
        "Ok(Some(Err(err)))",
        "Ok(None)",
        "Err(_)",
    ] {
        assert!(
            !binary_reader.contains(inline_pattern),
            "sync WebSocket binary response reader should classify timed read outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        sync_ws.contains("enum SyncWsBinaryFrameOutcome"),
        "sync WebSocket binary reads should expose a typed outcome enum"
    );
    assert!(
        sync_ws.contains("fn classify_sync_ws_binary_read("),
        "sync WebSocket binary reads should classify timed reads through a named helper"
    );
    assert!(
        binary_reader.contains("match recv_sync_ws_binary_message_with_timeout(ws).await"),
        "sync WebSocket binary response reader should branch on classified timeout helper outcomes"
    );
    assert!(
        binary_reader.contains("SyncWsBinaryFrameOutcome::Binary(data) => return Ok(data)"),
        "sync WebSocket binary response reader should return classified binary payloads"
    );
    assert!(
        binary_reader.contains("SyncWsBinaryFrameOutcome::KeepAlive => continue"),
        "sync WebSocket binary response reader should explicitly tolerate Ping/Pong keepalives"
    );
    assert!(
        binary_reader.contains("SyncWsBinaryFrameOutcome::Unexpected(frame) =>"),
        "sync WebSocket binary response reader should explicitly reject unexpected frames"
    );
    assert!(
        binary_reader.contains("SyncWsBinaryFrameOutcome::ReadFailed(err) =>"),
        "sync WebSocket binary response reader should explicitly surface websocket read errors"
    );
    assert!(
        binary_reader.contains("SyncWsBinaryFrameOutcome::Closed =>"),
        "sync WebSocket binary response reader should explicitly surface EOF before a binary response"
    );
    assert!(
        binary_reader.contains("SyncWsBinaryFrameOutcome::TimedOut =>"),
        "sync WebSocket binary response reader should explicitly surface read timeouts"
    );
}

#[test]
fn sync_ws_close_read_outcomes_are_classified() {
    let sync_ws = include_str!("sync_ws.rs");
    let close_observer = source_between_markers(
        sync_ws,
        "async fn expect_sync_ws_close_or_eof(",
        "fn classify_sync_ws_close_read(",
        "expect_sync_ws_close_or_eof body",
    );

    for inline_pattern in [
        "Ok(Some(Ok(Message::Close(_))))",
        "Ok(Some(Err(_)))",
        "Ok(None)",
        "Ok(Some(Ok(other)))",
        "Err(_)",
    ] {
        assert!(
            !close_observer.contains(inline_pattern),
            "sync WebSocket close observer should classify timed read outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        sync_ws.contains("enum SyncWsCloseReadOutcome"),
        "sync WebSocket close reads should expose a typed outcome enum"
    );
    assert!(
        sync_ws.contains("fn classify_sync_ws_close_read("),
        "sync WebSocket close reads should classify timed reads through a named helper"
    );
    assert!(
        close_observer.contains("match recv_sync_ws_close_message_with_timeout(ws).await"),
        "sync WebSocket close observer should branch on classified timeout helper outcomes"
    );
    assert!(
        close_observer.contains("SyncWsCloseReadOutcome::CloseFrame"),
        "sync WebSocket close observer should explicitly accept close frames"
    );
    assert!(
        close_observer.contains("SyncWsCloseReadOutcome::ReadFailed"),
        "sync WebSocket close observer should explicitly accept read errors"
    );
    assert!(
        close_observer.contains("SyncWsCloseReadOutcome::Eof"),
        "sync WebSocket close observer should explicitly accept EOF"
    );
    assert!(
        close_observer.contains("SyncWsCloseReadOutcome::Unexpected(frame) =>"),
        "sync WebSocket close observer should explicitly reject unexpected frames"
    );
    assert!(
        close_observer.contains("SyncWsCloseReadOutcome::TimedOut =>"),
        "sync WebSocket close observer should explicitly surface close-read timeouts"
    );
}

#[test]
fn sync_ws_uses_typed_close_observer() {
    let sync_ws = include_str!("sync_ws.rs");

    for panic_message in [
        "oversized frame produced unexpected response",
        "oversized frame left sync websocket open without a rejection",
        "Bye produced unexpected sync response",
        "Bye left sync websocket open without close or EOF",
    ] {
        assert!(
            !sync_ws.contains(panic_message),
            "sync WebSocket close/EOF checks should return typed helper errors, not inline panics: {panic_message}"
        );
    }
    assert!(
        sync_ws.contains("async fn expect_sync_ws_close_or_eof("),
        "sync WebSocket close/EOF checks should share a typed close observer"
    );
    assert!(
        !sync_ws
            .contains("tokio::time::timeout(std::time::Duration::from_secs(1), ws.next()).await"),
        "sync WebSocket close/EOF observer should use a named close timeout"
    );
    assert!(
        sync_ws.contains("const SYNC_WS_CLOSE_TIMEOUT: std::time::Duration"),
        "sync WebSocket close/EOF observer should share a named close timeout"
    );
    assert!(
        sync_ws.contains("recv_sync_ws_close_message_with_timeout(ws).await"),
        "sync WebSocket close/EOF observer should route ws.next through the named timeout helper"
    );
}

#[test]
fn sync_ws_oversized_send_outcomes_are_classified() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !contains_normalized_source(sync_ws, ".await.is_ok()"),
        "sync WebSocket oversized frame sends should classify send outcomes instead of branching on is_ok inline"
    );
    assert!(
        sync_ws.contains("enum OversizedSyncSendOutcome"),
        "sync WebSocket oversized frame sends should expose sent/closed outcomes"
    );
    assert!(
        sync_ws.contains("async fn send_oversized_sync_frame("),
        "sync WebSocket oversized frame sends should use a named helper"
    );
    assert!(
        sync_ws.contains("match send_oversized_sync_frame(&mut ws).await"),
        "sync WebSocket oversized frame test should branch on classified send outcomes"
    );
}

#[test]
fn sync_ws_setup_uses_named_diagnostic_helpers() {
    let sync_ws = include_str!("sync_ws.rs");

    for inline_expect in [
        ".expect(",
        ".expect_err(",
        ".unwrap()",
        "into_client_request().expect",
        ".send(tokio_tungstenite::tungstenite::Message::Binary(",
    ] {
        assert!(
            !sync_ws.contains(inline_expect),
            "sync WebSocket tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "fn expect_sync_ws_request(",
        "fn expect_sync_ws_header_value(",
        "async fn expect_sync_ws_auth_rejection",
        "fn assert_sync_ws_no_server_error(",
        "async fn connect_sync_ws(",
        "fn expect_sync_ws_hello(",
        "async fn send_sync_ws_binary(",
        "async fn expect_sync_ws_binary_data(",
        "async fn assert_sync_ws_close_or_eof(",
    ] {
        assert!(
            sync_ws.contains(helper),
            "sync WebSocket setup should define `{helper}`"
        );
    }
    assert_eq!(
        count_normalized_source(sync_ws, "connect_async("),
        2,
        "sync WebSocket tests should centralize connect_async in success and expected-error helpers"
    );
    assert_eq!(
        count_normalized_source(sync_ws, "HeaderValue::from_str("),
        1,
        "sync WebSocket tests should centralize fallible header parsing in one named helper"
    );
    assert_eq!(
        count_normalized_source(sync_ws, "mnemed::sync::encode_hello("),
        1,
        "sync WebSocket tests should centralize hello encoding in the named helper"
    );
    for diagnostic in [
        "sync WebSocket request build failed",
        "sync WebSocket header build failed",
        "expected sync WebSocket connect error",
        "sync WebSocket connect failed",
        "sync WebSocket hello encode failed",
        "sync WebSocket binary send failed",
        "sync WebSocket binary response failed",
        "sync WebSocket close/EOF check failed",
    ] {
        assert!(
            sync_ws.contains(diagnostic),
            "sync WebSocket setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn sync_websocket_receive_outcomes_are_classified() {
    let sync = include_str!("../src/sync.rs");

    assert!(
        !sync.contains("while let Some(Ok(msg)) = socket.recv().await"),
        "sync WebSocket receive loop must classify receive errors separately from clean close"
    );
    assert!(
        sync.contains("enum SyncReceiveOutcome"),
        "sync WebSocket receive loop should expose message/closed/failed outcomes"
    );
    assert!(
        sync.contains("fn classify_sync_receive("),
        "sync WebSocket receive loop should use a named receive classifier"
    );
    assert!(
        sync.contains("match classify_sync_receive(socket.recv().await)"),
        "sync WebSocket handler should route socket.recv through the classifier"
    );
}

#[test]
fn sync_websocket_send_outcomes_are_classified() {
    let sync = include_str!("../src/sync.rs");

    assert!(
        !sync.contains("socket.send(Message::Binary(bytes.into())).await.is_err()"),
        "sync WebSocket response send failures must be classified explicitly"
    );
    assert!(
        sync.contains("enum SyncSendOutcome"),
        "sync WebSocket response sends should expose sent/failed outcomes"
    );
    assert!(
        sync.contains("async fn send_sync_response("),
        "sync WebSocket response sends should use a named send helper"
    );
    assert!(
        sync.contains("match send_sync_response(&mut socket, bytes).await"),
        "sync WebSocket handler should route response sends through the helper"
    );
}

#[test]
fn sync_websocket_server_response_build_failures_are_classified() {
    let sync = include_str!("../src/sync.rs");
    let handle_sync = source_between_markers(
        sync,
        "async fn handle_sync(",
        "async fn handle_hello(",
        "sync WebSocket server loop",
    );

    for (marker, end_marker, context) in [
        (
            "async fn handle_hello(",
            "// --- §11 canonical object-transfer protocol",
            "handle_hello",
        ),
        (
            "fn handle_diff_req(",
            "/// Answer `WantObjects",
            "handle_diff_req",
        ),
        (
            "fn handle_want_objects(",
            "/// Build a canonical §11 `DiffReq`",
            "handle_want_objects",
        ),
        (
            "fn encode_snapshot(",
            "/// Build a bare `MSG_SNAPSHOT_REQ`",
            "encode_snapshot",
        ),
        (
            "fn encode_manifest(",
            "/// Answer a `MSG_WANT_OBJECTS` request",
            "encode_manifest",
        ),
        (
            "fn encode_have_objects(",
            "/// Bare `MSG_MANIFEST_REQ`",
            "encode_have_objects",
        ),
    ] {
        let builder = source_between_markers(sync, marker, end_marker, context);
        assert!(
            !builder.contains(".ok()?"),
            "sync WebSocket server response builder `{context}` should classify failures instead of collapsing through `.ok()?`"
        );
    }

    assert!(
        sync.contains("enum SyncResponseBuildOutcome"),
        "sync WebSocket response builders should expose typed build outcomes"
    );
    assert!(
        sync.contains("enum SyncNoResponseReason"),
        "sync WebSocket no-response paths should name the reason"
    );
    assert!(
        sync.contains("fn sync_no_response("),
        "sync WebSocket no-response paths should route through a named helper"
    );
    assert!(
        sync.contains("fn sync_tagged_cbor_response"),
        "sync WebSocket tagged CBOR responses should route through a named helper"
    );
    assert!(
        sync.contains("fn sync_message_response("),
        "canonical sync-message responses should route through a named helper"
    );
    assert!(
        handle_sync.contains("response.into_response()"),
        "sync WebSocket loop should convert classified response outcomes at the send boundary"
    );
}

#[test]
fn sync_public_helper_failures_are_typed_not_option_collapsed() {
    let sync = include_str!("../src/sync.rs");

    for (marker, end_marker, context) in [
        (
            "pub fn encode_diff_request(",
            "/// Decode a `DiffResp`",
            "encode_diff_request",
        ),
        (
            "pub fn decode_diff_response(",
            "/// Build a canonical §11 `WantObjects`",
            "decode_diff_response",
        ),
        (
            "pub fn encode_want_objects_canonical(",
            "/// Decode a canonical §11 `HaveObjects`",
            "encode_want_objects_canonical",
        ),
        (
            "pub fn encode_have_objects_canonical_for_test(",
            "/// Serialize this node's",
            "encode_have_objects_canonical_for_test",
        ),
        (
            "pub fn decode_snapshot(",
            "// --- §11 incremental anti-entropy",
            "decode_snapshot",
        ),
        (
            "pub fn decode_manifest(",
            "/// Build a `MSG_WANT_OBJECTS`",
            "decode_manifest",
        ),
        (
            "pub fn encode_want_objects(",
            "/// Decode a `MSG_HAVE_OBJECTS`",
            "encode_want_objects",
        ),
        (
            "pub fn decode_have_objects(",
            "pub fn encode_hello(",
            "decode_have_objects",
        ),
        ("pub fn encode_hello(", "#[cfg(test)]", "encode_hello"),
    ] {
        let helper = source_between_markers(sync, marker, end_marker, context);
        assert!(
            !helper.contains("-> Option<"),
            "sync helper `{context}` should expose typed Result failures"
        );
        assert!(
            !helper.contains(".ok()?") && !helper.contains(".ok()"),
            "sync helper `{context}` should not collapse helper failures through `.ok()`"
        );
    }

    assert!(
        sync.contains("pub enum SyncFrameError"),
        "sync helper failures should expose a public typed error enum"
    );
    assert!(
        sync.contains("SyncFrameError::CanonicalEncode"),
        "canonical sync helper encode failures should be classified"
    );
    assert!(
        sync.contains("SyncFrameError::CanonicalDecode"),
        "canonical sync helper decode failures should be classified"
    );
    assert!(
        sync.contains("SyncFrameError::UnexpectedMessageType"),
        "canonical sync helper wrong-message failures should be classified"
    );
    assert!(
        sync.contains("SyncFrameError::UnexpectedTag"),
        "tagged legacy sync helper wrong-tag failures should be classified"
    );
}

#[test]
fn sync_canonical_have_objects_decode_failures_are_typed() {
    let sync = include_str!("../src/sync.rs");
    let decoder = source_between_markers(
        sync,
        "pub fn decode_have_objects_canonical(",
        "/// Test-support",
        "decode_have_objects_canonical",
    );

    assert!(
        decoder.contains("Result<SyncSnapshot, SyncFrameError>"),
        "canonical HaveObjects decode should use the sync frame error boundary"
    );
    assert!(
        !decoder.contains("MnemeError::SchemaDrift"),
        "canonical HaveObjects decode should not collapse wire failures into SchemaDrift"
    );
    assert!(
        decoder.contains("SyncFrameError::UnexpectedMessageType"),
        "canonical HaveObjects wrong-message failures should be typed"
    );
    assert!(
        decoder.contains("SyncFrameError::TaggedCborDecode"),
        "canonical HaveObjects bundle decode failures should be typed"
    );
    assert!(
        decoder.contains("SyncFrameError::ObjectTampered"),
        "canonical HaveObjects hash mismatches should remain typed as tamper"
    );
}

#[test]
fn two_peer_ws_sync_uses_typed_binary_frame_reader() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");

    assert!(
        !two_peer_ws_sync.contains("ws.next().await.expect(\"frame\").expect(\"ok\")"),
        "two-peer WebSocket sync tests should use a typed binary frame reader instead of generic expect chains"
    );
    assert!(
        two_peer_ws_sync.contains("async fn recv_ws_binary_frame("),
        "two-peer WebSocket sync tests should share a typed binary frame reader"
    );
}

#[test]
fn two_peer_ws_sync_binary_frame_reads_are_bounded() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");

    assert!(
        !two_peer_ws_sync.contains("match ws.next().await"),
        "two-peer WebSocket binary frame reader should not wait forever in raw ws.next().await loops"
    );
    assert!(
        two_peer_ws_sync.contains("const TWO_PEER_WS_BINARY_FRAME_TIMEOUT: Duration"),
        "two-peer WebSocket binary frame reader should share a named timeout"
    );
    assert!(
        two_peer_ws_sync.contains("recv_two_peer_ws_binary_message_with_timeout(ws).await"),
        "two-peer WebSocket binary frame reader should route ws.next through the named timeout helper"
    );
}

#[test]
fn two_peer_ws_sync_timeout_policy_uses_named_read_helper() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");
    let binary_reader = source_between_markers(
        two_peer_ws_sync,
        "async fn recv_ws_binary_frame(",
        "fn classify_two_peer_ws_binary_read(",
        "recv_ws_binary_frame body",
    );

    assert!(
        !binary_reader
            .contains("tokio::time::timeout(TWO_PEER_WS_BINARY_FRAME_TIMEOUT, ws.next()).await"),
        "two-peer WebSocket binary frame reader should route timed reads through a named helper"
    );
    assert!(
        two_peer_ws_sync.contains("async fn recv_two_peer_ws_binary_message_with_timeout("),
        "two-peer WebSocket binary read timeout policy should have a named helper"
    );
    assert!(
        binary_reader.contains("recv_two_peer_ws_binary_message_with_timeout(ws).await"),
        "two-peer WebSocket binary frame reader should call the named timeout helper"
    );
}

#[test]
fn two_peer_ws_sync_timeout_helper_returns_classified_outcomes() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");
    let binary_timeout_helper = source_between_markers(
        two_peer_ws_sync,
        "async fn recv_two_peer_ws_binary_message_with_timeout(",
        "async fn recv_ws_binary_frame(",
        "recv_two_peer_ws_binary_message_with_timeout body",
    );
    let binary_reader = source_between_markers(
        two_peer_ws_sync,
        "async fn recv_ws_binary_frame(",
        "fn classify_two_peer_ws_binary_read(",
        "recv_ws_binary_frame body",
    );

    assert!(
        contains_normalized_source(
            two_peer_ws_sync,
            "async fn recv_two_peer_ws_binary_message_with_timeout(ws: &mut ClientWebSocket,) -> TwoPeerWsBinaryFrameOutcome"
        ),
        "two-peer WebSocket binary timeout helper should return classified binary outcomes"
    );
    assert!(
        binary_timeout_helper.contains("classify_two_peer_ws_binary_read("),
        "two-peer WebSocket binary timeout helper should classify its raw timeout result"
    );
    assert!(
        !helper_directly_returns_raw_timeout_result(
            binary_timeout_helper,
            "tokio::time::timeout(TWO_PEER_WS_BINARY_FRAME_TIMEOUT, ws.next()).await"
        ),
        "two-peer WebSocket binary timeout helper should not return the raw timeout result directly"
    );
    assert!(
        binary_reader.contains("match recv_two_peer_ws_binary_message_with_timeout(ws).await"),
        "two-peer WebSocket binary reader should branch on classified timeout helper outcomes"
    );
    assert!(
        !contains_normalized_source(
            binary_reader,
            "match classify_two_peer_ws_binary_read(recv_two_peer_ws_binary_message_with_timeout"
        ),
        "two-peer WebSocket binary reader should not classify timeout-helper output at the call site"
    );
}

#[test]
fn two_peer_ws_sync_binary_read_outcomes_are_classified() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");
    let binary_reader = source_between_markers(
        two_peer_ws_sync,
        "async fn recv_ws_binary_frame(",
        "fn classify_two_peer_ws_binary_read(",
        "recv_ws_binary_frame body",
    );

    for inline_pattern in [
        "Ok(Some(Ok(Message::Binary(data))))",
        "Ok(Some(Ok(Message::Ping(_))))",
        "Ok(Some(Ok(Message::Pong(_))))",
        "Ok(Some(Err(err)))",
        "Ok(None)",
        "Err(_)",
    ] {
        assert!(
            !binary_reader.contains(inline_pattern),
            "two-peer WebSocket binary frame reader should classify timed read outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        two_peer_ws_sync.contains("enum TwoPeerWsBinaryFrameOutcome"),
        "two-peer WebSocket binary reads should expose a typed outcome enum"
    );
    assert!(
        two_peer_ws_sync.contains("fn classify_two_peer_ws_binary_read("),
        "two-peer WebSocket binary reads should classify timed reads through a named helper"
    );
    assert!(
        binary_reader.contains("match recv_two_peer_ws_binary_message_with_timeout(ws).await"),
        "two-peer WebSocket binary frame reader should branch on classified timeout helper outcomes"
    );
    assert!(
        binary_reader.contains("TwoPeerWsBinaryFrameOutcome::Binary(data) => return Ok(data)"),
        "two-peer WebSocket binary frame reader should return classified binary payloads"
    );
    assert!(
        binary_reader.contains("TwoPeerWsBinaryFrameOutcome::KeepAlive => continue"),
        "two-peer WebSocket binary frame reader should explicitly tolerate Ping/Pong keepalives"
    );
    assert!(
        binary_reader.contains("TwoPeerWsBinaryFrameOutcome::Unexpected(frame) =>"),
        "two-peer WebSocket binary frame reader should explicitly reject unexpected frames"
    );
    assert!(
        binary_reader.contains("TwoPeerWsBinaryFrameOutcome::ReadFailed(err) =>"),
        "two-peer WebSocket binary frame reader should explicitly surface websocket read errors"
    );
    assert!(
        binary_reader.contains("TwoPeerWsBinaryFrameOutcome::Closed =>"),
        "two-peer WebSocket binary frame reader should explicitly surface EOF before a binary frame"
    );
    assert!(
        binary_reader.contains("TwoPeerWsBinaryFrameOutcome::TimedOut =>"),
        "two-peer WebSocket binary frame reader should explicitly surface read timeouts"
    );
}

#[test]
fn two_peer_ws_setup_uses_named_diagnostic_helpers() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");

    for inline_expect in [".expect(", ".expect_err(", ".unwrap()"] {
        assert!(
            !two_peer_ws_sync.contains(inline_expect),
            "two-peer WebSocket tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "fn expect_two_peer_cap(",
        "fn expect_two_peer_cap_b64(",
        "fn expect_two_peer_tempdir(",
        "fn expect_two_peer_store(",
        "fn expect_two_peer_remember",
        "async fn start_two_peer_server(",
        "fn expect_two_peer_ws_request(",
        "fn expect_two_peer_ws_header_value(",
        "async fn connect_two_peer_ws(",
        "async fn expect_two_peer_pull",
        "fn expect_two_peer_recall_entry",
        "fn expect_two_peer_merge_result",
    ] {
        assert!(
            two_peer_ws_sync.contains(helper),
            "two-peer WebSocket setup should define `{helper}`"
        );
    }
    for (fallible_call, expected_count) in [
        ("agent_cap(operator, operator.public_key_bytes())", 1),
        ("tempfile::tempdir()", 1),
        ("mneme_store::Store::create(", 1),
        ("start_with_state(config, state).await", 1),
        ("into_client_request()", 1),
        ("cap_to_b64(cap)", 1),
        ("HeaderValue::from_str(", 1),
        ("connect_async(", 1),
    ] {
        assert_eq!(
            count_normalized_source(two_peer_ws_sync, fallible_call),
            expected_count,
            "two-peer WebSocket setup should centralize `{fallible_call}` in named diagnostic helpers"
        );
    }
    for diagnostic in [
        "two-peer capability creation failed",
        "two-peer capability encoding failed",
        "two-peer tempdir failed",
        "two-peer store create failed",
        "two-peer remember failed",
        "two-peer server start failed",
        "two-peer WebSocket request build failed",
        "two-peer WebSocket header build failed",
        "two-peer WebSocket connect failed",
        "two-peer pull failed",
        "two-peer recall failed",
        "two-peer merge failed",
    ] {
        assert!(
            two_peer_ws_sync.contains(diagnostic),
            "two-peer WebSocket setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn running_server_shutdown_does_not_ignore_join_results() {
    let lib = include_str!("../src/lib.rs");
    let running_server_impl = source_between_markers(
        lib,
        "impl RunningServer {",
        "fn notify_running_server_shutdown(",
        "RunningServer impl",
    );

    assert!(
        !lib.contains("let _ = h.await"),
        "RunningServer::shutdown must not discard join results"
    );
    assert!(
        !running_server_impl.contains(".expect(\"server task panicked during shutdown\")"),
        "RunningServer::shutdown must classify task panics instead of relying on an expect chain"
    );
    assert!(
        running_server_impl.contains("assert_server_task_shutdown_completed("),
        "RunningServer::shutdown must surface task panics through the named shutdown reporter"
    );
}

#[test]
fn running_server_shutdown_classifies_task_join_results() {
    let lib = include_str!("../src/lib.rs");
    let running_server_impl = source_between_markers(
        lib,
        "impl RunningServer {",
        "fn notify_running_server_shutdown(",
        "RunningServer impl",
    );

    for inline_report in [
        ".expect(\"server task panicked during shutdown\")",
        ".expect(\"server task failed during shutdown\")",
    ] {
        assert!(
            !running_server_impl.contains(inline_report),
            "RunningServer::shutdown should classify task join outcomes instead of using `{inline_report}`"
        );
    }
    for helper in [
        "type ServerTaskJoin = Result<ServerTaskResult, tokio::task::JoinError>",
        "enum ServerTaskShutdownOutcome",
        "async fn observe_server_task_shutdown(",
        "fn classify_server_task_shutdown(",
        "fn assert_server_task_shutdown_completed(",
    ] {
        assert!(
            lib.contains(helper),
            "RunningServer shutdown join handling should define `{helper}`"
        );
    }
    assert!(
        running_server_impl
            .contains("let task_shutdown = observe_server_task_shutdown(handle).await;"),
        "RunningServer::shutdown should observe each task join through the named helper"
    );
    assert!(
        running_server_impl.contains("assert_server_task_shutdown_completed(task_shutdown);"),
        "RunningServer::shutdown should report each classified task outcome through the named helper"
    );
    assert!(
        lib.contains("ServerTaskShutdownOutcome::Panicked(err)"),
        "RunningServer shutdown join classifier should preserve JoinError outcomes"
    );
    assert!(
        lib.contains("ServerTaskShutdownOutcome::Failed(err)"),
        "RunningServer shutdown join classifier should preserve server task errors"
    );
}

#[test]
fn task_panic_fixtures_use_named_payload_helpers() {
    let lib = include_str!("../src/lib.rs");
    let unix = include_str!("../src/unix.rs");
    let running_server_panic_test = source_between_markers(
        lib,
        "async fn running_server_shutdown_surfaces_task_panic()",
        "#[tokio::test]\n    #[should_panic(expected = \"server task failed during shutdown\")]",
        "running_server_shutdown_surfaces_task_panic body",
    );
    let unix_connection_panic_test = source_between_markers(
        unix,
        "async fn connection_task_panic_surfaces_as_server_error()",
        "#[test]\n    fn connection_io_error_is_observed_not_server_fatal()",
        "connection_task_panic_surfaces_as_server_error body",
    );

    assert!(
        !running_server_panic_test.contains("panic!(\"server task boom\")"),
        "running-server shutdown panic test should route spawned-task panic payload through a named helper"
    );
    assert!(
        !unix_connection_panic_test.contains("panic!(\"connection task boom\")"),
        "Unix connection panic test should route spawned-task panic payload through a named helper"
    );
    assert!(
        lib.contains("fn panic_server_task_boom("),
        "running-server shutdown panic fixture should define a named panic helper"
    );
    assert!(
        unix.contains("fn panic_connection_task_boom("),
        "Unix connection panic fixture should define a named panic helper"
    );
    assert!(
        running_server_panic_test.contains("panic_server_task_boom();"),
        "running-server shutdown panic test should call the named panic helper"
    );
    assert!(
        unix_connection_panic_test.contains("panic_connection_task_boom();"),
        "Unix connection panic test should call the named panic helper"
    );
}

#[test]
fn running_server_tasks_return_serve_errors_to_shutdown() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        lib.contains("type ServerTaskResult = Result<(), MnemeError>"),
        "mnemed server tasks must return typed results"
    );
    assert!(
        lib.contains("JoinHandle<ServerTaskResult>"),
        "RunningServer must retain task results through the join handle"
    );
    assert!(
        lib.contains("ServerTaskShutdownOutcome::Failed(err)"),
        "RunningServer::shutdown must surface serve errors from server tasks through typed outcomes"
    );
    for swallowed in [
        "tracing::error!(\"http serve failed",
        "tracing::error!(\"grpc serve failed",
        "tracing::error!(\"unix serve failed",
    ] {
        assert!(
            !lib.contains(swallowed),
            "server task serve errors must be returned to shutdown, not only logged: {swallowed}"
        );
    }
}

#[test]
fn running_server_shutdown_notification_result_is_explicit() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        !lib.contains("let _ = self.shutdown.send(())"),
        "RunningServer::shutdown must not discard shutdown notification results inline"
    );
    assert!(
        lib.contains("enum ShutdownSignalDelivery"),
        "RunningServer shutdown notification should expose delivered/no-receiver outcomes"
    );
    assert!(
        lib.contains("fn notify_running_server_shutdown("),
        "RunningServer shutdown notification should use a named helper"
    );
    assert!(
        lib.contains("notify_running_server_shutdown(&self.shutdown)"),
        "RunningServer::shutdown should route notification through the helper"
    );
}

#[test]
fn running_server_graceful_shutdown_signal_is_explicitly_observed() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        !lib.contains("let _ = shutdown_rx_http.changed().await"),
        "HTTP graceful shutdown must not discard the watch receiver result inline"
    );
    assert!(
        !lib.contains("let _ = shutdown_rx_grpc.changed().await"),
        "gRPC graceful shutdown must not discard the watch receiver result inline"
    );
    assert!(
        lib.contains("async fn wait_for_running_server_shutdown("),
        "RunningServer graceful shutdown should use a named shutdown-signal helper"
    );
    assert_eq!(
        lib.matches("wait_for_running_server_shutdown(shutdown_rx_")
            .count(),
        2,
        "HTTP and gRPC servers should both route graceful shutdown through the helper"
    );
}

#[test]
fn running_server_shutdown_helper_tests_use_named_timeout() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        !contains_normalized_source(
            lib,
            "std::time::Duration::from_secs(1), wait_for_running_server_shutdown(shutdown_rx),"
        ),
        "RunningServer shutdown-helper tests should use a named timeout"
    );
    assert!(
        lib.contains("const RUNNING_SERVER_SHUTDOWN_HELPER_TIMEOUT: std::time::Duration"),
        "RunningServer shutdown-helper tests should share a named timeout"
    );
    assert_eq!(
        count_normalized_source(
            lib,
            "RUNNING_SERVER_SHUTDOWN_HELPER_TIMEOUT, wait_for_running_server_shutdown(shutdown_rx),"
        ),
        1,
        "RunningServer shutdown-helper timeout should be centralized in the named helper"
    );
    assert!(
        lib.contains("async fn expect_running_server_shutdown_helper_exit("),
        "RunningServer shutdown-helper tests should share a timeout assertion helper"
    );
    assert_eq!(
        lib.matches("expect_running_server_shutdown_helper_exit(shutdown_rx,")
            .count(),
        2,
        "both RunningServer shutdown-helper tests should route through the timeout assertion helper"
    );
}

#[test]
fn running_server_shutdown_unit_tests_use_named_diagnostic_helpers() {
    let lib = include_str!("../src/lib.rs");

    for inline_expect in [
        ".expect(\"send shutdown\")",
        ".expect(\"shutdown helper exits after signal\")",
        ".expect(\"shutdown helper exits after owner drop\")",
        "tempfile::tempdir().expect(\"tempdir\")",
        "test_state(dir.path()).expect(\"test_state\")",
    ] {
        assert!(
            !lib.contains(inline_expect),
            "RunningServer shutdown unit tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_shutdown_signal_sent(",
        "async fn expect_running_server_shutdown_helper_exit(",
        "fn expect_running_server_tempdir(",
        "fn expect_running_server_test_state(",
    ] {
        assert!(
            lib.contains(helper),
            "RunningServer shutdown unit tests should define `{helper}`"
        );
    }

    for diagnostic in [
        "shutdown signal send failed",
        "shutdown helper did not exit",
        "RunningServer tempdir failed",
        "RunningServer test state failed",
    ] {
        assert!(
            lib.contains(diagnostic),
            "RunningServer shutdown unit test helpers should preserve `{diagnostic}` context"
        );
    }
}

#[test]
fn daemon_main_does_not_discard_ctrl_c_errors() {
    let main = include_str!("../src/main.rs");

    assert!(
        !main.contains("let _ = tokio::signal::ctrl_c().await"),
        "mnemed main must not discard ctrl-c signal listener errors"
    );
    assert!(
        main.contains("wait_for_shutdown_signal(tokio::signal::ctrl_c()).await"),
        "mnemed main must route ctrl-c through the checked shutdown signal helper"
    );
    assert!(
        main.contains("failed to listen for shutdown signal"),
        "mnemed main must preserve signal listener error context"
    );
}

#[test]
fn daemon_main_unit_tests_use_named_diagnostic_helpers() {
    let main = include_str!("../src/main.rs");

    for inline_expect in [
        ".expect(\"parse args\")",
        ".expect(\"server config\")",
        ".expect(\"successful shutdown signal\")",
        ".expect_err(\"signal listener errors must be surfaced\")",
    ] {
        assert!(
            !main.contains(inline_expect),
            "mnemed main tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_cli_args(",
        "fn expect_server_config(",
        "async fn expect_shutdown_signal_success(",
        "async fn expect_shutdown_signal_error(",
    ] {
        assert!(
            main.contains(helper),
            "mnemed main tests should define `{helper}`"
        );
    }

    for diagnostic in [
        "CLI args parse failed",
        "server config build failed",
        "shutdown signal unexpectedly failed",
        "expected shutdown signal error",
    ] {
        assert!(
            main.contains(diagnostic),
            "mnemed main test helpers should preserve `{diagnostic}` context"
        );
    }
}

#[test]
fn mnemed_default_rate_limit_policy_is_named() {
    let lib = include_str!("../src/lib.rs");
    let common = include_str!("common/mod.rs");
    let unix_api = include_str!("unix_api.rs");

    assert!(
        !lib.contains("rate_limit_per_minute: 120"),
        "ServerConfig::default should use the named default rate-limit policy"
    );
    assert!(
        !lib.contains("RateLimiter::new(120)"),
        "test_state should use the named default rate-limit policy"
    );
    assert!(
        lib.contains("pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;"),
        "mnemed should expose the default rate-limit policy once"
    );
    assert!(
        lib.contains("rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE"),
        "ServerConfig::default should route through the named default rate-limit policy"
    );
    assert!(
        lib.contains("RateLimiter::new(DEFAULT_RATE_LIMIT_PER_MINUTE)"),
        "test_state should route through the named default rate-limit policy"
    );

    assert!(
        !common.contains("rate_limit_per_minute: 120"),
        "shared test harness should use the named default rate-limit policy"
    );
    assert!(
        common.contains("rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE"),
        "shared test harness should route ServerConfig through the named default rate-limit policy"
    );

    assert!(
        !unix_api.contains("rate_limit_per_minute: 120"),
        "Unix API daemon-start configs should use the named default rate-limit policy"
    );
    assert_eq!(
        unix_api
            .matches("rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE")
            .count(),
        2,
        "the Unix API daemon-start success and failure helper configs should route through the named default policy"
    );
    for daemon_start_helper in [
        "async fn expect_daemon_start_with_unix_socket(",
        "async fn expect_daemon_start_failure_with_unix_socket(",
    ] {
        assert!(
            unix_api.contains(daemon_start_helper),
            "Unix API daemon-start rate-limit policy should be centralized in `{daemon_start_helper}`"
        );
    }
}

#[test]
fn http_rate_limit_enforcement_tests_use_named_low_limit() {
    let http_api = include_str!("http_api.rs");

    assert!(
        !http_api.contains("rate_limit_per_minute: 1"),
        "HTTP rate-limit enforcement tests should use a named low-limit policy"
    );
    assert!(
        http_api.contains("const HTTP_RATE_LIMIT_ENFORCEMENT_TEST_LIMIT: u32 = 1;"),
        "HTTP rate-limit enforcement tests should define their low-limit policy once"
    );
    assert_eq!(
        http_api
            .matches("rate_limit_per_minute: HTTP_RATE_LIMIT_ENFORCEMENT_TEST_LIMIT")
            .count(),
        1,
        "HTTP rate-limit enforcement tests should centralize the named low-limit policy in one helper"
    );
    assert_eq!(
        http_api.matches("start_rate_limited_http_server(").count(),
        3,
        "both HTTP rate-limit enforcement tests should route through the shared low-limit helper"
    );
}

#[test]
fn http_api_setup_uses_named_diagnostic_helpers() {
    let http_api = include_str!("http_api.rs");

    for inline_expect in [
        ".expect(",
        ".expect_err(",
        ".unwrap()",
        "tempdir().expect",
        "test_state(dir.path()).expect",
        "cap_to_b64(&cap).expect",
        "cap_to_b64(&h.agent_cap).expect",
        "\"127.0.0.1:0\".parse().expect",
    ] {
        assert!(
            !http_api.contains(inline_expect),
            "HTTP API tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "async fn expect_http_response",
        "async fn expect_http_json",
        "fn expect_http_cap_b64(",
        "fn expect_http_tempdir(",
        "fn expect_http_state(",
        "fn expect_http_agent_capability(",
        "fn http_loopback_addr(",
        "async fn start_rate_limited_http_server(",
    ] {
        assert!(
            http_api.contains(helper),
            "HTTP API setup should define `{helper}`"
        );
    }
    for diagnostic in [
        "HTTP request failed",
        "HTTP JSON decode failed",
        "HTTP capability encoding failed",
        "HTTP tempdir failed",
        "HTTP test state setup failed",
        "HTTP agent capability failed",
        "HTTP loopback address parse failed",
        "HTTP rate-limit server start failed",
    ] {
        assert!(
            http_api.contains(diagnostic),
            "HTTP API setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn api_error_status_is_typed_not_silent_u16_fallback() {
    let state = include_str!("../src/state.rs");
    let http = include_str!("../src/http.rs");
    let grpc = include_str!("../src/grpc.rs");

    assert!(
        !state.contains("pub status: u16"),
        "ApiError should not expose raw u16 status codes"
    );
    assert!(
        !state.contains("status: 400")
            && !state.contains("status: 401")
            && !state.contains("status: 403")
            && !state.contains("status: 404")
            && !state.contains("status: 429")
            && !state.contains("status: 500"),
        "ApiError constructors should use typed StatusCode constants"
    );
    assert!(
        state.contains("pub status: StatusCode"),
        "ApiError should carry a typed StatusCode so invalid statuses are unrepresentable"
    );
    assert!(
        !http.contains("StatusCode::from_u16(self.status)"),
        "HTTP ApiError responses should not recover from invalid raw statuses"
    );
    assert!(
        !http.contains("unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)"),
        "HTTP ApiError responses should not silently fallback from invalid raw statuses"
    );
    assert!(
        contains_normalized_source(http, "(self.status,"),
        "HTTP ApiError responses should use the typed status directly"
    );
    assert!(
        grpc.contains("match err.status {") || grpc.contains("match err.status"),
        "gRPC ApiError mapping should explicitly consume the typed status"
    );
    for raw_status_arm in ["400 =>", "401 =>", "403 =>", "404 =>", "410 =>", "429 =>"] {
        assert!(
            !grpc.contains(raw_status_arm),
            "gRPC ApiError mapping should not match raw numeric status arm `{raw_status_arm}`"
        );
    }
    for status_constant in [
        "StatusCode::BAD_REQUEST",
        "StatusCode::UNAUTHORIZED",
        "StatusCode::FORBIDDEN",
        "StatusCode::NOT_FOUND",
        "StatusCode::GONE",
        "StatusCode::TOO_MANY_REQUESTS",
        "StatusCode::INTERNAL_SERVER_ERROR",
    ] {
        assert!(
            state.contains(status_constant),
            "ApiError status mapping should use typed `{status_constant}`"
        );
    }
}

#[test]
fn http_recall_default_min_tier_is_typed_not_string_fallback() {
    let http = include_str!("../src/http.rs");
    let recall_handler =
        source_top_level_item_after_marker(http, "async fn recall(", "HTTP recall handler");
    let optional_tier_parser = source_top_level_item_after_marker(
        http,
        "fn parse_optional_tier(",
        "HTTP optional trust-tier parser",
    );

    assert!(
        !recall_handler.contains("params.min_tier.as_deref().unwrap_or(\"working\")"),
        "HTTP recall should not default missing min_tier through a string literal parser fallback"
    );
    assert!(
        http.contains("const DEFAULT_RECALL_MIN_TIER: TrustTier = TrustTier::Working;"),
        "HTTP recall should name the typed default min_tier policy"
    );
    assert!(
        contains_normalized_source(
            recall_handler,
            "let min_tier = parse_optional_tier(params.min_tier.as_deref())?;",
        ),
        "HTTP recall should route optional min_tier through the typed default helper"
    );
    assert!(
        optional_tier_parser.contains("None => Ok(DEFAULT_RECALL_MIN_TIER)"),
        "HTTP optional tier parsing should use the typed default policy when min_tier is omitted"
    );
    assert!(
        optional_tier_parser.contains("Some(tier) => parse_tier(tier)"),
        "HTTP optional tier parsing should preserve explicit min_tier validation"
    );
}

#[test]
fn api_trust_tier_parsers_return_typed_variants_not_numeric_discriminants() {
    let http = include_str!("../src/http.rs");
    let grpc = include_str!("../src/grpc.rs");

    for (transport, source, parser_marker) in [
        ("HTTP", http, "fn parse_tier("),
        ("gRPC", grpc, "fn parse_tier_grpc("),
    ] {
        let parser = source_top_level_item_after_marker(
            source,
            parser_marker,
            &format!("{transport} trust-tier parser"),
        );

        assert!(
            !parser.contains("TrustTier::from_u8(match s.to_lowercase().as_str()"),
            "{transport} trust-tier parser should not detour through numeric discriminants"
        );
        for numeric_arm in [
            "\"quarantine\" => 0",
            "\"working\" => 1",
            "\"trusted\" => 2",
            "\"identity\" => 3",
        ] {
            assert!(
                !parser.contains(numeric_arm),
                "{transport} trust-tier parser should not use numeric arm `{numeric_arm}`"
            );
        }
        for typed_arm in [
            "\"quarantine\" => Ok(TrustTier::Quarantine)",
            "\"working\" => Ok(TrustTier::Working)",
            "\"trusted\" => Ok(TrustTier::Trusted)",
            "\"identity\" => Ok(TrustTier::Identity)",
        ] {
            assert!(
                parser.contains(typed_arm),
                "{transport} trust-tier parser should map directly to typed arm `{typed_arm}`"
            );
        }
    }
}

#[test]
fn recall_response_serializers_validate_trust_tier_before_export() {
    let http = include_str!("../src/http.rs");
    let grpc = include_str!("../src/grpc.rs");
    let http_recall_handler =
        source_top_level_item_after_marker(http, "async fn recall(", "HTTP recall handler");
    let grpc_recall_handler = source_between_markers(
        grpc,
        "    async fn recall(",
        "    async fn forget(",
        "gRPC recall handler",
    );
    let http_serializer = source_top_level_item_after_marker(
        http,
        "fn recall_entry_json(",
        "HTTP recall entry serializer",
    );
    let grpc_serializer = source_top_level_item_after_marker(
        grpc,
        "fn recall_entry_grpc(",
        "gRPC recall entry serializer",
    );

    assert!(
        !http_recall_handler.contains("trust_tier: e.record.trust_tier"),
        "HTTP recall should not export stored trust_tier bytes without validation"
    );
    assert!(
        !grpc_recall_handler.contains("trust_tier: e.record.trust_tier as u32"),
        "gRPC recall should not widen stored trust_tier bytes without validation"
    );
    assert!(
        contains_normalized_source(http_recall_handler, ".map(recall_entry_json)"),
        "HTTP recall should route entries through the named serializer"
    );
    assert!(
        contains_normalized_source(grpc_recall_handler, ".map(recall_entry_grpc)"),
        "gRPC recall should route entries through the named serializer"
    );
    for (transport, serializer, error_mapper) in [
        ("HTTP", http_serializer, "map_err(ApiError::from_mneme)"),
        ("gRPC", grpc_serializer, "map_err(grpc_status_mneme)"),
    ] {
        assert!(
            serializer.contains("TrustTier::from_u8(entry.record.trust_tier)"),
            "{transport} recall entry serializer should validate stored trust_tier bytes"
        );
        assert!(
            contains_normalized_source(serializer, error_mapper),
            "{transport} recall entry serializer should preserve typed schema-drift errors"
        );
        assert!(
            serializer.contains(".as_u8()"),
            "{transport} recall entry serializer should export the validated tier value"
        );
    }
}

#[test]
fn http_recall_entry_serializer_rejects_non_utf8_without_lossy_rewrite() {
    let http = include_str!("../src/http.rs");
    let serializer = source_top_level_item_after_marker(
        http,
        "fn recall_entry_json(",
        "HTTP recall entry serializer",
    );

    assert!(
        !serializer.contains("String::from_utf8_lossy"),
        "HTTP recall entry serializer should not silently rewrite invalid UTF-8 bodies"
    );
    assert!(
        serializer.contains("String::from_utf8(entry.plaintext)"),
        "HTTP recall entry serializer should validate plaintext UTF-8 before JSON export"
    );
    assert!(
        serializer.contains("MnemeError::SchemaDrift"),
        "HTTP recall entry serializer should map non-UTF-8 plaintext to a typed fail-closed error"
    );
}

#[test]
fn rate_limiter_pruning_tests_use_named_stale_window_age() {
    let state = include_str!("../src/state.rs");

    assert!(
        !state.contains("Instant::now() - Duration::from_secs(61)"),
        "RateLimiter pruning tests should use a named stale-window age"
    );
    assert!(
        state.contains("const RATE_LIMIT_STALE_WINDOW_AGE: Duration"),
        "RateLimiter pruning tests should share a named stale-window age"
    );
    assert_eq!(
        state
            .matches("Instant::now() - RATE_LIMIT_STALE_WINDOW_AGE")
            .count(),
        2,
        "both RateLimiter pruning tests should route stale starts through the named age"
    );
}

#[test]
fn rate_limiter_tests_use_named_limit_policies() {
    let state = include_str!("../src/state.rs");

    assert!(
        !state.contains("RateLimiter::new(10)"),
        "RateLimiter tests should use a named multi-request test limit"
    );
    assert!(
        !state.contains("RateLimiter::new(1)"),
        "RateLimiter tests should use a named single-request test limit"
    );
    assert!(
        state.contains("const RATE_LIMIT_MULTI_REQUEST_TEST_LIMIT: u32"),
        "RateLimiter tests should define the reusable multi-request test limit"
    );
    assert!(
        state.contains("const RATE_LIMIT_SINGLE_REQUEST_TEST_LIMIT: u32"),
        "RateLimiter tests should define the reusable single-request test limit"
    );
    assert_eq!(
        state
            .matches("RateLimiter::new(RATE_LIMIT_MULTI_REQUEST_TEST_LIMIT)")
            .count(),
        3,
        "the three multi-request RateLimiter tests should route through the named policy"
    );
    assert_eq!(
        state
            .matches("RateLimiter::new(RATE_LIMIT_SINGLE_REQUEST_TEST_LIMIT)")
            .count(),
        1,
        "the live-window limiting test should route through the named single-request policy"
    );
}

#[test]
fn rate_limiter_active_window_cap_tests_use_shared_prefill_fixture() {
    let state = include_str!("../src/state.rs");

    assert!(
        !contains_normalized_source(
            state,
            "for subject_index in 0..MAX_RATE_LIMIT_SUBJECT_WINDOWS { limiter.windows.insert(format!(\"subject-{subject_index}\"), (1, now)); }"
        ),
        "RateLimiter active-window-cap tests should use a shared prefill fixture"
    );
    assert!(
        state.contains("fn fill_active_rate_limit_windows("),
        "RateLimiter active-window-cap tests should define a shared prefill fixture"
    );
    assert_eq!(
        state
            .matches("fill_active_rate_limit_windows(&mut limiter, now);")
            .count(),
        2,
        "both active-window-cap tests should route prefill through the shared fixture"
    );
}

#[test]
fn state_unit_tests_use_named_diagnostic_helpers() {
    let state = include_str!("../src/state.rs");

    for inline_expect in [
        ".expect_err(\"oversized capability must fail\")",
        ".expect(\"fresh subject allowed\")",
        ".expect(\"first live request allowed\")",
        ".expect_err(\"live subject remains limited\")",
        ".expect_err(\"new subject must fail closed when active window cap is full\")",
        ".expect(\"existing subject remains governed by its own window\")",
    ] {
        assert!(
            !state.contains(inline_expect),
            "state unit tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_oversized_capability_error(",
        "fn expect_rate_limit_allowed(",
        "fn expect_rate_limit_denied(",
    ] {
        assert!(
            state.contains(helper),
            "state unit tests should define `{helper}`"
        );
    }

    for diagnostic in [
        "oversized capability unexpectedly parsed",
        "rate limiter unexpectedly rejected",
        "rate limiter unexpectedly allowed",
    ] {
        assert!(
            state.contains(diagnostic),
            "state unit test helpers should preserve `{diagnostic}` context"
        );
    }
}

#[test]
fn websocket_sync_tests_use_named_rate_limit_fixture() {
    for (path, contents) in [
        ("v11_object_sync.rs", include_str!("v11_object_sync.rs")),
        ("two_peer_ws_sync.rs", include_str!("two_peer_ws_sync.rs")),
    ] {
        assert!(
            !contents.contains("RateLimiter::new(1000)"),
            "{path} should use a named rate-limit fixture for peer AppState construction"
        );
        assert!(
            !contents.contains("rate_limit_per_minute: 1000"),
            "{path} should use the same named rate-limit fixture for ServerConfig"
        );
        assert!(
            contents.contains("const WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE: u32"),
            "{path} should define the WebSocket sync test rate-limit fixture once"
        );
        assert!(
            contains_normalized_source(
                contents,
                "RateLimiter::new(WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE,)"
            ),
            "{path} should route peer AppState construction through the named rate-limit fixture"
        );
        assert!(
            contents.contains("rate_limit_per_minute: WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE"),
            "{path} should route ServerConfig through the named rate-limit fixture"
        );
    }
}

#[test]
fn websocket_sync_membership_assertions_preserve_proof_errors() {
    for (path, contents, expected_contexts) in [
        (
            "v11_object_sync.rs",
            include_str!("v11_object_sync.rs"),
            &[
                "A has only-a",
                "A received only-b via canonical",
                "B received only-a via canonical",
                "B has only-b",
            ][..],
        ),
        (
            "two_peer_ws_sync.rs",
            include_str!("two_peer_ws_sync.rs"),
            &[
                "A has only-a",
                "A received only-b over the wire",
                "B received only-a over the wire",
                "B has only-b",
                "A got only-b via incremental wire",
                "B got only-a via incremental wire",
            ][..],
        ),
    ] {
        assert!(
            !contains_normalized_source(contents, ".prove_membership(&key_a).is_ok()"),
            "{path} should not discard positive membership proof errors for key_a"
        );
        assert!(
            !contains_normalized_source(contents, ".prove_membership(&key_b).is_ok()"),
            "{path} should not discard positive membership proof errors for key_b"
        );
        assert!(
            contains_normalized_source(
                contents,
                "fn assert_membership_proof<T, E: std::fmt::Debug>("
            ),
            "{path} should define a shared membership-proof assertion helper"
        );
        assert!(
            contains_normalized_source(
                contents,
                "proof.unwrap_or_else(|err| panic!(\"{context}: membership proof failed: {err:?}\"));"
            ),
            "{path} membership helper should surface the original proof error"
        );

        for context in expected_contexts {
            assert!(
                contents.contains(context),
                "{path} should keep membership assertion context `{context}`"
            );
        }
    }
}

#[test]
fn two_peer_store_sync_membership_assertions_preserve_proof_errors() {
    let two_peer_sync = include_str!("two_peer_sync.rs");

    assert!(
        !contains_normalized_source(two_peer_sync, ".prove_membership(&key_a).is_ok()"),
        "two_peer_sync.rs should not discard positive membership proof errors for key_a"
    );
    assert!(
        !contains_normalized_source(two_peer_sync, ".prove_membership(&key_b).is_ok()"),
        "two_peer_sync.rs should not discard positive membership proof errors for key_b"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "fn assert_membership_proof<T, E: std::fmt::Debug>("
        ),
        "two_peer_sync.rs should define a shared membership-proof assertion helper"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "proof.unwrap_or_else(|err| panic!(\"{context}: membership proof failed: {err:?}\"));"
        ),
        "two_peer_sync.rs membership helper should surface the original proof error"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "assert_membership_proof(store_a.prove_membership(&key_a), \"store A received only-b from B\",);"
        ),
        "two_peer_sync.rs should name the store A merged-key membership proof"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "assert_membership_proof(store_b.prove_membership(&key_b), \"store B received only-a from A\",);"
        ),
        "two_peer_sync.rs should name the store B merged-key membership proof"
    );
}

#[test]
fn two_peer_store_sync_root_assertions_preserve_store_errors() {
    let two_peer_sync = include_str!("two_peer_sync.rs");

    assert!(
        !contains_normalized_source(two_peer_sync, ".current_root().unwrap()"),
        "two_peer_sync.rs should not discard current-root extraction errors"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "fn expect_current_root<T, E: std::fmt::Debug>(root: Result<T, E>, context: &str) -> T"
        ),
        "two_peer_sync.rs should define a shared current-root expectation helper"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "root.unwrap_or_else(|err| panic!(\"{context}: current root failed: {err:?}\"))"
        ),
        "two_peer_sync.rs current-root helper should surface the original store error"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "let root_a = expect_current_root(store_a.current_root(), \"store A current root after mutual merge\",);"
        ),
        "two_peer_sync.rs should name store A root extraction context"
    );
    assert!(
        contains_normalized_source(
            two_peer_sync,
            "let root_b = expect_current_root(store_b.current_root(), \"store B current root after mutual merge\",);"
        ),
        "two_peer_sync.rs should name store B root extraction context"
    );
}

#[test]
fn two_peer_store_sync_setup_uses_named_diagnostic_helpers() {
    let two_peer_sync = include_str!("two_peer_sync.rs");

    for inline_expect in [".expect(", ".expect_err(", ".unwrap()"] {
        assert!(
            !two_peer_sync.contains(inline_expect),
            "two_peer_sync.rs should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "fn expect_two_peer_tempdir(",
        "fn expect_two_peer_store(",
        "fn expect_two_peer_agent_cap(",
        "fn expect_two_peer_remember",
        "fn expect_two_peer_store_merge",
    ] {
        assert!(
            two_peer_sync.contains(helper),
            "two_peer_sync.rs setup should define `{helper}`"
        );
    }
    for (fallible_call, expected_count) in [
        ("tempdir()", 1),
        ("Store::create(", 1),
        ("agent_cap(operator, operator.public_key_bytes())", 1),
        ("store.remember(", 1),
    ] {
        assert_eq!(
            count_normalized_source(two_peer_sync, fallible_call),
            expected_count,
            "two_peer_sync.rs should centralize `{fallible_call}` in named diagnostic helpers"
        );
    }
    assert_eq!(
        two_peer_sync
            .matches("expect_two_peer_store_merge(")
            .count(),
        2,
        "two_peer_sync.rs should define and call the named merge helper for both merge directions"
    );
    for diagnostic in [
        "two-peer tempdir failed",
        "two-peer store create failed",
        "two-peer capability creation failed",
        "two-peer remember failed",
        "two-peer merge failed",
    ] {
        assert!(
            two_peer_sync.contains(diagnostic),
            "two_peer_sync.rs diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn websocket_sync_store_locks_preserve_poison_errors() {
    for (path, contents, expected_contexts) in [
        (
            "v11_object_sync.rs",
            include_str!("v11_object_sync.rs"),
            &[
                "store lock while remembering",
                "local store during canonical v11 pull",
                "state A store after canonical v11 wire convergence",
                "state B store after canonical v11 wire convergence",
            ][..],
        ),
        (
            "two_peer_ws_sync.rs",
            include_str!("two_peer_ws_sync.rs"),
            &[
                "store lock while remembering",
                "state A store after WebSocket anti-entropy",
                "state B store after WebSocket anti-entropy",
                "state B store before plaintext recall after WebSocket sync",
                "state B store before exporting tampered wire snapshot",
                "state A store before tampered snapshot merge",
                "state A store after tampered snapshot merge",
                "state A store after incremental WebSocket anti-entropy",
                "state B store after incremental WebSocket anti-entropy",
            ][..],
        ),
    ] {
        assert!(
            !contains_normalized_source(contents, ".store.lock().unwrap()"),
            "{path} should not discard poisoned store-lock errors"
        );
        assert!(
            !contains_normalized_source(contents, ".store.lock().expect(\"lock\")"),
            "{path} should not use generic store-lock expect messages"
        );
        assert!(
            contains_normalized_source(
                contents,
                "fn expect_store_lock<T, E: std::fmt::Debug>(lock: Result<T, E>, context: &str) -> T"
            ),
            "{path} should define a shared store-lock expectation helper"
        );
        assert!(
            contains_normalized_source(
                contents,
                "lock.unwrap_or_else(|err| panic!(\"{context}: store lock failed: {err:?}\"))"
            ),
            "{path} store-lock helper should surface the poisoned-lock error"
        );

        for context in expected_contexts {
            assert!(
                contents.contains(context),
                "{path} should keep store-lock context `{context}`"
            );
        }
    }
}

#[test]
fn websocket_sync_root_assertions_preserve_store_errors() {
    for (path, contents, expected_contexts) in [
        (
            "v11_object_sync.rs",
            include_str!("v11_object_sync.rs"),
            &[
                "state A current root after canonical v11 wire convergence",
                "state B current root after canonical v11 wire convergence",
            ][..],
        ),
        (
            "two_peer_ws_sync.rs",
            include_str!("two_peer_ws_sync.rs"),
            &[
                "state A current root after WebSocket anti-entropy",
                "state B current root after WebSocket anti-entropy",
                "state A current root after incremental WebSocket anti-entropy",
                "state B current root after incremental WebSocket anti-entropy",
            ][..],
        ),
    ] {
        assert!(
            !contains_normalized_source(contents, ".current_root().unwrap()"),
            "{path} should not discard current-root extraction errors"
        );
        assert!(
            contains_normalized_source(
                contents,
                "fn expect_current_root<T, E: std::fmt::Debug>(root: Result<T, E>, context: &str) -> T"
            ),
            "{path} should define a shared current-root expectation helper"
        );
        assert!(
            contains_normalized_source(
                contents,
                "root.unwrap_or_else(|err| panic!(\"{context}: current root failed: {err:?}\"))"
            ),
            "{path} current-root helper should surface the original store error"
        );

        for context in expected_contexts {
            assert!(
                contents.contains(context),
                "{path} should keep current-root context `{context}`"
            );
        }
    }
}

#[test]
fn websocket_sync_server_configs_use_named_loopback_addr_fixture() {
    for (path, contents) in [
        ("v11_object_sync.rs", include_str!("v11_object_sync.rs")),
        ("two_peer_ws_sync.rs", include_str!("two_peer_ws_sync.rs")),
    ] {
        assert!(
            !contents.contains("\"127.0.0.1:0\".parse().unwrap()"),
            "{path} should not parse the test HTTP listen address inline"
        );
        assert!(
            contains_normalized_source(contents, "fn test_loopback_addr() -> std::net::SocketAddr"),
            "{path} should define a named loopback listen address fixture"
        );
        assert!(
            contains_normalized_source(contents, "http_addr: test_loopback_addr(),"),
            "{path} ServerConfig should use the named loopback address fixture"
        );
    }
}

#[test]
fn unix_connection_task_join_failures_are_not_only_logged() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        contains_normalized_source(
            unix,
            "fn observe_connection_result(joined: Option<Result<Result<(), std::io::Error>, tokio::task::JoinError>>,) -> Result<(), std::io::Error>"
        ),
        "Unix connection join observation must be a result-returning contract"
    );
    assert!(
        unix.contains("connection task panicked"),
        "Unix connection task panics must surface as server errors"
    );
    assert!(
        unix.contains("is_cancelled()"),
        "Unix shutdown cleanup must distinguish expected aborted connection tasks"
    );
    assert!(
        !unix.contains("tracing::debug!(\"unix kernel connection task join failed"),
        "Unix connection join failures must not be only debug-logged"
    );
}

#[test]
fn unix_framing_error_writes_are_classified() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        !unix.contains("let _ = write_kernel_err("),
        "Unix framing-error response writes must be classified, not discarded"
    );
    assert!(
        unix.contains("enum KernelErrWriteOutcome"),
        "Unix kernel error writes should expose sent/failed outcomes"
    );
    assert!(
        unix.contains("fn classify_kernel_err_write_result("),
        "Unix kernel error write results should be classified through a named helper"
    );
    assert!(
        unix.contains("async fn write_framing_error_response("),
        "Unix framing-error responses should use a named write helper"
    );
}

#[test]
fn unix_response_serialization_is_checked() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        !unix.contains("unwrap_or_default()"),
        "Unix response serialization must not silently fall back to empty frames"
    );
    assert!(
        unix.contains("fn encode_kernel_response("),
        "Unix response serialization should use a named checked helper"
    );
    assert_eq!(
        unix.matches("let out = encode_kernel_response(&").count(),
        2,
        "Unix error and dispatch response writes should both use checked serialization"
    );
}

#[test]
fn unix_unit_tests_use_named_diagnostic_helpers() {
    let unix = include_str!("../src/unix.rs");

    for inline_expect in [
        ".expect_err(\"connection task panic must fail the Unix server\")",
        ".expect(\"per-connection I/O errors should not fail the Unix server\")",
        ".expect(\"encode error response\")",
        ".expect(\"encode ok response\")",
        ".expect(\"utf8 response\")",
        ".expect(\"shutdown-aborted connection tasks should not fail the Unix server\")",
    ] {
        assert!(
            !unix.contains(inline_expect),
            "Unix unit tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_unix_connection_result_error(",
        "fn expect_unix_connection_result_success(",
        "fn expect_encoded_kernel_response(",
        "fn expect_kernel_response_text(",
    ] {
        assert!(
            unix.contains(helper),
            "Unix unit tests should define `{helper}`"
        );
    }

    for diagnostic in [
        "expected Unix connection result failure",
        "Unix connection result unexpectedly failed",
        "Unix kernel response encoding failed",
        "Unix kernel response UTF-8 decode failed",
    ] {
        assert!(
            unix.contains(diagnostic),
            "Unix unit test helpers should preserve `{diagnostic}` context"
        );
    }
}

#[test]
fn unix_kernel_dispatch_failures_are_classified_not_schema_drift_collapsed() {
    let unix = include_str!("../src/unix.rs");

    for (marker, end_marker, context) in [
        (
            "fn validate_logical_key(",
            "fn head(",
            "validate_logical_key",
        ),
        ("fn head(", "fn remember(", "head"),
        ("fn remember(", "fn recall(", "remember"),
        ("fn recall(", "fn forget(", "recall"),
        ("fn forget(", "fn prove_absent(", "forget"),
        ("fn prove_absent(", "fn sync_frame(", "prove_absent"),
        ("fn sync_frame(", "#[cfg(test)]", "sync_frame"),
    ] {
        let section = source_between_markers(unix, marker, end_marker, context);
        assert!(
            !section.contains("map_err(|_| MnemeError::SchemaDrift)"),
            "Unix kernel `{context}` should route fallible local operations through typed helpers"
        );
        assert!(
            !section.contains("return Err(MnemeError::SchemaDrift)"),
            "Unix kernel `{context}` should not return bare SchemaDrift for local validation"
        );
    }

    for required in [
        "enum UnixKernelFailure",
        "fn unix_kernel_failure_to_mneme(",
        "fn invalid_logical_key_error(",
        "fn decode_unix_body_b64(",
        "fn decode_unix_sync_frame_b64(",
        "fn lock_unix_store",
        "UnixKernelFailure::InvalidLogicalKey",
        "UnixKernelFailure::BodyBase64Decode",
        "UnixKernelFailure::SyncFrameBase64Decode",
        "UnixKernelFailure::StoreUnavailable",
    ] {
        assert!(
            unix.contains(required),
            "Unix kernel dispatch failure classification should include `{required}`"
        );
    }
}

#[test]
fn context_gate_decode_failures_are_classified_not_schema_drift_collapsed() {
    let context_gate = include_str!("../src/context_gate.rs");

    for (marker, end_marker, context) in [
        (
            "pub fn decode_cca_b64(",
            "pub fn decode_output_binding_b64(",
            "decode_cca_b64",
        ),
        (
            "pub fn decode_output_binding_b64(",
            "pub const HEADER_CONTEXT_ATTESTATION",
            "decode_output_binding_b64",
        ),
        (
            "pub fn recall_verified_context_gated_from_b64(",
            "#[cfg(test)]",
            "recall_verified_context_gated_from_b64",
        ),
    ] {
        let section = source_between_markers(context_gate, marker, end_marker, context);
        assert!(
            !section.contains("map_err(|_| MnemeError::SchemaDrift)"),
            "context-gate `{context}` should route local decode failures through typed helpers"
        );
    }

    for required in [
        "enum ContextGateDecodeFailure",
        "fn context_gate_decode_failure_to_mneme(",
        "fn decode_context_attestation_b64_bytes(",
        "fn decode_output_binding_b64_bytes(",
        "fn decode_context_embedding_b64_bytes(",
        "fn decode_context_model_output_b64_bytes(",
        "fn decode_context_model_identity_b64(",
        "ContextGateDecodeFailure::ContextAttestationBase64",
        "ContextGateDecodeFailure::OutputBindingBase64",
        "ContextGateDecodeFailure::EmbeddingBase64",
        "ContextGateDecodeFailure::ModelOutputBase64",
        "ContextGateDecodeFailure::ModelIdentityBase64",
        "ContextGateDecodeFailure::ModelIdentityLength",
    ] {
        assert!(
            context_gate.contains(required),
            "context-gate decode classification should include `{required}`"
        );
    }
}

#[test]
fn store_layout_parse_failures_are_classified_not_schema_drift_collapsed() {
    let layout = include_str!("../../mneme-store/src/layout.rs");

    for (marker, end_marker, context) in [
        (
            "fn load_object_keys(",
            "pub fn load_state(",
            "load_object_keys",
        ),
        (
            "fn load_embeddings(",
            "fn load_key_index(",
            "load_embeddings",
        ),
        (
            "fn load_key_index(",
            "fn append_key_index_journal_entry(",
            "load_key_index",
        ),
        (
            "fn apply_key_index_journal(",
            "fn sync_parent_dir(",
            "apply_key_index_journal",
        ),
        (
            "fn apply_sidecar(",
            "fn walk_objects(",
            "apply_sidecar decode_hex32",
        ),
    ] {
        let section = source_between_markers(layout, marker, end_marker, context);
        assert!(
            !section.contains("map_err(|_| MnemeError::SchemaDrift)"),
            "store layout `{context}` should route parse failures through typed helpers"
        );
        assert!(
            !section.contains("return Err(MnemeError::SchemaDrift)"),
            "store layout `{context}` should not return bare SchemaDrift for local parsing"
        );
    }

    for required in [
        "enum LayoutParseFailure",
        "fn layout_parse_failure_to_mneme(",
        "fn layout_json_parse_error(",
        "fn layout_embedding_shape_error(",
        "fn layout_duplicate_object_error(",
        "decode_hex32(",
        "LayoutParseFailure::ObjectKeysSidecarJson",
        "LayoutParseFailure::ObjectKeysJournalJson",
        "LayoutParseFailure::EmbeddingSidecarJson",
        "LayoutParseFailure::EmbeddingShape",
        "LayoutParseFailure::EmbeddingJournalJson",
        "LayoutParseFailure::DuplicateObject",
    ] {
        assert!(
            layout.contains(required),
            "store layout parse classification should include `{required}`"
        );
    }
}

#[test]
fn store_kernel_schema_failures_are_classified_not_schema_drift_collapsed() {
    let store = include_str!("../../mneme-store/src/lib.rs");
    let verify_store = include_str!("../../mneme-verify/src/store.rs");
    let dag = include_str!("../../mneme-dag/src/lib.rs");

    for (source, marker, end_marker, context) in [
        (
            store,
            "fn decrypt_entries(",
            "pub(crate) fn rebuild_semantic_index(",
            "store decrypt_entries",
        ),
        (
            store,
            "pub fn bench_embedding(",
            "fn provenance_objects_for_bytes(",
            "store bench_embedding",
        ),
        (
            dag,
            "pub fn load_content_addressed_objects(",
            "fn walk_objects(",
            "dag load_content_addressed_objects",
        ),
    ] {
        let section = source_between_markers(source, marker, end_marker, context);
        for direct_schema_drift in [
            "ok_or(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(direct_schema_drift),
                "`{context}` should route `{direct_schema_drift}` through a named fail-closed classifier"
            );
        }
    }

    for required in [
        "enum StoreLocalSchemaFailure",
        "fn store_local_schema_failure_to_mneme(",
        "fn missing_object_key_error(",
        "fn bench_embedding_dimension_error(",
        "StoreLocalSchemaFailure::MissingObjectKey",
        "StoreLocalSchemaFailure::BenchEmbeddingZeroDimension",
    ] {
        assert!(
            store.contains(required),
            "store kernel schema-failure classification should include `{required}`"
        );
    }

    let verify_store_body = source_between_markers(
        verify_store,
        "pub fn verify_store(",
        "fn read_head(",
        "verify_store body",
    );
    assert!(
        verify_store_body.contains("load_content_addressed_objects(path)?"),
        "verify_store should delegate object filename/path parsing to the shared DAG loader"
    );
    assert!(
        !verify_store_body.contains("decode_hex32(")
            && !verify_store_body.contains("MnemeError::SchemaDrift"),
        "verify_store should not inline object filename parsing or collapse it directly"
    );

    let dag_loader = source_between_markers(
        dag,
        "pub fn load_content_addressed_objects(",
        "fn io_err(",
        "dag loader",
    );
    assert!(
        dag_loader.contains("decode_content_addressed_object_path(objects_dir, &path)?"),
        "content-addressed object loading should use the canonical object path parser"
    );

    let load_error_sites = source_top_level_item_after_marker(
        verify_store,
        "fn load_previous_root(",
        "verify_store load_previous_root",
    );
    assert!(
        !load_error_sites.contains("MnemeError::SchemaDrift"),
        "verify_store local load helpers should not add a bare SchemaDrift bypass"
    );
}

#[test]
fn unix_api_tests_do_not_use_long_sleep_as_io_signal() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("tokio::time::sleep(Duration::from_millis(120))"),
        "Unix API silent-client timeout tests should wait on socket closure, not a long sleep"
    );
    assert!(
        !unix_api_tests.contains("tokio::time::sleep(Duration::from_millis(200))"),
        "Unix API stalled-peer tests should wait on client timeout/peer closure, not a long sleep"
    );
    assert!(
        !contains_normalized_source(
            unix_api_tests,
            "tokio::time::sleep(Duration::from_millis(20)).await; let _ = shutdown_tx.send(());"
        ),
        "Unix API startup-failure tests should await the failing server task directly, not sleep before shutdown"
    );
    assert!(
        !unix_api_tests.contains("tokio::time::sleep(Duration::from_millis(20))"),
        "Unix API zero-timeout tests should use explicit handshakes, not short wall-clock sleeps"
    );
}

#[test]
fn unix_api_connection_close_reporting_uses_named_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let assert_helper = source_between_markers(
        unix_api_tests,
        "fn assert_connection_closed_error(",
        "fn expect_connection_closed_error(",
        "assert_connection_closed_error body",
    );

    assert!(
        !assert_helper.contains("unwrap_or_else(|message| panic!"),
        "Unix API connection-close assertion should route inline panic reporting through a named helper"
    );
    assert!(
        unix_api_tests.contains("type ConnectionClosedErrorCheck = Result<(), String>"),
        "Unix API connection-close checks should name the validation result type"
    );
    assert!(
        unix_api_tests.contains("fn assert_connection_closed_check_passed("),
        "Unix API connection-close assertion should use a named reporting helper"
    );
    assert!(
        contains_normalized_source(
            unix_api_tests,
            "fn expect_connection_closed_error(err: &std::io::Error, context: &str,) -> ConnectionClosedErrorCheck"
        ),
        "Unix API connection-close validation should return the named result type"
    );
    assert!(
        assert_helper
            .contains("let connection_closed = expect_connection_closed_error(err, context);"),
        "Unix API connection-close assertion should keep validation separate from reporting"
    );
    assert!(
        assert_helper.contains("assert_connection_closed_check_passed(connection_closed);"),
        "Unix API connection-close assertion should call the named reporting helper"
    );
}

#[test]
fn unix_api_response_code_assertions_use_named_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let schema_drift_helper = source_between_markers(
        unix_api_tests,
        "fn assert_schema_drift(",
        "fn assert_cap_denied(",
        "assert_schema_drift body",
    );
    let cap_denied_helper = source_between_markers(
        unix_api_tests,
        "fn assert_cap_denied(",
        "fn assert_connection_closed_error(",
        "assert_cap_denied body",
    );

    for (helper, context) in [
        (schema_drift_helper, "assert_schema_drift"),
        (cap_denied_helper, "assert_cap_denied"),
    ] {
        assert!(
            !helper.contains("KernelResponse::Ok { payload } => panic!"),
            "Unix API {context} should not duplicate unexpected-success panic reporting"
        );
        assert!(
            !helper.contains("assert_eq!(code,"),
            "Unix API {context} should delegate response-code comparison to the shared helper"
        );
    }
    assert!(
        unix_api_tests.contains("type KernelResponseCodeCheck = Result<(), String>"),
        "Unix API response-code checks should name the validation result type"
    );
    assert!(
        unix_api_tests.contains("fn assert_kernel_response_error_code("),
        "Unix API response-code assertions should use a named shared assertion helper"
    );
    assert!(
        unix_api_tests.contains("fn expect_kernel_response_error_code("),
        "Unix API response-code validation should use a named expectation helper"
    );
    assert!(
        unix_api_tests.contains("fn assert_kernel_response_code_check_passed("),
        "Unix API response-code assertion failures should route through a named reporting helper"
    );
    let shared_assertion = source_between_markers(
        unix_api_tests,
        "fn assert_kernel_response_error_code(",
        "fn expect_kernel_response_error_code(",
        "assert_kernel_response_error_code body",
    );

    assert!(
        schema_drift_helper
            .contains("assert_kernel_response_error_code(resp, \"SchemaDrift\", context);"),
        "Unix API schema-drift assertion should delegate expected-code checking"
    );
    assert!(
        cap_denied_helper
            .contains("assert_kernel_response_error_code(resp, \"CapDenied\", context);"),
        "Unix API cap-denied assertion should delegate expected-code checking"
    );
    assert!(
        shared_assertion.contains(
            "let response_code = expect_kernel_response_error_code(resp, expected_code, context);"
        ),
        "Unix API shared response-code assertion should separate validation from reporting"
    );
    assert!(
        shared_assertion.contains("assert_kernel_response_code_check_passed(response_code);"),
        "Unix API shared response-code assertion should call the named reporting helper"
    );
}

#[test]
fn unix_api_cap_denied_tests_use_shared_assertion() {
    let unix_api_tests = include_str!("unix_api.rs");
    let cap_denied_tests = [
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_server_zero_timeout_uses_default_deadline()",
                "unix_server_zero_timeout_uses_default_deadline body",
            ),
            "zero-timeout invalid-capability test",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_sync_frame_requires_capability()",
                "unix_sync_frame_requires_capability body",
            ),
            "sync-frame missing-capability test",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_prove_absent_requires_capability()",
                "unix_prove_absent_requires_capability body",
            ),
            "prove-absent missing-capability test",
        ),
    ];

    for (test_body, context) in cap_denied_tests {
        assert!(
            !test_body.contains("assert_eq!(code, \"CapDenied\")"),
            "Unix API {context} should route CapDenied checks through assert_cap_denied"
        );
        assert!(
            !test_body.contains("KernelResponse::Ok { payload } =>"),
            "Unix API {context} should route unexpected-success reporting through assert_cap_denied"
        );
        assert!(
            contains_normalized_source(test_body, "assert_cap_denied(resp,"),
            "Unix API {context} should call the shared CapDenied assertion helper"
        );
    }
}

#[test]
fn unix_api_head_capability_rejection_tests_use_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let head_capability_tests = [
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_head_rejects_malformed_decoded_capability_as_cap_denied()",
                "unix_head_rejects_malformed_decoded_capability_as_cap_denied body",
            ),
            "malformed head capability",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_head_rejects_oversized_capability_as_cap_denied()",
                "unix_head_rejects_oversized_capability_as_cap_denied body",
            ),
            "oversized head capability",
        ),
    ];

    for (test_body, context) in head_capability_tests {
        for inline_expect in [
            "tempdir().expect(\"tempdir\")",
            "test_state(dir.path()).expect(\"test_state\")",
            ".expect(\"head\")",
        ] {
            assert!(
                !test_body.contains(inline_expect),
                "Unix API {context} test should route `{inline_expect}` through named diagnostic helpers"
            );
        }
        assert!(
            contains_normalized_source(test_body, "let dir = expect_unix_api_tempdir("),
            "Unix API {context} test should create tempdirs through the named helper"
        );
        assert!(
            contains_normalized_source(test_body, "let state = expect_unix_api_state("),
            "Unix API {context} test should create state through the named helper"
        );
        assert!(
            contains_normalized_source(test_body, "let resp = expect_request_json_response("),
            "Unix API {context} test should issue Head requests through the named helper"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_unix_api_state(",
        "async fn expect_request_json_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API head capability rejection diagnostics should define `{helper}`"
        );
    }

    for diagnostic in [
        "Unix API tempdir failed",
        "Unix API test state failed",
        "request-json request failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API head capability rejection diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_prove_absent_requires_capability_uses_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let prove_absent_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn unix_prove_absent_requires_capability()",
        "unix_prove_absent_requires_capability body",
    );

    for inline_expect in [
        "tempdir().expect(\"tempdir\")",
        "test_state(dir.path()).expect(\"test_state\")",
        ".expect(\"prove absent\")",
    ] {
        assert!(
            !prove_absent_test.contains(inline_expect),
            "Unix API prove-absent missing-capability test should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper_call in [
        "let dir = expect_unix_api_tempdir(\"prove-absent missing capability\");",
        "let state = expect_unix_api_state(dir.path(), \"prove-absent missing capability\");",
        "let resp = expect_request_json_response(",
    ] {
        assert!(
            contains_normalized_source(prove_absent_test, helper_call),
            "Unix API prove-absent missing-capability test should call `{helper_call}`"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_unix_api_state(",
        "async fn expect_request_json_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API prove-absent missing-capability diagnostics should define `{helper}`"
        );
    }

    for diagnostic in [
        "Unix API tempdir failed",
        "Unix API test state failed",
        "request-json request failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API prove-absent missing-capability diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_delayed_response_test_uses_shared_code_assertion() {
    let unix_api_tests = include_str!("unix_api.rs");
    let zero_timeout_client_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn request_json_zero_timeout_uses_default_deadline()",
        "request_json_zero_timeout_uses_default_deadline body",
    );

    assert!(
        !zero_timeout_client_test.contains("assert_eq!(code, \"delayed\")"),
        "Unix API zero-timeout client test should route delayed response-code checks through the shared helper"
    );
    assert!(
        !zero_timeout_client_test.contains("KernelResponse::Ok { payload } =>"),
        "Unix API zero-timeout client test should route unexpected-success reporting through the shared helper"
    );
    assert!(
        contains_normalized_source(
            zero_timeout_client_test,
            "assert_kernel_response_error_code(resp, \"delayed\", \"zero-timeout delayed response\");"
        ),
        "Unix API zero-timeout client test should call the shared response-code assertion helper"
    );
}

#[test]
fn unix_api_success_response_payloads_use_named_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let success_response_tests = [
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_remember_and_head_roundtrip()",
                "unix_remember_and_head_roundtrip body",
            ),
            "remember/head roundtrip",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn daemon_start_serves_configured_unix_socket()",
                "daemon_start_serves_configured_unix_socket body",
            ),
            "daemon Unix head",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_sync_hello_returns_root_proof()",
                "unix_sync_hello_returns_root_proof body",
            ),
            "sync hello",
        ),
    ];

    for (test_body, context) in success_response_tests {
        assert!(
            !test_body.contains("KernelResponse::Err { message, .. } => panic!"),
            "Unix API {context} should route response failure-message reporting through a named helper"
        );
        assert!(
            !test_body.contains("KernelResponse::Ok { payload } =>"),
            "Unix API {context} should route response payload extraction through a named helper"
        );
        assert!(
            test_body.contains("expect_kernel_response_payload("),
            "Unix API {context} should extract success payloads through the named helper"
        );
    }
    assert!(
        unix_api_tests
            .contains("type KernelResponsePayloadCheck = Result<serde_json::Value, String>"),
        "Unix API success-response checks should name the payload validation result type"
    );
    assert!(
        unix_api_tests.contains("fn expect_kernel_response_payload("),
        "Unix API success-response checks should use a named payload extraction helper"
    );
    assert!(
        unix_api_tests.contains("fn validate_kernel_response_payload("),
        "Unix API success-response checks should use a named payload validation helper"
    );
    assert!(
        unix_api_tests.contains("fn expect_kernel_response_payload_check_passed("),
        "Unix API success-response failure messages should route through a named reporting helper"
    );
}

#[test]
fn unix_api_remember_head_roundtrip_uses_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let remember_head_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn unix_remember_and_head_roundtrip()",
        "unix_remember_and_head_roundtrip body",
    );

    for inline_expect in [
        "tempdir().expect(\"tempdir\")",
        "test_state(dir.path()).expect(\"test_state\")",
        "agent_cap(&operator, agent.public_key_bytes()).expect(\"cap\")",
        "cap_to_b64(&cap).expect(\"cap b64\")",
        "state.store.lock().expect(\"lock\")",
        ".expect(\"connect\")",
        ".expect(\"head\")",
    ] {
        assert!(
            !remember_head_test.contains(inline_expect),
            "Unix API remember/head roundtrip should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "type UnixApiStateWithKeys = (mnemed::AppState, KeyPair, KeyPair)",
        "fn expect_unix_api_state_with_keys(",
        "fn expect_unix_agent_cap_b64(",
        "fn authorize_unix_api_writer(",
        "async fn expect_request_json_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API remember/head roundtrip diagnostics should define `{helper}`"
        );
    }

    for helper_call in [
        "let (state, operator, agent) =
            expect_unix_api_state_with_keys(dir.path(), \"remember/head roundtrip\");",
        "let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, \"remember/head roundtrip\");",
        "authorize_unix_api_writer(&state, &agent, \"remember/head roundtrip\");",
        "let remember = expect_request_json_response(",
        "let head = expect_request_json_response(",
    ] {
        assert!(
            contains_normalized_source(remember_head_test, helper_call),
            "Unix API remember/head roundtrip should call `{helper_call}`"
        );
    }

    for diagnostic in [
        "Unix API state with keys failed",
        "Unix API agent capability failed",
        "Unix API capability encoding failed",
        "Unix API store lock failed",
        "request-json request failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API remember/head roundtrip diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_key_scoped_and_sync_tests_use_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let key_scoped_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn unix_key_scoped_requests_reject_empty_logical_key()",
        "unix_key_scoped_requests_reject_empty_logical_key body",
    );
    let sync_hello_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn unix_sync_hello_returns_root_proof()",
        "unix_sync_hello_returns_root_proof body",
    );
    let sync_cap_denied_tests = [
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_sync_frame_requires_capability()",
                "unix_sync_frame_requires_capability body",
            ),
            "sync frame without capability",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_sync_frame_rejects_malformed_decoded_capability_as_cap_denied()",
                "unix_sync_frame_rejects_malformed_decoded_capability_as_cap_denied body",
            ),
            "malformed sync capability",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_sync_frame_rejects_oversized_capability_as_cap_denied()",
                "unix_sync_frame_rejects_oversized_capability_as_cap_denied body",
            ),
            "oversized sync capability",
        ),
    ];

    for inline_expect in [
        "tempdir().expect(\"tempdir\")",
        "test_state(dir.path()).expect(\"test_state\")",
        "agent_cap(&operator, agent.public_key_bytes()).expect(\"cap\")",
        "cap_to_b64(&cap).expect(\"cap b64\")",
        "state.store.lock().expect(\"lock\")",
        ".expect(\"remember request\")",
        ".expect(\"recall request\")",
        ".expect(\"forget request\")",
        ".expect(\"prove-absent request\")",
    ] {
        assert!(
            !key_scoped_test.contains(inline_expect),
            "Unix API key-scoped empty-key test should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper_call in [
        "let dir = expect_unix_api_tempdir(\"key-scoped empty logical key\");",
        "let (state, operator, agent) =
            expect_unix_api_state_with_keys(dir.path(), \"key-scoped empty logical key\");",
        "let cap_b64 =
            expect_unix_agent_cap_b64(&operator, &agent, \"key-scoped empty logical key\");",
        "authorize_unix_api_writer(&state, &agent, \"key-scoped empty logical key\");",
        "let remember = expect_request_json_response(",
        "let recall = expect_request_json_response(",
        "let forget = expect_request_json_response(",
        "let prove_absent = expect_request_json_response(",
    ] {
        assert!(
            contains_normalized_source(key_scoped_test, helper_call),
            "Unix API key-scoped empty-key test should call `{helper_call}`"
        );
    }

    for (test_body, context) in
        std::iter::once((sync_hello_test, "sync hello")).chain(sync_cap_denied_tests.into_iter())
    {
        for inline_expect in [
            "tempdir().expect(\"tempdir\")",
            "test_state(dir.path()).expect(\"test_state\")",
            "encode_sync_message(&hello).expect(\"encode\")",
            ".expect(\"sync\")",
            "SyncMessage::Hello {",
            "NodeId([0x01; 16])",
        ] {
            assert!(
                !test_body.contains(inline_expect),
                "Unix API {context} test should route `{inline_expect}` through named diagnostic helpers"
            );
        }
        assert!(
            contains_normalized_source(test_body, "let dir = expect_unix_api_tempdir("),
            "Unix API {context} test should create tempdirs through the named helper"
        );
        assert!(
            contains_normalized_source(
                test_body,
                "let sync_request = expect_unix_sync_frame_request("
            ),
            "Unix API {context} test should construct SyncFrame requests through the named helper"
        );
        assert!(
            contains_normalized_source(test_body, "let resp = expect_request_json_response("),
            "Unix API {context} test should issue SyncFrame requests through the named request helper"
        );
    }

    for inline_expect in [
        "agent_cap(&operator, agent.public_key_bytes()).expect(\"cap\")",
        "cap_to_b64(&cap).expect(\"cap b64\")",
    ] {
        assert!(
            !sync_hello_test.contains(inline_expect),
            "Unix API sync hello test should route `{inline_expect}` through named capability helpers"
        );
    }
    assert!(
        contains_normalized_source(
            sync_hello_test,
            "let (state, operator, agent) =
            expect_unix_api_state_with_keys(dir.path(), \"sync hello\");"
        ),
        "Unix API sync hello test should create state/keys through the named helper"
    );
    assert!(
        contains_normalized_source(
            sync_hello_test,
            "let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, \"sync hello\");"
        ),
        "Unix API sync hello test should encode the capability through the named helper"
    );

    for (test_body, context) in sync_cap_denied_tests {
        assert!(
            contains_normalized_source(test_body, "let state = expect_unix_api_state("),
            "Unix API {context} test should create state through the named helper"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_unix_api_state(",
        "fn expect_unix_api_state_with_keys(",
        "fn expect_unix_agent_cap_b64(",
        "fn authorize_unix_api_writer(",
        "fn expect_unix_sync_hello_bytes_b64(",
        "fn expect_unix_sync_frame_request(",
        "async fn expect_request_json_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API key/sync diagnostics should define `{helper}`"
        );
    }

    for diagnostic in [
        "Unix API tempdir failed",
        "Unix API test state failed",
        "Unix API state with keys failed",
        "Unix API agent capability failed",
        "Unix API capability encoding failed",
        "Unix API store lock failed",
        "Unix sync hello encode failed",
        "request-json request failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API key/sync diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_daemon_start_success_uses_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let daemon_start_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn daemon_start_serves_configured_unix_socket()",
        "daemon_start_serves_configured_unix_socket body",
    );

    for inline_expect in [
        "tempdir().expect(\"tempdir\")",
        "test_state(dir.path()).expect(\"test_state\")",
        "agent_cap(&operator, agent.public_key_bytes()).expect(\"cap\")",
        "cap_to_b64(&cap).expect(\"cap b64\")",
        "\"127.0.0.1:0\".parse().expect(\"http addr\")",
        ".expect(\"start daemon\")",
        ".expect(\"unix head\")",
    ] {
        assert!(
            !daemon_start_test.contains(inline_expect),
            "Unix API daemon start success test should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "type UnixApiStateWithKeys = (mnemed::AppState, KeyPair, KeyPair)",
        "fn expect_unix_api_state_with_keys(",
        "fn expect_unix_agent_cap_b64(",
        "fn expect_daemon_loopback_http_addr(",
        "async fn expect_daemon_start_with_unix_socket(",
        "async fn expect_request_json_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API daemon start success diagnostics should define `{helper}`"
        );
    }

    for helper_call in [
        "let dir = expect_unix_api_tempdir(\"daemon configured Unix socket\");",
        "let (state, operator, agent) =
            expect_unix_api_state_with_keys(dir.path(), \"daemon configured Unix socket\");",
        "let cap_b64 =
            expect_unix_agent_cap_b64(&operator, &agent, \"daemon configured Unix socket\");",
        "let server =
            expect_daemon_start_with_unix_socket(&sock, state, \"daemon configured Unix socket\")
                .await;",
        "let head = expect_request_json_response(",
    ] {
        assert!(
            contains_normalized_source(daemon_start_test, helper_call),
            "Unix API daemon start success test should call `{helper_call}`"
        );
    }

    for diagnostic in [
        "daemon loopback HTTP address parse failed",
        "daemon Unix socket start failed",
        "request-json request failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API daemon start success diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_fake_peer_tasks_return_typed_results() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("server.await.expect(\"server task\");"),
        "Unix API fake-peer tasks should assert typed task results instead of bare joins"
    );
    assert!(
        unix_api_tests.contains("type FakeUnixPeerResult = Result<(), String>"),
        "Unix API fake-peer tasks should share a typed peer-result contract"
    );
    assert!(
        unix_api_tests.contains("expect_fake_unix_peer(server,"),
        "Unix API tests should route fake-peer joins through the shared typed assertion helper"
    );
}

#[test]
fn unix_api_fake_peer_join_reporting_uses_named_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let join_helper = source_between_markers(
        unix_api_tests,
        "async fn expect_fake_unix_peer(",
        "async fn accept_fake_unix_peer(",
        "expect_fake_unix_peer body",
    );

    assert!(
        !join_helper.contains("unwrap_or_else(|err| panic!"),
        "Unix API fake-peer join helper should route inline panic closures through named reporting helpers"
    );
    assert!(
        unix_api_tests
            .contains("type FakeUnixPeerJoin = Result<FakeUnixPeerResult, tokio::task::JoinError>"),
        "Unix API fake-peer joins should name the raw JoinHandle result type"
    );
    assert!(
        unix_api_tests.contains("async fn observe_fake_unix_peer_join("),
        "Unix API fake-peer join observation should be named"
    );
    assert!(
        unix_api_tests.contains("fn expect_joined_fake_unix_peer_task("),
        "Unix API fake-peer JoinError reporting should be named"
    );
    assert!(
        unix_api_tests.contains("fn expect_successful_fake_unix_peer_result("),
        "Unix API fake-peer typed task-result reporting should be named"
    );
    assert!(
        join_helper.contains("observe_fake_unix_peer_join(handle).await"),
        "Unix API fake-peer join helper should call the named join observer"
    );
    assert!(
        join_helper.contains("expect_joined_fake_unix_peer_task(joined, context)"),
        "Unix API fake-peer join helper should call the named JoinError reporter"
    );
    assert!(
        join_helper.contains("expect_successful_fake_unix_peer_result(task_result, context)"),
        "Unix API fake-peer join helper should call the named task-result reporter"
    );
}

#[test]
fn unix_api_fake_peer_accepts_are_bounded() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !contains_normalized_source(unix_api_tests, "listener.accept().await"),
        "Unix API fake peers should not wait forever in bare listener.accept().await calls"
    );
    assert!(
        unix_api_tests.contains("const FAKE_UNIX_PEER_ACCEPT_TIMEOUT: Duration"),
        "Unix API fake peers should share a bounded accept timeout"
    );
    assert!(
        unix_api_tests.contains("async fn accept_fake_unix_peer("),
        "Unix API fake peers should share a named accept helper"
    );
    assert!(
        unix_api_tests.contains("accept_fake_unix_peer_stream_with_timeout(listener).await"),
        "Unix API fake peer accepts should route listener accepts through the shared timeout helper"
    );
    assert_eq!(
        unix_api_tests
            .matches("accept_fake_unix_peer(listener,")
            .count(),
        3,
        "all Unix API fake peers should route listener accepts through the shared helper"
    );
}

#[test]
fn unix_api_fake_peer_accept_policy_uses_named_timeout_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let accept_helper = source_between_markers(
        unix_api_tests,
        "async fn accept_fake_unix_peer(",
        "async fn accept_fake_unix_peer_stream_with_timeout(",
        "accept_fake_unix_peer body",
    );

    assert!(
        !accept_helper
            .contains("tokio::time::timeout(FAKE_UNIX_PEER_ACCEPT_TIMEOUT, listener.accept())"),
        "Unix API fake-peer accept helper should route listener.accept through a named timeout helper"
    );
    assert!(
        unix_api_tests.contains("async fn accept_fake_unix_peer_stream_with_timeout("),
        "Unix API fake-peer accept timeout policy should have a named helper"
    );
    assert!(
        accept_helper.contains("accept_fake_unix_peer_stream_with_timeout(listener).await"),
        "Unix API fake-peer accept helper should call the named timeout helper"
    );
}

#[test]
fn unix_api_fake_peer_request_reads_are_bounded() {
    let unix_api_tests = include_str!("unix_api.rs");
    let request_reader = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_request(",
        "async fn assert_silent_client_connection_close(",
        "read_fake_unix_request body",
    );

    assert!(
        !contains_normalized_source(request_reader, "stream.read_exact(&mut len_buf).await"),
        "Unix API fake peers should not wait forever reading request lengths"
    );
    assert!(
        !contains_normalized_source(request_reader, "stream.read_exact(&mut req_buf).await"),
        "Unix API fake peers should not wait forever reading request bodies"
    );
    assert!(
        unix_api_tests.contains("const FAKE_UNIX_PEER_REQUEST_TIMEOUT: Duration"),
        "Unix API fake peers should share a bounded request-read timeout"
    );
    assert!(
        unix_api_tests.contains("async fn read_fake_unix_request_exact("),
        "Unix API fake peers should share a named exact-read helper"
    );
    assert!(
        unix_api_tests.contains("read_fake_unix_request_exact_with_timeout(stream, buf).await"),
        "Unix API fake peer request reads should route read_exact through the shared timeout helper"
    );
    assert!(
        unix_api_tests.contains(
            "read_fake_unix_request_exact(stream, &mut len_buf, context, \"length\").await",
        ),
        "Unix API fake peer request length reads should use the timeout helper"
    );
    assert!(
        unix_api_tests.contains(
            "read_fake_unix_request_exact(stream, &mut req_buf, context, \"body\").await",
        ),
        "Unix API fake peer request body reads should use the timeout helper"
    );
}

#[test]
fn unix_api_fake_peer_request_read_policy_uses_named_timeout_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let exact_reader = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_request_exact(",
        "async fn read_fake_unix_request_exact_with_timeout(",
        "read_fake_unix_request_exact body",
    );

    assert!(
        !exact_reader.contains(
            "tokio::time::timeout(FAKE_UNIX_PEER_REQUEST_TIMEOUT, stream.read_exact(buf))"
        ),
        "Unix API fake-peer exact-read helper should route read_exact through a named timeout helper"
    );
    assert!(
        unix_api_tests.contains("async fn read_fake_unix_request_exact_with_timeout("),
        "Unix API fake-peer request-read timeout policy should have a named helper"
    );
    assert!(
        exact_reader.contains("read_fake_unix_request_exact_with_timeout(stream, buf).await"),
        "Unix API fake-peer exact-read helper should call the named timeout helper"
    );
}

#[test]
fn unix_api_fake_peer_timeout_helpers_return_classified_outcomes() {
    let unix_api_tests = include_str!("unix_api.rs");
    let accept_helper = source_between_markers(
        unix_api_tests,
        "async fn accept_fake_unix_peer(",
        "async fn accept_fake_unix_peer_stream_with_timeout(",
        "accept_fake_unix_peer body",
    );
    let exact_reader = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_request_exact(",
        "async fn read_fake_unix_request_exact_with_timeout(",
        "read_fake_unix_request_exact body",
    );
    let accept_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn accept_fake_unix_peer_stream_with_timeout(",
        "fn classify_fake_unix_peer_accept(",
        "accept_fake_unix_peer_stream_with_timeout body",
    );
    let request_read_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_request_exact_with_timeout(",
        "fn classify_fake_unix_request_exact_read(",
        "read_fake_unix_request_exact_with_timeout body",
    );

    assert!(
        contains_normalized_source(
            unix_api_tests,
            "async fn accept_fake_unix_peer_stream_with_timeout(listener: UnixListener,) -> FakeUnixPeerAcceptOutcome"
        ),
        "Unix API fake-peer accept timeout helper should return classified accept outcomes"
    );
    assert!(
        contains_normalized_source(
            unix_api_tests,
            "async fn read_fake_unix_request_exact_with_timeout(stream: &mut UnixStream, buf: &mut [u8],) -> FakeUnixPeerRequestReadOutcome"
        ),
        "Unix API fake-peer request exact-read timeout helper should return classified read outcomes"
    );
    assert!(
        accept_timeout_helper.contains("classify_fake_unix_peer_accept("),
        "Unix API fake-peer accept timeout helper should classify its raw timeout result"
    );
    assert!(
        request_read_timeout_helper.contains("classify_fake_unix_request_exact_read("),
        "Unix API fake-peer request exact-read timeout helper should classify its raw timeout result"
    );
    for remapped_pattern in ["=> Ok(Ok(stream))", "=> Ok(Err(err))", "=> Err(err)"] {
        assert!(
            !accept_timeout_helper.contains(remapped_pattern),
            "Unix API fake-peer accept timeout helper should not remap classified outcomes back into `{remapped_pattern}`"
        );
    }
    for remapped_pattern in ["=> Ok(Ok(()))", "=> Ok(Err(err))", "=> Err(err)"] {
        assert!(
            !request_read_timeout_helper.contains(remapped_pattern),
            "Unix API fake-peer request exact-read timeout helper should not remap classified outcomes back into `{remapped_pattern}`"
        );
    }
    assert!(
        accept_helper.contains("match accept_fake_unix_peer_stream_with_timeout(listener).await"),
        "Unix API fake-peer accept helper should branch on classified accept helper outcomes"
    );
    assert!(
        exact_reader.contains("match read_fake_unix_request_exact_with_timeout(stream, buf).await"),
        "Unix API fake-peer exact-read helper should branch on classified read helper outcomes"
    );
}

#[test]
fn unix_api_fake_peer_timeout_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");
    let accept_helper = source_between_markers(
        unix_api_tests,
        "async fn accept_fake_unix_peer(",
        "async fn accept_fake_unix_peer_stream_with_timeout(",
        "accept_fake_unix_peer body",
    );
    let exact_reader = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_request_exact(",
        "async fn read_fake_unix_request_exact_with_timeout(",
        "read_fake_unix_request_exact body",
    );
    let accept_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn accept_fake_unix_peer_stream_with_timeout(",
        "fn classify_fake_unix_peer_accept(",
        "accept_fake_unix_peer_stream_with_timeout body",
    );
    let request_read_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_request_exact_with_timeout(",
        "fn classify_fake_unix_request_exact_read(",
        "read_fake_unix_request_exact_with_timeout body",
    );

    for inline_pattern in ["Ok(Ok((stream, _))) =>", "Ok(Err(err)) =>", "Err(err) =>"] {
        assert!(
            !contains_normalized_source(accept_timeout_helper, inline_pattern),
            "Unix API fake-peer accept timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    for inline_pattern in ["Ok(Ok(_)) =>", "Ok(Err(err)) =>", "Err(err) =>"] {
        assert!(
            !contains_normalized_source(request_read_timeout_helper, inline_pattern),
            "Unix API fake-peer request-read timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    assert!(
        unix_api_tests.contains("enum FakeUnixPeerAcceptOutcome"),
        "Unix API fake-peer accept timeout outcomes should have a named classifier enum"
    );
    assert!(
        unix_api_tests.contains("enum FakeUnixPeerRequestReadOutcome"),
        "Unix API fake-peer request-read timeout outcomes should have a named classifier enum"
    );
    assert!(
        unix_api_tests.contains("fn classify_fake_unix_peer_accept("),
        "Unix API fake-peer accept timeout outcomes should route through a classifier"
    );
    assert!(
        unix_api_tests.contains("fn classify_fake_unix_request_exact_read("),
        "Unix API fake-peer request-read timeout outcomes should route through a classifier"
    );
    assert!(
        accept_timeout_helper.contains("classify_fake_unix_peer_accept("),
        "Unix API fake-peer accept timeout helper should return classified outcomes"
    );
    assert!(
        request_read_timeout_helper.contains("classify_fake_unix_request_exact_read("),
        "Unix API fake-peer request-read timeout helper should return classified outcomes"
    );
    assert!(
        accept_helper.contains("match accept_fake_unix_peer_stream_with_timeout(listener).await"),
        "Unix API fake-peer accept helper should branch on classified accept outcomes"
    );
    assert!(
        accept_helper.contains("FakeUnixPeerAcceptOutcome::Accepted(stream) => Ok(stream)"),
        "Unix API fake-peer accepted outcome should preserve the accepted stream"
    );
    assert!(
        accept_helper.contains("FakeUnixPeerAcceptOutcome::Failed(err) =>"),
        "Unix API fake-peer failed accept outcome should remain explicit"
    );
    assert!(
        accept_helper.contains("format!(\"{context} accept failed: {err}\")"),
        "Unix API fake-peer failed accept outcome should preserve its context"
    );
    assert!(
        accept_helper.contains("FakeUnixPeerAcceptOutcome::TimedOut(_) =>"),
        "Unix API fake-peer timed-out accept outcome should remain explicit"
    );
    assert!(
        accept_helper.contains("{context} timed out waiting for client connection"),
        "Unix API fake-peer timed-out accept outcome should preserve its context"
    );
    assert!(
        exact_reader.contains("match read_fake_unix_request_exact_with_timeout(stream, buf).await"),
        "Unix API fake-peer request-read helper should branch on classified read outcomes"
    );
    assert!(
        exact_reader.contains("FakeUnixPeerRequestReadOutcome::Read => Ok(())"),
        "Unix API fake-peer request-read success outcome should preserve success"
    );
    assert!(
        exact_reader.contains("FakeUnixPeerRequestReadOutcome::Failed(err) =>"),
        "Unix API fake-peer request-read failure outcome should remain explicit"
    );
    assert!(
        exact_reader.contains("format!(\"{context} request {part} read failed: {err}\")"),
        "Unix API fake-peer request-read failure outcome should preserve its context"
    );
    assert!(
        exact_reader.contains("FakeUnixPeerRequestReadOutcome::TimedOut(_) =>"),
        "Unix API fake-peer request-read timeout outcome should remain explicit"
    );
    assert!(
        exact_reader.contains("format!(\"{context} timed out waiting for request {part}\")"),
        "Unix API fake-peer request-read timeout outcome should preserve its context"
    );
}

#[test]
fn unix_api_stalled_peer_client_close_read_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");
    let client_close_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_peer_client_close_with_timeout(",
        "fn classify_fake_unix_peer_client_close(",
        "read_fake_unix_peer_client_close_with_timeout body",
    );

    assert!(
        !unix_api_tests.contains(
            "tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut extra))"
        ),
        "Unix API stalled-peer client-close reads should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT: Duration"),
        "Unix API stalled-peer client-close reads should share a named timeout"
    );
    assert!(
        client_close_timeout_helper.contains("tokio::time::timeout(")
            && client_close_timeout_helper.contains("FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT")
            && client_close_timeout_helper.contains("stream.read_exact(buf)"),
        "Unix API stalled-peer client-close reads should route through the named timeout"
    );
}

#[test]
fn unix_api_stalled_peer_client_close_read_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");
    let stalled_response_peer = source_between_markers(
        unix_api_tests,
        "async fn request_json_times_out_when_peer_stalls_response()",
        "#[tokio::test]\nasync fn request_json_zero_timeout_uses_default_deadline()",
        "stalled-response peer test body",
    );

    for raw_pattern in ["Ok(Err(err))", "Ok(Ok(_))", "Err(_)"] {
        assert!(
            !stalled_response_peer.contains(raw_pattern),
            "Unix API stalled-response peer should classify client-close reads instead of matching {raw_pattern} inline"
        );
    }

    let client_close_observer = source_between_markers(
        unix_api_tests,
        "async fn expect_fake_unix_peer_client_close(",
        "async fn read_fake_unix_peer_client_close_with_timeout(",
        "expect_fake_unix_peer_client_close body",
    );
    let client_close_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn read_fake_unix_peer_client_close_with_timeout(",
        "fn classify_fake_unix_peer_client_close(",
        "read_fake_unix_peer_client_close_with_timeout body",
    );

    for inline_pattern in ["Ok(Err(err)) =>", "Ok(Ok(_)) =>", "Err(err) =>"] {
        assert!(
            !contains_normalized_source(client_close_timeout_helper, inline_pattern),
            "Unix API stalled-peer client-close timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    assert!(
        unix_api_tests.contains("type TimedRawFakeUnixPeerClientCloseRead"),
        "Unix API stalled-peer client-close reads should name the raw timeout/read result type"
    );
    assert!(
        unix_api_tests.contains("enum FakeUnixPeerClientCloseReadOutcome"),
        "Unix API stalled-peer client-close reads should expose classified outcomes"
    );
    assert!(
        unix_api_tests.contains("fn classify_fake_unix_peer_client_close("),
        "Unix API stalled-peer client-close reads should route through a classifier"
    );
    assert!(
        client_close_timeout_helper.contains("classify_fake_unix_peer_client_close("),
        "Unix API stalled-peer client-close timeout helper should return classified outcomes"
    );
    assert!(
        stalled_response_peer.contains("expect_fake_unix_peer_client_close(")
            && stalled_response_peer.contains("&mut stream"),
        "Unix API stalled-response peer should call the named close observer"
    );
    assert!(
        client_close_observer.contains(
            "match read_fake_unix_peer_client_close_with_timeout(stream, &mut extra).await"
        ),
        "Unix API stalled-peer client-close observer should branch on classified close-read outcomes"
    );
    assert!(
        client_close_observer.contains("FakeUnixPeerClientCloseReadOutcome::Closed(err) =>"),
        "Unix API stalled-peer client-close observer should preserve closed-stream errors"
    );
    assert!(
        client_close_observer.contains("expect_connection_closed_error(&err, close_context)"),
        "Unix API stalled-peer client-close observer should preserve closed-stream validation"
    );
    assert!(
        client_close_observer.contains("FakeUnixPeerClientCloseReadOutcome::WroteExtra =>"),
        "Unix API stalled-peer client-close observer should keep unexpected writes explicit"
    );
    assert!(
        client_close_observer.contains("client unexpectedly wrote another frame"),
        "Unix API stalled-peer client-close observer should preserve unexpected-write context"
    );
    assert!(
        client_close_observer.contains("FakeUnixPeerClientCloseReadOutcome::TimedOut(_) =>"),
        "Unix API stalled-peer client-close observer should keep timeout outcomes explicit"
    );
    assert!(
        client_close_observer.contains("did not observe client close before timeout"),
        "Unix API stalled-peer client-close observer should preserve timeout context"
    );
}

#[test]
fn unix_api_zero_timeout_request_seen_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("tokio::time::timeout(Duration::from_secs(1), request_seen_rx)"),
        "Unix API zero-timeout request-seen waits should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT: Duration"),
        "Unix API zero-timeout request-seen waits should share a named timeout"
    );
    assert!(
        unix_api_tests
            .contains("tokio::time::timeout(ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT, request_seen_rx)"),
        "Unix API zero-timeout request-seen waits should route through the named timeout"
    );
}

#[test]
fn unix_api_zero_timeout_client_test_uses_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let zero_timeout_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn request_json_zero_timeout_uses_default_deadline()",
        "request_json_zero_timeout_uses_default_deadline body",
    );

    for inline_expect in [
        "tempdir().expect(\"tempdir\")",
        "UnixListener::bind(&sock).expect(\"bind\")",
        ".expect(\"server observes client request before timeout\")",
        ".expect(\"server request seen signal\")",
        "send_response_tx.send(()).expect(\"release response\")",
    ] {
        assert!(
            !zero_timeout_test.contains(inline_expect),
            "Unix API zero-timeout client test should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_fake_unix_listener(",
        "type ZeroTimeoutRequestSeenReceiver = tokio::sync::oneshot::Receiver<()>",
        "type ZeroTimeoutResponseReleaseSender = tokio::sync::oneshot::Sender<()>",
        "async fn expect_zero_timeout_request_seen(",
        "fn release_zero_timeout_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API zero-timeout client diagnostics should define `{helper}`"
        );
    }

    assert!(
        contains_normalized_source(
            zero_timeout_test,
            "expect_zero_timeout_request_seen(request_seen_rx, \"zero-timeout response peer\").await;"
        ),
        "Unix API zero-timeout client test should observe request-seen through the named helper"
    );
    assert!(
        contains_normalized_source(
            zero_timeout_test,
            "release_zero_timeout_response(send_response_tx, \"zero-timeout response peer\");"
        ),
        "Unix API zero-timeout client test should release the fake peer through the named helper"
    );

    for diagnostic in [
        "zero-timeout request seen wait timed out",
        "zero-timeout request seen signal failed",
        "zero-timeout response release failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API zero-timeout client diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_zero_timeout_server_test_uses_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let zero_timeout_server_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn unix_server_zero_timeout_uses_default_deadline()",
        "unix_server_zero_timeout_uses_default_deadline body",
    );

    for inline_expect in [
        "tempdir().expect(\"tempdir\")",
        "test_state(dir.path()).expect(\"test_state\")",
        "UnixStream::connect(&sock).await.expect(\"connect\")",
        ".expect(\"delayed request write\")",
        ".expect(\"response length\")",
        ".expect(\"response body\")",
        ".expect(\"response json\")",
    ] {
        assert!(
            !zero_timeout_server_test.contains(inline_expect),
            "Unix API zero-timeout server test should route `{inline_expect}` through named diagnostic helpers"
        );
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_unix_api_state(",
        "async fn expect_unix_api_stream_connect(",
        "async fn expect_raw_unix_request_written(",
        "async fn expect_raw_unix_kernel_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API zero-timeout server diagnostics should define `{helper}`"
        );
    }

    assert!(
        contains_normalized_source(
            zero_timeout_server_test,
            "expect_raw_unix_request_written(
                &mut stream,
                &KernelRequest::Head {
                    cap_b64: \"invalid\".into(),
                },
                \"server zero-timeout test\",
            )
            .await;"
        ),
        "Unix API zero-timeout server test should write the request through the named helper"
    );
    assert!(
        contains_normalized_source(
            zero_timeout_server_test,
            "let resp = expect_raw_unix_kernel_response(&mut stream, \"server zero-timeout test\").await;"
        ),
        "Unix API zero-timeout server test should read the response through the named helper"
    );

    for diagnostic in [
        "Unix API raw request write failed",
        "Unix API raw response length read failed",
        "Unix API raw response body read failed",
        "Unix API raw response JSON failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API zero-timeout server diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_zero_timeout_client_join_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("tokio::time::timeout(Duration::from_secs(1), client)"),
        "Unix API zero-timeout client joins should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT: Duration"),
        "Unix API zero-timeout client joins should share a named timeout"
    );
    assert!(
        unix_api_tests.contains("tokio::time::timeout(ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT, client)"),
        "Unix API zero-timeout client joins should route through the named timeout"
    );
}

#[test]
fn unix_api_zero_timeout_client_join_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");
    let zero_timeout_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn request_json_zero_timeout_uses_default_deadline()",
        "request_json_zero_timeout_uses_default_deadline body",
    );

    for inline_report in [
        ".expect(\"client exits after released response\")",
        ".expect(\"client task joins\")",
        ".expect(\"zero timeout should fall back to default deadline\")",
    ] {
        assert!(
            !zero_timeout_test.contains(inline_report),
            "Unix API zero-timeout client join should classify outcomes instead of using `{inline_report}`"
        );
    }
    for helper in [
        "type ZeroTimeoutClientResult = Result<KernelResponse, std::io::Error>",
        "type ZeroTimeoutClientJoin = Result<ZeroTimeoutClientResult, tokio::task::JoinError>",
        "type TimedZeroTimeoutClientJoin = Result<ZeroTimeoutClientJoin, tokio::time::error::Elapsed>",
        "enum ZeroTimeoutClientJoinOutcome",
        "async fn join_zero_timeout_client(",
        "fn classify_zero_timeout_client_join(",
        "fn expect_zero_timeout_client_response(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API zero-timeout client join helpers should define `{helper}`"
        );
    }
    assert!(
        zero_timeout_test.contains("let client_join = join_zero_timeout_client(client).await;"),
        "Unix API zero-timeout test should join the client through the named timeout helper"
    );
    assert!(
        zero_timeout_test.contains("let resp = expect_zero_timeout_client_response(client_join);"),
        "Unix API zero-timeout test should extract the response through the named reporter"
    );
}

#[test]
fn unix_api_zero_timeout_progress_yields_use_shared_helper() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !contains_normalized_source(
            unix_api_tests,
            "for _ in 0..3 { tokio::task::yield_now().await; }"
        ),
        "Unix API zero-timeout progress checks should use a shared yield helper"
    );
    assert!(
        unix_api_tests.contains("const ZERO_TIMEOUT_PROGRESS_YIELDS: usize"),
        "Unix API zero-timeout progress checks should share a named yield count"
    );
    assert!(
        unix_api_tests.contains("async fn yield_zero_timeout_progress()"),
        "Unix API zero-timeout progress checks should define a shared yield helper"
    );
    assert_eq!(
        unix_api_tests
            .matches("yield_zero_timeout_progress().await;")
            .count(),
        2,
        "both Unix API zero-timeout tests should route progress yields through the shared helper"
    );
}

#[test]
fn unix_api_shutdown_write_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("if write_raw_request(&mut stream, &req).await.is_err()"),
        "Unix API shutdown tests should classify post-shutdown write outcomes instead of returning from a bare is_err branch"
    );
    assert!(
        unix_api_tests.contains("enum PostShutdownWriteOutcome"),
        "Unix API shutdown tests should expose written/closed outcomes"
    );
    assert!(
        unix_api_tests.contains("async fn write_after_shutdown("),
        "Unix API shutdown tests should use a named post-shutdown write observer"
    );
    assert!(
        unix_api_tests.contains("match write_after_shutdown(&mut stream, &req).await"),
        "Unix API shutdown tests should branch on classified post-shutdown write outcomes"
    );
}

#[test]
fn unix_api_shutdown_read_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(
            "Ok(Ok(_)) => panic!(\"idle connection processed a request after server shutdown\")"
        ),
        "Unix API shutdown tests should classify post-shutdown read outcomes instead of matching raw timeout/read results inline"
    );
    assert!(
        unix_api_tests.contains("enum PostShutdownReadOutcome"),
        "Unix API shutdown tests should expose closed/timed-out/replied outcomes"
    );
    assert!(
        unix_api_tests.contains("async fn read_after_shutdown("),
        "Unix API shutdown tests should use a named post-shutdown read observer"
    );
    assert!(
        unix_api_tests.contains("match read_after_shutdown(&mut stream).await"),
        "Unix API shutdown tests should branch on classified post-shutdown read outcomes"
    );
}

#[test]
fn unix_api_post_shutdown_reply_reporting_uses_named_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let shutdown_test = source_between_markers(
        unix_api_tests,
        "async fn unix_shutdown_closes_idle_connections()",
        "#[tokio::test]\nasync fn unix_connection_io_timeout_closes_silent_client()",
        "unix_shutdown_closes_idle_connections body",
    );

    assert!(
        !shutdown_test
            .contains("panic!(\"idle connection processed a request after server shutdown\")"),
        "Unix API shutdown test should route unexpected post-shutdown replies through a named reporter"
    );
    assert!(
        unix_api_tests.contains("fn panic_post_shutdown_unexpected_response("),
        "Unix API shutdown test should define a named unexpected-response reporter"
    );
    assert!(
        shutdown_test.contains("panic_post_shutdown_unexpected_response();"),
        "Unix API shutdown test should call the named unexpected-response reporter"
    );

    let reply_reporter = source_between_markers(
        unix_api_tests,
        "fn panic_post_shutdown_unexpected_response(",
        "async fn expect_fake_unix_peer(",
        "panic_post_shutdown_unexpected_response body",
    );
    assert!(
        reply_reporter.contains("idle connection processed a request after server shutdown"),
        "Unix API shutdown unexpected-response reporter should preserve the diagnostic context"
    );
}

#[test]
fn unix_api_post_shutdown_read_timeout_outcomes_are_classified_by_helper() {
    let unix_api_tests = include_str!("unix_api.rs");
    let read_observer = source_between_markers(
        unix_api_tests,
        "async fn read_after_shutdown(",
        "async fn expect_fake_unix_peer(",
        "read_after_shutdown body",
    );

    for raw_pattern in ["Ok(Err(err))", "Err(_)", "Ok(Ok(_))"] {
        assert!(
            !read_observer.contains(raw_pattern),
            "Unix API post-shutdown read observer should classify timed read outcomes instead of matching {raw_pattern} inline"
        );
    }
    assert!(
        unix_api_tests.contains("type TimedPostShutdownRead"),
        "Unix API post-shutdown read classification should name the raw timeout/read result type"
    );
    assert!(
        unix_api_tests.contains("fn classify_post_shutdown_read("),
        "Unix API post-shutdown read classification should use a named helper"
    );
    assert!(
        read_observer.contains("match classify_post_shutdown_read("),
        "Unix API post-shutdown read observer should branch on classified outcomes"
    );
    for classified_outcome in [
        "PostShutdownReadOutcome::Closed",
        "PostShutdownReadOutcome::TimedOut",
        "PostShutdownReadOutcome::Replied",
    ] {
        assert!(
            unix_api_tests.contains(classified_outcome),
            "Unix API post-shutdown read classification should preserve {classified_outcome}"
        );
    }
    assert!(
        read_observer
            .contains("assert_connection_closed_error(&err, \"post-shutdown response read\")"),
        "Unix API post-shutdown read observer should keep asserting closed-stream errors"
    );
}

#[test]
fn unix_api_post_shutdown_response_read_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");
    let read_observer = source_between_markers(
        unix_api_tests,
        "async fn read_after_shutdown(",
        "async fn expect_fake_unix_peer(",
        "read_after_shutdown body",
    );

    assert!(
        !unix_api_tests.contains("std::time::Duration::from_millis(200)"),
        "Unix API post-shutdown response reads should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const POST_SHUTDOWN_RESPONSE_READ_TIMEOUT: Duration"),
        "Unix API post-shutdown response reads should share a named timeout"
    );
    assert!(
        read_observer.contains("tokio::time::timeout(")
            && read_observer.contains("POST_SHUTDOWN_RESPONSE_READ_TIMEOUT")
            && read_observer.contains("stream.read_exact(&mut len_buf)"),
        "Unix API post-shutdown response reads should route through the named timeout"
    );
}

#[test]
fn unix_api_real_server_lifecycle_uses_typed_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert_eq!(
        unix_api_tests
            .matches(".expect(\"server task joins\")")
            .count(),
        0,
        "Unix API real-server task joins should be classified instead of asserted through expect chains"
    );
    assert!(
        !unix_api_tests
            .contains("tokio::time::timeout(std::time::Duration::from_secs(1), self.handle)"),
        "Unix API real-server shutdown joins should use a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("const UNIX_SERVER_SHUTDOWN_TIMEOUT: Duration"),
        "Unix API real-server shutdown joins should share a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("tokio::time::timeout(UNIX_SERVER_SHUTDOWN_TIMEOUT, handle)"),
        "Unix API real-server shutdown joins should route through the named timeout"
    );
    assert!(
        unix_api_tests.contains("async fn join_unix_server_shutdown("),
        "Unix API real-server shutdown joins should use a named timeout helper"
    );
    assert_eq!(
        unix_api_tests
            .matches("tokio::sync::watch::channel(())")
            .count(),
        2,
        "Unix API real-server watch channels should be centralized in spawn/error helpers"
    );
    assert!(
        unix_api_tests.contains("async fn spawn_unix_with_io_timeout("),
        "Unix API configured-timeout servers should use a named lifecycle helper"
    );
    assert!(
        unix_api_tests.contains("async fn expect_unix_start_error("),
        "Unix API startup-failure tests should observe task errors through a named helper"
    );
    assert!(
        !unix_api_tests.contains("tokio::time::timeout(Duration::from_secs(1), handle)"),
        "Unix API startup-failure joins should use a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("const UNIX_START_ERROR_TIMEOUT: Duration"),
        "Unix API startup-failure joins should share a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("tokio::time::timeout(UNIX_START_ERROR_TIMEOUT, handle)"),
        "Unix API startup-failure joins should route through the named timeout"
    );
    assert!(
        unix_api_tests.contains("async fn join_unix_start_error("),
        "Unix API startup-failure joins should use a named timeout helper"
    );
}

#[test]
fn unix_api_daemon_lifecycle_setup_uses_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let lifecycle_tests = [
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_server_exits_on_shutdown_signal()",
                "unix_server_exits_on_shutdown_signal body",
            ),
            "shutdown-signal test",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_server_refuses_to_clobber_existing_non_socket_path()",
                "unix_server_refuses_to_clobber_existing_non_socket_path body",
            ),
            "existing-path refusal test",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_shutdown_closes_idle_connections()",
                "unix_shutdown_closes_idle_connections body",
            ),
            "idle-shutdown test",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn unix_connection_io_timeout_closes_silent_client()",
                "unix_connection_io_timeout_closes_silent_client body",
            ),
            "silent-client close test",
        ),
    ];

    for (test_body, context) in lifecycle_tests {
        for inline_expect in [
            "tempdir().expect(\"tempdir\")",
            "test_state(dir.path()).expect(\"test_state\")",
            "std::fs::write(&sock, b\"preserve this file\").expect(\"write occupied path\")",
            "std::fs::read(&sock).expect(\"occupied path still exists\")",
            "UnixStream::connect(&sock).await.expect(\"connect\")",
        ] {
            assert!(
                !test_body.contains(inline_expect),
                "Unix API {context} should route `{inline_expect}` through named diagnostic helpers"
            );
        }
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_unix_api_state(",
        "fn expect_occupied_socket_file_written(",
        "fn expect_occupied_socket_file_bytes(",
        "async fn expect_unix_api_stream_connect(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API daemon lifecycle setup should define `{helper}`"
        );
    }

    for diagnostic in [
        "Unix API tempdir failed",
        "Unix API test state failed",
        "occupied socket file write failed",
        "occupied socket file read failed",
        "Unix API stream connect failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API daemon lifecycle setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_request_json_tests_use_named_diagnostic_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let request_json_tests = [
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn request_json_rejects_oversized_request_before_connect()",
                "request_json_rejects_oversized_request_before_connect body",
            ),
            "oversized request before connect",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn request_json_rejects_oversized_response_frame()",
                "request_json_rejects_oversized_response_frame body",
            ),
            "oversized response frame",
        ),
        (
            source_top_level_item_after_marker(
                unix_api_tests,
                "async fn request_json_times_out_when_peer_stalls_response()",
                "request_json_times_out_when_peer_stalls_response body",
            ),
            "stalled response peer",
        ),
    ];

    for (test_body, context) in request_json_tests {
        for inline_expect in [
            "tempdir().expect(\"tempdir\")",
            "UnixListener::bind(&sock).expect(\"bind\")",
            ".expect_err(\"oversized request frame must fail before connect\")",
            ".expect_err(\"oversized response frame must be rejected\")",
            ".expect_err(\"stalled peer must trip the client timeout\")",
        ] {
            assert!(
                !test_body.contains(inline_expect),
                "Unix API request-json {context} should route `{inline_expect}` through named diagnostic helpers"
            );
        }
    }

    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_fake_unix_listener(",
        "type RequestJsonResult = Result<KernelResponse, std::io::Error>",
        "async fn expect_request_json_error(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API request-json tests should define `{helper}`"
        );
    }

    for diagnostic in [
        "Unix API tempdir failed",
        "fake Unix listener bind failed",
        "request-json unexpectedly succeeded",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API request-json diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_real_server_lifecycle_classifies_shutdown_and_start_outcomes() {
    let unix_api_tests = include_str!("unix_api.rs");
    let running_unix_impl = source_between_markers(
        unix_api_tests,
        "impl RunningUnix {",
        "async fn spawn_unix(",
        "RunningUnix impl",
    );
    let start_error_helper = source_between_markers(
        unix_api_tests,
        "async fn expect_unix_start_error(",
        "async fn expect_daemon_start_failure(",
        "expect_unix_start_error body",
    );

    for inline_report in [
        ".expect(\"send shutdown\")",
        ".expect(\"server exits before timeout\")",
        ".expect(\"server task joins\")",
        "assert!(result.is_ok()",
    ] {
        assert!(
            !running_unix_impl.contains(inline_report),
            "Unix API real-server shutdown should classify lifecycle outcome instead of using `{inline_report}`"
        );
    }
    for inline_report in [
        ".expect(\"server exits before timeout\")",
        ".expect(\"start-failure Unix server task joins\")",
        ".expect_err(\"Unix server start must fail closed\")",
    ] {
        assert!(
            !start_error_helper.contains(inline_report),
            "Unix API startup-failure helper should classify lifecycle outcome instead of using `{inline_report}`"
        );
    }
    for helper in [
        "type UnixServerTaskResult = Result<(), std::io::Error>",
        "type UnixServerTaskJoin = Result<UnixServerTaskResult, tokio::task::JoinError>",
        "type TimedUnixServerTaskJoin = Result<UnixServerTaskJoin, tokio::time::error::Elapsed>",
        "enum UnixShutdownSignalDelivery",
        "enum UnixServerJoinOutcome",
        "fn observe_unix_shutdown_signal(",
        "async fn join_unix_server_shutdown(",
        "async fn join_unix_start_error(",
        "fn classify_unix_server_task_join(",
        "fn assert_unix_shutdown_join_completed(",
        "fn expect_unix_start_error_join_failed_closed(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API real-server lifecycle helpers should define `{helper}`"
        );
    }
    assert!(
        running_unix_impl.contains("observe_unix_shutdown_signal(&self.shutdown_tx);"),
        "Unix API real-server shutdown should explicitly observe shutdown signal delivery"
    );
    assert!(
        running_unix_impl
            .contains("let shutdown_join = join_unix_server_shutdown(self.handle).await;"),
        "Unix API real-server shutdown should join through the named timeout helper"
    );
    assert!(
        running_unix_impl.contains("assert_unix_shutdown_join_completed(shutdown_join);"),
        "Unix API real-server shutdown should report classified join outcomes through the named reporter"
    );
    assert!(
        start_error_helper.contains("let start_error_join = join_unix_start_error(handle).await;"),
        "Unix API startup-failure helper should join through the named timeout helper"
    );
    assert!(
        start_error_helper.contains("expect_unix_start_error_join_failed_closed(start_error_join)"),
        "Unix API startup-failure helper should report classified join outcomes through the named reporter"
    );
}

#[test]
fn unix_api_daemon_start_failures_use_named_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let occupied_path_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn daemon_start_refuses_to_clobber_existing_non_socket_path()",
        "daemon_start_refuses_to_clobber_existing_non_socket_path body",
    );
    let unbindable_path_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn daemon_start_rejects_unbindable_unix_socket_path()",
        "daemon_start_rejects_unbindable_unix_socket_path body",
    );

    for (test_body, context) in [
        (occupied_path_test, "occupied Unix socket path"),
        (unbindable_path_test, "unbindable Unix socket path"),
    ] {
        for inline_expect in [
            "tempdir().expect(\"tempdir\")",
            "test_state(dir.path()).expect(\"test_state\")",
            "\"127.0.0.1:0\".parse().expect(\"http addr\")",
        ] {
            assert!(
                !test_body.contains(inline_expect),
                "Unix API daemon start failure test for {context} should route `{inline_expect}` through named diagnostic helpers"
            );
        }
        for inline_daemon_start in ["start_with_state(", "ServerConfig {"] {
            assert!(
                !test_body.contains(inline_daemon_start),
                "Unix API daemon start failure test for {context} should route `{inline_daemon_start}` through the named daemon-start helper"
            );
        }
        assert!(
            !test_body.contains("Ok(server) =>"),
            "Unix API daemon start failure test for {context} should route unexpected success cleanup through a named helper"
        );
        assert!(
            !test_body.contains("other => panic!(\"expected daemon Unix socket I/O failure"),
            "Unix API daemon start failure test for {context} should route non-IoFailed reporting through a named helper"
        );
        assert!(
            contains_normalized_source(
                test_body,
                "expect_daemon_start_failure_with_unix_socket(&sock, state,"
            ),
            "Unix API daemon start failure test for {context} should call the named daemon-start helper"
        );
        assert!(
            contains_normalized_source(test_body, "expect_daemon_start_io_failure(err, &sock,"),
            "Unix API daemon start failure test for {context} should call the named IoFailed helper"
        );
    }
    for occupied_path_inline_expect in [
        "std::fs::write(&sock, b\"preserve daemon path\").expect(\"write occupied path\")",
        "std::fs::read(&sock).expect(\"occupied path still exists\")",
    ] {
        assert!(
            !occupied_path_test.contains(occupied_path_inline_expect),
            "Unix API occupied daemon path failure test should route `{occupied_path_inline_expect}` through named preservation helpers"
        );
    }

    for helper_call in [
        "let dir = expect_unix_api_tempdir(\"occupied Unix socket path\");",
        "expect_occupied_socket_file_written(
            &sock,
            b\"preserve daemon path\",
            \"occupied Unix socket path\",
        );",
        "let state = expect_unix_api_state(dir.path(), \"occupied Unix socket path\");",
        "let err =
            expect_daemon_start_failure_with_unix_socket(&sock, state, \"occupied Unix socket path\")
                .await;",
        "expect_occupied_socket_file_bytes(&sock, \"occupied Unix socket path\")",
    ] {
        assert!(
            contains_normalized_source(occupied_path_test, helper_call),
            "Unix API occupied daemon path failure test should call `{helper_call}`"
        );
    }

    for helper_call in [
        "let dir = expect_unix_api_tempdir(\"unbindable Unix socket path\");",
        "let state = expect_unix_api_state(dir.path(), \"unbindable Unix socket path\");",
        "let err =
            expect_daemon_start_failure_with_unix_socket(&sock, state, \"unbindable Unix socket path\")
                .await;",
    ] {
        assert!(
            contains_normalized_source(unbindable_path_test, helper_call),
            "Unix API unbindable daemon path failure test should call `{helper_call}`"
        );
    }

    assert!(
        contains_normalized_source(
            unix_api_tests,
            "type DaemonStartResult = Result<mnemed::RunningServer, mneme_core::MnemeError>"
        ),
        "Unix API daemon start failure checks should name the raw daemon start result"
    );
    assert!(
        unix_api_tests.contains("async fn expect_daemon_start_failure("),
        "Unix API daemon start failure checks should use a named unexpected-success helper"
    );
    assert!(
        unix_api_tests.contains("fn expect_daemon_start_io_failure("),
        "Unix API daemon start failure checks should use a named IoFailed extraction helper"
    );
    for helper in [
        "fn expect_unix_api_tempdir(",
        "fn expect_unix_api_state(",
        "fn expect_occupied_socket_file_written(",
        "fn expect_occupied_socket_file_bytes(",
        "fn expect_daemon_loopback_http_addr(",
        "async fn expect_daemon_start_failure_with_unix_socket(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API daemon start failure setup should define `{helper}`"
        );
    }
    for diagnostic in [
        "Unix API tempdir failed",
        "Unix API test state failed",
        "occupied socket file write failed",
        "occupied socket file read failed",
        "daemon loopback HTTP address parse failed",
    ] {
        assert!(
            unix_api_tests.contains(diagnostic),
            "Unix API daemon start failure setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn unix_api_daemon_start_failure_helpers_split_reporting() {
    let unix_api_tests = include_str!("unix_api.rs");
    let start_failure_helper = source_between_markers(
        unix_api_tests,
        "async fn expect_daemon_start_failure(",
        "async fn shutdown_unexpected_daemon_start(",
        "expect_daemon_start_failure body",
    );
    let io_failure_helper = source_between_markers(
        unix_api_tests,
        "fn expect_daemon_start_io_failure(",
        "async fn yield_zero_timeout_progress()",
        "expect_daemon_start_io_failure body",
    );

    assert!(
        !start_failure_helper.contains("panic!(\"{context} unexpectedly started\")"),
        "Unix API daemon start helper should route unexpected-success reporting through a named reporter"
    );
    assert!(
        !io_failure_helper.contains(
            "panic!(\"expected {context} daemon Unix socket I/O failure, got {other:?}\")"
        ),
        "Unix API daemon start IoFailed helper should route non-IoFailed reporting through a named reporter"
    );
    assert!(
        !io_failure_helper.contains("assert_eq!(path, sock.display().to_string())"),
        "Unix API daemon start IoFailed helper should separate path validation from reporting"
    );
    for helper in [
        "async fn shutdown_unexpected_daemon_start(",
        "fn panic_unexpected_daemon_start(",
        "type DaemonStartIoFailureCheck = Result<String, String>",
        "fn validate_daemon_start_io_failure(",
        "fn expect_daemon_start_io_failure_check_passed(",
    ] {
        assert!(
            unix_api_tests.contains(helper),
            "Unix API daemon start failure helpers should define `{helper}`"
        );
    }
    assert!(
        start_failure_helper.contains("shutdown_unexpected_daemon_start(server).await;"),
        "Unix API daemon start helper should call the named unexpected-success cleanup helper"
    );
    assert!(
        start_failure_helper.contains("panic_unexpected_daemon_start(context);"),
        "Unix API daemon start helper should call the named unexpected-success reporter"
    );
    assert!(
        io_failure_helper.contains("validate_daemon_start_io_failure(err, sock, context);"),
        "Unix API daemon start IoFailed helper should call the named validator"
    );
    assert!(
        io_failure_helper.contains("expect_daemon_start_io_failure_check_passed(daemon_start_io)"),
        "Unix API daemon start IoFailed helper should call the named validation reporter"
    );
}

#[test]
fn unix_api_silent_client_close_read_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");
    let silent_close_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn read_silent_client_close_with_timeout(",
        "fn classify_silent_client_close_read(",
        "read_silent_client_close_with_timeout body",
    );

    assert!(
        !unix_api_tests.contains(
            "tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf))"
        ),
        "Unix API silent-client close reads should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const UNIX_SILENT_CLIENT_CLOSE_TIMEOUT: Duration"),
        "Unix API silent-client close reads should share a named timeout"
    );
    assert!(
        silent_close_timeout_helper.contains("tokio::time::timeout(")
            && silent_close_timeout_helper.contains("UNIX_SILENT_CLIENT_CLOSE_TIMEOUT")
            && silent_close_timeout_helper.contains("stream.read_exact(buf)"),
        "Unix API silent-client close reads should route through the named timeout"
    );
}

#[test]
fn unix_api_silent_client_close_read_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");
    let silent_client_test = source_between_markers(
        unix_api_tests,
        "async fn unix_connection_io_timeout_closes_silent_client()",
        "#[tokio::test]\nasync fn request_json_rejects_oversized_request_before_connect()",
        "silent-client close test body",
    );

    for raw_pattern in [
        "tokio::time::timeout(",
        ".expect(\"silent client connection should close after server I/O timeout\")",
        ".expect_err(\"silent client unexpectedly received a response frame\")",
    ] {
        assert!(
            !silent_client_test.contains(raw_pattern),
            "Unix API silent-client close test should route timed close reads through a classifier instead of using `{raw_pattern}` inline"
        );
    }

    let silent_close_observer = source_between_markers(
        unix_api_tests,
        "async fn assert_silent_client_connection_close(",
        "async fn read_silent_client_close_with_timeout(",
        "assert_silent_client_connection_close body",
    );
    let silent_close_timeout_helper = source_between_markers(
        unix_api_tests,
        "async fn read_silent_client_close_with_timeout(",
        "fn classify_silent_client_close_read(",
        "read_silent_client_close_with_timeout body",
    );
    let unexpected_reply_reporter = source_between_markers(
        unix_api_tests,
        "fn panic_silent_client_unexpected_response_frame(",
        "fn panic_silent_client_close_timeout(",
        "panic_silent_client_unexpected_response_frame body",
    );
    let timeout_reporter = source_between_markers(
        unix_api_tests,
        "fn panic_silent_client_close_timeout(",
        "async fn assert_silent_client_connection_close(",
        "panic_silent_client_close_timeout body",
    );

    for inline_pattern in ["Ok(Err(err)) =>", "Ok(Ok(_)) =>", "Err(err) =>"] {
        assert!(
            !contains_normalized_source(silent_close_timeout_helper, inline_pattern),
            "Unix API silent-client close timeout helper should classify raw `{inline_pattern}` outcomes before mapping them"
        );
    }
    assert!(
        unix_api_tests.contains("type TimedSilentClientCloseRead"),
        "Unix API silent-client close reads should name the raw timeout/read result type"
    );
    assert!(
        unix_api_tests.contains("enum SilentClientCloseReadOutcome"),
        "Unix API silent-client close reads should expose classified outcomes"
    );
    assert!(
        unix_api_tests.contains("fn classify_silent_client_close_read("),
        "Unix API silent-client close reads should route through a classifier"
    );
    assert!(
        silent_client_test.contains("assert_silent_client_connection_close(&mut stream).await"),
        "Unix API silent-client close test should call the named close observer"
    );
    assert!(
        silent_close_observer
            .contains("match read_silent_client_close_with_timeout(stream, &mut len_buf).await"),
        "Unix API silent-client close observer should branch on classified close-read outcomes"
    );
    assert!(
        silent_close_observer.contains("SilentClientCloseReadOutcome::Closed(err) =>"),
        "Unix API silent-client close observer should preserve closed-stream errors"
    );
    assert!(
        silent_close_observer
            .contains("assert_connection_closed_error(&err, \"silent client connection close\")"),
        "Unix API silent-client close observer should preserve closed-stream validation"
    );
    assert!(
        silent_close_observer.contains("SilentClientCloseReadOutcome::Replied =>"),
        "Unix API silent-client close observer should keep unexpected replies explicit"
    );
    assert!(
        unexpected_reply_reporter.contains("silent client unexpectedly received a response frame"),
        "Unix API silent-client close observer should preserve unexpected-reply context"
    );
    assert!(
        silent_close_observer.contains("SilentClientCloseReadOutcome::TimedOut(_) =>"),
        "Unix API silent-client close observer should keep timeout outcomes explicit"
    );
    assert!(
        timeout_reporter.contains("silent client connection should close after server I/O timeout"),
        "Unix API silent-client close observer should preserve timeout context"
    );
}

#[test]
fn unix_api_silent_client_close_reporting_uses_named_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");
    let silent_close_observer = source_between_markers(
        unix_api_tests,
        "async fn assert_silent_client_connection_close(",
        "async fn read_silent_client_close_with_timeout(",
        "assert_silent_client_connection_close body",
    );

    for inline_report in [
        "panic!(\"silent client unexpectedly received a response frame\")",
        "panic!(\"silent client connection should close after server I/O timeout\")",
    ] {
        assert!(
            !silent_close_observer.contains(inline_report),
            "Unix API silent-client close observer should route `{inline_report}` through a named reporting helper"
        );
    }
    assert!(
        unix_api_tests.contains("fn panic_silent_client_unexpected_response_frame("),
        "Unix API silent-client close observer should use a named unexpected-reply reporter"
    );
    assert!(
        unix_api_tests.contains("fn panic_silent_client_close_timeout("),
        "Unix API silent-client close observer should use a named timeout reporter"
    );
    assert!(
        silent_close_observer.contains("panic_silent_client_unexpected_response_frame();"),
        "Unix API silent-client close observer should call the named unexpected-reply reporter"
    );
    assert!(
        silent_close_observer.contains("panic_silent_client_close_timeout();"),
        "Unix API silent-client close observer should call the named timeout reporter"
    );
}

#[test]
fn unix_api_silent_client_io_timeout_uses_named_parameter() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests
            .contains("spawn_unix_with_io_timeout(sock.clone(), state, Duration::from_millis(50))"),
        "Unix API silent-client server I/O timeout should use a named parameter"
    );
    assert!(
        unix_api_tests.contains("const UNIX_SILENT_CLIENT_IO_TIMEOUT: Duration"),
        "Unix API silent-client server I/O timeout should be named"
    );
    assert!(
        unix_api_tests.contains(
            "spawn_unix_with_io_timeout(sock.clone(), state, UNIX_SILENT_CLIENT_IO_TIMEOUT)"
        ),
        "Unix API silent-client server I/O timeout should route through the named parameter"
    );
}

#[test]
fn unix_api_stalled_response_client_timeout_uses_named_parameter() {
    let unix_api_tests = include_str!("unix_api.rs");
    let stalled_response_test = source_top_level_item_after_marker(
        unix_api_tests,
        "async fn request_json_times_out_when_peer_stalls_response()",
        "request_json_times_out_when_peer_stalls_response body",
    );

    assert!(
        !stalled_response_test.contains("Duration::from_millis(50)"),
        "Unix API stalled-response client timeout should use a named parameter"
    );
    assert!(
        unix_api_tests.contains("const STALLED_RESPONSE_CLIENT_TIMEOUT: Duration"),
        "Unix API stalled-response client timeout should be named"
    );
    assert!(
        contains_normalized_source(
            stalled_response_test,
            "expect_request_json_error(
                request_json_with_timeout(
                    &sock,
                    &KernelRequest::Head {
                        cap_b64: \"invalid\".into(),
                    },
                    STALLED_RESPONSE_CLIENT_TIMEOUT,
                ),
                \"stalled response peer\",
            )"
        ),
        "Unix API stalled-response client timeout should route through the named parameter"
    );
}

#[test]
fn unix_zero_io_timeout_normalizes_to_default_deadline() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        unix.contains("fn normalize_io_timeout(io_timeout: Duration) -> Duration"),
        "Unix API must keep a single timeout normalization helper"
    );
    assert!(
        unix.contains("if io_timeout.is_zero()"),
        "Unix API zero I/O timeout must not be passed through as an immediate timeout"
    );
    assert!(
        unix.contains("DEFAULT_CONNECTION_IO_TIMEOUT"),
        "Unix API zero I/O timeout must normalize to the default connection deadline"
    );
}

#[test]
fn unix_client_connect_timeout_uses_named_helper() {
    let unix = include_str!("../src/unix.rs");
    let request_json = source_between_markers(
        unix,
        "pub async fn request_json_with_timeout(",
        "async fn connect_unix_stream_with_timeout(",
        "request_json_with_timeout body",
    );

    assert!(
        !request_json.contains("tokio::time::timeout(io_timeout, UnixStream::connect(path)).await"),
        "Unix client request path should route connects through a named timeout helper"
    );
    assert!(
        unix.contains("async fn connect_unix_stream_with_timeout("),
        "Unix client connect timeout policy should have a named helper"
    );
    assert!(
        request_json.contains("connect_unix_stream_with_timeout(path, io_timeout).await"),
        "Unix client request path should call the named connect timeout helper"
    );
}

#[test]
fn unix_client_connect_outcomes_are_classified() {
    let unix = include_str!("../src/unix.rs");
    let connect_helper = source_between_markers(
        unix,
        "async fn connect_unix_stream_with_timeout(",
        "fn classify_unix_connect(",
        "connect_unix_stream_with_timeout body",
    );

    for inline_pattern in ["Ok(result)", "Err(_)"] {
        assert!(
            !connect_helper.contains(inline_pattern),
            "Unix client connect timeout helper should classify timed connect outcomes instead of matching {inline_pattern} inline"
        );
    }
    assert!(
        unix.contains("type TimedUnixConnect"),
        "Unix client connect timeout helper should name the timed connect result type"
    );
    assert!(
        unix.contains("enum UnixConnectOutcome"),
        "Unix client connect timeout helper should expose a typed outcome enum"
    );
    assert!(
        unix.contains("fn classify_unix_connect("),
        "Unix client connect timeout helper should classify timed connect results through a named helper"
    );
    assert!(
        connect_helper.contains("match classify_unix_connect("),
        "Unix client connect timeout helper should branch on classified connect outcomes"
    );
    assert!(
        connect_helper.contains("UnixConnectOutcome::Connected(stream) => Ok(stream)"),
        "Unix client connect timeout helper should preserve successful connects"
    );
    assert!(
        connect_helper.contains("UnixConnectOutcome::Failed(e) => Err(e)"),
        "Unix client connect timeout helper should preserve connect errors"
    );
    assert!(
        connect_helper.contains("UnixConnectOutcome::TimedOut => Err(request_timeout_error())"),
        "Unix client connect timeout helper should preserve request timeout errors"
    );
}

#[test]
fn unix_timeout_io_helpers_classify_read_write_outcomes() {
    let unix = include_str!("../src/unix.rs");
    let read_helper = source_between_markers(
        unix,
        "async fn read_exact_with_timeout(",
        "fn classify_unix_read_exact(",
        "read_exact_with_timeout body",
    );
    let write_helper = source_between_markers(
        unix,
        "async fn write_all_with_timeout(",
        "fn classify_unix_write_all(",
        "write_all_with_timeout body",
    );

    for inline_pattern in ["Ok(Ok(_))", "Ok(Err(e))", "Err(_)"] {
        assert!(
            !read_helper.contains(inline_pattern),
            "Unix exact-read timeout helper should classify timed read outcomes instead of matching {inline_pattern} inline"
        );
    }
    for inline_pattern in ["Ok(Ok(()))", "Ok(Err(e))", "Err(_)"] {
        assert!(
            !write_helper.contains(inline_pattern),
            "Unix write-all timeout helper should classify timed write outcomes instead of matching {inline_pattern} inline"
        );
    }

    assert!(
        unix.contains("enum UnixReadExactOutcome"),
        "Unix exact-read timeout helper should expose a typed outcome enum"
    );
    assert!(
        unix.contains("enum UnixWriteAllOutcome"),
        "Unix write-all timeout helper should expose a typed outcome enum"
    );
    assert!(
        unix.contains("fn classify_unix_read_exact("),
        "Unix exact-read timeout helper should classify timed read results through a named helper"
    );
    assert!(
        unix.contains("fn classify_unix_write_all("),
        "Unix write-all timeout helper should classify timed write results through a named helper"
    );
    assert!(
        read_helper.contains("match classify_unix_read_exact("),
        "Unix exact-read timeout helper should branch on classified read outcomes"
    );
    assert!(
        write_helper.contains("match classify_unix_write_all("),
        "Unix write-all timeout helper should branch on classified write outcomes"
    );
    assert!(
        read_helper.contains("UnixReadExactOutcome::Read => Ok(())"),
        "Unix exact-read timeout helper should preserve successful read handling"
    );
    assert!(
        read_helper.contains("UnixReadExactOutcome::Failed(e) => Err(e)"),
        "Unix exact-read timeout helper should preserve read errors"
    );
    assert!(
        read_helper.contains("UnixReadExactOutcome::TimedOut => Err(timeout_error())"),
        "Unix exact-read timeout helper should preserve caller-specific timeout errors"
    );
    assert!(
        write_helper.contains("UnixWriteAllOutcome::Written => Ok(())"),
        "Unix write-all timeout helper should preserve successful write handling"
    );
    assert!(
        write_helper.contains("UnixWriteAllOutcome::Failed(e) => Err(e)"),
        "Unix write-all timeout helper should preserve write errors"
    );
    assert!(
        write_helper.contains("UnixWriteAllOutcome::TimedOut => Err(timeout_error())"),
        "Unix write-all timeout helper should preserve caller-specific timeout errors"
    );
}

#[test]
fn unix_socket_readiness_tests_probe_connection_not_path_existence() {
    let unix_ready = include_str!("unix_ready.rs");

    assert!(
        unix_ready.contains("UnixStream::connect(path).await"),
        "shared Unix readiness helper must prove readiness by opening a Unix socket connection"
    );
    assert!(
        !unix_ready.contains("path.exists()"),
        "shared Unix readiness helper must not treat socket path existence as readiness"
    );

    for (path, contents) in [
        ("unix_api.rs", include_str!("unix_api.rs")),
        ("redteam_paths.rs", include_str!("redteam_paths.rs")),
    ] {
        assert!(
            !contents.contains("async fn wait_for_socket"),
            "{path} should use the shared connect-based Unix readiness helper"
        );
        assert!(
            !contents.contains("path.exists()"),
            "{path} should not treat Unix socket path existence as readiness"
        );
    }
}

#[test]
fn unix_socket_readiness_policy_uses_named_helpers() {
    let unix_ready = include_str!("unix_ready.rs");
    let wait_for_accepting = source_top_level_item_after_marker(
        unix_ready,
        "pub async fn wait_for_unix_socket_accepting(path: &Path) {",
        "wait_for_unix_socket_accepting body",
    );

    assert!(
        !wait_for_accepting.contains("Instant::now() + UNIX_SOCKET_READY_TIMEOUT"),
        "shared Unix readiness helper should route deadline creation through a named helper"
    );
    assert!(
        !wait_for_accepting.contains("tokio::time::sleep(UNIX_SOCKET_READY_RETRY).await;"),
        "shared Unix readiness helper should route retry sleeps through a named helper"
    );
    assert!(
        unix_ready.contains("fn unix_socket_ready_deadline() -> Instant"),
        "shared Unix readiness helper should expose a named deadline policy"
    );
    assert!(
        unix_ready.contains("async fn wait_for_unix_socket_ready_retry()"),
        "shared Unix readiness helper should expose a named retry-wait policy"
    );
    assert!(
        unix_ready.contains("let deadline = unix_socket_ready_deadline();"),
        "shared Unix readiness helper should use the named deadline policy"
    );
    assert!(
        unix_ready.contains("wait_for_unix_socket_ready_retry().await;"),
        "shared Unix readiness helper should use the named retry-wait policy"
    );
}

#[test]
fn unix_socket_readiness_timeout_reporting_uses_named_helper() {
    let unix_ready = include_str!("unix_ready.rs");
    let wait_for_accepting = source_top_level_item_after_marker(
        unix_ready,
        "pub async fn wait_for_unix_socket_accepting(path: &Path) {",
        "wait_for_unix_socket_accepting body",
    );

    assert!(
        !wait_for_accepting.contains("Unix socket did not accept connections before timeout"),
        "shared Unix readiness helper should not inline timeout panic messages in the retry loop"
    );
    assert!(
        unix_ready.contains("fn unix_socket_ready_timeout_message("),
        "shared Unix readiness helper should use a named timeout message formatter"
    );
    assert!(
        unix_ready.contains("fn panic_unix_socket_not_accepting("),
        "shared Unix readiness helper should route timeout panics through a named helper"
    );
    assert!(
        wait_for_accepting.contains("panic_unix_socket_not_accepting(path, &e);"),
        "shared Unix readiness helper should call the named timeout panic helper"
    );
}

#[test]
fn redteam_paths_uses_typed_unix_server_lifecycle_helper() {
    let redteam = include_str!("redteam_paths.rs");

    assert!(
        !redteam.contains(".expect(\"redteam Unix server task joins\")"),
        "redteam Unix server lifecycle should assert typed task results through a helper"
    );
    assert!(
        redteam.contains("struct RedteamUnixServer"),
        "redteam Unix server lifecycle should be owned by a typed helper"
    );
    assert!(
        !redteam.contains("tokio::time::timeout(std::time::Duration::from_secs(1), self.handle)"),
        "redteam Unix server shutdown joins should use a named lifecycle timeout"
    );
    assert!(
        redteam.contains("const REDTEAM_UNIX_SERVER_SHUTDOWN_TIMEOUT: std::time::Duration"),
        "redteam Unix server shutdown joins should share a named lifecycle timeout"
    );
    assert!(
        redteam.contains("tokio::time::timeout(REDTEAM_UNIX_SERVER_SHUTDOWN_TIMEOUT, handle)"),
        "redteam Unix server shutdown joins should route through the named timeout"
    );
    assert!(
        redteam.contains("async fn shutdown(self)"),
        "redteam Unix server lifecycle helper should expose explicit async shutdown"
    );
}

#[test]
fn redteam_paths_classifies_unix_server_shutdown_outcomes() {
    let redteam = include_str!("redteam_paths.rs");
    let redteam_server_impl = source_between_markers(
        redteam,
        "impl RedteamUnixServer {",
        "async fn spawn_redteam_unix_server(",
        "RedteamUnixServer impl",
    );

    for inline_report in [
        ".expect(\"send shutdown\")",
        ".expect(\"redteam Unix server exits before timeout\")",
        ".expect(\"redteam Unix server task joins\")",
        "assert!(\n            result.is_ok()",
    ] {
        assert!(
            !redteam_server_impl.contains(inline_report),
            "redteam Unix server shutdown should classify lifecycle outcome instead of using `{inline_report}`"
        );
    }
    for helper in [
        "type RedteamUnixServerJoin = Result<RedteamUnixServerResult, tokio::task::JoinError>",
        "type TimedRedteamUnixServerJoin = Result<RedteamUnixServerJoin, tokio::time::error::Elapsed>",
        "enum RedteamUnixShutdownSignalDelivery",
        "enum RedteamUnixServerJoinOutcome",
        "fn observe_redteam_unix_shutdown_signal(",
        "async fn join_redteam_unix_server_shutdown(",
        "fn classify_redteam_unix_server_join(",
        "fn assert_redteam_unix_shutdown_completed(",
    ] {
        assert!(
            redteam.contains(helper),
            "redteam Unix server lifecycle helpers should define `{helper}`"
        );
    }
    assert!(
        redteam_server_impl.contains("observe_redteam_unix_shutdown_signal(&self.shutdown_tx);"),
        "redteam Unix server shutdown should explicitly observe shutdown signal delivery"
    );
    assert!(
        redteam_server_impl
            .contains("let shutdown_join = join_redteam_unix_server_shutdown(self.handle).await;"),
        "redteam Unix server shutdown should join through the named timeout helper"
    );
    assert!(
        redteam_server_impl.contains("assert_redteam_unix_shutdown_completed(shutdown_join);"),
        "redteam Unix server shutdown should report classified join outcomes through the named reporter"
    );
}

#[test]
fn redteam_http_grpc_setup_uses_named_diagnostic_helpers() {
    let redteam = include_str!("redteam_paths.rs");
    let http_tamper_test = source_top_level_item_after_marker(
        redteam,
        "async fn redteam_http_recall_rejects_out_of_band_object_tamper()",
        "redteam_http_recall_rejects_out_of_band_object_tamper body",
    );
    let grpc_tamper_test = source_top_level_item_after_marker(
        redteam,
        "async fn redteam_grpc_recall_rejects_out_of_band_object_tamper()",
        "redteam_grpc_recall_rejects_out_of_band_object_tamper body",
    );

    assert!(
        !http_tamper_test.contains(".unwrap()"),
        "HTTP redteam tamper test should route fallible setup through named helpers"
    );
    assert!(
        !grpc_tamper_test.contains(".unwrap()"),
        "gRPC redteam tamper test should route fallible setup through named helpers"
    );
    for helper in [
        "fn object_id_from_hex(",
        "fn expect_json_str_field",
        "async fn expect_http_response",
        "async fn expect_json_response",
        "fn expect_cap_b64(",
        "async fn connect_memory_service(",
        "fn expect_grpc_response<T>(",
        "fn tamper_harness_object_bytes(",
    ] {
        assert!(
            redteam.contains(helper),
            "redteam HTTP/gRPC setup should define `{helper}`"
        );
    }
    for diagnostic in [
        "object id hex decode failed",
        "object id hex decoded to",
        "missing string field",
        "HTTP request failed",
        "JSON response decode failed",
        "capability encoding failed",
        "gRPC connect failed",
        "gRPC request failed",
        "store lock failed",
        "object tamper failed",
    ] {
        assert!(
            redteam.contains(diagnostic),
            "redteam helper diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn redteam_unix_setup_uses_named_diagnostic_helpers() {
    let redteam = include_str!("redteam_paths.rs");
    let unix_tamper_test = source_top_level_item_after_marker(
        redteam,
        "async fn redteam_unix_recall_verified_rejects_out_of_band_object_tamper()",
        "redteam_unix_recall_verified_rejects_out_of_band_object_tamper body",
    );

    assert!(
        !unix_tamper_test.contains(".unwrap()"),
        "Unix redteam tamper test should route fallible setup through named helpers"
    );
    for helper in [
        "fn expect_tempdir(",
        "fn expect_test_state(",
        "fn expect_agent_cap(",
        "fn remember_and_tamper_unix_object(",
        "async fn expect_unix_response(",
    ] {
        assert!(
            redteam.contains(helper),
            "redteam Unix setup should define `{helper}`"
        );
    }
    for diagnostic in [
        "tempdir failed",
        "test state setup failed",
        "agent capability creation failed",
        "Unix redteam store remember failed",
        "Unix request failed",
    ] {
        assert!(
            redteam.contains(diagnostic),
            "redteam Unix setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn redteam_unix_tamper_recall_uses_named_rejection_helper() {
    let redteam = include_str!("redteam_paths.rs");
    let unix_tamper_test = source_top_level_item_after_marker(
        redteam,
        "async fn redteam_unix_recall_verified_rejects_out_of_band_object_tamper()",
        "redteam_unix_recall_verified_rejects_out_of_band_object_tamper body",
    );

    for inline_report in [
        "tampered recall succeeded",
        "unexpected unix error",
        "KernelResponse::Ok { payload } =>",
    ] {
        assert!(
            !unix_tamper_test.contains(inline_report),
            "redteam Unix tamper test should route `{inline_report}` reporting through a named helper"
        );
    }
    assert!(
        redteam.contains("type UnixTamperRecallCheck = Result<(), String>"),
        "redteam Unix tamper recall checks should name the validation result type"
    );
    assert!(
        redteam.contains("fn assert_unix_tamper_recall_rejected("),
        "redteam Unix tamper recall checks should use a named assertion helper"
    );
    assert!(
        redteam.contains("fn expect_unix_tamper_recall_rejected("),
        "redteam Unix tamper recall checks should separate validation from reporting"
    );
    assert!(
        redteam.contains("fn is_unix_tamper_rejection("),
        "redteam Unix tamper recall checks should use a named rejection classifier"
    );
    assert!(
        redteam.contains("fn assert_unix_tamper_recall_check_passed("),
        "redteam Unix tamper recall failures should route through a named reporter"
    );
    assert!(
        unix_tamper_test.contains("assert_unix_tamper_recall_rejected(resp);"),
        "redteam Unix tamper test should call the named tamper-rejection assertion"
    );
}

#[test]
fn grpc_api_setup_uses_named_diagnostic_helpers() {
    let grpc_api = include_str!("grpc_api.rs");

    assert_eq!(
        count_normalized_source(grpc_api, "MemoryServiceClient::connect("),
        1,
        "gRPC API tests should route client connections through one shared diagnostic helper"
    );
    for inline_expect in [
        ".expect(\"connect grpc\")",
        ".expect(\"connect\")",
        ".expect(\"cap b64\")",
        ".expect(\"remember\")",
        ".expect(\"recall\")",
        ".expect(\"forget\")",
        ".expect(\"health\")",
        ".expect(\"authenticated prove absent\")",
        ".expect_err(",
        ".store.lock().expect(\"lock\")",
        ".expect(\"seed oversized entry\")",
    ] {
        assert!(
            !grpc_api.contains(inline_expect),
            "gRPC API tests should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "async fn connect_grpc_memory_service(",
        "fn expect_grpc_cap_b64(",
        "fn expect_grpc_response<T>(",
        "fn expect_grpc_status_error<T>(",
        "fn expect_grpc_store_lock<T, E: std::fmt::Debug>(",
        "fn seed_oversized_grpc_recall_entry(",
    ] {
        assert!(
            grpc_api.contains(helper),
            "gRPC API setup should define `{helper}`"
        );
    }
    for diagnostic in [
        "gRPC connect failed",
        "gRPC capability encoding failed",
        "gRPC request failed",
        "expected gRPC status error",
        "gRPC store lock failed",
        "oversized gRPC recall entry seed failed",
    ] {
        assert!(
            grpc_api.contains(diagnostic),
            "gRPC API setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn test_harness_uses_explicit_async_shutdown() {
    let common = include_str!("common/mod.rs");

    assert!(
        common.contains("pub async fn shutdown(self)"),
        "TestHarness must expose an explicit async shutdown method"
    );
    assert!(
        !common.contains("impl Drop for TestHarness"),
        "TestHarness must not rely on no-op Drop/runtime teardown for server lifecycle"
    );
    assert!(
        !common.contains("OS reclaims port on process exit"),
        "TestHarness lifecycle comments must not normalize leaked test servers"
    );
}

#[test]
fn test_harness_setup_uses_named_diagnostic_helpers() {
    let common = include_str!("common/mod.rs");

    for inline_expect in [
        ".expect(\"tempdir\")",
        ".expect(\"test_state\")",
        ".expect(\"agent cap\")",
        ".expect(\"tool cap\")",
        ".expect(\"lock\")",
        ".expect(\"addr\")",
        ".expect(\"start\")",
        ".expect(\"grpc\")",
        ".expect(\"cap b64\")",
        ".unwrap()",
    ] {
        assert!(
            !common.contains(inline_expect),
            "TestHarness setup should route `{inline_expect}` through named diagnostic helpers"
        );
    }
    for helper in [
        "fn expect_harness_tempdir(",
        "fn expect_harness_state(",
        "fn expect_agent_capability(",
        "fn expect_tool_capability(",
        "fn authorize_harness_tool_writer(",
        "fn loopback_test_addr(",
        "async fn start_harness_server(",
        "fn expect_harness_grpc_addr(",
        "fn expect_harness_cap_b64(",
    ] {
        assert!(
            common.contains(helper),
            "TestHarness setup should define `{helper}`"
        );
    }
    for diagnostic in [
        "test harness tempdir failed",
        "test harness state setup failed",
        "test harness agent capability failed",
        "test harness tool capability failed",
        "test harness store lock failed",
        "test harness loopback address parse failed",
        "test harness server start failed",
        "test harness gRPC address missing",
        "test harness capability encoding failed",
    ] {
        assert!(
            common.contains(diagnostic),
            "TestHarness setup diagnostics should include `{diagnostic}`"
        );
    }
}

#[test]
fn test_harness_users_shutdown_explicitly() {
    for (path, contents) in [
        ("http_api.rs", include_str!("http_api.rs")),
        ("grpc_api.rs", include_str!("grpc_api.rs")),
        ("sync_ws.rs", include_str!("sync_ws.rs")),
        ("redteam_paths.rs", include_str!("redteam_paths.rs")),
    ] {
        let starts = contents.matches("TestHarness::new().await").count();
        let shutdowns = contents.matches("h.shutdown().await").count();
        assert_eq!(
            starts, shutdowns,
            "{path} must explicitly shut down every TestHarness it starts"
        );
    }
}

#[test]
fn daemon_integration_modules_are_wired_through_declared_targets() {
    let cargo = include_str!("../Cargo.toml");
    let api_integration = include_str!("api_integration.rs");
    let unix_api = include_str!("unix_api.rs");
    let redteam_paths = include_str!("redteam_paths.rs");

    for target in [
        "name = \"api_integration\"",
        "name = \"unix_api\"",
        "name = \"redteam_paths\"",
    ] {
        assert!(
            cargo.contains(target),
            "mnemed Cargo.toml should declare `{target}` under autotests = false"
        );
    }
    for module in ["mod http_api;", "mod grpc_api;", "mod sync_ws;"] {
        assert!(
            api_integration.contains(module),
            "api_integration should compile `{module}`"
        );
    }
    assert!(
        unix_api.contains("mod unix_ready;") && redteam_paths.contains("mod unix_ready;"),
        "unix_ready should compile through unix_api and redteam_paths"
    );
}

#[test]
fn daemon_http_bind_refuses_non_loopback_without_tls() {
    let lib = include_str!("../src/lib.rs");
    let main = include_str!("../src/main.rs");

    assert!(
        lib.contains("pub fn ensure_http_bind_loopback("),
        "mnemed library should expose loopback-only HTTP bind guard"
    );
    assert!(
        lib.contains("ensure_http_bind_loopback(config.http_addr)?"),
        "mnemed start path should enforce loopback-only HTTP binds"
    );
    assert!(
        main.contains("refusing non-loopback --http bind without TLS"),
        "mnemed CLI should fail closed on non-loopback --http without TLS"
    );
    assert!(
        main.contains("let http_addr: SocketAddr"),
        "mnemed CLI HTTP bind parse should be typed for loopback enforcement"
    );
}

#[test]
fn boot_daemon_state_opens_existing_store_instead_of_recreating() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        lib.contains("pub fn boot_daemon_state("),
        "mnemed should expose a production boot helper"
    );
    assert!(
        lib.contains("store_head_entry_exists_no_follow(store_path)?"),
        "boot path should use a no-follow HEAD entry check before open-vs-create"
    );
    assert!(
        lib.contains("Store::open(store_path, operator.clone())?"),
        "boot path should call Store::open for existing stores"
    );
}

#[test]
fn unix_peer_credentials_are_checked_before_serving() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        unix.contains("fn verify_unix_peer_credentials("),
        "Unix kernel API should verify peer credentials"
    );
    assert!(
        unix.contains("getpeereid(") || unix.contains("SO_PEERCRED"),
        "Unix kernel API should use getpeereid or SO_PEERCRED for same-uid enforcement"
    );
    assert!(
        unix.contains("unix peer uid mismatch"),
        "Unix kernel API should reject cross-uid peers"
    );
}
