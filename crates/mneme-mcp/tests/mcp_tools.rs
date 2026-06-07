//! MCP protocol harness — JSON-RPC dispatch without live stdio.

use mneme_core::MnemeError;
use mneme_mcp::protocol::{dispatch, tool_definitions};
use mneme_mcp::store_open::test_runtime;
use mneme_mcp::{HONESTY_FOOTER, tool_error_message};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn lists_three_memory_tools_with_honesty_descriptions() {
    let tools = tool_definitions();
    let names: Vec<_> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    assert_eq!(names, ["memory.remember", "memory.recall", "memory.forget"]);
    let remember = tools[0]["description"].as_str().unwrap_or("");
    assert!(remember.contains("quarantine"));
    assert!(remember.contains("authenticated"));
    let recall = tools[1]["description"].as_str().unwrap_or("");
    assert!(recall.contains("recall_verified"));
    assert!(recall.contains("procedure-faithfulness"));
}

#[test]
fn mcp_honesty_surface_preserves_exact_dominance_distance_caveat() {
    assert_distance_caveat("HONESTY_FOOTER", HONESTY_FOOTER);

    for tool in tool_definitions() {
        let name = tool["name"].as_str().unwrap_or("<unnamed>");
        let description = tool["description"].as_str().unwrap_or("");
        assert_distance_caveat(name, description);
    }

    let error = tool_error_message(MnemeError::ProcedureMismatch);
    assert_distance_caveat("tool error", &error);
}

#[test]
fn mcp_contract_doc_preserves_exact_dominance_distance_caveat() {
    assert_distance_caveat("mneme-mcp contract", include_str!("../docs/CONTRACT.md"));
}

fn assert_distance_caveat(surface: &str, text: &str) {
    for phrase in [
        "authenticated",
        "not truth",
        "procedure-faithfulness",
        "not exact nearest-neighbor",
        "top-k over prover-asserted distances",
        "not top-k by true query-to-embedding distance",
    ] {
        assert!(
            text.contains(phrase),
            "{surface} missing required honesty phrase `{phrase}`: {text}"
        );
    }
}

#[test]
fn mcp_tools_call_remember_recall_forget_roundtrip() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let h = &rt.handlers;

    let remember = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.remember",
            "arguments": {
                "content": "dark mode",
                "kind": "semantic",
                "namespace": "user",
                "name": "theme"
            }
        }),
    )
    .unwrap();
    assert_eq!(remember["isError"], false);

    let recall = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.recall",
            "arguments": {
                "query": "theme",
                "min_tier": "quarantine",
                "namespace": "user"
            }
        }),
    )
    .unwrap();
    let text = recall["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("dark mode"));

    dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.forget",
            "arguments": { "namespace": "user", "target": "theme" }
        }),
    )
    .unwrap();

    let err = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.recall",
            "arguments": {
                "query": "theme",
                "min_tier": "quarantine",
                "namespace": "user"
            }
        }),
    )
    .unwrap_err();
    assert!(err.contains("Forgotten") || err.contains("forgotten"));
}

#[test]
fn initialize_returns_server_info() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let res = dispatch(&rt.handlers, "initialize", &json!({})).unwrap();
    assert_eq!(res["serverInfo"]["name"], "mneme-mcp");
}
