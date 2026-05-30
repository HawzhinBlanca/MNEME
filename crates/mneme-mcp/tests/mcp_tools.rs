//! MCP protocol harness — JSON-RPC dispatch without live stdio.

use mneme_mcp::protocol::{dispatch, tool_definitions};
use mneme_mcp::store_open::test_runtime;
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
