//! MCP protocol harness — JSON-RPC dispatch without live stdio.

use mneme_mcp::protocol::{dispatch, tool_definitions};
use mneme_mcp::store_open::test_runtime;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn lists_four_record_tools_with_honesty_descriptions() {
    let tools = tool_definitions();
    let names: Vec<_> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            "record-with-provenance",
            "recall-with-signed-chain",
            "erase-with-receipt-and-proof-of-absence",
            "verify"
        ]
    );
    let record = tools[0]["description"].as_str().unwrap_or("");
    assert!(record.contains("quarantine"));
    assert!(record.contains("cryptographically airtight"));
    let recall = tools[1]["description"].as_str().unwrap_or("");
    assert!(recall.contains("recall_verified"));
    assert!(recall.contains("procedure-faithfulness"));
    let erase = tools[2]["description"].as_str().unwrap_or("");
    assert!(erase.contains("proof of absence"));
    assert!(erase.contains("STATISTICAL attestation"));
    let verify = tools[3]["description"].as_str().unwrap_or("");
    assert!(verify.contains("fail-closed"));
}

#[test]
fn mcp_tools_call_record_recall_erase_verify_roundtrip() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let h = &rt.handlers;

    let record = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "record-with-provenance",
            "arguments": {
                "content": "dark mode",
                "kind": "semantic",
                "namespace": "user",
                "name": "theme"
            }
        }),
    )
    .unwrap();
    assert_eq!(record["isError"], false);
    let record_text = record["content"][0]["text"].as_str().unwrap();
    assert!(record_text.contains("root_signature_hex"));

    let recall = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "recall-with-signed-chain",
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
    assert!(text.contains("root_signature_hex"));

    let erase = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "erase-with-receipt-and-proof-of-absence",
            "arguments": { "namespace": "user", "target": "theme" }
        }),
    )
    .unwrap();
    let erase_text = erase["content"][0]["text"].as_str().unwrap();
    assert!(erase_text.contains("forget_proof"));
    assert!(erase_text.contains("absence_proof"));
    assert!(erase_text.contains("shred_commit_hex"));

    let verify = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "verify",
            "arguments": {}
        }),
    )
    .unwrap();
    let verify_text = verify["content"][0]["text"].as_str().unwrap();
    assert!(verify_text.contains("object_count"));

    let err = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "recall-with-signed-chain",
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
