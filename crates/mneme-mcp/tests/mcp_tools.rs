//! MCP protocol harness — JSON-RPC dispatch without live stdio.

use base64::Engine;
use mneme_core::MnemeError;
use mneme_mcp::protocol::{dispatch, tool_definitions};
use mneme_mcp::store_open::test_runtime;
use mneme_mcp::{HONESTY_FOOTER, tool_error_message};
use serde_json::Value;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn lists_memory_tools_with_honesty_descriptions() {
    let tools = tool_definitions();
    let names: Vec<_> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            "memory.remember",
            "memory.recall",
            "memory.forget",
            "memory.forget_proof"
        ]
    );
    let remember = tools[0]["description"].as_str().unwrap_or("");
    assert!(remember.contains("quarantine"));
    assert!(remember.contains("authenticated"));
    let recall = tools[1]["description"].as_str().unwrap_or("");
    assert!(recall.contains("recall_verified"));
    assert!(recall.contains("procedure-faithfulness"));
    let forget_proof = tools[3]["description"].as_str().unwrap_or("");
    assert!(forget_proof.contains("ForgetProof"));
    assert!(forget_proof.contains("signed-root"));
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
fn mcp_forget_proof_tool_returns_verifiable_cbor_and_signed_root_fields() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let h = &rt.handlers;

    let remember = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.remember",
            "arguments": {
                "content": "delete me",
                "kind": "semantic",
                "namespace": "user",
                "name": "proof-target"
            }
        }),
    )
    .unwrap();
    assert_eq!(remember["isError"], false);

    let forget_proof = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.forget_proof",
            "arguments": { "namespace": "user", "target": "proof-target" }
        }),
    )
    .unwrap();
    assert_eq!(forget_proof["isError"], false);
    let body = tool_result_body(&forget_proof);
    let proof_b64 = body["proof_cbor_b64"].as_str().expect("proof b64");
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .expect("decode proof");
    let proof = mneme_core::decode_forget_proof(&proof_bytes).expect("parse proof");

    let root = body["root"].as_object().expect("root object");
    assert_eq!(
        hex::encode(proof.root_bound),
        root["preimage_hash_hex"].as_str().expect("root hash")
    );
    assert_eq!(
        hex::encode(proof.root_bound),
        body["root_hash_hex"].as_str().expect("root hash alias")
    );
    assert_eq!(proof.version, mneme_core::FORGET_PROOF_VERSION);
    assert!(root["signature_hex"].as_str().expect("signature").len() >= 128);
    assert!(root["sequence"].as_u64().expect("root sequence") > 0);

    let err = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.recall",
            "arguments": {
                "query": "proof-target",
                "min_tier": "quarantine",
                "namespace": "user"
            }
        }),
    )
    .unwrap_err();
    assert!(err.contains("Forgotten") || err.contains("forgotten"));
}

#[test]
fn mcp_forget_proof_failure_returns_is_error_with_honesty_footer() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let h = &rt.handlers;

    let err = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.forget_proof",
            "arguments": { "namespace": "user", "target": "never-written" }
        }),
    )
    .unwrap_err();
    assert!(
        err.contains("Forgotten") || err.to_ascii_lowercase().contains("forgotten"),
        "expected forgotten/absent error, got: {err}"
    );
    for phrase in ["authenticated", "procedure-faithfulness"] {
        assert!(
            err.contains(phrase),
            "forget-proof error missing `{phrase}`: {err}"
        );
    }
}

#[test]
fn mcp_protocol_validation_errors_include_honesty_footer() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let h = &rt.handlers;

    let err = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.recall",
            "arguments": { "min_tier": "quarantine" }
        }),
    )
    .unwrap_err();
    assert!(
        err.contains("missing argument: key"),
        "expected missing key error, got: {err}"
    );
    assert_honesty_footer(&err);

    let err = dispatch(
        h,
        "tools/call",
        &json!({
            "name": "memory.remember",
            "arguments": { "kind": "semantic", "namespace": "user" }
        }),
    )
    .unwrap_err();
    assert!(
        err.contains("missing argument: content"),
        "expected missing content error, got: {err}"
    );
    assert_honesty_footer(&err);

    let err = dispatch(
        h,
        "tools/call",
        &json!({ "name": "memory.nope", "arguments": {} }),
    )
    .unwrap_err();
    assert!(
        err.contains("unknown tool"),
        "expected unknown tool error, got: {err}"
    );
    assert_honesty_footer(&err);
}

fn assert_honesty_footer(err: &str) {
    for phrase in ["authenticated", "procedure-faithfulness"] {
        assert!(
            err.contains(phrase),
            "protocol validation error missing `{phrase}`: {err}"
        );
    }
}

#[test]
fn initialize_returns_server_info() {
    let dir = tempdir().unwrap();
    let rt = test_runtime(dir.path());
    let res = dispatch(&rt.handlers, "initialize", &json!({})).unwrap();
    assert_eq!(res["serverInfo"]["name"], "mneme-mcp");
}

fn tool_result_body(result: &Value) -> Value {
    let text = result["content"][0]["text"]
        .as_str()
        .expect("tool text body");
    serde_json::from_str(text).expect("tool JSON body")
}
