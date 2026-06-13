//! Minimal MCP JSON-RPC 2.0 over stdio (tools/list + tools/call + initialize).

use crate::handlers::{self, MemoryHandlers};
use crate::honesty::{
    AINJ_MITIGATION, FORGET_DESCRIPTION, FORGET_PROOF_DESCRIPTION, HONESTY_FOOTER,
    RECALL_DESCRIPTION, REMEMBER_DESCRIPTION, protocol_error_message, tool_error_message,
};
use mneme_core::FixedPointEmbedding;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_TOOL_CONTENT_BYTES: usize = 1_048_576;
const MAX_TOOL_QUERY_BYTES: usize = 16_384;
/// Upper bound on query/record embedding dimensionality accepted over the wire.
const MAX_EMBEDDING_DIMS: usize = 4096;
/// Default fixed-point scale for `quantize_from_f32` when the caller omits one.
/// `component = round(value / 2^scale)`; -8 (factor 1/256) suits unit-norm
/// embeddings. remember and recall MUST use the same scale for distances to align.
const DEFAULT_EMBEDDING_SCALE: i8 = -8;

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

pub fn run_stdio_loop(handlers: &MemoryHandlers) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_error(&mut stdout, Value::Null, -32700, e.to_string())?;
                continue;
            }
        };
        if req.jsonrpc != "2.0" {
            if let Some(id) = req.id {
                write_error(&mut stdout, id, -32600, "invalid jsonrpc version".into())?;
            }
            continue;
        }
        let id = req.id.unwrap_or(Value::Null);
        if req.method == "notifications/initialized" {
            continue;
        }
        match dispatch(handlers, &req.method, &req.params) {
            Ok(value) => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(value),
                    error: None,
                };
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            Err(msg) => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(tool_result_error(msg)),
                    error: None,
                };
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
        }
    }
    Ok(())
}

fn write_error(out: &mut impl Write, id: Value, code: i32, message: String) -> io::Result<()> {
    let resp = JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError { code, message }),
    };
    writeln!(out, "{}", serde_json::to_string(&resp)?)?;
    out.flush()
}

pub fn dispatch(handlers: &MemoryHandlers, method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "mneme-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("tools/call: missing name")?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            call_tool(handlers, name, &args)
        }
        _ => Err(protocol_error_message(format!(
            "method not found: {method}"
        ))),
    }
}

fn remember_description() -> String {
    format!("{REMEMBER_DESCRIPTION}{AINJ_MITIGATION} {HONESTY_FOOTER}")
}

fn recall_description() -> String {
    format!("{RECALL_DESCRIPTION}{HONESTY_FOOTER}")
}

fn forget_description() -> String {
    format!("{FORGET_DESCRIPTION}{HONESTY_FOOTER}")
}

fn forget_proof_description() -> String {
    format!("{FORGET_PROOF_DESCRIPTION}{HONESTY_FOOTER}")
}

pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "memory.remember",
            "description": remember_description(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": { "type": "string" },
                    "kind": { "type": "string", "enum": ["episodic", "semantic", "procedural", "working", "identity"] },
                    "namespace": { "type": "string" },
                    "name": { "type": "string", "description": "logical key name (default: entry)" },
                    "embedding": { "type": "array", "items": { "type": "number" }, "description": "Optional query/record vector; when present the entry is indexed as semantic (kind forced to semantic) for embedding recall." },
                    "embedding_scale": { "type": "integer", "description": "Fixed-point scale for quantization (component = round(value / 2^scale)); default -8. Use the SAME scale for remember and recall." }
                },
                "required": ["content", "kind", "namespace"]
            }
        }),
        json!({
            "name": "memory.recall",
            "description": recall_description(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "Exact logical key name (required unless `embedding` is given)" },
                    "query": { "type": "string", "description": "Deprecated alias for `key`" },
                    "embedding": { "type": "array", "items": { "type": "number" }, "description": "Optional query vector; when present, runs verified semantic (HNSW) recall instead of exact-key lookup. Procedure-faithful over the committed candidate set under the quantized metric — NOT true nearest neighbors (§3)." },
                    "embedding_scale": { "type": "integer", "description": "Fixed-point scale (default -8); must match the scale used at remember time." },
                    "min_tier": { "type": "string", "enum": ["quarantine", "working", "trusted", "identity"] },
                    "namespace": { "type": "string" }
                },
                "required": ["min_tier"]
            }
        }),
        json!({
            "name": "memory.forget",
            "description": forget_description(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": { "type": "string" },
                    "target": { "type": "string" }
                },
                "required": ["namespace", "target"]
            }
        }),
        json!({
            "name": "memory.forget_proof",
            "description": forget_proof_description(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": { "type": "string" },
                    "target": { "type": "string" }
                },
                "required": ["namespace", "target"]
            }
        }),
    ]
}

fn call_tool(handlers: &MemoryHandlers, name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "memory.remember" => {
            let content = bounded_arg_str(args, "content", MAX_TOOL_CONTENT_BYTES)?;
            let kind = handlers::parse_kind(arg_str(args, "kind")?).map_err(tool_error_message)?;
            let namespace = arg_str(args, "namespace")?;
            let entry_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("entry")
                .to_string();
            let embedding = parse_embedding_arg(args)?;
            let session = [0x4d, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let out = handlers
                .remember(
                    content.as_bytes(),
                    kind,
                    namespace,
                    &entry_name,
                    session,
                    embedding,
                )
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "object_id_hex": out.object_id_hex,
                "root_hash_hex": out.root_hash_hex,
                "trust_tier": out.trust_tier,
            })))
        }
        "memory.recall" => {
            let embedding = parse_embedding_arg(args)?;
            let semantic = embedding.is_some();
            let min_tier =
                handlers::parse_min_tier(arg_str(args, "min_tier")?).map_err(tool_error_message)?;
            let namespace = args
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("user");
            // Exact recall needs a logical key; semantic recall searches purely by the
            // embedding (the kernel ignores logical_key on that path), so key is optional.
            let key = if semantic {
                args.get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                recall_key_arg(args)?
            };
            let entries = handlers
                .recall(namespace, &key, min_tier, embedding)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(
                json!({ "entries": entries, "key": key, "semantic": semantic }),
            ))
        }
        "memory.forget" => {
            let namespace = arg_str(args, "namespace")?;
            let target = bounded_arg_str(args, "target", MAX_TOOL_QUERY_BYTES)?;
            let out = handlers
                .forget(namespace, target)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(
                json!({ "root_hash_hex": out.root_hash_hex }),
            ))
        }
        "memory.forget_proof" => {
            let namespace = arg_str(args, "namespace")?;
            let target = bounded_arg_str(args, "target", MAX_TOOL_QUERY_BYTES)?;
            let out = handlers
                .forget_with_proof(namespace, target)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "root_hash_hex": out.root_hash_hex,
                "proof_version": out.proof_version,
                "proof_cbor_b64": out.proof_cbor_b64,
                "root": out.root,
            })))
        }
        _ => Err(protocol_error_message(format!("unknown tool: {name}"))),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| protocol_error_message(format!("missing argument: {key}")))
}

fn bounded_arg_str<'a>(args: &'a Value, key: &str, max_bytes: usize) -> Result<&'a str, String> {
    let value = arg_str(args, key)?;
    if value.len() > max_bytes {
        return Err(protocol_error_message(format!(
            "argument `{key}` exceeds {max_bytes} byte limit"
        )));
    }
    Ok(value)
}

/// Parse an optional `embedding` (array of numbers) + optional `embedding_scale`
/// (i8) into a quantized fixed-point embedding. Returns `Ok(None)` when absent.
/// Fail-closed on malformed input (non-array, non-numeric, empty, oversized, or
/// out-of-range quantization).
fn parse_embedding_arg(args: &Value) -> Result<Option<FixedPointEmbedding>, String> {
    let Some(raw) = args.get("embedding") else {
        return Ok(None);
    };
    let arr = raw.as_array().ok_or_else(|| {
        protocol_error_message("argument `embedding` must be an array of numbers")
    })?;
    if arr.is_empty() || arr.len() > MAX_EMBEDDING_DIMS {
        return Err(protocol_error_message(format!(
            "argument `embedding` length must be 1..={MAX_EMBEDDING_DIMS}"
        )));
    }
    let mut values = Vec::with_capacity(arr.len());
    for v in arr {
        let f = v.as_f64().ok_or_else(|| {
            protocol_error_message("argument `embedding` entries must be numbers")
        })?;
        values.push(f as f32);
    }
    let scale: i8 = match args.get("embedding_scale") {
        Some(s) => {
            let n = s.as_i64().ok_or_else(|| {
                protocol_error_message("argument `embedding_scale` must be an integer")
            })?;
            i8::try_from(n).map_err(|_| {
                protocol_error_message("argument `embedding_scale` out of range (i8)")
            })?
        }
        None => DEFAULT_EMBEDDING_SCALE,
    };
    FixedPointEmbedding::quantize_from_f32(&values, scale)
        .map(Some)
        .map_err(tool_error_message)
}

fn recall_key_arg(args: &Value) -> Result<String, String> {
    if args.get("key").and_then(|v| v.as_str()).is_some() {
        return bounded_arg_str(args, "key", MAX_TOOL_QUERY_BYTES).map(str::to_string);
    }
    if let Some(query) = args.get("query").and_then(|v| v.as_str()) {
        if query.len() > MAX_TOOL_QUERY_BYTES {
            return Err(protocol_error_message(format!(
                "argument `query` exceeds {MAX_TOOL_QUERY_BYTES} byte limit"
            )));
        }
        return Ok(query.to_string());
    }
    Err(protocol_error_message(
        "missing argument: key (exact logical key name; semantic search is not supported)",
    ))
}

fn tool_result_json(value: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
        "isError": false
    })
}

fn tool_result_error(message: String) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}
