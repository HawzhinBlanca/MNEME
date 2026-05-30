//! Minimal MCP JSON-RPC 2.0 over stdio (tools/list + tools/call + initialize).

use crate::handlers::{self, MemoryHandlers};
use crate::honesty::{
    AINJ_MITIGATION, FORGET_DESCRIPTION, HONESTY_FOOTER, RECALL_DESCRIPTION, REMEMBER_DESCRIPTION,
    tool_error_message,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

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
        let result = dispatch(handlers, &req.method, &req.params);
        match result {
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
            Err(msg) => write_error(&mut stdout, id, -32000, msg)?,
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
        _ => Err(format!("method not found: {method}")),
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
                    "name": { "type": "string", "description": "logical key name (default: entry)" }
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
                    "query": { "type": "string" },
                    "min_tier": { "type": "string", "enum": ["quarantine", "working", "trusted", "identity"] },
                    "namespace": { "type": "string" }
                },
                "required": ["query", "min_tier"]
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
    ]
}

fn call_tool(handlers: &MemoryHandlers, name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "memory.remember" => {
            let content = arg_str(args, "content")?;
            let kind = handlers::parse_kind(arg_str(args, "kind")?).map_err(tool_error_message)?;
            let namespace = arg_str(args, "namespace")?;
            let entry_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("entry")
                .to_string();
            let session = [0x4d, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let out = handlers
                .remember(content.as_bytes(), kind, namespace, &entry_name, session)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "object_id_hex": out.object_id_hex,
                "root_hash_hex": out.root_hash_hex,
                "trust_tier": out.trust_tier,
            })))
        }
        "memory.recall" => {
            let query = arg_str(args, "query")?;
            let min_tier =
                handlers::parse_min_tier(arg_str(args, "min_tier")?).map_err(tool_error_message)?;
            let namespace = args
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("user");
            let entries = handlers
                .recall(namespace, query, min_tier)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({ "entries": entries })))
        }
        "memory.forget" => {
            let namespace = arg_str(args, "namespace")?;
            let target = arg_str(args, "target")?;
            let out = handlers
                .forget(namespace, target)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(
                json!({ "root_hash_hex": out.root_hash_hex }),
            ))
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing argument: {key}"))
}

fn tool_result_json(value: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
        "isError": false
    })
}
