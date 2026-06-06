//! Minimal MCP JSON-RPC 2.0 over stdio (tools/list + tools/call + initialize).

use crate::handlers::{self, MemoryHandlers};
use crate::honesty::{
    AINJ_MITIGATION, ERASE_DESCRIPTION, HONESTY_FOOTER, RECALL_DESCRIPTION, RECORD_DESCRIPTION,
    VERIFY_DESCRIPTION, tool_error_message,
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

/// Per-frame size cap for the stdio JSON-RPC transport. A single newline-
/// delimited request larger than this is rejected with a JSON-RPC error instead
/// of being buffered without bound (`BufRead::lines` would allocate the whole
/// line). 16 MiB is far above any legitimate tool call.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

enum Frame {
    Line(String),
    TooLarge,
    BadEncoding,
    Eof,
}

/// Read one newline-delimited frame, capped at `max` bytes, using buffered
/// `fill_buf`/`consume` (no byte-at-a-time reads). On overflow it keeps draining
/// to the next newline so the stream resynchronises, then reports `TooLarge`.
fn read_frame(reader: &mut impl BufRead, max: usize) -> io::Result<Frame> {
    let mut buf: Vec<u8> = Vec::new();
    let mut overflow = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(c) => c,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            if buf.is_empty() && !overflow {
                return Ok(Frame::Eof);
            }
            break;
        }
        if let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
            if !overflow && buf.len() + nl <= max {
                buf.extend_from_slice(&chunk[..nl]);
            } else {
                overflow = true;
            }
            reader.consume(nl + 1);
            break;
        }
        let len = chunk.len();
        if !overflow && buf.len() + len <= max {
            buf.extend_from_slice(chunk);
        } else {
            overflow = true;
        }
        reader.consume(len);
    }
    if overflow {
        return Ok(Frame::TooLarge);
    }
    match String::from_utf8(buf) {
        Ok(mut s) => {
            if s.ends_with('\r') {
                s.pop();
            }
            Ok(Frame::Line(s))
        }
        Err(_) => Ok(Frame::BadEncoding),
    }
}

pub fn run_stdio_loop(handlers: &MemoryHandlers) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = io::stdout();
    loop {
        let line = match read_frame(&mut reader, MAX_FRAME_BYTES)? {
            Frame::Eof => break,
            Frame::TooLarge => {
                write_error(
                    &mut stdout,
                    Value::Null,
                    -32600,
                    "request frame exceeds maximum size".into(),
                )?;
                continue;
            }
            Frame::BadEncoding => {
                write_error(
                    &mut stdout,
                    Value::Null,
                    -32700,
                    "request frame is not valid UTF-8".into(),
                )?;
                continue;
            }
            Frame::Line(line) => line,
        };
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

fn record_description() -> String {
    format!("{RECORD_DESCRIPTION}{AINJ_MITIGATION} {HONESTY_FOOTER}")
}

fn recall_description() -> String {
    format!("{RECALL_DESCRIPTION}{HONESTY_FOOTER}")
}

fn erase_description() -> String {
    format!("{ERASE_DESCRIPTION}{HONESTY_FOOTER}")
}

fn verify_description() -> String {
    format!("{VERIFY_DESCRIPTION}{HONESTY_FOOTER}")
}

pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "record-with-provenance",
            "description": record_description(),
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
            "name": "recall-with-signed-chain",
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
            "name": "erase-with-receipt-and-proof-of-absence",
            "description": erase_description(),
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
            "name": "verify",
            "description": verify_description(),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
    ]
}

fn call_tool(handlers: &MemoryHandlers, name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "record-with-provenance" => {
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
                .record_with_provenance(content.as_bytes(), kind, namespace, &entry_name, session)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "object_id_hex": out.object_id_hex,
                "root_hash_hex": out.root_hash_hex,
                "root": out.root,
                "trust_tier": out.trust_tier,
            })))
        }
        "recall-with-signed-chain" => {
            let query = arg_str(args, "query")?;
            let min_tier =
                handlers::parse_min_tier(arg_str(args, "min_tier")?).map_err(tool_error_message)?;
            let namespace = args
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("user");
            let out = handlers
                .recall_with_signed_chain(namespace, query, min_tier)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "entries": out.entries,
                "root_hash_hex": out.root_hash_hex,
                "root": out.root,
            })))
        }
        "erase-with-receipt-and-proof-of-absence" => {
            let namespace = arg_str(args, "namespace")?;
            let target = arg_str(args, "target")?;
            let out = handlers
                .erase_with_receipt_and_proof_of_absence(namespace, target)
                .map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "root_hash_hex": out.root_hash_hex,
                "root": out.root,
                "forget_proof": out.forget_proof,
                "absence_proof": out.absence_proof,
            })))
        }
        "verify" => {
            let out = handlers.verify().map_err(tool_error_message)?;
            Ok(tool_result_json(json!({
                "root_hash_hex": out.root_hash_hex,
                "root": out.root,
                "object_count": out.object_count,
            })))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_frame_splits_lines_then_eof() {
        let mut r = Cursor::new(b"abc\ndef\n".to_vec());
        assert!(matches!(read_frame(&mut r, 1024).unwrap(), Frame::Line(s) if s == "abc"));
        assert!(matches!(read_frame(&mut r, 1024).unwrap(), Frame::Line(s) if s == "def"));
        assert!(matches!(read_frame(&mut r, 1024).unwrap(), Frame::Eof));
    }

    #[test]
    fn read_frame_strips_trailing_cr() {
        let mut r = Cursor::new(b"abc\r\n".to_vec());
        assert!(matches!(read_frame(&mut r, 1024).unwrap(), Frame::Line(s) if s == "abc"));
    }

    #[test]
    fn read_frame_trailing_line_without_newline() {
        let mut r = Cursor::new(b"tail".to_vec());
        assert!(matches!(read_frame(&mut r, 1024).unwrap(), Frame::Line(s) if s == "tail"));
        assert!(matches!(read_frame(&mut r, 1024).unwrap(), Frame::Eof));
    }

    #[test]
    fn read_frame_caps_oversized_and_resyncs() {
        // A line over the cap, then a normal line: the big line is rejected as
        // TooLarge and the reader resynchronises to the next frame.
        let mut data = vec![b'x'; 100];
        data.push(b'\n');
        data.extend_from_slice(b"ok\n");
        let mut r = Cursor::new(data);
        assert!(matches!(read_frame(&mut r, 10).unwrap(), Frame::TooLarge));
        assert!(matches!(read_frame(&mut r, 10).unwrap(), Frame::Line(s) if s == "ok"));
        assert!(matches!(read_frame(&mut r, 10).unwrap(), Frame::Eof));
    }

    #[test]
    fn read_frame_exact_cap_is_accepted() {
        let mut r = Cursor::new(b"0123456789\n".to_vec());
        assert!(matches!(read_frame(&mut r, 10).unwrap(), Frame::Line(s) if s == "0123456789"));
    }

    #[test]
    fn read_frame_rejects_invalid_utf8() {
        let mut r = Cursor::new(vec![0xff, 0xfe, b'\n']);
        assert!(matches!(
            read_frame(&mut r, 1024).unwrap(),
            Frame::BadEncoding
        ));
    }
}
