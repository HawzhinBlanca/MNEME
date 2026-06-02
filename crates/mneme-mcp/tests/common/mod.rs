//! Shared stdio JSON-RPC client for live `mneme-mcp` subprocess tests (B5).

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

pub struct McpStdioClient {
    child: Child,
    next_id: u64,
}

impl McpStdioClient {
    pub fn spawn(store_path: &Path) -> Self {
        let bin = env!("CARGO_BIN_EXE_mneme-mcp");
        let child = Command::new(bin)
            .env("MNEME_STORE_PATH", store_path)
            .env(
                "MNEME_OPERATOR_SEED",
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mneme-mcp");
        Self { child, next_id: 1 }
    }

    pub fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{}", req).expect("write request");
        stdin.flush().expect("flush stdin");

        let stdout = self.child.stdout.as_mut().expect("stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        let resp: Value = serde_json::from_str(line.trim()).expect("parse response");
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], id);
        if let Some(err) = resp.get("error") {
            panic!("JSON-RPC error for {method}: {err}");
        }
        resp["result"].clone()
    }

    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        self.call(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    pub fn call_tool_expect_error(&mut self, name: &str, arguments: Value) -> String {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        });
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{}", req).expect("write request");
        stdin.flush().expect("flush stdin");

        let stdout = self.child.stdout.as_mut().expect("stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        let resp: Value = serde_json::from_str(line.trim()).expect("parse response");
        resp["error"]["message"]
            .as_str()
            .expect("error message")
            .to_string()
    }

    /// MCP clients send `notifications/initialized` after `initialize`; server ignores it.
    pub fn notify_initialized(&mut self) {
        let req = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{}", req).expect("write initialized notification");
        stdin.flush().expect("flush stdin");
    }
}

impl Drop for McpStdioClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn tool_text(result: &Value) -> String {
    result["content"][0]["text"]
        .as_str()
        .expect("tool text")
        .to_string()
}
