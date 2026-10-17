//! Protocol-level tests for the local MCP stdio server.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpClient {
    fn start(allow: &[&str]) -> Self {
        let mut command = Command::new(binary());
        command.arg("mcp");
        for target in allow {
            command.args(["--allow-target", target]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start MCP server");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut client = Self {
            child,
            stdin,
            stdout,
        };
        let init = client.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pathtrial-test", "version": "1"}
            }),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "pathtrial");
        client.notify("notifications/initialized", json!({}));
        client
    }

    fn write(&mut self, value: Value) {
        writeln!(self.stdin, "{value}").expect("write MCP");
        self.stdin.flush().expect("flush MCP");
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.write(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.write(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read MCP");
        assert!(!line.trim().is_empty(), "MCP closed stdout");
        serde_json::from_str(&line).expect("MCP line is JSON")
    }

    fn call(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
    }

    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn http_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            );
        }
    });
    port
}

#[test]
fn initialize_list_tools_and_capabilities() {
    let mut client = McpClient::start(&[]);
    let tools = client.request(2, "tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names.len(), 9);
    assert!(names.contains(&"pathtrial_capabilities"));
    assert!(names.contains(&"pathtrial_explain_report"));
    let caps = client.call(3, "pathtrial_capabilities", json!({}));
    assert_eq!(caps["result"]["isError"], false);
    assert_eq!(
        caps["result"]["structuredContent"]["core_version"],
        env!("CARGO_PKG_VERSION")
    );
    client.close();
}

#[test]
fn probe_requires_exact_allowlist() {
    let mut client = McpClient::start(&[]);
    let denied = client.call(
        2,
        "pathtrial_http",
        json!({"url": "http://127.0.0.1:9/", "timeout_ms": 500}),
    );
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    client.close();
}

#[test]
fn hostname_rule_cannot_authorize_a_private_resolution() {
    let port = free_port();
    let rule = format!("localhost:{port}");
    let mut client = McpClient::start(&[&rule]);
    let denied = client.call(
        2,
        "pathtrial_http",
        json!({"url": format!("http://localhost:{port}/"), "timeout_ms": 500}),
    );
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    client.close();
}

#[test]
fn authorized_scan_http_and_explain_report() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let scan = client.call(
        2,
        "pathtrial_scan",
        json!({
            "target": "127.0.0.1",
            "port": port,
            "profile": "tcp",
            "rounds": 1,
            "timeout_ms": 800,
            "max_seconds": 5
        }),
    );
    assert_eq!(scan["result"]["isError"], false);
    let report = scan["result"]["structuredContent"]["report"].clone();
    assert_eq!(report["target"]["input"], "127.0.0.1");
    assert_eq!(report["stages"].as_array().unwrap().len(), 5);

    let explained = client.call(3, "pathtrial_explain_report", json!({"report": report}));
    assert_eq!(explained["result"]["isError"], false);
    assert!(explained["result"]["structuredContent"]["probe_counts"]
        .as_object()
        .unwrap()
        .contains_key("tcp"));
    assert!(explained["result"]["structuredContent"]["missing_evidence"]
        .as_array()
        .unwrap()
        .is_empty());

    let http = client.call(
        4,
        "pathtrial_http",
        json!({"url": format!("http://127.0.0.1:{port}/"), "timeout_ms": 2000}),
    );
    assert_eq!(http["result"]["isError"], false);
    assert_eq!(
        http["result"]["structuredContent"]["report"]["status"],
        "PASS"
    );
    client.close();
}

#[test]
fn invalid_limits_are_rejected() {
    let port = free_port();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let response = client.call(
        2,
        "pathtrial_scan",
        json!({
            "target": "127.0.0.1",
            "port": port,
            "rounds": 1000,
            "timeout_ms": 500,
            "max_seconds": 5
        }),
    );
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["structuredContent"]["error"]["code"],
        "invalid_params"
    );
    client.close();
}

#[test]
fn compare_reports_rejects_different_targets() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let scan = client.call(
        2,
        "pathtrial_scan",
        json!({
            "target": "127.0.0.1",
            "port": port,
            "profile": "tcp",
            "rounds": 1,
            "timeout_ms": 800,
            "max_seconds": 5
        }),
    );
    let mut after = scan["result"]["structuredContent"]["report"].clone();
    after["target"]["input"] = json!("other.example");
    let comparison = client.call(
        3,
        "pathtrial_compare_reports",
        json!({
            "before": scan["result"]["structuredContent"]["report"],
            "after": after
        }),
    );
    assert_eq!(comparison["result"]["isError"], false);
    assert_eq!(
        comparison["result"]["structuredContent"]["comparison"]["comparability"]["verdict"],
        "NOT DIRECTLY COMPARABLE"
    );
    client.close();
}

#[test]
fn unknown_method_and_eof_exit_are_clean() {
    let mut client = McpClient::start(&[]);
    let response = client.request(2, "does/not/exist", json!({}));
    assert_eq!(response["error"]["code"], -32601);
    client.close();
}

#[test]
fn stdout_only_contains_json_rpc_messages() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let _ = client.call(
        2,
        "pathtrial_http",
        json!({"url": format!("http://127.0.0.1:{port}/"), "timeout_ms": 2000}),
    );
    // `request` already parses each response line with serde_json, so a log
    // line would have failed the test.
    client.close();
}
