//! Protocol-level tests for the local MCP stdio server.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

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

    fn write_raw(&mut self, text: &str) {
        writeln!(self.stdin, "{text}").expect("write raw MCP");
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

fn http_stub_with_response(response: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(&response);
        }
    });
    port
}

fn silent_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0u8; 1024];
            while stream
                .read(&mut buffer)
                .map(|read| read > 0)
                .unwrap_or(false)
            {}
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
    assert_eq!(names.len(), 10);
    assert!(names.contains(&"pathtrial_capabilities"));
    assert!(names.contains(&"pathtrial_diagnose"));
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
fn capabilities_do_not_expose_allowlist_addresses() {
    let private_rule = "127.0.0.1:9".to_string();
    let host_rule = "public.example:443".to_string();
    let mut client = McpClient::start(&[&private_rule, &host_rule]);
    let caps = client.call(2, "pathtrial_capabilities", json!({}));
    let serialized = serde_json::to_string(&caps).expect("serialize capabilities");
    assert!(!serialized.contains("127.0.0.1"));
    assert!(!serialized.contains("public.example"));
    let authorization = &caps["result"]["structuredContent"]["authorization"];
    assert_eq!(authorization["allow_rule_count"], 2);
    assert_eq!(authorization["allow_rules_redacted"], true);
    assert_eq!(authorization["contains_hostname_rule"], true);
    assert_eq!(authorization["contains_non_public_literal"], true);
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
fn diagnose_local_runs_without_allowlist_and_network_is_denied() {
    let mut client = McpClient::start(&[]);
    let local = client.call(2, "pathtrial_diagnose", json!({"scenario": "local"}));
    assert_eq!(local["result"]["isError"], false);
    assert_eq!(
        local["result"]["structuredContent"]["report"]["scenario"],
        "local"
    );
    assert!(local["result"]["structuredContent"]["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["name"] == "Interfaces"));

    let denied = client.call(
        3,
        "pathtrial_diagnose",
        json!({
            "scenario": "tcp",
            "target": "127.0.0.1",
            "port": 9,
            "rounds": 1,
            "max_seconds": 5
        }),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    client.close();
}

#[test]
fn diagnose_network_scenario_uses_authorized_literal_ip() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let result = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "tcp",
            "target": "127.0.0.1",
            "port": port,
            "rounds": 1,
            "max_seconds": 5
        }),
    );
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(
        result["result"]["structuredContent"]["report"]["scenario"],
        "tcp"
    );
    assert!(result["result"]["structuredContent"]["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["name"] == "TCP" && check["status"] == "PASS"));
    client.close();
}

#[test]
fn diagnose_http_scenario_runs_the_real_cli() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let result = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "http",
            "url": format!("http://127.0.0.1:{port}/"),
            "max_seconds": 5
        }),
    );
    assert_eq!(result["result"]["isError"], false, "{result}");
    let content = &result["result"]["structuredContent"];
    assert_eq!(content["report"]["status"], "PASS", "{content}");
    let http = content["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "http")
        .expect("HTTP check");
    assert_eq!(http["status"], "PASS");
    client.close();
}

#[test]
fn diagnose_dns_keeps_the_requested_hostname() {
    let mut client = McpClient::start(&["localhost:53"]);
    let result = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "dns",
            "target": "localhost",
            "port": 53,
            "timeout_ms": 300,
            "max_seconds": 5
        }),
    );
    assert_eq!(result["result"]["isError"], false, "{result}");
    let content = &result["result"]["structuredContent"];
    assert_eq!(content["requested_target"], "localhost");
    assert_eq!(content["report"]["target"], "localhost");
    assert_eq!(
        content["report"]["sources"][0]["report"]["target"],
        "localhost"
    );
    client.close();
}

#[test]
fn diagnose_dual_stack_marks_the_unauthorized_family_skip() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let result = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "dual-stack",
            "target": "127.0.0.1",
            "port": port,
            "rounds": 1,
            "max_seconds": 5
        }),
    );
    assert_eq!(result["result"]["isError"], false, "{result}");
    let content = &result["result"]["structuredContent"];
    assert_eq!(content["connect_ipv4"], "127.0.0.1");
    assert!(content.get("connect_ipv6").is_none());
    let dual = content["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "dual-stack")
        .expect("dual-stack check");
    assert_eq!(dual["status"], "SKIP");
    assert!(dual["observed"].to_string().contains("ipv6: SKIP"));
    client.close();
}

#[test]
fn diagnose_dual_stack_rejects_an_unauthorized_family() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let denied = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "dual-stack",
            "target": "127.0.0.1",
            "port": port,
            "family": "ipv6",
            "rounds": 1,
            "max_seconds": 5
        }),
    );
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    client.close();
}

#[test]
fn diagnose_rejects_target_and_url_mismatch() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let mismatch = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "http",
            "target": "127.0.0.1",
            "url": format!("http://127.0.0.2:{port}/"),
            "max_seconds": 5
        }),
    );
    assert_eq!(mismatch["result"]["isError"], true);
    assert_eq!(
        mismatch["result"]["structuredContent"]["error"]["code"],
        "invalid_params"
    );
    client.close();
}

#[test]
fn diagnose_proxy_requires_authorization_for_both_endpoints() {
    let target_port = http_stub();
    let proxy_port = start_connect_stub(200);
    let target_rule = format!("127.0.0.1:{target_port}");
    let proxy_rule = format!("127.0.0.1:{proxy_port}");
    let mut client = McpClient::start(&[&target_rule]);
    let denied = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "proxy",
            "url": format!("http://127.0.0.1:{target_port}/"),
            "proxy": format!("http://127.0.0.1:{proxy_port}"),
            "rounds": 1,
            "max_seconds": 5
        }),
    );
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    client.close();

    let mut client = McpClient::start(&[&target_rule, &proxy_rule]);
    let result = client.call(
        2,
        "pathtrial_diagnose",
        json!({
            "scenario": "proxy",
            "url": format!("http://127.0.0.1:{target_port}/"),
            "proxy": format!("http://127.0.0.1:{proxy_port}"),
            "rounds": 1,
            "max_seconds": 10
        }),
    );
    assert_eq!(result["result"]["isError"], false, "{result}");
    let content = &result["result"]["structuredContent"];
    assert_eq!(content["connect_ip"], "127.0.0.1");
    assert_eq!(content["report"]["checks"][0]["status"], "PASS");
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
fn mcp_redaction_covers_structured_results_and_summaries() {
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
            "max_seconds": 5,
            "redact_ips": true
        }),
    );
    let serialized = serde_json::to_string(&scan).expect("serialize response");
    assert!(
        !serialized.contains("127.0.0.1"),
        "target IP leaked: {serialized}"
    );
    assert!(serialized.contains("<ipv4-1>"));
    client.close();
}

#[test]
fn mcp_http_never_returns_query_secrets() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let response = client.call(
        2,
        "pathtrial_http",
        json!({
            "url": format!("http://127.0.0.1:{port}/private?token=secret"),
            "timeout_ms": 2000
        }),
    );
    let serialized = serde_json::to_string(&response).expect("serialize HTTP result");
    assert!(!serialized.contains("token=secret"));
    assert!(!serialized.contains("?token"));
    assert_eq!(
        response["result"]["structuredContent"]["measured_url"],
        format!("http://127.0.0.1:{port}/private")
    );
    client.close();
}

#[test]
fn mcp_http_records_redirect_without_following_it() {
    let redirect_listener = TcpListener::bind("127.0.0.1:0").expect("redirect listener");
    redirect_listener
        .set_nonblocking(true)
        .expect("nonblocking redirect listener");
    let redirect_port = redirect_listener.local_addr().unwrap().port();
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{redirect_port}/next?token=secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let port = http_stub_with_response(response.into_bytes());
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let result = client.call(
        2,
        "pathtrial_http",
        json!({"url": format!("http://127.0.0.1:{port}/start"), "timeout_ms": 2000}),
    );
    let serialized = serde_json::to_string(&result).expect("serialize redirect result");
    assert!(!serialized.contains("token=secret"));
    assert!(serialized.contains("重定向未被跟随"));
    match redirect_listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("redirect target was contacted"),
        Err(error) => panic!("redirect listener failed: {error}"),
    }
    client.close();
}

#[test]
fn client_disconnect_cancels_a_running_probe() {
    let port = silent_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    client.write(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "pathtrial_scan",
            "arguments": {
                "target": "127.0.0.1",
                "port": port,
                "profile": "web",
                "rounds": 1,
                "timeout_ms": 15000,
                "max_seconds": 60
            }
        }
    }));
    std::thread::sleep(Duration::from_millis(300));
    drop(client.stdin);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let exited = loop {
        if client.child.try_wait().expect("wait for MCP").is_some() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !exited {
        let _ = client.child.kill();
        let _ = client.child.wait();
        panic!("MCP server did not stop after its client disconnected");
    }
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

#[test]
fn malformed_and_oversized_messages_get_json_rpc_errors() {
    let mut client = McpClient::start(&[]);
    client.write_raw("{not json");
    let mut line = String::new();
    client
        .stdout
        .read_line(&mut line)
        .expect("read parse error");
    let response: Value = serde_json::from_str(&line).expect("parse error JSON");
    assert_eq!(response["error"]["code"], -32700);

    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\",\"params\":{{\"x\":\"{}\"}}}}",
        "a".repeat(12 * 1024 * 1024 + 1)
    );
    client.write_raw(&huge);
    line.clear();
    client.stdout.read_line(&mut line).expect("read size error");
    let response: Value = serde_json::from_str(&line).expect("parse size error JSON");
    assert_eq!(response["error"]["code"], -32600);
    client.close();
}

fn start_http3_stub(status: u16, alpn: &'static str, http3: bool) -> u16 {
    use std::sync::Arc;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let generated =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
            let cert = rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
            let key =
                rustls::pki_types::PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
            let mut tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("tls");
            tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
            let quic_tls =
                quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic tls");
            let endpoint = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(quic_tls)),
                "127.0.0.1:0".parse().unwrap(),
            )
            .expect("endpoint");
            tx.send(endpoint.local_addr().unwrap().port()).unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    if !http3 {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        connection.close(0u32.into(), b"done");
                        return;
                    }
                    let Ok(mut h3_conn) =
                        h3::server::Connection::new(h3_quinn::Connection::new(connection)).await
                    else {
                        return;
                    };
                    while let Ok(Some(resolver)) = h3_conn.accept().await {
                        let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                            continue;
                        };
                        let response = http::Response::builder().status(status).body(()).unwrap();
                        if stream.send_response(response).await.is_err() {
                            continue;
                        }
                        let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
                        let _ = stream.finish().await;
                    }
                });
            }
        });
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("server port")
}

fn start_connect_stub(status: u16) -> u16 {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut buffer = [0u8; 512];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => head.extend_from_slice(&buffer[..read]),
                }
            }
            if status != 200 {
                let body = format!("HTTP/1.1 {status} Error\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.write_all(body.as_bytes());
                continue;
            }
            let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

#[test]
fn mcp_udp_echo_tool_uses_real_endpoint() {
    let port = free_port();
    let mut endpoint = Command::new(binary())
        .args([
            "endpoint",
            "--udp-echo",
            "--bind",
            &format!("127.0.0.1:{port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("endpoint");
    std::thread::sleep(Duration::from_millis(700));
    let rule = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&rule]);
    let result = client.call(
        2,
        "pathtrial_udp_echo",
        json!({"target": format!("127.0.0.1:{port}"), "rounds": 3, "timeout_ms": 800}),
    );
    let _ = endpoint.kill();
    let _ = endpoint.wait();
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(
        result["result"]["structuredContent"]["report"]["status"],
        "PASS"
    );
    client.close();
}

#[test]
fn mcp_udp_echo_reports_closed_port_without_fake_success() {
    let port = free_port();
    let rule = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&rule]);
    let result = client.call(
        2,
        "pathtrial_udp_echo",
        json!({"target": format!("127.0.0.1:{port}"), "rounds": 2, "timeout_ms": 500}),
    );
    assert_eq!(result["result"]["isError"], false);
    assert_ne!(
        result["result"]["structuredContent"]["report"]["status"],
        "PASS"
    );
    assert!(result["result"]["structuredContent"]["report"]["probes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|probe| probe["detail"]["result"] != "echo"));
    client.close();
}

#[test]
fn mcp_quic_and_http3_tools_use_real_local_server() {
    let port = start_http3_stub(200, "h3", true);
    let bad_alpn_port = start_http3_stub(200, "not-h3", false);
    let rule = format!("127.0.0.1:{port}");
    let bad_rule = format!("127.0.0.1:{bad_alpn_port}");
    let mut client = McpClient::start(&[&rule, &bad_rule]);
    let quic = client.call(
        2,
        "pathtrial_quic",
        json!({
            "host": "127.0.0.1",
            "port": port,
            "alpn": "h3",
            "insecure": true,
            "timeout_ms": 2000
        }),
    );
    assert_eq!(quic["result"]["isError"], false);
    assert_eq!(
        quic["result"]["structuredContent"]["report"]["probes"][0]["detail"]["handshake_ok"],
        true
    );
    let http3 = client.call(
        3,
        "pathtrial_http3",
        json!({
            "url": format!("https://127.0.0.1:{port}/"),
            "insecure": true,
            "timeout_ms": 2000
        }),
    );
    assert_eq!(http3["result"]["isError"], false);
    assert_eq!(
        http3["result"]["structuredContent"]["report"]["probes"][0]["detail"]["http3_status"],
        200
    );
    let cert_failure = client.call(
        4,
        "pathtrial_quic",
        json!({
            "host": "127.0.0.1",
            "port": port,
            "alpn": "h3",
            "timeout_ms": 2000
        }),
    );
    assert_eq!(
        cert_failure["result"]["structuredContent"]["report"]["status"],
        "FAIL"
    );
    assert_eq!(
        cert_failure["result"]["structuredContent"]["report"]["probes"][0]["detail"]
            ["handshake_ok"],
        false
    );
    let alpn_failure = client.call(
        5,
        "pathtrial_quic",
        json!({
            "host": "127.0.0.1",
            "port": bad_alpn_port,
            "alpn": "h3",
            "insecure": true,
            "timeout_ms": 2000
        }),
    );
    assert_eq!(
        alpn_failure["result"]["structuredContent"]["report"]["status"],
        "SKIP"
    );
    client.close();
}

#[test]
fn mcp_proxy_tool_uses_authorized_connect_endpoint() {
    let proxy = start_connect_stub(200);
    let target_rule = "127.0.0.1:9".to_string();
    let proxy_rule = format!("127.0.0.1:{proxy}");
    let mut client = McpClient::start(&[&target_rule, &proxy_rule]);
    let result = client.call(
        2,
        "pathtrial_proxy_test",
        json!({
            "url": "http://127.0.0.1:9/",
            "proxy": format!("http://127.0.0.1:{proxy}"),
            "timeout_ms": 2000
        }),
    );
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(
        result["result"]["structuredContent"]["report"]["status"],
        "PASS"
    );
    client.close();
}

#[test]
fn mcp_proxy_tool_classifies_connect_failures() {
    for (status, expected) in [
        (403, "http_status:403"),
        (407, "auth_required"),
        (502, "http_status:502"),
    ] {
        let proxy = start_connect_stub(status);
        let target_rule = "127.0.0.1:9".to_string();
        let proxy_rule = format!("127.0.0.1:{proxy}");
        let mut client = McpClient::start(&[&target_rule, &proxy_rule]);
        let result = client.call(
            2,
            "pathtrial_proxy_test",
            json!({
                "url": "http://127.0.0.1:9/",
                "proxy": format!("http://127.0.0.1:{proxy}"),
                "timeout_ms": 2000
            }),
        );
        assert_eq!(result["result"]["isError"], false);
        assert_eq!(
            result["result"]["structuredContent"]["report"]["probes"][0]["detail"]["error"],
            expected
        );
        client.close();
    }
}

#[test]
fn proxy_target_and_proxy_endpoint_need_separate_authorization() {
    let proxy = start_connect_stub(200);
    let proxy_rule = format!("127.0.0.1:{proxy}");
    let mut target_denied = McpClient::start(&[&proxy_rule]);
    let denied = target_denied.call(
        2,
        "pathtrial_proxy_test",
        json!({
            "url": "http://127.0.0.1:9/",
            "proxy": format!("http://127.0.0.1:{proxy}"),
            "timeout_ms": 2000
        }),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    target_denied.close();

    let mut proxy_denied = McpClient::start(&["127.0.0.1:9"]);
    let denied = proxy_denied.call(
        2,
        "pathtrial_proxy_test",
        json!({
            "url": "http://127.0.0.1:9/",
            "proxy": format!("http://127.0.0.1:{proxy}"),
            "timeout_ms": 2000
        }),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["error"]["code"],
        "target_not_allowed"
    );
    proxy_denied.close();
}

#[test]
fn mcp_explain_rejects_missing_evidence_ids() {
    let port = http_stub();
    let target = format!("127.0.0.1:{port}");
    let mut client = McpClient::start(&[&target]);
    let scan = client.call(
        2,
        "pathtrial_scan",
        json!({"target": "127.0.0.1", "port": port, "profile": "tcp", "rounds": 1, "timeout_ms": 800, "max_seconds": 5}),
    );
    let mut report = scan["result"]["structuredContent"]["report"].clone();
    if let Some(findings) = report["findings"].as_array_mut() {
        if let Some(finding) = findings.first_mut() {
            finding["evidence"] = json!(["missing_probe_999"]);
        }
    }
    let explained = client.call(3, "pathtrial_explain_report", json!({"report": report}));
    assert_eq!(explained["result"]["isError"], true);
    assert!(explained["result"]["structuredContent"]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("missing evidence"));
    client.close();
}
