//! Scenario-level tests for the guided diagnosis command.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

fn run(args: &[&str]) -> (std::process::ExitStatus, Value) {
    let output = Command::new(binary()).args(args).output().expect("run");
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON ({error}): {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    });
    (output.status, value)
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().unwrap().port()
}

fn tcp_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            drop(stream);
        }
    });
    port
}

fn http_stub(status: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let reason = match status {
                200 => "OK",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                504 => "Gateway Timeout",
                _ => "Error",
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            );
        }
    });
    port
}

fn connect_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut buffer = [0u8; 512];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => head.extend_from_slice(&buffer[..read]),
                }
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

fn checks(report: &Value) -> &Vec<Value> {
    report["checks"].as_array().expect("checks")
}

fn check<'a>(report: &'a Value, name: &str) -> &'a Value {
    checks(report)
        .iter()
        .find(|item| item["name"] == name)
        .unwrap_or_else(|| panic!("missing check {name}: {report}"))
}

#[test]
fn local_scenario_reports_interfaces_routes_and_optional_facts() {
    let (status, value) = run(&["diagnose", "--scenario", "local", "--format", "json"]);
    assert!(status.success() || status.code() == Some(3));
    assert_eq!(value["scenario"], "local");
    assert_eq!(check(&value, "Interfaces")["status"], "PASS");
    assert_eq!(check(&value, "Default route")["status"], "PASS");
    assert!(value["sources"][0]["report"]["links"].is_array());
}

#[test]
fn tcp_scenario_passes_and_refused_is_a_failure() {
    let port = tcp_stub();
    let (_, ok) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "tcp",
        "--port",
        &port.to_string(),
        "--rounds",
        "2",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert_eq!(check(&ok, "TCP")["status"], "PASS");

    let closed = free_port();
    let (status, refused) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "tcp",
        "--port",
        &closed.to_string(),
        "--rounds",
        "1",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert_eq!(status.code(), Some(2));
    assert_eq!(check(&refused, "TCP")["status"], "FAIL");
}

#[test]
fn latency_scenario_reports_p50_p95_and_icmp_separately() {
    let port = tcp_stub();
    let (_, value) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "latency",
        "--port",
        &port.to_string(),
        "--rounds",
        "3",
        "--timeout-ms",
        "1000",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ]);
    let stats = check(&value, "Latency statistics");
    assert!(stats["summary"].as_str().unwrap().contains("p50"));
    assert!(stats["summary"].as_str().unwrap().contains("p95"));
    assert!(checks(&value)
        .iter()
        .any(|item| item["name"] == "ICMP latency and loss"));
}

#[test]
fn http_502_is_classified_without_inventing_upstream_cause() {
    let port = http_stub(502);
    let url = format!("http://127.0.0.1:{port}/");
    let (status, value) = run(&[
        "diagnose",
        "--scenario",
        "http",
        "--url",
        &url,
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert_eq!(status.code(), Some(2));
    let http = check(&value, "HTTP");
    assert_eq!(http["status"], "FAIL");
    assert!(http["observed"].to_string().contains("502"));
    assert!(http["possible"]
        .to_string()
        .contains("reverse proxy or upstream"));
    assert!(http["not_established"]
        .to_string()
        .contains("failing server component"));
}

#[test]
fn tls_scenario_separates_plain_tcp_from_tls_failure() {
    let port = tcp_stub();
    let (status, value) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "tls",
        "--port",
        &port.to_string(),
        "--rounds",
        "1",
        "--timeout-ms",
        "500",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert_eq!(status.code(), Some(2));
    let tcp_tls = check(&value, "TCP and TLS");
    assert_eq!(tcp_tls["status"], "FAIL");
    assert!(tcp_tls["observed"].to_string().contains("TLS transport 0/"));
}

#[test]
fn dual_stack_scenario_marks_unavailable_family_skip() {
    let port = tcp_stub();
    let (_, value) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "dual-stack",
        "--port",
        &port.to_string(),
        "--rounds",
        "1",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    let compare = check(&value, "IPv4 / IPv6");
    assert_eq!(compare["status"], "SKIP");
}

#[test]
fn proxy_scenario_uses_direct_comparison() {
    let target = http_stub(200);
    let proxy = connect_stub();
    let url = format!("http://127.0.0.1:{target}/");
    let proxy_url = format!("http://127.0.0.1:{proxy}");
    let (_, value) = run(&[
        "diagnose",
        "--scenario",
        "proxy",
        "--url",
        &url,
        "--proxy",
        &proxy_url,
        "--rounds",
        "1",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ]);
    assert_eq!(check(&value, "Proxy comparison")["status"], "PASS");
}

#[test]
fn dns_timeout_is_reported_without_poisoning_claim() {
    let port = free_port();
    let (status, value) = run(&[
        "diagnose",
        "example.invalid",
        "--scenario",
        "dns",
        "--server",
        &format!("127.0.0.1:{port}"),
        "--timeout-ms",
        "100",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert_eq!(status.code(), Some(2));
    let dns = check(&value, "DNS");
    assert_ne!(dns["status"], "PASS");
    assert!(dns["not_established"]
        .to_string()
        .contains("do not prove DNS poisoning"));
}

#[test]
fn udp_quic_scenario_keeps_checks_separate() {
    let port = free_port();
    let (status, value) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "udp-quic",
        "--port",
        &port.to_string(),
        "--rounds",
        "1",
        "--timeout-ms",
        "300",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert_eq!(status.code(), Some(2));
    assert!(checks(&value).iter().any(|item| item["name"] == "UDP Echo"));
    assert!(checks(&value).iter().any(|item| item["name"] == "QUIC"));
    let udp = check(&value, "UDP Echo");
    assert!(udp["not_established"]
        .to_string()
        .contains("may not run an Echo service"));
}

#[test]
fn redact_ips_covers_nested_reports() {
    let port = tcp_stub();
    let (_, value) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "tcp",
        "--port",
        &port.to_string(),
        "--rounds",
        "1",
        "--max-seconds",
        "5",
        "--redact-ips",
        "--format",
        "json",
    ]);
    let text = value.to_string();
    assert!(!text.contains("127.0.0.1"), "{text}");
    assert!(text.contains("<ipv4-"));
}

#[test]
fn diagnose_schema_is_available_and_validates_report() {
    let schema_output = Command::new(binary())
        .args(["schema", "--diagnose"])
        .output()
        .expect("schema");
    assert!(schema_output.status.success());
    let schema: Value = serde_json::from_slice(&schema_output.stdout).expect("schema json");
    assert_eq!(
        schema["$id"],
        "https://pathtrial.dev/schemas/diagnose-1.0.0.json"
    );

    let port = tcp_stub();
    let (_, report) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "tcp",
        "--port",
        &port.to_string(),
        "--rounds",
        "1",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
}

#[test]
fn invalid_arguments_are_tool_errors() {
    let output = Command::new(binary())
        .args(["diagnose", "--scenario", "proxy"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("target"));
}

#[test]
fn tcp_stream_drop_does_not_block_test_cleanup() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
    thread.join().unwrap();
    std::thread::sleep(Duration::from_millis(10));
}
