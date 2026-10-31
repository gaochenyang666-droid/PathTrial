//! Scenario-level tests for the guided diagnosis command.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

fn capture_request_stub() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buffer[..read]).to_string());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, rx)
}

fn silent_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
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

fn capture_client_hello_stub() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 8192];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let _ = tx.send(buffer[..read].to_vec());
        }
    });
    (port, rx)
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

fn probe_ids(report: &Value) -> Vec<String> {
    report
        .get("probes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|probe| probe["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn assert_evidence_refs_exist(report: &Value) {
    let sources = report["sources"].as_array().expect("sources array");
    for item in checks(report) {
        assert!(!item["claim"].as_str().unwrap_or_default().is_empty());
        assert!(!item["limits"].as_array().unwrap().is_empty());
        assert!(["low", "moderate", "high"].contains(&item["confidence"].as_str().unwrap()));
        if let Some(probe_id) = item["probe_id"].as_str() {
            assert!(
                item["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|evidence| evidence.as_str() == Some(probe_id)),
                "probe_id {probe_id} is absent from evidence"
            );
        }
        for evidence in item["evidence"].as_array().expect("evidence array") {
            let evidence = evidence.as_str().expect("evidence string");
            let (source, id) = evidence
                .split_once(':')
                .unwrap_or_else(|| panic!("evidence {evidence} has no source prefix"));
            let entry = sources
                .iter()
                .find(|entry| entry["name"].as_str() == Some(source))
                .unwrap_or_else(|| panic!("evidence {evidence} cites a missing source"));
            let known = probe_ids(&entry["report"]);
            assert!(
                known.iter().any(|known| known == id),
                "evidence {evidence} does not resolve to a probe; known={known:?}"
            );
        }
    }
}

#[test]
fn local_scenario_reports_interfaces_routes_and_optional_facts() {
    let (status, value) = run(&["diagnose", "--scenario", "local", "--format", "json"]);
    assert!(status.success() || status.code() == Some(3));
    assert_eq!(value["scenario"], "local");
    assert_eq!(check(&value, "Interfaces")["status"], "PASS");
    assert_eq!(check(&value, "Default route")["status"], "PASS");
    assert!(value["sources"][0]["report"]["links"].is_array());
    assert!(checks(&value)
        .iter()
        .flat_map(|item| item["evidence"].as_array().unwrap())
        .all(|evidence| evidence.as_str().unwrap().starts_with("local:")));
}

#[test]
fn every_diagnose_evidence_reference_resolves_to_a_recorded_probe() {
    let local = run(&["diagnose", "--scenario", "local", "--format", "json"]).1;
    assert_evidence_refs_exist(&local);

    let port = tcp_stub();
    let port_text = port.to_string();
    let tcp = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "tcp",
        "--port",
        &port_text,
        "--rounds",
        "2",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&tcp);

    let latency = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "latency",
        "--port",
        &port_text,
        "--rounds",
        "2",
        "--timeout-ms",
        "1000",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&latency);

    let dns = run(&[
        "diagnose",
        "localhost",
        "--scenario",
        "dns",
        "--timeout-ms",
        "800",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&dns);

    let http_port = http_stub(200);
    let url = format!("http://127.0.0.1:{http_port}/");
    let http = run(&[
        "diagnose",
        "--scenario",
        "http",
        "--url",
        &url,
        "--max-seconds",
        "5",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&http);

    let dual = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "dual-stack",
        "--port",
        &port_text,
        "--connect-ipv4",
        "127.0.0.1",
        "--rounds",
        "2",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&dual);

    let web = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "web",
        "--port",
        &port_text,
        "--rounds",
        "1",
        "--timeout-ms",
        "500",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&web);

    let vps = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "vps",
        "--port",
        &port_text,
        "--rounds",
        "1",
        "--timeout-ms",
        "500",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&vps);

    let closed = free_port().to_string();
    let udp_quic = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "udp-quic",
        "--port",
        &closed,
        "--rounds",
        "1",
        "--timeout-ms",
        "300",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ])
    .1;
    assert_evidence_refs_exist(&udp_quic);
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
fn http_target_ip_keeps_the_url_host_header() {
    let (port, captured) = capture_request_stub();
    let url = format!("http://origin.invalid:{port}/probe");
    let (status, value) = run(&[
        "http",
        &url,
        "--target-ip",
        "127.0.0.1",
        "--timeout-ms",
        "2000",
        "--format",
        "json",
    ]);
    assert!(status.success(), "probe failed: {value}");
    let request = captured
        .recv_timeout(Duration::from_secs(2))
        .expect("request");
    assert!(
        request.contains(&format!("Host: origin.invalid:{port}")),
        "{request}"
    );
    assert!(request.starts_with("GET /probe "), "{request}");
}

#[test]
fn http_target_ip_keeps_the_original_sni() {
    let (port, captured) = capture_client_hello_stub();
    let url = format!("https://origin.invalid:{port}/");
    let (_status, _value) = run(&[
        "http",
        &url,
        "--target-ip",
        "127.0.0.1",
        "--sni",
        "origin.invalid",
        "--timeout-ms",
        "1500",
        "--format",
        "json",
    ]);
    let hello = captured
        .recv_timeout(Duration::from_secs(2))
        .expect("hello");
    assert!(
        hello
            .windows(b"origin.invalid".len())
            .any(|window| window == b"origin.invalid"),
        "ClientHello did not carry the requested SNI"
    );
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
fn vps_unreachable_emits_reachability_evidence() {
    let port = tcp_stub();
    let (_, value) = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "vps-unreachable",
        "--port",
        &port.to_string(),
        "--rounds",
        "1",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ]);
    let reachability = check(&value, "VPS reachability");
    assert_eq!(reachability["status"], "PASS");
    assert!(!reachability["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn proxy_split_emits_direct_and_proxy_evidence() {
    let target = http_stub(200);
    let proxy = connect_stub();
    let url = format!("http://127.0.0.1:{target}/");
    let proxy_url = format!("http://127.0.0.1:{proxy}");
    let (_, value) = run(&[
        "diagnose",
        "--scenario",
        "proxy-split",
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
    let split = check(&value, "Direct / proxy split");
    assert_eq!(split["status"], "PASS");
    assert!(!split["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn http3_fallback_reports_https_after_h3_failure() {
    let port = free_port();
    let url = format!("https://127.0.0.1:{port}/");
    let (status, value) = run(&[
        "diagnose",
        "--scenario",
        "http3-fallback",
        "--url",
        &url,
        "--rounds",
        "1",
        "--timeout-ms",
        "500",
        "--max-seconds",
        "10",
        "--format",
        "json",
    ]);
    assert_eq!(status.code(), Some(2));
    let fallback = check(&value, "HTTP/3 fallback");
    assert_eq!(fallback["status"], "FAIL");
    assert!(fallback["claim"]
        .as_str()
        .unwrap()
        .contains("Both HTTP/3 and the HTTPS fallback failed"));
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
        "https://pathtrial.dev/schemas/diagnose-1.1.0.json"
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

    let local = run(&["diagnose", "--scenario", "local", "--format", "json"]).1;
    let errors: Vec<String> = validator
        .iter_errors(&local)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "local schema errors: {errors:#?}");

    let dual = run(&[
        "diagnose",
        "127.0.0.1",
        "--scenario",
        "dual-stack",
        "--port",
        &port.to_string(),
        "--connect-ipv4",
        "127.0.0.1",
        "--rounds",
        "1",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ])
    .1;
    let errors: Vec<String> = validator
        .iter_errors(&dual)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "dual-stack schema errors: {errors:#?}");
}

#[test]
fn diagnose_stops_at_the_wall_clock_budget_without_claiming_success() {
    let port = silent_stub();
    let started = Instant::now();
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
        "30000",
        "--max-seconds",
        "5",
        "--format",
        "json",
    ]);
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "diagnosis exceeded its wall-clock budget"
    );
    assert_eq!(status.code(), Some(3), "{value}");
    assert_eq!(value["status"], "INCONCLUSIVE");
    let budget = check(&value, "Scenario budget");
    assert_eq!(budget["status"], "INCONCLUSIVE");
    assert!(budget["observed"]
        .to_string()
        .contains("timeout:child process"));
    assert!(value["limitations"]
        .to_string()
        .contains("not successful results"));
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
