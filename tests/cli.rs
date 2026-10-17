//! End to end CLI checks that do not depend on the public internet.

use std::net::TcpListener;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

#[test]
fn version_and_help_are_available() {
    let version = Command::new(binary())
        .arg("--version")
        .output()
        .expect("run");
    assert!(version.status.success());
    let text = String::from_utf8_lossy(&version.stdout);
    assert!(
        text.contains("pathtrial"),
        "unexpected version output: {text}"
    );

    let help = Command::new(binary()).arg("--help").output().expect("run");
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("scan"));
    assert!(help_text.contains("Exit codes"));

    let schema = Command::new(binary())
        .args(["schema", "--command"])
        .output()
        .expect("run schema");
    assert!(schema.status.success());
    let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).expect("schema json");
    assert_eq!(
        schema["$id"],
        "https://pathtrial.dev/schemas/command-1.0.0.json"
    );
}

#[test]
fn invalid_arguments_exit_with_tool_error() {
    let output = Command::new(binary())
        .args(["scan", "example.com", "--rounds", "0"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"), "stderr was {stderr}");
}

#[test]
fn scan_against_loopback_listener_emits_valid_json() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let _ = listener.accept();
        }
    });

    let output = Command::new(binary())
        .args([
            "scan",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--profile",
            "tcp",
            "--rounds",
            "2",
            "--timeout-ms",
            "1000",
            "--interval-ms",
            "50",
            "--format",
            "json",
            "--no-files",
        ])
        .output()
        .expect("run scan");

    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(value["schema_version"], "1.4.0");
    assert_eq!(value["stages"].as_array().unwrap().len(), 5);
    assert_eq!(value["summaries"][0]["tcp_success"], 2);
    assert_eq!(value["configuration"]["tls_enabled"], false);

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/report.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|error| format!("{} at {}", error, error.instance_path))
        .collect();
    assert!(errors.is_empty(), "schema violations: {errors:#?}");
}

/// Start a loopback listener that serves `accepts` connections.
fn loopback(accepts: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for _ in 0..accepts {
            let _ = listener.accept();
        }
    });
    port
}

fn scan_args(port: u16) -> Vec<String> {
    [
        "scan",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--profile",
        "tcp",
        "--rounds",
        "1",
        "--timeout-ms",
        "1000",
        "--interval-ms",
        "20",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

fn scan_args_with(
    port: u16,
    rounds: u32,
    profile: &str,
    timeout_ms: u32,
    extra: &[&str],
) -> Vec<String> {
    let mut args: Vec<String> = [
        "scan".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        port.to_string(),
        "--profile".to_string(),
        profile.to_string(),
        "--rounds".to_string(),
        rounds.to_string(),
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--interval-ms".to_string(),
        "20".to_string(),
    ]
    .to_vec();
    args.extend(extra.iter().map(|value| value.to_string()));
    args
}

fn run_json(args: &[String]) -> (std::process::ExitStatus, serde_json::Value) {
    let mut args = args.to_vec();
    args.push("--format".to_string());
    args.push("json".to_string());
    args.push("--no-files".to_string());
    let output = Command::new(binary()).args(&args).output().expect("run");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    (output.status, value)
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

#[test]
fn closed_port_is_a_failed_check_with_exit_2() {
    let port = free_port();
    let (status, value) = run_json(&scan_args_with(port, 5, "tcp", 1000, &[]));
    assert_eq!(status.code(), Some(2), "refused connections are a finding");
    let stage = value["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["id"] == "tcp_tls")
        .expect("tcp stage");
    assert_eq!(stage["status"], "FAIL");
    assert_eq!(value["summaries"][0]["tcp_success"], 0);
    let finding = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule_id"] == "R015")
        .expect("R015 finding");
    assert_eq!(finding["status"], "FAIL");
    let claim = finding["claim"].as_str().unwrap();
    assert!(claim.contains("拒绝"));
    assert!(!claim.contains("主机可达"));
}

#[test]
fn web_profile_against_plain_tcp_reports_tls_failure() {
    let port = loopback(4);
    let (status, value) = run_json(&scan_args_with(port, 2, "web", 1000, &[]));
    assert_eq!(status.code(), Some(2));
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "R008"),
        "plain TCP must fail the TLS stage"
    );
}

#[test]
fn ssh_profile_skips_tls() {
    let port = loopback(4);
    let (status, value) = run_json(&scan_args_with(port, 2, "ssh", 1000, &[]));
    assert!(status.success(), "TCP-only profile should pass");
    assert_eq!(value["configuration"]["tls_enabled"], false);
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["rule_id"] != "R008"),
        "TLS must not be evaluated for an SSH profile"
    );
}

#[test]
fn per_attempt_timeout_is_bounded() {
    // 192.0.2.0/24 is reserved for documentation and never routable. The probe
    // may fail immediately (unreachable) or time out; either way the recorded
    // duration must respect --timeout-ms.
    let output = Command::new(binary())
        .args([
            "scan",
            "192.0.2.1",
            "--port",
            "443",
            "--profile",
            "tcp",
            "--rounds",
            "3",
            "--timeout-ms",
            "1000",
            "--interval-ms",
            "20",
            "--max-seconds",
            "30",
            "--format",
            "json",
            "--no-files",
        ])
        .output()
        .expect("run");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let durations: Vec<f64> = value["probes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|probe| probe["kind"] == "tcp")
        .map(|probe| probe["duration_ms"].as_f64().unwrap_or(0.0))
        .collect();
    assert!(!durations.is_empty());
    for duration in durations {
        assert!(
            duration <= 1600.0,
            "attempt took {duration} ms with a 1000 ms timeout"
        );
    }
}

#[test]
fn budget_shrinks_rounds_and_says_so() {
    let port = loopback(40);
    let (status, value) = run_json(&scan_args_with(
        port,
        50,
        "tcp",
        800,
        &["--max-seconds", "5"],
    ));
    assert!(status.success() || status.code() == Some(3));
    let rounds = value["configuration"]["rounds"].as_u64().unwrap();
    assert!(rounds < 50, "budget must reduce rounds, got {rounds}");
    assert!(
        value["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap_or("").contains("预算")),
        "the reduced round count must be explained"
    );
}

#[test]
fn long_timeout_is_accepted() {
    let port = loopback(4);
    let (status, value) = run_json(&scan_args_with(port, 2, "tcp", 6000, &[]));
    assert!(status.success());
    assert_eq!(value["configuration"]["timeout_ms"], 6000);
}

#[test]
fn unknown_bind_interface_is_a_tool_error() {
    let port = loopback(2);
    let mut args = scan_args_with(port, 2, "tcp", 1000, &[]);
    args.push("--bind-interface".to_string());
    args.push("definitely-not-an-interface".to_string());
    let output = Command::new(binary()).args(&args).output().expect("run");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a bad interface name is a tool error, not a network finding"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist"), "stderr: {stderr}");
    assert!(output.stdout.is_empty(), "no report may be produced");
}

/// Minimal HTTP/1.1 responder for deterministic tests.
fn http_stub(status_line: &'static str, body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let response = format!(
                "{status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn http_command_reports_status_and_timings() {
    let port = http_stub("HTTP/1.1 200 OK", "ok");
    let output = Command::new(binary())
        .args([
            "http",
            &format!("http://127.0.0.1:{port}/"),
            "--expect-status",
            "200",
            "--format",
            "json",
        ])
        .output()
        .expect("run");
    assert!(output.status.success(), "expected PASS");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "http");
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["status"], 200);
    assert_eq!(detail["matches_expectation"], true);
    assert!(detail["total_ms"].as_f64().unwrap() > 0.0);
}

#[test]
fn http_expectation_mismatch_fails() {
    let port = http_stub("HTTP/1.1 200 OK", "ok");
    let output = Command::new(binary())
        .args([
            "http",
            &format!("http://127.0.0.1:{port}/"),
            "--expect-status",
            "404",
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("verdict: FAIL"), "output: {text}");
}

#[test]
fn http_4xx_without_expectation_is_warn_not_unreachable() {
    let port = http_stub("HTTP/1.1 403 Forbidden", "no");
    let output = Command::new(binary())
        .args(["http", &format!("http://127.0.0.1:{port}/")])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("status: 403"), "output: {text}");
    assert!(text.contains("verdict: WARN"), "output: {text}");
}

#[test]
fn http_connection_refused_is_reported() {
    let port = free_port();
    let output = Command::new(binary())
        .args([
            "http",
            &format!("http://127.0.0.1:{port}/"),
            "--format",
            "json",
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["probes"][0]["detail"]["error"], "connection_refused");
}

#[test]
fn ping_and_trace_commands_emit_json() {
    for args in [
        vec!["ping", "127.0.0.1", "--count", "2", "--timeout-ms", "8000"],
        vec![
            "trace",
            "127.0.0.1",
            "--max-hops",
            "3",
            "--timeout-ms",
            "15000",
        ],
    ] {
        let mut args = args;
        args.extend(["--format", "json"]);
        let output = Command::new(binary()).args(&args).output().expect("run");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
                panic!(
                    "{} did not emit JSON: {}",
                    args[0],
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        assert_eq!(value["command"], args[0]);
        assert!(!value["probes"].as_array().unwrap().is_empty());
    }
}

#[test]
fn dns_command_reports_resolvers() {
    let output = Command::new(binary())
        .args(["dns", "localhost", "--format", "json"])
        .output()
        .expect("run");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "dns");
    assert!(!value["probes"].as_array().unwrap().is_empty());
}

fn spawn_udp_endpoint(port: u16) -> std::process::Child {
    spawn_udp_endpoint_on(&format!("127.0.0.1:{port}"))
}

fn spawn_udp_endpoint_on(bind: &str) -> std::process::Child {
    Command::new(binary())
        .args(["endpoint", "--udp-echo", "--bind", bind])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn endpoint")
}

#[test]
fn udp_echo_round_trip_passes() {
    let port = free_port();
    let mut endpoint = spawn_udp_endpoint(port);
    std::thread::sleep(std::time::Duration::from_millis(800));
    let output = Command::new(binary())
        .args([
            "udp",
            "--target",
            &format!("127.0.0.1:{port}"),
            "--rounds",
            "5",
            "--timeout-ms",
            "800",
            "--format",
            "json",
        ])
        .output()
        .expect("run udp");
    let _ = endpoint.kill();
    let _ = endpoint.wait();
    assert!(output.status.success(), "echo should pass");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let probes = value["probes"].as_array().unwrap();
    assert!(probes.len() >= 5);
    assert!(probes
        .iter()
        .all(|probe| probe["detail"]["result"] == "echo"));
}

#[test]
fn udp_without_server_reports_icmp_unreachable() {
    let port = free_port();
    let output = Command::new(binary())
        .args([
            "udp",
            "--target",
            &format!("127.0.0.1:{port}"),
            "--rounds",
            "3",
            "--timeout-ms",
            "600",
            "--format",
            "json",
        ])
        .output()
        .expect("run udp");
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(value["probes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|probe| probe["detail"]["result"] == "icmp_unreachable"
            || probe["detail"]["result"] == "timeout"));
}

#[test]
fn udp_echo_over_ipv6_when_loopback_is_available() {
    let port = free_port();
    let mut endpoint = spawn_udp_endpoint_on(&format!("[::1]:{port}"));
    std::thread::sleep(std::time::Duration::from_millis(800));
    if endpoint.try_wait().ok().flatten().is_some() {
        eprintln!("IPv6 loopback is unavailable on this host; test not exercised");
        return;
    }
    let output = Command::new(binary())
        .args([
            "udp",
            "--target",
            &format!("[::1]:{port}"),
            "--rounds",
            "3",
            "--timeout-ms",
            "800",
            "--format",
            "json",
        ])
        .output()
        .expect("run udp");
    let _ = endpoint.kill();
    let _ = endpoint.wait();
    assert!(
        output.status.success(),
        "IPv6 echo should pass: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(value["probes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|probe| probe["detail"]["result"] == "echo"));
}

#[test]
fn udp_total_budget_stops_the_run() {
    let port = free_port();
    let started = std::time::Instant::now();
    let output = Command::new(binary())
        .args([
            "udp",
            "--target",
            &format!("127.0.0.1:{port}"),
            "--rounds",
            "100",
            "--timeout-ms",
            "800",
            "--interval-ms",
            "400",
            "--max-seconds",
            "1",
            "--format",
            "json",
        ])
        .output()
        .expect("run udp");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "budget should stop the run, took {elapsed:?}"
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let probes = value["probes"].as_array().unwrap().len();
    assert!(probes < 100, "budget must reduce rounds, got {probes}");
}

#[test]
fn endpoint_refuses_public_bind_without_flag() {
    let output = Command::new(binary())
        .args(["endpoint", "--udp-echo", "--bind", "0.0.0.0:19999"])
        .output()
        .expect("run endpoint");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a loopback"), "stderr: {stderr}");
}

/// Minimal SOCKS5 server that accepts no-auth CONNECT and then answers the
/// tunnelled HTTP request. `expected_atyp` makes address-type regressions fail
/// loudly instead of being masked by a lenient parser.
fn socks5_stub(require_auth: bool, expected_atyp: Option<u8>) -> u16 {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_err() {
                continue;
            }
            if require_auth {
                let _ = stream.write_all(&[0x05, 0xFF]);
                continue;
            }
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut head = [0u8; 4];
            if stream.read_exact(&mut head).is_err() {
                continue;
            }
            if let Some(expected) = expected_atyp {
                if head[3] != expected {
                    let _ = stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                    continue;
                }
            }
            let address_len = match head[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut length = [0u8; 1];
                    if stream.read_exact(&mut length).is_err() {
                        continue;
                    }
                    length[0] as usize
                }
                _ => continue,
            };
            if address_len > 0 {
                let mut host = vec![0u8; address_len + 2];
                if stream.read_exact(&mut host).is_err() {
                    continue;
                }
            } else {
                let mut length = [0u8; 1];
                let _ = stream.read_exact(&mut length);
                let mut host = vec![0u8; length[0] as usize + 2];
                if stream.read_exact(&mut host).is_err() {
                    continue;
                }
            }
            let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    port
}

#[derive(Clone, Copy)]
enum SocksBehavior {
    BadVersion,
    ConnectRefused,
    BadBoundAddress,
}

fn socks5_error_stub(behavior: SocksBehavior) -> u16 {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let Ok(mut stream) = stream else { continue };
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_err() {
                continue;
            }
            if matches!(behavior, SocksBehavior::BadVersion) {
                let _ = stream.write_all(&[0x04, 0x00]);
                continue;
            }
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut head = [0u8; 4];
            if stream.read_exact(&mut head).is_err() {
                continue;
            }
            let mut rest = [0u8; 6];
            if stream.read_exact(&mut rest).is_err() {
                continue;
            }
            match behavior {
                SocksBehavior::ConnectRefused => {
                    let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                }
                SocksBehavior::BadBoundAddress => {
                    let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0]);
                }
                SocksBehavior::BadVersion => {}
            }
        }
    });
    port
}

#[test]
fn socks5_tunnel_reaches_http_status() {
    let proxy = socks5_stub(false, Some(0x01));
    let output = Command::new(binary())
        .args([
            "proxy",
            "http://127.0.0.1:9/?token=secret",
            "--proxy",
            &format!("socks5://127.0.0.1:{proxy}"),
            "--timeout-ms",
            "3000",
            "--format",
            "json",
        ])
        .output()
        .expect("run proxy");
    assert!(output.status.success(), "tunnel should succeed");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["tunnel_ok"], true);
    assert_eq!(detail["http_status"], 200);
    assert_eq!(detail["target"], "http://127.0.0.1:9/");
    assert_eq!(value["target"], "http://127.0.0.1:9/");
    assert!(!output_text(&value).contains("token=secret"));
}

fn output_text(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[test]
fn socks5_version_and_reply_errors_are_classified() {
    for (behavior, expected) in [
        (SocksBehavior::BadVersion, "unexpected SOCKS version 4"),
        (SocksBehavior::ConnectRefused, "socks_reply:5"),
        (
            SocksBehavior::BadBoundAddress,
            "unsupported bound address type 0x02",
        ),
    ] {
        let proxy = socks5_error_stub(behavior);
        let output = Command::new(binary())
            .args([
                "proxy",
                "http://127.0.0.1:9/",
                "--proxy",
                &format!("socks5://127.0.0.1:{proxy}"),
                "--timeout-ms",
                "1500",
                "--format",
                "json",
            ])
            .output()
            .expect("run proxy");
        assert_eq!(output.status.code(), Some(2));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        let error = value["probes"][0]["detail"]["error"].as_str().unwrap();
        assert!(error.contains(expected), "expected {expected}, got {error}");
    }
}

#[test]
fn socks5_auth_required_is_reported_not_guessed() {
    let proxy = socks5_stub(true, None);
    let output = Command::new(binary())
        .args([
            "proxy",
            "http://127.0.0.1:9/",
            "--proxy",
            &format!("socks5://127.0.0.1:{proxy}"),
            "--timeout-ms",
            "3000",
        ])
        .output()
        .expect("run proxy");
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("auth_required"), "output: {text}");
}

#[test]
fn closed_proxy_port_is_reported() {
    let port = free_port();
    let output = Command::new(binary())
        .args([
            "proxy",
            "http://127.0.0.1:9/",
            "--proxy",
            &format!("socks5://127.0.0.1:{port}"),
            "--timeout-ms",
            "1500",
        ])
        .output()
        .expect("run proxy");
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("proxy_unreachable"), "output: {text}");
}

#[test]
fn socks5_literal_ipv6_uses_atyp4() {
    let proxy = socks5_stub(false, Some(0x04));
    let output = Command::new(binary())
        .args([
            "proxy",
            "http://[::1]:9/",
            "--proxy",
            &format!("socks5://127.0.0.1:{proxy}"),
            "--timeout-ms",
            "3000",
            "--format",
            "json",
        ])
        .output()
        .expect("run proxy");
    assert!(
        output.status.success(),
        "IPv6 literal should use ATYP 4: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn socks5_stage_timings_are_measured_separately() {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut greeting = [0u8; 3];
        let _ = stream.read_exact(&mut greeting);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _ = stream.write_all(&[0x05, 0x00]);
        let mut head = [0u8; 4];
        let _ = stream.read_exact(&mut head);
        let mut rest = [0u8; 6];
        let _ = stream.read_exact(&mut rest);
        let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    });
    let output = Command::new(binary())
        .args([
            "proxy",
            "http://127.0.0.1:9/",
            "--proxy",
            &format!("socks5://127.0.0.1:{port}"),
            "--timeout-ms",
            "3000",
            "--format",
            "json",
        ])
        .output()
        .expect("run proxy");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let detail = &value["probes"][0]["detail"];
    let negotiation = detail["negotiation_ms"].as_f64().unwrap();
    let connect = detail["connect_ms"].as_f64().unwrap();
    assert!(
        negotiation >= 250.0,
        "greeting delay must appear in negotiation, got {negotiation}"
    );
    assert!(
        connect < 200.0,
        "CONNECT must not inherit the greeting delay, got {connect}"
    );
}

enum ConnectBehavior {
    Tunnel,
    AuthRequired,
    Forbidden,
    ServerError,
    HugeHead,
    Tls,
    Close,
}

/// Minimal HTTP CONNECT proxy. For `Tls` it performs a real rustls server
/// handshake inside the tunnel and answers the HTTPS request.
fn http_connect_stub(behavior: ConnectBehavior) -> u16 {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
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
                if head.len() > 8192 {
                    break;
                }
            }
            match behavior {
                ConnectBehavior::AuthRequired => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                    );
                }
                ConnectBehavior::Forbidden => {
                    let _ =
                        stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                }
                ConnectBehavior::ServerError => {
                    let _ =
                        stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                }
                ConnectBehavior::HugeHead => {
                    let _ = stream.write_all(&vec![b'X'; 9000]);
                }
                ConnectBehavior::Close => {
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                }
                ConnectBehavior::Tunnel => {
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                }
                ConnectBehavior::Tls => {
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    let _ = rustls::crypto::ring::default_provider().install_default();
                    let generated =
                        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                            .expect("certificate");
                    let cert =
                        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
                    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                        generated.key_pair.serialize_der().into(),
                    );
                    let config = rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(vec![cert], key)
                        .expect("server config");
                    let connection = rustls::ServerConnection::new(std::sync::Arc::new(config))
                        .expect("server connection");
                    let mut tls = rustls::StreamOwned::new(connection, stream);
                    let mut request = [0u8; 1024];
                    let _ = tls.read(&mut request);
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    );
                    let _ = tls.flush();
                }
            }
        }
    });
    port
}

fn run_http_proxy(proxy: u16, target: &str, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "proxy".to_string(),
        target.to_string(),
        "--proxy".to_string(),
        format!("http://127.0.0.1:{proxy}"),
        "--timeout-ms".to_string(),
        "3000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    args.extend(extra.iter().map(|value| value.to_string()));
    Command::new(binary())
        .args(&args)
        .output()
        .expect("run proxy")
}

#[test]
fn http_connect_tunnel_reaches_http_status() {
    let proxy = http_connect_stub(ConnectBehavior::Tunnel);
    let output = run_http_proxy(proxy, "http://127.0.0.1:9/", &[]);
    assert!(
        output.status.success(),
        "CONNECT should pass: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["type"], "proxy_exchange");
    assert_eq!(detail["proxy_kind"], "http_connect");
    assert_eq!(detail["tunnel_ok"], true);
    assert_eq!(detail["http_status"], 200);
    assert_eq!(detail["negotiation_ms"], 0.0);
}

#[test]
fn http_connect_407_is_auth_required() {
    let proxy = http_connect_stub(ConnectBehavior::AuthRequired);
    let output = run_http_proxy(proxy, "http://127.0.0.1:9/", &[]);
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["probes"][0]["detail"]["error"], "auth_required");
}

#[test]
fn http_connect_403_is_not_auth_and_not_target_health() {
    let proxy = http_connect_stub(ConnectBehavior::Forbidden);
    let output = run_http_proxy(proxy, "http://127.0.0.1:9/", &[]);
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["probes"][0]["detail"]["error"], "http_status:403");
    assert_eq!(value["probes"][0]["detail"]["tunnel_ok"], false);
}

#[test]
fn http_connect_5xx_and_oversized_head_are_reported() {
    let proxy = http_connect_stub(ConnectBehavior::ServerError);
    let output = run_http_proxy(proxy, "http://127.0.0.1:9/", &[]);
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["probes"][0]["detail"]["error"], "http_status:502");

    let proxy = http_connect_stub(ConnectBehavior::HugeHead);
    let output = run_http_proxy(proxy, "http://127.0.0.1:9/", &[]);
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let error = value["probes"][0]["detail"]["error"].as_str().unwrap();
    assert!(error.contains("CONNECT head too large"), "error: {error}");
}

#[test]
fn http_connect_tls_failure_stays_separate_from_tunnel() {
    let proxy = http_connect_stub(ConnectBehavior::Close);
    let output = run_http_proxy(proxy, "https://127.0.0.1:9/", &[]);
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["tunnel_ok"], true);
    assert!(detail["error"].as_str().unwrap().starts_with("tls:"));
    assert!(detail["http_status"].is_null());
}

#[test]
fn http_connect_https_request_through_real_tls_tunnel() {
    let proxy = http_connect_stub(ConnectBehavior::Tls);
    let output = run_http_proxy(proxy, "https://127.0.0.1:9/", &["--insecure"]);
    assert!(
        output.status.success(),
        "HTTPS through CONNECT should pass: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["tunnel_ok"], true);
    assert_eq!(detail["tls_verified"], false);
    assert_eq!(detail["http_status"], 200);
    assert!(detail["tls_ms"].as_f64().unwrap() >= 0.0);
}

#[test]
fn closed_http_proxy_is_reported() {
    let port = free_port();
    let output = run_http_proxy(port, "http://127.0.0.1:9/", &[]);
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(value["probes"][0]["detail"]["error"]
        .as_str()
        .unwrap()
        .starts_with("proxy_unreachable"));
}

#[test]
fn compare_direct_alternates_both_paths_and_states_limits() {
    let target = http_stub("HTTP/1.1 200 OK", "ok");
    let proxy = http_connect_stub(ConnectBehavior::Tunnel);
    let output = Command::new(binary())
        .args([
            "proxy",
            &format!("http://127.0.0.1:{target}/"),
            "--proxy",
            &format!("http://127.0.0.1:{proxy}"),
            "--compare-direct",
            "--rounds",
            "2",
            "--interval-ms",
            "10",
            "--timeout-ms",
            "2000",
            "--format",
            "json",
        ])
        .output()
        .expect("run proxy");
    assert!(
        output.status.success(),
        "comparison should pass: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let comparison = value["probes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|probe| probe["detail"]["type"] == "path_comparison")
        .expect("path comparison detail");
    assert_eq!(comparison["detail"]["direct_total"], 2);
    assert_eq!(comparison["detail"]["proxy_total"], 2);
    assert_eq!(comparison["detail"]["direct_success"], 2);
    assert_eq!(comparison["detail"]["proxy_success"], 2);
    assert_eq!(
        comparison["detail"]["direct_dns"],
        "literal address (no DNS)"
    );
    assert_eq!(
        comparison["detail"]["proxy_dns"],
        "literal address (no DNS)"
    );
    assert!(value["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("Fake-IP")));

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/command.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|error| format!("{} at {}", error, error.instance_path))
        .collect();
    assert!(errors.is_empty(), "schema violations: {errors:#?}");
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    std::env::temp_dir().join(format!("pathtrial-{tag}-{}-{nanos}", std::process::id()))
}

#[test]
fn report_files_use_unique_names_and_do_not_collide() {
    let dir = unique_dir("files");
    std::fs::create_dir_all(&dir).unwrap();
    for _ in 0..2 {
        let port = loopback(2);
        let mut args = scan_args(port);
        args.push("--out-dir".to_string());
        args.push(dir.to_str().unwrap().to_string());
        let status = Command::new(binary()).args(&args).status().expect("run");
        assert!(status.success());
    }
    let jsons: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with("pathtrial-report-"))
        .collect();
    let json_count = jsons.iter().filter(|name| name.ends_with(".json")).count();
    let md_count = jsons.iter().filter(|name| name.ends_with(".md")).count();
    assert_eq!(json_count, 2, "two runs must not overwrite each other");
    assert_eq!(md_count, 2);
}

#[test]
fn no_files_writes_nothing() {
    let dir = unique_dir("nofiles");
    std::fs::create_dir_all(&dir).unwrap();
    let port = loopback(2);
    let mut args = scan_args(port);
    args.push("--no-files".to_string());
    args.push("--format".to_string());
    args.push("json".to_string());
    let output = Command::new(binary())
        .args(&args)
        .current_dir(&dir)
        .output()
        .expect("run");
    assert!(output.status.success());
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(entries.is_empty(), "--no-files must not create files");
}

#[test]
fn json_stdout_is_pure() {
    let port = loopback(2);
    let mut args = scan_args(port);
    args.push("--format".to_string());
    args.push("json".to_string());
    args.push("--no-files".to_string());
    let output = Command::new(binary()).args(&args).output().expect("run");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.trim_start().starts_with('{'), "stdout: {stdout:.80}");
    assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_ok());
    assert!(!stdout.contains("Report:"));
}

#[test]
fn explicit_out_prefix_overwrites_on_purpose() {
    let dir = unique_dir("outprefix");
    std::fs::create_dir_all(&dir).unwrap();
    let prefix = dir.join("fixed");
    for _ in 0..2 {
        let port = loopback(2);
        let mut args = scan_args(port);
        args.push("--out".to_string());
        args.push(prefix.to_str().unwrap().to_string());
        let output = Command::new(binary()).args(&args).output().expect("run");
        assert!(output.status.success());
    }
    assert!(dir.join("fixed.json").exists());
    assert!(dir.join("fixed.md").exists());
    let count = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(count, 2, "explicit prefix writes exactly two files");
}

fn comparison_fixture(target: &str, successes: usize, duration: f64) -> serde_json::Value {
    let mut probes = Vec::new();
    for index in 0..2 {
        let ok = index < successes;
        probes.push(serde_json::json!({
            "id": format!("tcp_ipv4_{:03}", index + 1),
            "kind": "tcp",
            "outcome": if ok { "ok" } else { "fail" },
            "family": "ipv4",
            "started_at": "2026-10-17T00:00:00Z",
            "duration_ms": duration,
            "detail": {
                "type": "tcp_connect",
                "connect_ms": if ok { serde_json::json!(duration) } else { serde_json::Value::Null },
                "error": if ok { serde_json::Value::Null } else { serde_json::json!("timeout") }
            }
        }));
    }
    serde_json::json!({
        "schema_version": "1.3.0",
        "tool_version": "1.2.0-rc.1",
        "run_id": "fixture",
        "started_at": "2026-10-17T00:00:00Z",
        "finished_at": "2026-10-17T00:00:01Z",
        "target": {"input": target, "port": 443, "profile": "web"},
        "configuration": {
            "rounds": 2,
            "timeout_ms": 3000,
            "interval_ms": 200,
            "max_total_seconds": 180,
            "connect_budget": 4,
            "tls_enabled": true,
            "allow_insecure_tls": false,
            "output_format": "json",
            "redact_ips": false
        },
        "environment": {"os": "macos", "arch": "arm64"},
        "stages": [],
        "probes": probes,
        "summaries": [],
        "findings": [
            {"id": "F1", "rule_id": "R006", "status": "WARN", "claim": "one connect failed"}
        ],
        "recommendations": [],
        "limitations": [],
        "redaction": {"applied": false, "ips_masked": 0, "notes": []}
    })
}

#[test]
fn compare_reports_metric_changes_and_rejects_different_targets() {
    let dir = unique_dir("compare");
    std::fs::create_dir_all(&dir).unwrap();
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    std::fs::write(
        &before,
        serde_json::to_vec(&comparison_fixture("example.com", 1, 100.0)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &after,
        serde_json::to_vec(&comparison_fixture("example.com", 2, 80.0)).unwrap(),
    )
    .unwrap();

    let output = Command::new(binary())
        .args([
            "compare",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run compare");
    assert!(output.status.success(), "same conditions should compare");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["comparability"]["verdict"], "DIRECTLY COMPARABLE");
    let metrics = value["metrics"].as_array().unwrap();
    let tcp = metrics
        .iter()
        .find(|metric| metric["name"] == "TCP success")
        .unwrap();
    assert_eq!(tcp["before"], 50.0);
    assert_eq!(tcp["after"], 100.0);
    assert_eq!(tcp["change"], "Improved");

    std::fs::write(
        &after,
        serde_json::to_vec(&comparison_fixture("other.example", 2, 80.0)).unwrap(),
    )
    .unwrap();
    let output = Command::new(binary())
        .args([
            "compare",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run compare");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["comparability"]["verdict"], "NOT DIRECTLY COMPARABLE");
    assert!(value["comparability"]["issues"][0]
        .as_str()
        .unwrap()
        .contains("target differs"));
}

#[test]
fn compare_writes_json_and_markdown_without_overwriting() {
    let dir = unique_dir("compare-out");
    std::fs::create_dir_all(&dir).unwrap();
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    std::fs::write(
        &before,
        serde_json::to_vec(&comparison_fixture("example.com", 1, 100.0)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &after,
        serde_json::to_vec(&comparison_fixture("example.com", 2, 80.0)).unwrap(),
    )
    .unwrap();
    let prefix = dir.join("diff");
    let output = Command::new(binary())
        .args([
            "compare",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--out",
            prefix.to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .output()
        .expect("run compare");
    assert!(output.status.success());
    assert!(dir.join("diff.json").exists());
    assert!(dir.join("diff.md").exists());
    let markdown = std::fs::read_to_string(dir.join("diff.md")).unwrap();
    assert!(markdown.contains("DIRECTLY COMPARABLE"));

    let again = Command::new(binary())
        .args([
            "compare",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--out",
            prefix.to_str().unwrap(),
        ])
        .output()
        .expect("run compare");
    assert_eq!(again.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&again.stderr).contains("refusing to overwrite"));
}
