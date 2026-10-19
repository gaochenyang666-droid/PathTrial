//! M12: offline two-endpoint collection and correlation.
//!
//! The client and server write independent JSON files. Correlation compares
//! observed connection attempts and accepts. These reports are not packet
//! captures and never identify the hop where a packet was lost.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cli::{CollectArgs, CollectRole, OutputFormat};

pub const COLLECT_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Serialize, Deserialize)]
pub struct CollectReport {
    pub schema_version: String,
    pub tool_version: String,
    pub kind: String,
    pub task_id: String,
    pub role: String,
    pub protocol: String,
    pub target: Option<String>,
    pub listen: Option<String>,
    pub window: Window,
    pub clock: ClockInfo,
    pub resolved_addresses: Vec<String>,
    pub events: Vec<CollectEvent>,
    pub summary: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Window {
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClockInfo {
    pub source: String,
    pub synchronized: bool,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CollectEvent {
    pub id: String,
    pub at: String,
    pub kind: String,
    pub peer: Option<String>,
    pub local: Option<String>,
    pub sequence: u32,
    pub task_id_seen: Option<String>,
    pub duration_ms: Option<f64>,
    pub error: Option<String>,
}

pub fn collect(args: &CollectArgs) -> Result<u8, String> {
    if args.task_id.trim().is_empty() {
        return Err("--task-id must not be empty".to_string());
    }
    if args.max_seconds == 0 {
        return Err("--max-seconds must be greater than zero".to_string());
    }
    crate::probes::quic::check_interface(args.bind_interface.as_deref())?;
    let report = match args.role {
        CollectRole::Client => collect_client(args)?,
        CollectRole::Server => collect_server(args)?,
    };
    write_report(&args.output, &report)?;
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| format!("render JSON: {error}"))?
        ),
        OutputFormat::Markdown => print!("{}", render_markdown(&report)),
        OutputFormat::Summary => print!("{}", report.summary),
    }
    Ok(match args.role {
        CollectRole::Client => {
            let successes = report
                .events
                .iter()
                .filter(|event| event.kind == "connect_ok")
                .count();
            let attempts = report.events.len();
            if successes == attempts && attempts > 0 {
                0
            } else {
                2
            }
        }
        CollectRole::Server => 0,
    })
}

fn collect_client(args: &CollectArgs) -> Result<CollectReport, String> {
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| "--target is required for --role client".to_string())?;
    let (host, port) = crate::commands::split_target(target)?;
    let timeout = Duration::from_millis(args.timeout_ms.max(1));
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    let mut resolved_addresses = Vec::new();
    let address = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            resolved_addresses.push(ip.to_string());
            ip
        }
        Err(_) => {
            let mut recorder = crate::probes::Recorder::new();
            let resolved = crate::probes::dns::resolve(&host, &mut recorder, timeout / 3);
            resolved_addresses.extend(resolved.addresses_v4.iter().cloned());
            resolved_addresses.extend(resolved.addresses_v6.iter().cloned());
            resolved_addresses
                .first()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| format!("cannot resolve {host}"))?
        }
    };
    let socket = SocketAddr::new(address, port);
    let started_at = crate::util::now_rfc3339();
    let mut events = Vec::new();
    for sequence in 1..=args.rounds {
        if Instant::now() >= deadline {
            break;
        }
        let started = Instant::now();
        let event_at = crate::util::now_rfc3339();
        match crate::net::connect(socket, timeout, args.bind_interface.as_deref()) {
            Ok(mut stream) => {
                let payload = format!("PTCT {} {}\n", args.task_id, sequence);
                let write = stream
                    .set_write_timeout(Some(timeout))
                    .and_then(|_| stream.write_all(payload.as_bytes()));
                let duration_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
                events.push(CollectEvent {
                    id: format!("client_{sequence:03}"),
                    at: event_at,
                    kind: if write.is_ok() {
                        "connect_ok".to_string()
                    } else {
                        "write_fail".to_string()
                    },
                    peer: stream.peer_addr().ok().map(|value| value.to_string()),
                    local: stream.local_addr().ok().map(|value| value.to_string()),
                    sequence,
                    task_id_seen: Some(args.task_id.clone()),
                    duration_ms: Some(duration_ms),
                    error: write.err().map(|error| error.to_string()),
                });
            }
            Err(error) => {
                events.push(CollectEvent {
                    id: format!("client_{sequence:03}"),
                    at: event_at,
                    kind: "connect_fail".to_string(),
                    peer: Some(socket.to_string()),
                    local: None,
                    sequence,
                    task_id_seen: None,
                    duration_ms: Some(round2(started.elapsed().as_secs_f64() * 1000.0)),
                    error: Some(crate::util::classify_io_error(&error).label()),
                });
            }
        }
        if !args.interval_ms.eq(&0) {
            std::thread::sleep(Duration::from_millis(args.interval_ms));
        }
    }
    let finished_at = crate::util::now_rfc3339();
    let successes = events
        .iter()
        .filter(|event| event.kind == "connect_ok")
        .count();
    let summary = format!(
        "PathTrial collect client\nTask: {}\nTarget: {}\nAttempts: {}\nConnect OK: {}\nWindow: {} .. {}\nOutput: {}\n",
        args.task_id,
        target,
        events.len(),
        successes,
        started_at,
        finished_at,
        args.output.display()
    );
    Ok(CollectReport {
        schema_version: COLLECT_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        kind: "collect".to_string(),
        task_id: args.task_id.clone(),
        role: "client".to_string(),
        protocol: "tcp".to_string(),
        target: Some(target.to_string()),
        listen: None,
        window: Window {
            started_at,
            finished_at,
        },
        clock: ClockInfo {
            source: "system clock".to_string(),
            synchronized: false,
            note: "No clock synchronization has been established between endpoints".to_string(),
        },
        resolved_addresses,
        events,
        summary,
        limitations: vec![
            "Client success means the TCP connect and small task payload write completed"
                .to_string(),
            "This report contains no packet capture and cannot locate packet loss".to_string(),
        ],
    })
}

fn collect_server(args: &CollectArgs) -> Result<CollectReport, String> {
    let listen = args
        .listen
        .as_deref()
        .ok_or_else(|| "--listen is required for --role server".to_string())?;
    let address: SocketAddr = listen
        .parse()
        .map_err(|_| format!("--listen needs IP:PORT, got {listen}"))?;
    let listener =
        TcpListener::bind(address).map_err(|error| format!("bind {address}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set nonblocking: {error}"))?;
    let started_at = crate::util::now_rfc3339();
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    let mut events = Vec::new();
    let mut sequence = 0u32;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, peer)) => {
                sequence += 1;
                let at = crate::util::now_rfc3339();
                let local = stream.local_addr().ok().map(|value| value.to_string());
                let (task_seen, read_error) = read_task_id(&stream);
                events.push(CollectEvent {
                    id: format!("server_{sequence:03}"),
                    at,
                    kind: "accept".to_string(),
                    peer: Some(peer.to_string()),
                    local,
                    sequence,
                    task_id_seen: task_seen,
                    duration_ms: None,
                    error: read_error,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(format!("accept on {address}: {error}")),
        }
    }
    let finished_at = crate::util::now_rfc3339();
    let matched = events
        .iter()
        .filter(|event| event.task_id_seen.as_deref() == Some(args.task_id.as_str()))
        .count();
    let summary = format!(
        "PathTrial collect server\nTask: {}\nListen: {}\nAccepts: {}\nTask payloads: {}\nWindow: {} .. {}\nOutput: {}\n",
        args.task_id,
        listen,
        events.len(),
        matched,
        started_at,
        finished_at,
        args.output.display()
    );
    Ok(CollectReport {
        schema_version: COLLECT_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        kind: "collect".to_string(),
        task_id: args.task_id.clone(),
        role: "server".to_string(),
        protocol: "tcp".to_string(),
        target: None,
        listen: Some(listen.to_string()),
        window: Window {
            started_at,
            finished_at,
        },
        clock: ClockInfo {
            source: "system clock".to_string(),
            synchronized: false,
            note: "No clock synchronization has been established between endpoints".to_string(),
        },
        resolved_addresses: Vec::new(),
        events,
        summary,
        limitations: vec![
            "Server accept proves this endpoint observed a TCP connection".to_string(),
            "No packet capture was performed; this report cannot identify a loss location"
                .to_string(),
        ],
    })
}

fn read_task_id(stream: &TcpStream) -> (Option<String>, Option<String>) {
    let mut stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(error) => return (None, Some(format!("clone: {error}"))),
    };
    let deadline = Instant::now() + Duration::from_millis(300);
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))));
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let room = 256 - buffer.len();
                buffer.extend_from_slice(&chunk[..read.min(room)]);
                if buffer.len() >= 256 || buffer.contains(&b'\n') {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // TCP payload bytes may arrive after the first read timeout.
                // Wait for the entire bounded read window even when no bytes
                // have arrived yet; a short scheduling delay is not a failure.
                if Instant::now() >= deadline {
                    if buffer.is_empty() {
                        return (None, Some(format!("read: {error}")));
                    }
                    break;
                }
            }
            Err(error) => return (None, Some(format!("read: {error}"))),
        }
    }
    if buffer.is_empty() {
        return (None, None);
    }
    let text = String::from_utf8_lossy(&buffer);
    let mut parts = text.lines().next().unwrap_or("").split_whitespace();
    if parts.next() == Some("PTCT") {
        (parts.next().map(str::to_string), None)
    } else {
        (None, Some("unrecognized client payload".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn task_payload_delayed_past_initial_read_timeout_is_reassembled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            // Longer than the first 100 ms read timeout, shorter than the
            // 300 ms total deadline.
            std::thread::sleep(Duration::from_millis(150));
            stream.write_all(b"PTCT task-delayed 1\n").unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let (task, error) = read_task_id(&stream);
        assert_eq!(task.as_deref(), Some("task-delayed"));
        assert_eq!(error, None);
        writer.join().unwrap();
    }

    #[test]
    fn task_payload_split_across_reads_is_reassembled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.write_all(b"PT").unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(80));
            stream.write_all(b"CT task-split 1\n").unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let (task, error) = read_task_id(&stream);
        writer.join().unwrap();
        assert_eq!(task.as_deref(), Some("task-split"));
        assert_eq!(error, None);
    }

    fn report(role: &str, schema_version: &str, events: usize) -> CollectReport {
        let kind = if role == "client" {
            "connect_ok"
        } else {
            "accept"
        };
        CollectReport {
            schema_version: schema_version.to_string(),
            tool_version: "test".to_string(),
            kind: "collect".to_string(),
            task_id: "task-a".to_string(),
            role: role.to_string(),
            protocol: "tcp".to_string(),
            target: (role == "client").then(|| "127.0.0.1:40000".to_string()),
            listen: (role == "server").then(|| "127.0.0.1:40000".to_string()),
            window: Window {
                started_at: "2026-10-19T00:00:00Z".to_string(),
                finished_at: "2026-10-19T00:00:01Z".to_string(),
            },
            clock: ClockInfo {
                source: "system clock".to_string(),
                synchronized: false,
                note: "test".to_string(),
            },
            resolved_addresses: if role == "client" {
                vec!["127.0.0.1".to_string()]
            } else {
                Vec::new()
            },
            events: (1..=events)
                .map(|sequence| CollectEvent {
                    id: format!("{role}_{sequence:03}"),
                    at: "2026-10-19T00:00:00Z".to_string(),
                    kind: kind.to_string(),
                    peer: Some("127.0.0.1:40001".to_string()),
                    local: Some("127.0.0.1:40000".to_string()),
                    sequence: sequence as u32,
                    task_id_seen: Some("task-a".to_string()),
                    duration_ms: Some(1.0),
                    error: None,
                })
                .collect(),
            summary: String::new(),
            limitations: Vec::new(),
        }
    }

    #[test]
    fn schema_difference_is_a_limit_not_a_failure() {
        let report = build_correlation(
            report("client", COLLECT_SCHEMA_VERSION, 2),
            report("server", "0.9.0", 2),
        );
        assert_eq!(report.finding.status, "PASS");
        assert_eq!(report.comparability.verdict, "DIRECTLY COMPARABLE");
        assert!(report
            .comparability
            .limits
            .iter()
            .any(|limit| limit.contains("schema versions differ")));
    }
}

fn write_report(path: &Path, report: &CollectReport) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite {}; choose a new --output",
            path.display()
        ));
    }
    let json = serde_json::to_string_pretty(report)
        .map_err(|error| format!("render collect JSON: {error}"))?;
    std::fs::write(path, json).map_err(|error| format!("write {}: {error}", path.display()))
}

fn render_markdown(report: &CollectReport) -> String {
    format!(
        "# PathTrial collect ({})\n\n- Task: `{}`\n- Protocol: {}\n- Window: {} .. {}\n- Events: {}\n\n{}\n",
        report.role,
        report.task_id,
        report.protocol,
        report.window.started_at,
        report.window.finished_at,
        report.events.len(),
        report
            .limitations
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[derive(Debug, Serialize)]
pub struct CorrelationReport {
    pub schema_version: String,
    pub tool_version: String,
    pub kind: String,
    pub generated_at: String,
    pub task_id: Option<String>,
    pub comparability: CorrelationVerdict,
    pub client: SideSummary,
    pub server: SideSummary,
    pub finding: CorrelationFinding,
}

#[derive(Debug, Serialize)]
pub struct CorrelationVerdict {
    pub verdict: String,
    pub issues: Vec<String>,
    pub limits: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SideSummary {
    pub role: String,
    pub schema_version: String,
    pub events: usize,
    pub success: usize,
    pub task_matched: usize,
    pub window: Window,
}

#[derive(Debug, Serialize)]
pub struct CorrelationFinding {
    pub claim: String,
    pub status: String,
    pub evidence: Vec<String>,
    pub not_established: Vec<String>,
    pub confidence: String,
    pub limits: Vec<String>,
}

pub fn correlate(args: &crate::cli::CorrelateArgs) -> Result<u8, String> {
    let client = read_collect(&args.client)?;
    let server = read_collect(&args.server)?;
    let report = build_correlation(client, server);
    if let Some(prefix) = &args.out {
        write_correlation(prefix, &report)?;
    }
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| format!("render JSON: {error}"))?
        ),
        OutputFormat::Markdown => print!("{}", correlation_markdown(&report)),
        OutputFormat::Summary => print!("{}", correlation_summary(&report)),
    }
    Ok(match report.finding.status.as_str() {
        "PASS" => 0,
        "FAIL" => 2,
        _ => 3,
    })
}

fn read_collect(path: &PathBuf) -> Result<CollectReport, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let report: CollectReport = serde_json::from_str(&text)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if report.kind != "collect" {
        return Err(format!("{} is not a collect report", path.display()));
    }
    Ok(report)
}

fn build_correlation(client: CollectReport, server: CollectReport) -> CorrelationReport {
    let mut issues = Vec::new();
    let mut limits = Vec::new();
    if client.role != "client" {
        issues.push(format!("first report has role {}", client.role));
    }
    if server.role != "server" {
        issues.push(format!("second report has role {}", server.role));
    }
    if client.task_id != server.task_id {
        issues.push(format!(
            "task ids differ: {} -> {}",
            client.task_id, server.task_id
        ));
    }
    if client.protocol != server.protocol {
        issues.push(format!(
            "protocols differ: {} -> {}",
            client.protocol, server.protocol
        ));
    }
    let client_port = client
        .target
        .as_deref()
        .and_then(|target| crate::commands::split_target(target).ok())
        .map(|(_, port)| port);
    let server_port = server.listen.as_deref().and_then(|listen| {
        listen
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
    });
    if client_port.is_some() && server_port.is_some() && client_port != server_port {
        issues.push(format!(
            "ports differ: client {:?} -> server {:?}",
            client_port, server_port
        ));
    }
    let client_ip = client
        .resolved_addresses
        .first()
        .and_then(|value| value.parse::<std::net::IpAddr>().ok());
    let server_ip = server
        .listen
        .as_deref()
        .and_then(|listen| listen.parse::<SocketAddr>().ok())
        .map(|address| address.ip());
    if let (Some(client_ip), Some(server_ip)) = (client_ip, server_ip) {
        if !server_ip.is_unspecified() && client_ip != server_ip {
            issues.push(format!(
                "target address differs from server listen address: {client_ip} -> {server_ip}"
            ));
        }
    }
    if client.schema_version != server.schema_version {
        limits.push(format!(
            "collect schema versions differ: {} -> {}",
            client.schema_version, server.schema_version
        ));
    }
    if !windows_overlap(&client.window, &server.window) {
        issues.push("collection windows do not overlap".to_string());
    }
    limits.push(
        "Clock synchronization is not established; timestamps are compared as reported".to_string(),
    );
    limits.push(
        "No packet capture evidence exists; connection behavior cannot identify a loss location"
            .to_string(),
    );

    let client_success = client
        .events
        .iter()
        .filter(|event| event.kind == "connect_ok")
        .count();
    let server_matched = server
        .events
        .iter()
        .filter(|event| event.task_id_seen.as_deref() == Some(client.task_id.as_str()))
        .count();
    let mut evidence = Vec::new();
    evidence.extend(
        client
            .events
            .iter()
            .filter(|event| event.kind == "connect_ok")
            .take(5)
            .map(|event| event.id.clone()),
    );
    evidence.extend(
        server
            .events
            .iter()
            .filter(|event| event.task_id_seen.as_deref() == Some(client.task_id.as_str()))
            .take(5)
            .map(|event| event.id.clone()),
    );
    let (status, claim) = if issues.is_empty()
        && client_success > 0
        && client_success == server_matched
    {
        (
            "PASS",
            format!(
                "Client and server both observed {client_success} task-tagged connection attempts"
            ),
        )
    } else if client_success > server_matched && client_success > 0 {
        (
            "FAIL",
            format!(
                "Client reported {client_success} successful attempts; server observed {server_matched} matching task payloads"
            ),
        )
    } else if server_matched > client_success {
        (
            "FAIL",
            format!(
                "Server observed {server_matched} matching task payloads; client reported {client_success} successes"
            ),
        )
    } else {
        (
            "INCONCLUSIVE",
            "No successful task-tagged connection was observed on both sides".to_string(),
        )
    };
    let status = if issues.is_empty() {
        status
    } else {
        "INCONCLUSIVE"
    };
    let verdict = if issues.is_empty() {
        "DIRECTLY COMPARABLE"
    } else {
        "NOT DIRECTLY COMPARABLE"
    };
    CorrelationReport {
        schema_version: "1.0.0".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        kind: "correlation".to_string(),
        generated_at: crate::util::now_rfc3339(),
        task_id: Some(client.task_id.clone()),
        comparability: CorrelationVerdict {
            verdict: verdict.to_string(),
            issues,
            limits: limits.clone(),
        },
        client: SideSummary {
            role: client.role,
            schema_version: client.schema_version,
            events: client.events.len(),
            success: client_success,
            task_matched: client_success,
            window: client.window,
        },
        server: SideSummary {
            role: server.role,
            schema_version: server.schema_version,
            events: server.events.len(),
            success: server_matched,
            task_matched: server_matched,
            window: server.window,
        },
        finding: CorrelationFinding {
            claim: claim.to_string(),
            status: status.to_string(),
            evidence,
            not_established: vec![
                "Which hop, if any, dropped a packet".to_string(),
                "Whether the two clocks were synchronized".to_string(),
                "Whether middleboxes altered the path".to_string(),
            ],
            confidence: if status == "PASS" { "moderate" } else { "low" }.to_string(),
            limits,
        },
    }
}

fn windows_overlap(first: &Window, second: &Window) -> bool {
    let parse = |value: &str| chrono::DateTime::parse_from_rfc3339(value).ok();
    match (
        parse(&first.started_at),
        parse(&first.finished_at),
        parse(&second.started_at),
        parse(&second.finished_at),
    ) {
        (Some(a_start), Some(a_end), Some(b_start), Some(b_end)) => {
            a_start <= b_end && b_start <= a_end
        }
        _ => false,
    }
}

fn write_correlation(prefix: &Path, report: &CorrelationReport) -> Result<(), String> {
    let json_path = prefix.with_extension("json");
    let md_path = prefix.with_extension("md");
    for path in [&json_path, &md_path] {
        if path.exists() {
            return Err(format!("refusing to overwrite {}", path.display()));
        }
    }
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write {}: {error}", json_path.display()))?;
    std::fs::write(&md_path, correlation_markdown(report))
        .map_err(|error| format!("write {}: {error}", md_path.display()))?;
    Ok(())
}

fn correlation_summary(report: &CorrelationReport) -> String {
    format!(
        "PATH TRIAL CORRELATION\nTask: {}\nComparability: {}\nClient: {}/{} successful\nServer: {}/{} task-matched\nFinding: {} ({})\nEvidence: {}\n",
        report.task_id.as_deref().unwrap_or("unavailable"),
        report.comparability.verdict,
        report.client.success,
        report.client.events,
        report.server.task_matched,
        report.server.events,
        report.finding.claim,
        report.finding.status,
        report.finding.evidence.join(", ")
    )
}

fn correlation_markdown(report: &CorrelationReport) -> String {
    let mut out = String::new();
    out.push_str("# PathTrial correlation\n\n");
    out.push_str(&format!(
        "- Task: `{}`\n",
        report.task_id.as_deref().unwrap_or("unavailable")
    ));
    out.push_str(&format!(
        "- Comparability: **{}**\n",
        report.comparability.verdict
    ));
    out.push_str(&format!(
        "- Client: {}/{} successful\n- Server: {}/{} task-matched\n\n",
        report.client.success,
        report.client.events,
        report.server.task_matched,
        report.server.events
    ));
    out.push_str(&format!(
        "## Finding ({})\n\n{}\n\n",
        report.finding.status, report.finding.claim
    ));
    out.push_str("### Not established\n\n");
    for item in &report.finding.not_established {
        out.push_str(&format!("- {item}\n"));
    }
    if !report.comparability.issues.is_empty() {
        out.push_str("\n### Comparability issues\n\n");
        for issue in &report.comparability.issues {
            out.push_str(&format!("- {issue}\n"));
        }
    }
    out
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
