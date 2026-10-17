//! Minimal, auditable MCP stdio server for PathTrial AI Plugins.
//!
//! The server speaks newline-delimited JSON-RPC 2.0 on stdout and never writes
//! logs to stdout. Probe tools are denied unless the target matches a startup
//! allowlist. Report analysis tools do not perform network requests.

use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

use crate::cli::McpArgs;
pub const PLUGIN_VERSION: &str = "0.1.0";
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_ROUNDS: u32 = 50;
const MAX_TIMEOUT_MS: u64 = 15_000;
const MAX_SECONDS: u64 = 60;

#[derive(Debug, Clone)]
struct AllowRule {
    host: String,
    port: Option<u16>,
}

#[derive(Debug)]
struct ToolError {
    code: &'static str,
    message: String,
}

impl ToolError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_params",
            message: message.into(),
        }
    }

    fn denied(message: impl Into<String>) -> Self {
        Self {
            code: "target_not_allowed",
            message: message.into(),
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            code: "execution_failed",
            message: message.into(),
        }
    }
}

pub fn run(args: &McpArgs) -> Result<(), String> {
    let allowlist = build_allowlist(args)?;
    eprintln!(
        "pathtrial mcp {} starting with {} authorized target rule(s)",
        PLUGIN_VERSION,
        allowlist.len()
    );
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("read MCP stdin: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                write_message(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {"code": -32700, "message": format!("Parse error: {error}")}
                    }),
                )?;
                continue;
            }
        };
        let id = message.get("id").cloned();
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if id.is_none() {
            if method == "notifications/initialized" {
                eprintln!("MCP client initialized");
            }
            continue;
        }
        let id = id.unwrap_or(Value::Null);
        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": initialize_result(message.get("params"))
            }),
            "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"tools": tool_definitions()}
            }),
            "tools/call" => {
                let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": call_tool(params, &allowlist)
                })
            }
            "resources/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"resources": []}
            }),
            "prompts/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"prompts": []}
            }),
            "shutdown" => {
                write_message(
                    &mut stdout,
                    &json!({"jsonrpc": "2.0", "id": id, "result": Value::Null}),
                )?;
                return Ok(());
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("Method not found: {method}")}
            }),
        };
        write_message(&mut stdout, &response)?;
    }
    Ok(())
}

fn write_message(stdout: &mut std::io::Stdout, value: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *stdout, value)
        .map_err(|error| format!("write MCP response: {error}"))?;
    stdout
        .write_all(b"\n")
        .and_then(|_| stdout.flush())
        .map_err(|error| format!("flush MCP response: {error}"))
}

fn initialize_result(params: Option<&Value>) -> Value {
    let requested = params
        .and_then(|value| value.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(MCP_PROTOCOL_VERSION);
    let protocol = match requested {
        "2024-11-05" | "2025-03-26" | "2025-06-18" => requested,
        _ => MCP_PROTOCOL_VERSION,
    };
    json!({
        "protocolVersion": protocol,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "pathtrial", "version": PLUGIN_VERSION},
        "instructions": "PathTrial provides evidence-first local network diagnostics. Call pathtrial_capabilities first. Probe tools are restricted by the server-side target allowlist. Report analysis and comparison tools do not perform network requests. Treat HTTP 4xx/5xx as application responses, QUIC handshake success as transport evidence only, and never invent a packet-loss location without capture evidence."
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "pathtrial_capabilities",
            "Show PathTrial build, platform, supported probes, schema versions, limits and authorization rules.",
            json!({"type": "object", "additionalProperties": false}),
        ),
        tool(
            "pathtrial_scan",
            "Run the fixed five-stage PathTrial scan against one explicitly authorized target.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["target"],
                "properties": {
                    "target": {"type": "string", "minLength": 1, "maxLength": 253},
                    "profile": {"type": "string", "enum": ["web", "tcp", "ssh"], "default": "web"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "rounds": {"type": "integer", "minimum": 1, "maximum": MAX_ROUNDS, "default": 5},
                    "timeout_ms": {"type": "integer", "minimum": 200, "maximum": MAX_TIMEOUT_MS, "default": 3000},
                    "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS, "default": 30},
                    "address_family": {"type": "string", "enum": ["auto", "ipv4", "ipv6"], "default": "auto"},
                    "redact_ips": {"type": "boolean", "default": false}
                }
            }),
        ),
        tool(
            "pathtrial_http",
            "Send one real HTTP or HTTPS request and preserve DNS, TCP, TLS and HTTP status as separate evidence.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "expect_status": {"type": "integer", "minimum": 100, "maximum": 599},
                    "timeout_ms": {"type": "integer", "minimum": 200, "maximum": MAX_TIMEOUT_MS, "default": 8000}
                }
            }),
        ),
        tool(
            "pathtrial_quic",
            "Perform a real QUIC handshake and report transport, certificate, ALPN and timing separately.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["host"],
                "properties": {
                    "host": {"type": "string", "minLength": 1, "maxLength": 253},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 443},
                    "family": {"type": "string", "enum": ["auto", "ipv4", "ipv6"], "default": "auto"},
                    "alpn": {"type": "string", "minLength": 1, "maxLength": 64, "default": "h3"},
                    "timeout_ms": {"type": "integer", "minimum": 200, "maximum": MAX_TIMEOUT_MS, "default": 5000},
                    "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS, "default": 15}
                }
            }),
        ),
        tool(
            "pathtrial_http3",
            "Perform a real HTTP/3 GET over QUIC and keep HTTP/3 application failure separate from QUIC handshake success.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "family": {"type": "string", "enum": ["auto", "ipv4", "ipv6"], "default": "auto"},
                    "timeout_ms": {"type": "integer", "minimum": 200, "maximum": MAX_TIMEOUT_MS, "default": 5000},
                    "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS, "default": 15}
                }
            }),
        ),
        tool(
            "pathtrial_proxy_test",
            "Test a SOCKS5 or HTTP CONNECT proxy and optionally compare direct and proxied paths.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["url", "proxy"],
                "properties": {
                    "url": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "proxy": {"type": "string", "minLength": 1, "maxLength": 512},
                    "compare_direct": {"type": "boolean", "default": false},
                    "rounds": {"type": "integer", "minimum": 1, "maximum": 20, "default": 3},
                    "timeout_ms": {"type": "integer", "minimum": 200, "maximum": MAX_TIMEOUT_MS, "default": 8000},
                    "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS, "default": 30}
                }
            }),
        ),
        tool(
            "pathtrial_udp_echo",
            "Send application-level UDP Echo datagrams to a target that runs a compatible Echo service.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["target"],
                "properties": {
                    "target": {"type": "string", "minLength": 3, "maxLength": 300},
                    "rounds": {"type": "integer", "minimum": 1, "maximum": MAX_ROUNDS, "default": 5},
                    "timeout_ms": {"type": "integer", "minimum": 100, "maximum": MAX_TIMEOUT_MS, "default": 1500},
                    "interval_ms": {"type": "integer", "minimum": 0, "maximum": 5000, "default": 200},
                    "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS, "default": 15},
                    "payload": {"type": "integer", "minimum": 17, "maximum": 512, "default": 64}
                }
            }),
        ),
        tool(
            "pathtrial_compare_reports",
            "Compare two PathTrial report objects with target, port, family, interface, timeout and sample-count comparability checks.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["before", "after"],
                "properties": {
                    "before": {"type": "object"},
                    "after": {"type": "object"}
                }
            }),
        ),
        tool(
            "pathtrial_explain_report",
            "Extract a deterministic evidence summary from a PathTrial report object without calling any external AI API.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["report"],
                "properties": {
                    "report": {"type": "object"}
                }
            }),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": name == "pathtrial_capabilities"
                || name == "pathtrial_compare_reports"
                || name == "pathtrial_explain_report",
            "openWorldHint": name != "pathtrial_capabilities"
                && name != "pathtrial_compare_reports"
                && name != "pathtrial_explain_report",
            "destructiveHint": false
        }
    })
}

fn call_tool(params: Value, allowlist: &[AllowRule]) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let result = match name {
        "pathtrial_capabilities" => Ok(capabilities(allowlist)),
        "pathtrial_scan" => tool_scan(&arguments, allowlist),
        "pathtrial_http" => tool_http(&arguments, allowlist),
        "pathtrial_quic" => tool_quic(&arguments, allowlist),
        "pathtrial_http3" => tool_http3(&arguments, allowlist),
        "pathtrial_proxy_test" => tool_proxy(&arguments, allowlist),
        "pathtrial_udp_echo" => tool_udp(&arguments, allowlist),
        "pathtrial_compare_reports" => tool_compare(&arguments),
        "pathtrial_explain_report" => tool_explain(&arguments),
        _ => Err(ToolError::invalid(format!("unknown tool {name}"))),
    };
    match result {
        Ok(value) => tool_result(value, false),
        Err(error) => tool_result(
            json!({"error": {"code": error.code, "message": error.message}}),
            true,
        ),
    }
}

fn tool_result(value: Value, is_error: bool) -> Value {
    let text = value
        .get("summary")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| serde_json::to_string_pretty(&value).unwrap_or_default());
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": value,
        "isError": is_error
    })
}

fn capabilities(allowlist: &[AllowRule]) -> Value {
    let modules = [
        ("dns", true),
        ("tcp", true),
        ("tls", true),
        ("http", true),
        ("icmp", true),
        ("trace", true),
        ("udp_echo", true),
        ("proxy", true),
        ("quic", true),
        ("http3", true),
        ("dual_end_cli", true),
        ("dual_end_mcp", false),
        ("windows", false),
        ("packet_capture", false),
        ("ssh_orchestration", false),
    ];
    json!({
        "summary": format!("PathTrial {} MCP server on {}/{}; {} authorized target rule(s)", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH, allowlist.len()),
        "core_version": env!("CARGO_PKG_VERSION"),
        "plugin_version": PLUGIN_VERSION,
        "mcp_protocol": MCP_PROTOCOL_VERSION,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "modules": modules.iter().map(|(name, available)| json!({"name": name, "available": available})).collect::<Vec<_>>(),
        "unsupported": [
            "Windows",
            "automatic packet capture",
            "SSH orchestration",
            "MCP dual-end orchestration (use the collect and correlate CLI commands)"
        ],
        "schema_versions": {
            "scan": crate::models::SCHEMA_VERSION,
            "command": "1.1.0",
            "collect": crate::collect::COLLECT_SCHEMA_VERSION,
            "correlate": "1.0.0",
            "compare": "1.0.0"
        },
        "limits": {
            "rounds_max": MAX_ROUNDS,
            "timeout_ms_max": MAX_TIMEOUT_MS,
            "max_seconds_max": MAX_SECONDS,
            "no_network_scan": true,
            "no_port_scan": true,
            "no_credentials": true
        },
        "authorization": {
            "probe_requires_allowlist": true,
            "allow_rules": allowlist.iter().map(|rule| json!({"host": rule.host, "port": rule.port})).collect::<Vec<_>>()
        }
    })
}

fn tool_scan(arguments: &Value, allowlist: &[AllowRule]) -> Result<Value, ToolError> {
    let target = string_arg(arguments, "target", 253)?;
    let profile = enum_arg(arguments, "profile", &["web", "tcp", "ssh"], "web")?;
    let port = optional_u16(arguments, "port")?;
    let rounds = bounded_u32(arguments, "rounds", 1, MAX_ROUNDS, 5)?;
    let timeout_ms = bounded_u64(arguments, "timeout_ms", 200, MAX_TIMEOUT_MS, 3000)?;
    let max_seconds = bounded_u64(arguments, "max_seconds", 1, MAX_SECONDS, 30)?;
    let family = enum_arg(
        arguments,
        "address_family",
        &["auto", "ipv4", "ipv6"],
        "auto",
    )?;
    let redact = bool_arg(arguments, "redact_ips", false)?;
    let effective_port = port.unwrap_or(if profile == "ssh" { 22 } else { 443 });
    let effective_target = match family.as_str() {
        "ipv4" | "ipv6" => {
            let ip = resolve_for_family(&target, &family)
                .map_err(|error| ToolError::failed(format!("resolve {target}: {error}")))?;
            authorize_ip(ip, effective_port, allowlist)?;
            ip.to_string()
        }
        _ => {
            authorize(&target, effective_port, allowlist)?;
            target.clone()
        }
    };
    let mut args = vec![
        "scan".to_string(),
        effective_target.clone(),
        "--profile".to_string(),
        profile.to_string(),
        "--rounds".to_string(),
        rounds.to_string(),
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--max-seconds".to_string(),
        max_seconds.to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--no-files".to_string(),
    ];
    if let Some(port) = port {
        args.push("--port".to_string());
        args.push(port.to_string());
    }
    if redact {
        args.push("--redact-ips".to_string());
    }
    let report = run_cli_json(&args)?;
    Ok(json!({
        "summary": format!("scan completed for {target} ({family}, port {effective_port})"),
        "requested_target": target,
        "measured_target": effective_target,
        "address_family": family,
        "report": report
    }))
}

fn tool_http(arguments: &Value, allowlist: &[AllowRule]) -> Result<Value, ToolError> {
    let url = string_arg(arguments, "url", 2048)?;
    let parsed = crate::probes::http::parse_url(&url)
        .map_err(|error| ToolError::invalid(format!("invalid URL: {error}")))?;
    authorize(&parsed.host, parsed.port, allowlist)?;
    let timeout_ms = bounded_u64(arguments, "timeout_ms", 200, MAX_TIMEOUT_MS, 8000)?;
    let mut args = vec![
        "http".to_string(),
        url.clone(),
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if let Some(status) = optional_u16(arguments, "expect_status")? {
        if !(100..=599).contains(&status) {
            return Err(ToolError::invalid(
                "expect_status must be between 100 and 599",
            ));
        }
        args.push("--expect-status".to_string());
        args.push(status.to_string());
    }
    let report = run_cli_json(&args)?;
    Ok(
        json!({"summary": format!("HTTP probe completed for {}", parsed.redacted()), "report": report}),
    )
}

fn tool_quic(arguments: &Value, allowlist: &[AllowRule]) -> Result<Value, ToolError> {
    let host = string_arg(arguments, "host", 253)?;
    let port = bounded_u16(arguments, "port", 1, 65535, 443)?;
    authorize(&host, port, allowlist)?;
    let family = enum_arg(arguments, "family", &["auto", "ipv4", "ipv6"], "auto")?;
    let alpn = match arguments.get("alpn").and_then(Value::as_str) {
        Some(value) => {
            if value.is_empty() || value.len() > 64 {
                return Err(ToolError::invalid("alpn must be 1 to 64 bytes"));
            }
            value.to_string()
        }
        None => "h3".to_string(),
    };
    let timeout_ms = bounded_u64(arguments, "timeout_ms", 200, MAX_TIMEOUT_MS, 5000)?;
    let max_seconds = bounded_u64(arguments, "max_seconds", 1, MAX_SECONDS, 15)?;
    let report = run_cli_json(&[
        "quic".to_string(),
        host.clone(),
        "--port".to_string(),
        port.to_string(),
        "--family".to_string(),
        family.to_string(),
        "--alpn".to_string(),
        alpn,
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--max-seconds".to_string(),
        max_seconds.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ])?;
    Ok(json!({"summary": format!("QUIC probe completed for {host}:{port}"), "report": report}))
}

fn tool_http3(arguments: &Value, allowlist: &[AllowRule]) -> Result<Value, ToolError> {
    let url = string_arg(arguments, "url", 2048)?;
    let parsed = crate::probes::http::parse_url(&url)
        .map_err(|error| ToolError::invalid(format!("invalid URL: {error}")))?;
    authorize(&parsed.host, parsed.port, allowlist)?;
    let family = enum_arg(arguments, "family", &["auto", "ipv4", "ipv6"], "auto")?;
    let timeout_ms = bounded_u64(arguments, "timeout_ms", 200, MAX_TIMEOUT_MS, 5000)?;
    let max_seconds = bounded_u64(arguments, "max_seconds", 1, MAX_SECONDS, 15)?;
    let report = run_cli_json(&[
        "http3".to_string(),
        url.clone(),
        "--family".to_string(),
        family.to_string(),
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--max-seconds".to_string(),
        max_seconds.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ])?;
    Ok(
        json!({"summary": format!("HTTP/3 probe completed for {}", parsed.redacted()), "report": report}),
    )
}

fn tool_proxy(arguments: &Value, allowlist: &[AllowRule]) -> Result<Value, ToolError> {
    let url = string_arg(arguments, "url", 2048)?;
    let parsed = crate::probes::http::parse_url(&url)
        .map_err(|error| ToolError::invalid(format!("invalid URL: {error}")))?;
    let proxy = string_arg(arguments, "proxy", 512)?;
    let spec = crate::probes::proxy::parse_proxy(&proxy)
        .map_err(|error| ToolError::invalid(format!("invalid proxy: {error}")))?;
    authorize(&parsed.host, parsed.port, allowlist)?;
    authorize(&spec.host, spec.port, allowlist)?;
    let compare = bool_arg(arguments, "compare_direct", false)?;
    let rounds = bounded_u32(arguments, "rounds", 1, 20, 3)?;
    let timeout_ms = bounded_u64(arguments, "timeout_ms", 200, MAX_TIMEOUT_MS, 8000)?;
    let max_seconds = bounded_u64(arguments, "max_seconds", 1, MAX_SECONDS, 30)?;
    let mut args = vec![
        "proxy".to_string(),
        url.clone(),
        "--proxy".to_string(),
        proxy,
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if compare {
        args.extend([
            "--compare-direct".to_string(),
            "--rounds".to_string(),
            rounds.to_string(),
            "--max-seconds".to_string(),
            max_seconds.to_string(),
        ]);
    }
    let report = run_cli_json(&args)?;
    Ok(
        json!({"summary": format!("proxy probe completed for {}", parsed.redacted()), "report": report}),
    )
}

fn tool_udp(arguments: &Value, allowlist: &[AllowRule]) -> Result<Value, ToolError> {
    let target = string_arg(arguments, "target", 300)?;
    let (host, port) = crate::commands::split_target(&target)
        .map_err(|error| ToolError::invalid(format!("invalid target: {error}")))?;
    authorize(&host, port, allowlist)?;
    let rounds = bounded_u32(arguments, "rounds", 1, MAX_ROUNDS, 5)?;
    let timeout_ms = bounded_u64(arguments, "timeout_ms", 100, MAX_TIMEOUT_MS, 1500)?;
    let interval_ms = bounded_u64(arguments, "interval_ms", 0, 5000, 200)?;
    let max_seconds = bounded_u64(arguments, "max_seconds", 1, MAX_SECONDS, 15)?;
    let payload = bounded_u64(arguments, "payload", 17, 512, 64)?;
    let report = run_cli_json(&[
        "udp".to_string(),
        "--target".to_string(),
        target.clone(),
        "--rounds".to_string(),
        rounds.to_string(),
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
        "--interval-ms".to_string(),
        interval_ms.to_string(),
        "--max-seconds".to_string(),
        max_seconds.to_string(),
        "--payload".to_string(),
        payload.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ])?;
    Ok(json!({"summary": format!("UDP Echo probe completed for {target}"), "report": report}))
}

fn tool_compare(arguments: &Value) -> Result<Value, ToolError> {
    let before = arguments
        .get("before")
        .ok_or_else(|| ToolError::invalid("before report is required"))?;
    let after = arguments
        .get("after")
        .ok_or_else(|| ToolError::invalid("after report is required"))?;
    if !before.is_object() || !after.is_object() {
        return Err(ToolError::invalid(
            "before and after must be report objects",
        ));
    }
    if serde_json::to_vec(before)
        .map(|value| value.len())
        .unwrap_or(0)
        > 5 * 1024 * 1024
        || serde_json::to_vec(after)
            .map(|value| value.len())
            .unwrap_or(0)
            > 5 * 1024 * 1024
    {
        return Err(ToolError::invalid("each report must be at most 5 MiB"));
    }
    let report = crate::compare::compare_values(before, after).map_err(ToolError::invalid)?;
    let value = serde_json::to_value(&report)
        .map_err(|error| ToolError::failed(format!("serialize comparison: {error}")))?;
    Ok(json!({
        "summary": format!("comparison status: {}", report.comparability.verdict),
        "comparison": value
    }))
}

fn tool_explain(arguments: &Value) -> Result<Value, ToolError> {
    let report = arguments
        .get("report")
        .ok_or_else(|| ToolError::invalid("report object is required"))?;
    if serde_json::to_vec(report)
        .map(|value| value.len())
        .unwrap_or(0)
        > 5 * 1024 * 1024
    {
        return Err(ToolError::invalid("report must be at most 5 MiB"));
    }
    explain_report(report).map_err(ToolError::invalid)
}

fn explain_report(report: &Value) -> Result<Value, String> {
    if !report.is_object() {
        return Err("report must be a JSON object".to_string());
    }
    if report
        .get("schema_version")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("report is missing schema_version".to_string());
    }
    let target = report
        .get("target")
        .and_then(|value| {
            value
                .get("input")
                .and_then(Value::as_str)
                .or_else(|| value.as_str())
        })
        .unwrap_or("unknown");
    let probes = report
        .get("probes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let known_ids: std::collections::BTreeSet<&str> = probes
        .iter()
        .filter_map(|probe| probe.get("id").and_then(Value::as_str))
        .collect();
    let mut probe_counts = std::collections::BTreeMap::new();
    let mut error_counts = std::collections::BTreeMap::new();
    for probe in probes {
        let kind = probe
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        *probe_counts.entry(kind.to_string()).or_insert(0usize) += 1;
        let detail = probe.get("detail").unwrap_or(&Value::Null);
        if let Some(error) = detail.get("error").and_then(Value::as_str) {
            *error_counts.entry(error.to_string()).or_insert(0usize) += 1;
        }
    }
    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut missing_evidence = Vec::new();
    let mut not_established = Vec::new();
    let mut finding_summaries = Vec::new();
    for finding in &findings {
        let evidence = finding
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for id in &evidence {
            if let Some(id) = id.as_str() {
                if !known_ids.contains(id) {
                    missing_evidence.push(id.to_string());
                }
            }
        }
        if let Some(items) = finding.get("not_established").and_then(Value::as_array) {
            not_established.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
        }
        finding_summaries.push(json!({
            "rule_id": finding.get("rule_id"),
            "status": finding.get("status"),
            "claim": finding.get("claim"),
            "confidence": finding.get("confidence"),
            "evidence": evidence,
            "limits": finding.get("limits")
        }));
    }
    let status = report
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| {
            report
                .get("stages")
                .and_then(Value::as_array)
                .and_then(|stages| {
                    worst_status(stages.iter().filter_map(|stage| stage.get("status")))
                })
        })
        .unwrap_or("INCONCLUSIVE");
    let stages = report
        .get("stages")
        .and_then(Value::as_array)
        .map(|stages| {
            stages
                .iter()
                .map(|stage| {
                    json!({
                        "id": stage.get("id"),
                        "status": stage.get("status"),
                        "summary": stage.get("summary"),
                        "evidence": stage.get("evidence")
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let limitations = report
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let summary = format!(
        "Status {status} for {target}. {} probe(s), {} finding(s). {}",
        probes.len(),
        findings.len(),
        if missing_evidence.is_empty() {
            "All cited evidence IDs exist.".to_string()
        } else {
            format!("Missing evidence IDs: {}", missing_evidence.join(", "))
        }
    );
    Ok(json!({
        "summary": summary,
        "status": status,
        "target": target,
        "schema_version": report.get("schema_version"),
        "stages": stages,
        "findings": finding_summaries,
        "probe_counts": probe_counts,
        "error_counts": error_counts,
        "not_established": not_established,
        "limitations": limitations,
        "missing_evidence": missing_evidence,
        "evidence_boundary": "This summary reflects recorded probes only. It cannot establish a root cause or packet-loss location without matching capture evidence."
    }))
}

fn worst_status<'a>(statuses: impl Iterator<Item = &'a Value>) -> Option<&'a str> {
    let mut worst = 0u8;
    let mut label = None;
    for status in statuses.filter_map(Value::as_str) {
        let severity = match status {
            "FAIL" => 4,
            "WARN" => 3,
            "INCONCLUSIVE" => 2,
            "SKIP" => 1,
            _ => 0,
        };
        if severity > worst {
            worst = severity;
            label = Some(status);
        }
    }
    label
}

fn build_allowlist(args: &McpArgs) -> Result<Vec<AllowRule>, String> {
    let mut values = args.allow_target.clone();
    if let Ok(env) = std::env::var("PATHTRIAL_MCP_ALLOW_TARGETS") {
        values.extend(
            env.split(',')
                .flat_map(str::split_whitespace)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
    }
    let mut rules = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if value == "*" {
            return Err("wildcard target authorization is not supported".to_string());
        }
        let (host, port) = split_host_port(value)?;
        rules.push(AllowRule {
            host: normalize_host(&host),
            port,
        });
    }
    Ok(rules)
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 allow rule {value}"))?;
        let port = if let Some(port) = tail.strip_prefix(':') {
            Some(
                port.parse::<u16>()
                    .map_err(|_| format!("invalid port in allow rule {value}"))?,
            )
        } else if tail.is_empty() {
            None
        } else {
            return Err(format!("invalid allow rule {value}"));
        };
        return Ok((host.to_string(), port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((
            host.to_string(),
            Some(
                port.parse::<u16>()
                    .map_err(|_| format!("invalid port in allow rule {value}"))?,
            ),
        )),
        Some(_) => Ok((value.to_string(), None)),
        None => Ok((value.to_string(), None)),
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn authorize(host: &str, port: u16, allowlist: &[AllowRule]) -> Result<(), ToolError> {
    let host = normalize_host(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return authorize_ip(ip, port, allowlist);
    }
    let host_rule = allowlist
        .iter()
        .find(|rule| rule.host == host && rule.port.is_none_or(|allowed| allowed == port));
    if host_rule.is_none() {
        return Err(ToolError::denied(format!(
            "target {host}:{port} is not in the MCP allowlist; restart with --allow-target {host}:{port}"
        )));
    }
    let mut recorder = crate::probes::Recorder::new();
    let resolved = crate::probes::dns::resolve(&host, &mut recorder, Duration::from_secs(2));
    let ips: Vec<IpAddr> = resolved
        .addresses_v4
        .iter()
        .chain(resolved.addresses_v6.iter())
        .filter_map(|value| value.parse().ok())
        .collect();
    if ips.is_empty() {
        return Err(ToolError::denied(format!(
            "cannot resolve {host} for authorization; probe denied"
        )));
    }
    if ips
        .iter()
        .any(|ip| crate::net::scope_of(*ip) == crate::net::AddressScope::Public)
    {
        return Ok(());
    }
    if ips.iter().all(|ip| {
        allowlist.iter().any(|rule| {
            rule.host == ip.to_string() && rule.port.is_none_or(|allowed| allowed == port)
        })
    }) {
        return Ok(());
    }
    Err(ToolError::denied(format!(
        "{host} resolves only to private, loopback or special-use addresses; authorize the exact IP and port to probe it"
    )))
}

fn authorize_ip(ip: IpAddr, port: u16, allowlist: &[AllowRule]) -> Result<(), ToolError> {
    let text = ip.to_string();
    if allowlist
        .iter()
        .any(|rule| rule.host == text && rule.port.is_none_or(|allowed| allowed == port))
    {
        Ok(())
    } else {
        Err(ToolError::denied(format!(
            "target {ip}:{port} is not in the MCP allowlist"
        )))
    }
}

fn resolve_for_family(host: &str, family: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut recorder = crate::probes::Recorder::new();
    let resolved = crate::probes::dns::resolve(host, &mut recorder, Duration::from_secs(2));
    let values = if family == "ipv4" {
        &resolved.addresses_v4
    } else {
        &resolved.addresses_v6
    };
    values
        .first()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("no {family} address"))
}

fn run_cli_json(args: &[String]) -> Result<Value, ToolError> {
    let exe = std::env::current_exe()
        .map_err(|error| ToolError::failed(format!("locate PathTrial binary: {error}")))?;
    let output = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| ToolError::failed(format!("start PathTrial probe: {error}")))?;
    let text = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => Ok(value),
        Err(error) => Err(ToolError::failed(format!(
            "probe did not return JSON ({error}); stderr: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
    }
}

fn string_arg(arguments: &Value, key: &str, max: usize) -> Result<String, ToolError> {
    let value = arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::invalid(format!("{key} must be a string")))?;
    if value.is_empty() || value.len() > max {
        return Err(ToolError::invalid(format!(
            "{key} must be 1 to {max} bytes"
        )));
    }
    if value.chars().any(char::is_whitespace) || value.contains('/') && key == "target" {
        return Err(ToolError::invalid(format!(
            "{key} contains invalid characters"
        )));
    }
    Ok(value.to_string())
}

fn enum_arg(
    arguments: &Value,
    key: &str,
    allowed: &[&str],
    default: &str,
) -> Result<String, ToolError> {
    let value = arguments
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default);
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(ToolError::invalid(format!(
            "{key} must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn bool_arg(arguments: &Value, key: &str, default: bool) -> Result<bool, ToolError> {
    match arguments.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| ToolError::invalid(format!("{key} must be a boolean"))),
    }
}

fn optional_u16(arguments: &Value, key: &str) -> Result<Option<u16>, ToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or_else(|| ToolError::invalid(format!("{key} must be a valid port"))),
    }
}

fn bounded_u16(
    arguments: &Value,
    key: &str,
    min: u16,
    max: u16,
    default: u16,
) -> Result<u16, ToolError> {
    let value = arguments
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(default as u64);
    if value < min as u64 || value > max as u64 {
        return Err(ToolError::invalid(format!(
            "{key} must be between {min} and {max}"
        )));
    }
    Ok(value as u16)
}

fn bounded_u32(
    arguments: &Value,
    key: &str,
    min: u32,
    max: u32,
    default: u32,
) -> Result<u32, ToolError> {
    let value = arguments
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(default as u64);
    if value < min as u64 || value > max as u64 {
        return Err(ToolError::invalid(format!(
            "{key} must be between {min} and {max}"
        )));
    }
    Ok(value as u32)
}

fn bounded_u64(
    arguments: &Value,
    key: &str,
    min: u64,
    max: u64,
    default: u64,
) -> Result<u64, ToolError> {
    let value = arguments
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(default);
    if value < min || value > max {
        return Err(ToolError::invalid(format!(
            "{key} must be between {min} and {max}"
        )));
    }
    Ok(value)
}
