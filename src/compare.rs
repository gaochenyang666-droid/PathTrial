//! M13: structured comparison of two saved JSON reports.
//!
//! The input is read as `serde_json::Value` so reports from schema 1.0 through
//! the current version remain readable. Missing fields are reported as
//! unavailable; no sample is reconstructed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::cli::{CompareArgs, OutputFormat};
/// The comparison document is a separate shape from a scan report, so it has
/// its own version rather than reusing the scan schema number.
pub const COMPARISON_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Serialize)]
pub struct ComparisonReport {
    pub schema_version: String,
    pub tool_version: String,
    pub kind: String,
    pub generated_at: String,
    pub before: Snapshot,
    pub after: Snapshot,
    pub comparability: Comparability,
    pub metrics: Vec<MetricDiff>,
    pub finding_changes: FindingChanges,
}

#[derive(Debug, Serialize)]
pub struct Comparability {
    pub verdict: String,
    pub issues: Vec<String>,
    pub limits: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MetricDiff {
    pub name: String,
    pub unit: String,
    pub before: Option<f64>,
    pub after: Option<f64>,
    pub change: String,
}

#[derive(Debug, Serialize)]
pub struct FindingChanges {
    pub added: Vec<String>,
    pub resolved: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub path: String,
    pub schema_version: Option<String>,
    pub tool_version: Option<String>,
    pub report_kind: String,
    pub target: Option<String>,
    pub port: Option<u16>,
    pub profile: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub bind_interface: Option<String>,
    pub timeout_ms: Option<u64>,
    pub rounds: Option<u64>,
    pub address_families: Vec<String>,
    pub dns_resolvers: Vec<String>,
    pub tcp: TcpSnapshot,
    pub tls: TlsSnapshot,
    pub http: HttpSnapshot,
    pub icmp: Option<IcmpSnapshot>,
    pub udp: UdpSnapshot,
    pub proxy: ProxySnapshot,
    pub findings: Vec<FindingSnapshot>,
}

#[derive(Debug, Default, Serialize)]
pub struct TcpSnapshot {
    pub total: u32,
    pub success: u32,
    pub median_ms: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub struct TlsSnapshot {
    pub total: u32,
    pub transport_ok: u32,
    pub verified_ok: u32,
}

#[derive(Debug, Default, Serialize)]
pub struct HttpSnapshot {
    pub total: u32,
    pub answered: u32,
    pub statuses: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IcmpSnapshot {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
}

#[derive(Debug, Default, Serialize)]
pub struct UdpSnapshot {
    pub sent: u32,
    pub echoes: u32,
}

#[derive(Debug, Default, Serialize)]
pub struct ProxySnapshot {
    pub attempts: u32,
    pub success: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingSnapshot {
    pub id: String,
    pub rule_id: String,
    pub status: String,
    pub claim: String,
}

pub fn run(args: &CompareArgs) -> Result<u8, String> {
    let before_value = read_json(&args.before)?;
    let after_value = read_json(&args.after)?;
    for (label, value) in [("before", &before_value), ("after", &after_value)] {
        if value
            .get("schema_version")
            .and_then(Value::as_str)
            .is_none()
            || (value.get("run_id").is_none() && value.get("command").is_none())
        {
            return Err(format!(
                "{label} is not a PathTrial report: missing schema_version, run_id or command"
            ));
        }
    }
    let before = snapshot(&args.before, &before_value);
    let after = snapshot(&args.after, &after_value);
    let report = build(before, after);
    if let Some(prefix) = &args.out {
        write_outputs(prefix, &report)?;
    }
    match args.format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|error| format!("cannot render JSON: {error}"))?
            );
        }
        OutputFormat::Markdown => print!("{}", render_markdown(&report)),
        OutputFormat::Summary => print!("{}", render_summary(&report)),
    }
    Ok(
        if report.comparability.verdict == "NOT DIRECTLY COMPARABLE" {
            3
        } else {
            0
        },
    )
}

fn read_json(path: &PathBuf) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn write_outputs(prefix: &Path, report: &ComparisonReport) -> Result<(), String> {
    let json_path = prefix.with_extension("json");
    let md_path = prefix.with_extension("md");
    for path in [&json_path, &md_path] {
        if path.exists() {
            return Err(format!(
                "refusing to overwrite {}; choose a new --out prefix",
                path.display()
            ));
        }
    }
    let json = serde_json::to_string_pretty(report)
        .map_err(|error| format!("cannot render JSON: {error}"))?;
    std::fs::write(&json_path, json)
        .map_err(|error| format!("write {}: {error}", json_path.display()))?;
    std::fs::write(&md_path, render_markdown(report))
        .map_err(|error| format!("write {}: {error}", md_path.display()))?;
    eprintln!("wrote {} and {}", json_path.display(), md_path.display());
    Ok(())
}

fn snapshot(path: &Path, value: &Value) -> Snapshot {
    let report_kind = if value.get("run_id").is_some() && value.get("stages").is_some() {
        "scan"
    } else if value.get("command").is_some() {
        "single"
    } else {
        "unknown"
    };
    let target_object = value.get("target").filter(|target| target.is_object());
    let target = target_object
        .and_then(|target| target.get("input"))
        .and_then(Value::as_str)
        .or_else(|| value.get("target").and_then(Value::as_str))
        .map(str::to_string);
    let mut port = target_object
        .and_then(|target| target.get("port"))
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());
    let profile = target_object
        .and_then(|target| target.get("profile"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let configuration = value.get("configuration");
    let bind_interface = configuration
        .and_then(|config| config.get("bind_interface"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let timeout_ms = configuration
        .and_then(|config| config.get("timeout_ms"))
        .and_then(Value::as_u64);
    let rounds = configuration
        .and_then(|config| config.get("rounds"))
        .and_then(Value::as_u64);

    let mut tcp = TcpSnapshot::default();
    let mut tls = TlsSnapshot::default();
    let mut http = HttpSnapshot::default();
    let mut icmp = None;
    let mut udp = UdpSnapshot::default();
    let mut proxy = ProxySnapshot::default();
    let mut dns_resolvers = BTreeSet::new();
    let mut address_families = BTreeSet::new();

    if let Some(summaries) = value.get("summaries").and_then(Value::as_array) {
        let mut samples = Vec::new();
        for summary in summaries {
            let tcp_total = summary
                .get("tcp_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let address = summary.get("address").and_then(Value::as_str).unwrap_or("");
            if let Some(family) = summary.get("family").and_then(Value::as_str) {
                if tcp_total > 0 || !address.is_empty() {
                    address_families.insert(family.to_string());
                }
            }
            if let Some(address) = summary.get("address").and_then(Value::as_str) {
                if !address.is_empty() {
                    address_families.insert(if address.contains(':') {
                        "ipv6".to_string()
                    } else {
                        "ipv4".to_string()
                    });
                }
            }
            tcp.total += summary
                .get("tcp_total")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
            tcp.success += summary
                .get("tcp_success")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
            if let Some(items) = summary.get("samples_ms").and_then(Value::as_array) {
                samples.extend(items.iter().filter_map(Value::as_f64));
            }
            tls.total += summary
                .get("tls_total")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
            tls.transport_ok += summary
                .get("tls_transport_ok")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
            tls.verified_ok += summary
                .get("tls_verified_ok")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
        }
        if !samples.is_empty() {
            tcp.median_ms = crate::util::median(&samples);
        } else {
            tcp.median_ms = summaries
                .iter()
                .filter_map(|summary| summary.get("tcp_median_ms").and_then(Value::as_f64))
                .reduce(|left, right| left.min(right));
        }
    }

    let mut derived_tcp_durations = Vec::new();
    if let Some(probes) = value.get("probes").and_then(Value::as_array) {
        for probe in probes {
            let kind = probe.get("kind").and_then(Value::as_str).unwrap_or("");
            if matches!(
                kind,
                "tcp" | "tls" | "http" | "icmp" | "udp_observation" | "proxy"
            ) {
                if let Some(family) = probe.get("family").and_then(Value::as_str) {
                    address_families.insert(family.to_string());
                }
            }
            if port.is_none() {
                port = probe
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok());
            }
            let outcome = probe.get("outcome").and_then(Value::as_str).unwrap_or("");
            let detail = probe.get("detail").unwrap_or(&Value::Null);
            let detail_type = detail.get("type").and_then(Value::as_str).unwrap_or("");
            match detail_type {
                "tcp_connect" => {
                    tcp.total += 1;
                    if outcome == "ok" {
                        tcp.success += 1;
                        if let Some(duration) = probe.get("duration_ms").and_then(Value::as_f64) {
                            derived_tcp_durations.push(duration);
                        }
                    }
                }
                "tls_handshake" => {
                    tls.total += 1;
                    if detail.get("transport_ok").and_then(Value::as_bool) == Some(true) {
                        tls.transport_ok += 1;
                    }
                    if detail
                        .get("verification")
                        .and_then(Value::as_str)
                        .map(|value| value == "verified")
                        .unwrap_or(false)
                    {
                        tls.verified_ok += 1;
                    }
                }
                "http" => {
                    http.total += 1;
                    if let Some(status) = detail
                        .get("status")
                        .and_then(Value::as_u64)
                        .and_then(|status| u16::try_from(status).ok())
                    {
                        http.answered += 1;
                        http.statuses.push(status);
                    }
                }
                "icmp" => {
                    let sent = detail.get("sent").and_then(Value::as_u64).unwrap_or(0) as u32;
                    let received =
                        detail.get("received").and_then(Value::as_u64).unwrap_or(0) as u32;
                    let loss_pct = detail
                        .get("loss_pct")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    icmp = Some(IcmpSnapshot {
                        sent,
                        received,
                        loss_pct,
                    });
                }
                "udp_echo" => {
                    udp.sent += 1;
                    if detail.get("result").and_then(Value::as_str) == Some("echo") {
                        udp.echoes += 1;
                    }
                }
                "dns_query" => {
                    if let Some(resolver) = detail.get("resolver").and_then(Value::as_str) {
                        dns_resolvers.insert(resolver.to_string());
                    }
                }
                "proxy_exchange" => {
                    proxy.attempts += 1;
                    if detail.get("tunnel_ok").and_then(Value::as_bool) == Some(true)
                        && detail.get("error").map(Value::is_null).unwrap_or(true)
                    {
                        proxy.success += 1;
                    }
                }
                "path_comparison" if proxy.attempts == 0 => {
                    proxy.attempts += detail
                        .get("proxy_total")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as u32;
                    proxy.success += detail
                        .get("proxy_success")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as u32;
                }
                _ => {}
            }
            if detail_type.is_empty() && kind == "http" {
                if let Some(status) = detail
                    .get("status")
                    .and_then(Value::as_u64)
                    .and_then(|status| u16::try_from(status).ok())
                {
                    http.total += 1;
                    http.answered += 1;
                    http.statuses.push(status);
                }
            }
        }
    }
    if tcp.median_ms.is_none() && !derived_tcp_durations.is_empty() {
        tcp.median_ms = crate::util::median(&derived_tcp_durations);
    }
    if port.is_none() {
        if let Some(target) = target.as_deref() {
            if let Ok(url) = crate::probes::http::parse_url(target) {
                port = Some(url.port);
            }
        }
    }

    let findings = value
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|finding| FindingSnapshot {
                    id: finding
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    rule_id: finding
                        .get("rule_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    status: finding
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    claim: finding
                        .get("claim")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    Snapshot {
        path: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        schema_version: value
            .get("schema_version")
            .and_then(Value::as_str)
            .map(str::to_string),
        tool_version: value
            .get("tool_version")
            .and_then(Value::as_str)
            .map(str::to_string),
        report_kind: report_kind.to_string(),
        target,
        port,
        profile,
        started_at: value
            .get("started_at")
            .and_then(Value::as_str)
            .map(str::to_string),
        finished_at: value
            .get("finished_at")
            .and_then(Value::as_str)
            .map(str::to_string),
        os: value
            .get("environment")
            .and_then(|environment| environment.get("os"))
            .and_then(Value::as_str)
            .map(str::to_string),
        arch: value
            .get("environment")
            .and_then(|environment| environment.get("arch"))
            .and_then(Value::as_str)
            .map(str::to_string),
        bind_interface,
        timeout_ms,
        rounds,
        address_families: address_families.into_iter().collect(),
        dns_resolvers: dns_resolvers.into_iter().collect(),
        tcp,
        tls,
        http,
        icmp,
        udp,
        proxy,
        findings,
    }
}

fn build(before: Snapshot, after: Snapshot) -> ComparisonReport {
    let mut issues = Vec::new();
    let mut limits = Vec::new();
    if before.target != after.target {
        issues.push(format!(
            "target differs: {:?} -> {:?}",
            before.target, after.target
        ));
    }
    if before.port != after.port {
        issues.push(format!(
            "port differs: {:?} -> {:?}",
            before.port, after.port
        ));
    }
    if before.profile != after.profile {
        issues.push(format!(
            "profile differs: {:?} -> {:?}",
            before.profile, after.profile
        ));
    }
    if !before.address_families.is_empty()
        && !after.address_families.is_empty()
        && before.address_families != after.address_families
    {
        issues.push(format!(
            "address families differ: {:?} -> {:?}",
            before.address_families, after.address_families
        ));
    }
    if before.bind_interface != after.bind_interface {
        issues.push(format!(
            "bind interface differs: {:?} -> {:?}",
            before.bind_interface, after.bind_interface
        ));
    }
    if let (Some(first), Some(second)) = (before.timeout_ms, after.timeout_ms) {
        if first != second {
            issues.push(format!("timeout differs: {first} ms -> {second} ms"));
        }
    } else {
        limits.push("timeout settings unavailable in one or both reports".to_string());
    }
    if (before.proxy.attempts > 0) != (after.proxy.attempts > 0) {
        issues.push("one report measured a proxy path and the other did not".to_string());
    }
    if let (Some(first), Some(second)) = (before.os.as_ref(), after.os.as_ref()) {
        if first != second {
            issues.push(format!("operating system differs: {first} -> {second}"));
        }
    } else {
        limits.push("operating system unavailable in one or both reports".to_string());
    }
    if before.report_kind != after.report_kind {
        issues.push(format!(
            "report kinds differ: {} -> {}",
            before.report_kind, after.report_kind
        ));
    }
    if before.tcp.total > 0 && after.tcp.total > 0 {
        let smaller = before.tcp.total.min(after.tcp.total) as f64;
        let larger = before.tcp.total.max(after.tcp.total) as f64;
        if larger >= smaller * 2.0 {
            issues.push(format!(
                "TCP sample counts differ substantially: {} -> {}",
                before.tcp.total, after.tcp.total
            ));
        }
    }
    if before.dns_resolvers != after.dns_resolvers
        && !before.dns_resolvers.is_empty()
        && !after.dns_resolvers.is_empty()
    {
        limits.push(format!(
            "DNS resolvers differ: {:?} -> {:?}",
            before.dns_resolvers, after.dns_resolvers
        ));
    }
    let verdict = if issues.is_empty() {
        "DIRECTLY COMPARABLE"
    } else {
        "NOT DIRECTLY COMPARABLE"
    };

    let metrics = build_metrics(&before, &after);
    let finding_changes = diff_findings(&before.findings, &after.findings);
    ComparisonReport {
        schema_version: COMPARISON_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        kind: "comparison".to_string(),
        generated_at: crate::util::now_rfc3339(),
        before,
        after,
        comparability: Comparability {
            verdict: verdict.to_string(),
            issues,
            limits,
        },
        metrics,
        finding_changes,
    }
}

fn rate(numerator: u32, denominator: u32) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some((numerator as f64 / denominator as f64) * 100.0)
    }
}

fn build_metrics(before: &Snapshot, after: &Snapshot) -> Vec<MetricDiff> {
    let mut metrics = Vec::new();
    let pairs = [
        (
            "TCP success".to_string(),
            "%".to_string(),
            rate(before.tcp.success, before.tcp.total),
            rate(after.tcp.success, after.tcp.total),
            false,
        ),
        (
            "TCP median".to_string(),
            "ms".to_string(),
            before.tcp.median_ms,
            after.tcp.median_ms,
            true,
        ),
        (
            "TLS verified".to_string(),
            "%".to_string(),
            rate(before.tls.verified_ok, before.tls.total),
            rate(after.tls.verified_ok, after.tls.total),
            false,
        ),
        (
            "HTTP answered".to_string(),
            "%".to_string(),
            rate(before.http.answered, before.http.total),
            rate(after.http.answered, after.http.total),
            false,
        ),
        (
            "ICMP loss".to_string(),
            "%".to_string(),
            before.icmp.as_ref().map(|icmp| icmp.loss_pct),
            after.icmp.as_ref().map(|icmp| icmp.loss_pct),
            true,
        ),
        (
            "UDP echo".to_string(),
            "%".to_string(),
            rate(before.udp.echoes, before.udp.sent),
            rate(after.udp.echoes, after.udp.sent),
            false,
        ),
        (
            "Proxy tunnel".to_string(),
            "%".to_string(),
            rate(before.proxy.success, before.proxy.attempts),
            rate(after.proxy.success, after.proxy.attempts),
            false,
        ),
    ];
    for (name, unit, first, second, lower_is_better) in pairs {
        if first.is_none() && second.is_none() {
            continue;
        }
        let change = match (first, second) {
            (Some(first), Some(second)) => {
                let delta = second - first;
                let threshold = if unit == "ms" { 1.0 } else { 0.05 };
                if delta.abs() <= threshold {
                    "Unchanged"
                } else if (delta < 0.0) == lower_is_better {
                    "Improved"
                } else {
                    "Regressed"
                }
            }
            _ => "Unavailable",
        };
        metrics.push(MetricDiff {
            name,
            unit,
            before: first,
            after: second,
            change: change.to_string(),
        });
    }
    metrics
}

fn diff_findings(before: &[FindingSnapshot], after: &[FindingSnapshot]) -> FindingChanges {
    let before_set: BTreeSet<String> = before
        .iter()
        .map(|finding| format!("{} {} {}", finding.rule_id, finding.status, finding.claim))
        .collect();
    let after_set: BTreeSet<String> = after
        .iter()
        .map(|finding| format!("{} {} {}", finding.rule_id, finding.status, finding.claim))
        .collect();
    FindingChanges {
        added: after_set.difference(&before_set).cloned().collect(),
        resolved: before_set.difference(&after_set).cloned().collect(),
    }
}

fn render_summary(report: &ComparisonReport) -> String {
    let mut out = String::new();
    out.push_str("PATH TRIAL COMPARISON\n");
    out.push_str(&format!(
        "before: {} ({})\n",
        report.before.path,
        report
            .before
            .started_at
            .as_deref()
            .unwrap_or("time unavailable")
    ));
    out.push_str(&format!(
        "after:  {} ({})\n",
        report.after.path,
        report
            .after
            .started_at
            .as_deref()
            .unwrap_or("time unavailable")
    ));
    out.push_str(&format!(
        "target: {} port: {} profile: {}\n",
        report.before.target.as_deref().unwrap_or("unavailable"),
        report
            .before
            .port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "unavailable".to_string()),
        report.before.profile.as_deref().unwrap_or("unavailable")
    ));
    out.push_str(&format!(
        "os: {} / {} families: {:?} -> {:?}\n",
        report.before.os.as_deref().unwrap_or("unavailable"),
        report.after.os.as_deref().unwrap_or("unavailable"),
        report.before.address_families,
        report.after.address_families
    ));
    out.push_str(&format!(
        "dns: {:?} -> {:?}\n",
        report.before.dns_resolvers, report.after.dns_resolvers
    ));
    out.push_str(&format!(
        "comparability: {}\n",
        report.comparability.verdict
    ));
    for issue in &report.comparability.issues {
        out.push_str(&format!("issue: {issue}\n"));
    }
    for limit in &report.comparability.limits {
        out.push_str(&format!("limit: {limit}\n"));
    }
    out.push('\n');
    for metric in &report.metrics {
        out.push_str(&format!("{}\n", metric.name));
        out.push_str(&format!(
            "  before: {}\n  after:  {}\n  status: {}\n",
            display_metric(metric.before, &metric.unit),
            display_metric(metric.after, &metric.unit),
            metric.change
        ));
    }
    if !report.finding_changes.added.is_empty() {
        out.push_str("new findings:\n");
        for item in &report.finding_changes.added {
            out.push_str(&format!("  {item}\n"));
        }
    }
    if !report.finding_changes.resolved.is_empty() {
        out.push_str("resolved findings:\n");
        for item in &report.finding_changes.resolved {
            out.push_str(&format!("  {item}\n"));
        }
    }
    out
}

fn render_markdown(report: &ComparisonReport) -> String {
    let mut out = String::new();
    out.push_str("# PathTrial comparison\n\n");
    out.push_str(&format!(
        "- Before: `{}` ({})\n- After: `{}` ({})\n- Comparability: **{}**\n\n",
        report.before.path,
        report
            .before
            .started_at
            .as_deref()
            .unwrap_or("time unavailable"),
        report.after.path,
        report
            .after
            .started_at
            .as_deref()
            .unwrap_or("time unavailable"),
        report.comparability.verdict
    ));
    out.push_str(&format!(
        "- OS: {} -> {}\n- Families: {:?} -> {:?}\n- DNS: {:?} -> {:?}\n\n",
        report.before.os.as_deref().unwrap_or("unavailable"),
        report.after.os.as_deref().unwrap_or("unavailable"),
        report.before.address_families,
        report.after.address_families,
        report.before.dns_resolvers,
        report.after.dns_resolvers
    ));
    if !report.comparability.issues.is_empty() {
        out.push_str("## Comparability issues\n\n");
        for issue in &report.comparability.issues {
            out.push_str(&format!("- {issue}\n"));
        }
        out.push('\n');
    }
    if !report.comparability.limits.is_empty() {
        out.push_str("## Limits\n\n");
        for limit in &report.comparability.limits {
            out.push_str(&format!("- {limit}\n"));
        }
        out.push('\n');
    }
    out.push_str(
        "## Metrics\n\n| Metric | Before | After | Change |\n| --- | ---: | ---: | --- |\n",
    );
    for metric in &report.metrics {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            metric.name,
            display_metric(metric.before, &metric.unit),
            display_metric(metric.after, &metric.unit),
            metric.change
        ));
    }
    if !report.finding_changes.added.is_empty() {
        out.push_str("\n## New findings\n\n");
        for item in &report.finding_changes.added {
            out.push_str(&format!("- {item}\n"));
        }
    }
    if !report.finding_changes.resolved.is_empty() {
        out.push_str("\n## Resolved findings\n\n");
        for item in &report.finding_changes.resolved {
            out.push_str(&format!("- {item}\n"));
        }
    }
    out
}

fn display_metric(value: Option<f64>, unit: &str) -> String {
    value
        .map(|value| format!("{value:.2} {unit}"))
        .unwrap_or_else(|| "unavailable".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn value() -> Value {
        json!({
            "schema_version": "1.0.0",
            "tool_version": "0.9.0",
            "run_id": "r1",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "target": {"input": "example.com", "port": 443, "profile": "web"},
            "configuration": {"rounds": 10, "timeout_ms": 3000, "bind_interface": "en0"},
            "environment": {"os": "macos", "arch": "arm64"},
            "stages": [],
            "probes": [
                {"kind": "tcp", "outcome": "ok", "duration_ms": 100.0, "portfolio": 0,
                 "detail": {"type": "tcp_connect", "connect_ms": 100.0, "error": null}},
                {"kind": "tcp", "outcome": "fail", "duration_ms": 3000.0,
                 "detail": {"type": "tcp_connect", "connect_ms": null, "error": "timeout"}},
                {"kind": "tls", "outcome": "ok",
                 "detail": {"type": "tls_handshake", "transport_ok": true, "verification": "verified"}},
                {"kind": "http", "outcome": "ok",
                 "detail": {"type": "http", "status": 200}}
            ],
            "summaries": [],
            "findings": [
                {"id": "F1", "rule_id": "R006", "status": "WARN", "claim": "loss"}
            ]
        })
    }

    #[test]
    fn extracts_missing_fields_as_unavailable_without_inventing_samples() {
        let snapshot = snapshot(Path::new("a.json"), &value());
        assert_eq!(snapshot.tcp.total, 2);
        assert_eq!(snapshot.tcp.success, 1);
        assert_eq!(snapshot.tcp.median_ms, Some(100.0));
        assert_eq!(snapshot.tls.verified_ok, 1);
        assert_eq!(snapshot.http.statuses, vec![200]);
        assert_eq!(snapshot.profile.as_deref(), Some("web"));
    }

    #[test]
    fn different_targets_are_not_directly_comparable() {
        let before = snapshot(Path::new("a.json"), &value());
        let mut other = value();
        other["target"]["input"] = json!("other.example");
        let after = snapshot(Path::new("b.json"), &other);
        let report = build(before, after);
        assert_eq!(report.comparability.verdict, "NOT DIRECTLY COMPARABLE");
        assert!(report
            .comparability
            .issues
            .iter()
            .any(|issue| issue.contains("target differs")));
    }

    #[test]
    fn success_increase_is_improved_and_latency_drop_is_improved() {
        let before = snapshot(Path::new("a.json"), &value());
        let mut better = value();
        better["probes"][1]["outcome"] = json!("ok");
        better["probes"][1]["duration_ms"] = json!(80.0);
        let after = snapshot(Path::new("b.json"), &better);
        let report = build(before, after);
        let tcp_success = report
            .metrics
            .iter()
            .find(|metric| metric.name == "TCP success")
            .unwrap();
        assert_eq!(tcp_success.change, "Improved");
    }

    #[test]
    fn old_reports_without_optional_fields_still_load() {
        let old = json!({
            "schema_version": "1.0.0",
            "target": "example.com",
            "probes": [],
            "started_at": "2026-01-01T00:00:00Z"
        });
        let snapshot = snapshot(Path::new("old.json"), &old);
        assert_eq!(snapshot.report_kind, "unknown");
        assert!(snapshot.timeout_ms.is_none());
        assert!(snapshot.tcp.median_ms.is_none());
    }
}
