//! Single-purpose subcommands. Each one records real probes and reuses the same
//! status vocabulary as `scan`.

use crate::cli::{HttpArgs, OutputFormat};
use crate::models::{Probe, ProbeDetail, ProbeKind, ProbeOutcome, Status, TraceHop};
use crate::probes::http::{self, HttpRequest};
use crate::probes::Recorder;
use crate::single::CommandReport;

fn record(
    recorder: &mut Recorder,
    kind: ProbeKind,
    target: &str,
    detail: ProbeDetail,
    ok: bool,
) -> String {
    let id = recorder.next_id("probe");
    recorder.record(Probe {
        id: id.clone(),
        kind,
        outcome: if ok {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::Fail
        },
        family: None,
        target: Some(target.to_string()),
        port: None,
        started_at: crate::util::now_rfc3339(),
        duration_ms: None,
        detail,
    });
    id
}

/// `pathtrial ping HOST`
pub fn ping(args: &crate::cli::PingArgs) -> Result<u8, String> {
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let outcome = crate::probes::icmp::ping(
        &args.host,
        args.count,
        std::time::Duration::from_millis(args.timeout_ms),
    );
    let status = if outcome.sent == 0 && outcome.error.is_some() {
        Status::Skip
    } else if outcome.received == 0 {
        Status::Fail
    } else if outcome.loss_pct > 0.0 {
        Status::Warn
    } else {
        Status::Pass
    };
    record(
        &mut recorder,
        ProbeKind::Icmp,
        &args.host,
        ProbeDetail::Icmp {
            sent: outcome.sent,
            received: outcome.received,
            loss_pct: outcome.loss_pct,
            rtt_min: outcome.rtt_min,
            rtt_avg: outcome.rtt_avg,
            rtt_max: outcome.rtt_max,
            jitter: outcome.jitter,
            error: outcome.error.clone(),
        },
        outcome.usable(),
    );
    let summary = format!(
        "sent: {}\nreceived: {}\nloss: {:.1}%\nrtt min/avg/max: {}\njitter: {}",
        outcome.sent,
        outcome.received,
        outcome.loss_pct,
        match (outcome.rtt_min, outcome.rtt_avg, outcome.rtt_max) {
            (Some(min), Some(avg), Some(max)) => format!("{min:.1}/{avg:.1}/{max:.1} ms"),
            _ => "n/a".to_string(),
        },
        outcome
            .jitter
            .map(|value| format!("{value:.2} ms"))
            .unwrap_or_else(|| "n/a".to_string())
    );
    let mut report = CommandReport::new("ping", &args.host, started_at)
        .with_status(status, summary)
        .with_probes(recorder.into_probes());
    if let Some(error) = &outcome.error {
        report = report.with_limitation(format!("icmp: {error}"));
    }
    if status == Status::Fail {
        report = report.with_limitation(
            "ICMP 无响应不等于 TCP/UDP 不可用：目标或中间设备可能限制 ICMP".to_string(),
        );
    }
    Ok(report.emit(args.format))
}

/// `pathtrial trace HOST`
pub fn trace(args: &crate::cli::TraceArgs) -> Result<u8, String> {
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let outcome = crate::probes::trace::trace(
        &args.host,
        args.max_hops,
        std::time::Duration::from_millis(args.timeout_ms),
    );
    let status = if outcome.error.is_some() {
        Status::Skip
    } else if outcome.reached {
        Status::Pass
    } else {
        Status::Inconclusive
    };
    let hops: Vec<TraceHop> = outcome
        .hops
        .iter()
        .map(|hop| TraceHop {
            hop: hop.hop,
            address: hop.address.clone(),
            rtt_ms: hop.rtt_ms.clone(),
            timed_out: hop.timed_out,
        })
        .collect();
    record(
        &mut recorder,
        ProbeKind::Trace,
        &args.host,
        ProbeDetail::Trace {
            hops: hops.clone(),
            reached: outcome.reached,
            protocol: outcome.protocol.clone(),
            error: outcome.error.clone(),
        },
        outcome.error.is_none(),
    );
    let mut summary = format!(
        "protocol: {}\nreached: {}\n",
        outcome.protocol, outcome.reached
    );
    for hop in &hops {
        let address = hop.address.clone().unwrap_or_else(|| "*".to_string());
        let rtt = hop
            .rtt_ms
            .iter()
            .map(|value| format!("{value:.1}"))
            .collect::<Vec<_>>()
            .join("/");
        summary.push_str(&format!("{:>2}  {:<16} {}\n", hop.hop, address, rtt));
    }
    let mut report = CommandReport::new("trace", &args.host, started_at)
        .with_status(status, summary)
        .with_probes(recorder.into_probes());
    report =
        report.with_limitation("中间路由器不回复探测报文，不能据此判断业务路径丢包".to_string());
    if let Some(error) = &outcome.error {
        report = report.with_limitation(format!("trace: {error}"));
    }
    Ok(report.emit(args.format))
}

/// `pathtrial dns HOST [--server IP]...`
pub fn dns(args: &crate::cli::DnsArgs) -> Result<u8, String> {
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let outcome = crate::probes::dns::resolve_with_servers(
        &args.host,
        &args.servers,
        &mut recorder,
        std::time::Duration::from_millis(args.timeout_ms),
    );
    let probes = recorder.into_probes();

    // Compare answers per record type across resolvers.
    let mut disagreements = Vec::new();
    for record_type in ["A", "AAAA"] {
        let mut seen: Vec<(String, Vec<String>)> = Vec::new();
        for probe in &probes {
            if let ProbeDetail::DnsQuery {
                resolver,
                record_type: kind,
                answers,
                ..
            } = &probe.detail
            {
                if kind == record_type {
                    let mut sorted = answers.clone();
                    sorted.sort();
                    seen.push((resolver.clone(), sorted));
                }
            }
        }
        if seen.len() > 1 {
            let first = seen[0].1.clone();
            if seen.iter().any(|(_, answers)| *answers != first) {
                disagreements.push(record_type);
            }
        }
    }

    // A Fake-IP answer describes the local proxy, so comparing it with a real
    // resolver says nothing about DNS health.
    let fake_ip = outcome
        .addresses_v4
        .iter()
        .chain(outcome.addresses_v6.iter())
        .filter_map(|text| text.parse::<std::net::IpAddr>().ok())
        .any(|ip| crate::net::scope_of(ip) == crate::net::AddressScope::Benchmark);
    if fake_ip {
        disagreements.clear();
    }
    let status = if outcome.addresses_v4.is_empty() && outcome.addresses_v6.is_empty() {
        Status::Fail
    } else if fake_ip || !disagreements.is_empty() {
        Status::Warn
    } else {
        Status::Pass
    };
    let summary = format!(
        "A: {}\nAAAA: {}\nresolvers: {}\ncompared: {}\ntotal: {:.1} ms",
        if outcome.addresses_v4.is_empty() {
            "none".to_string()
        } else {
            outcome.addresses_v4.join(", ")
        },
        if outcome.addresses_v6.is_empty() {
            "none".to_string()
        } else {
            outcome.addresses_v6.join(", ")
        },
        outcome.resolvers.join(", "),
        if disagreements.is_empty() {
            "consistent".to_string()
        } else {
            format!("differs for {}", disagreements.join(", "))
        },
        outcome.total_ms
    );
    let mut report = CommandReport::new("dns", &args.host, started_at)
        .with_status(status, summary)
        .with_probes(probes);
    if fake_ip {
        report = report.with_limitation(
            "解析结果位于 198.18.0.0/15，疑似本地代理 Fake-IP；本次对照不代表真实 DNS 行为"
                .to_string(),
        );
    }
    if !disagreements.is_empty() {
        report = report.with_limitation(
            "不同解析器结果不同不等于 DNS 污染，也可能是 CDN、Split DNS 或本地策略".to_string(),
        );
    }
    for note in &outcome.notes {
        report = report.with_limitation(note.clone());
    }
    Ok(report.emit(args.format))
}

/// `pathtrial http URL`
pub fn http(args: &HttpArgs) -> Result<u8, String> {
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let request = HttpRequest {
        url: &args.url,
        method: "GET",
        expected_status: args.expect_status,
        timeout: std::time::Duration::from_millis(args.timeout_ms),
        interface: args.bind_interface.as_deref(),
        insecure: args.insecure,
        max_body: 64 * 1024,
    };
    let outcome = http::run(&mut recorder, &request)?;
    let probes = recorder.into_probes();

    let status = match (&outcome.error, outcome.status, outcome.matches_expectation) {
        (Some(_), _, _) => Status::Fail,
        (None, Some(_), Some(false)) => Status::Fail,
        (None, Some(code), None) if code >= 400 => Status::Warn,
        (None, Some(_), _) => Status::Pass,
        (None, None, _) => Status::Inconclusive,
    };
    let summary = format!(
        "status: {}\nversion: {}\ntls_verified: {}\nredirect: {}\nbody_bytes: {}\ntimings: dns {:.1} ms | tcp {:.1} ms | tls {:.1} ms | ttfb {:.1} ms | total {:.1} ms{}",
        outcome
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".to_string()),
        outcome.http_version.clone().unwrap_or_else(|| "unknown".to_string()),
        outcome
            .tls_verified
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        outcome.redirect.clone().unwrap_or_else(|| "none".to_string()),
        outcome.body_bytes,
        outcome.timings.dns_ms,
        outcome.timings.connect_ms,
        outcome.timings.tls_ms,
        outcome.timings.ttfb_ms,
        outcome.timings.total_ms,
        outcome
            .expected_status
            .map(|expected| format!("\nexpected: {expected}"))
            .unwrap_or_default()
    );
    let mut report = CommandReport::new("http", &args.url, started_at)
        .with_status(status, summary)
        .with_probes(probes);
    if outcome.error.is_some() {
        report = report.with_limitation("请求未完成，请查看 probes 中的错误分类".to_string());
    }
    if outcome.redirect.is_some() {
        report = report.with_limitation("重定向未被跟随，Location 仅作记录".to_string());
    }
    Ok(report.emit(args.format))
}

/// Format used when a subcommand has no explicit format flag.
pub const DEFAULT_FORMAT: OutputFormat = OutputFormat::Summary;
