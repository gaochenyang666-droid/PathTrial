//! Single-purpose subcommands. Each one records real probes and reuses the same
//! status vocabulary as `scan`.

use crate::cli::{AddressFamily, Http3Args, HttpArgs, OutputFormat, QuicArgs};
use crate::models::{Probe, ProbeDetail, ProbeKind, ProbeOutcome, Status, TraceHop};
use crate::probes::http::{self, HttpRequest};
use crate::probes::Recorder;
use crate::single::CommandReport;
use std::io::{Read, Write};

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

fn validate_interface(interface: Option<&str>) -> Result<(), String> {
    if let Some(name) = interface {
        if crate::net::interface_index(name).is_none() {
            return Err(format!(
                "interface {name} does not exist; check --bind-interface"
            ));
        }
    }
    Ok(())
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

/// `pathtrial udp --target HOST:PORT --mode echo`
pub fn udp(args: &crate::cli::UdpArgs) -> Result<u8, String> {
    if args.mode != "echo" {
        return Err(format!(
            "unsupported --mode {}; this build only implements `echo`",
            args.mode
        ));
    }
    if args.rounds == 0 || args.rounds > 200 {
        return Err("--rounds must be between 1 and 200".to_string());
    }
    if args.payload < crate::probes::udp::HEADER_LEN
        || args.payload > crate::probes::udp::MAX_PAYLOAD
    {
        return Err(format!(
            "--payload must be between {} and {} bytes",
            crate::probes::udp::HEADER_LEN,
            crate::probes::udp::MAX_PAYLOAD
        ));
    }
    if args.timeout_ms == 0 || args.max_seconds == 0 {
        return Err("--timeout-ms and --max-seconds must be greater than zero".to_string());
    }
    validate_interface(args.bind_interface.as_deref())?;
    let (host, port) = split_target(&args.target)?;
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let address = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            let resolved = crate::probes::dns::resolve(
                &host,
                &mut recorder,
                std::time::Duration::from_millis(args.timeout_ms),
            );
            resolved
                .addresses_v4
                .first()
                .or_else(|| resolved.addresses_v6.first())
                .and_then(|text| text.parse().ok())
                .ok_or_else(|| format!("could not resolve {host}"))?
        }
    };
    let target = std::net::SocketAddr::new(address, port);
    let request = crate::probes::udp::EchoRequest {
        target,
        rounds: args.rounds,
        timeout: std::time::Duration::from_millis(args.timeout_ms),
        interval: std::time::Duration::from_millis(args.interval_ms),
        interface: args.bind_interface.as_deref(),
        payload: args.payload,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(args.max_seconds),
    };
    let (samples, stats) = crate::probes::udp::run(&mut recorder, &request);
    let status = if stats.echoes == 0 {
        Status::Fail
    } else if stats.failures > 0 {
        Status::Warn
    } else {
        Status::Pass
    };
    let classes = stats
        .classes
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!(
        "target: {target}\nsent: {}\necho: {}\nfailures: {}\nsuccess: {:.0}%\nrtt min/avg/median/max: {}\njitter: {}\nclasses: {}",
        stats.sent,
        stats.echoes,
        stats.failures,
        stats.success_rate * 100.0,
        match (stats.rtt_min, stats.rtt_avg, stats.rtt_median, stats.rtt_max) {
            (Some(min), Some(avg), Some(median), Some(max)) =>
                format!("{min:.1}/{avg:.1}/{median:.1}/{max:.1} ms"),
            _ => "n/a".to_string(),
        },
        stats
            .jitter
            .map(|value| format!("{value:.2} ms"))
            .unwrap_or_else(|| "n/a".to_string()),
        if classes.is_empty() { "none".to_string() } else { classes }
    );
    let mut report = CommandReport::new("udp", &args.target, started_at)
        .with_status(status, summary)
        .with_probes(recorder.into_probes());
    report = report.with_limitation(
        "UDP Echo 只证明该端口的应用层往返；不能据此推断 QUIC 或其它 UDP 服务可用".to_string(),
    );
    if stats.echoes == 0 {
        report = report.with_limitation(
            "没有收到合法 Echo：目标可能未运行 Echo 服务、被防火墙拦截，或路径丢包；本结果不定位原因"
                .to_string(),
        );
    }
    if samples
        .iter()
        .any(|sample| sample.result == crate::probes::udp::EchoResult::IcmpUnreachable)
    {
        report = report.with_limitation(
            "收到 ICMP 端口不可达：说明某设备回了错误报文，不等于 UDP 应用层可用".to_string(),
        );
    }
    Ok(report.emit(args.format))
}

/// `pathtrial endpoint --udp-echo --bind 127.0.0.1:39001`
pub fn endpoint(args: &crate::cli::EndpointArgs) -> Result<u8, String> {
    if !args.udp_echo {
        return Err("only --udp-echo is implemented for `endpoint`".to_string());
    }
    crate::endpoint::udp_echo(
        &args.bind,
        args.allow_public_bind,
        crate::probes::udp::MAX_PAYLOAD,
    )?;
    Ok(0)
}

/// Split `HOST:PORT` (IPv6 uses brackets) into host and port.
pub fn split_target(target: &str) -> Result<(String, u16), String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {target}"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("missing port in {target}"))?
            .parse::<u16>()
            .map_err(|_| format!("invalid port in {target}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("expected HOST:PORT, got {target}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid port in {target}"))?;
    if host.is_empty() {
        return Err(format!("empty host in {target}"));
    }
    Ok((host.to_string(), port))
}

/// `pathtrial http URL`
pub fn http(args: &HttpArgs) -> Result<u8, String> {
    let started_at = crate::util::now_rfc3339();
    let display_url = crate::probes::http::parse_url(&args.url)?.redacted();
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
    let mut report = CommandReport::new("http", &display_url, started_at)
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

/// `pathtrial proxy URL --proxy socks5://host:port`
pub fn proxy(args: &crate::cli::ProxyArgs) -> Result<u8, String> {
    let started_at = crate::util::now_rfc3339();
    let url = crate::probes::http::parse_url(&args.url)?;
    let display_url = url.redacted();
    let spec = crate::probes::proxy::parse_proxy(&args.proxy)?;
    let timeout = std::time::Duration::from_millis(args.timeout_ms);
    if timeout.is_zero() {
        return Err("--timeout-ms must be greater than zero".to_string());
    }
    validate_interface(args.bind_interface.as_deref())?;
    let mut recorder = Recorder::new();

    if args.compare_direct {
        return compare_direct(
            args,
            &url,
            &display_url,
            &spec,
            timeout,
            started_at,
            recorder,
        );
    }

    let attempt = proxy_once(
        &spec,
        &url,
        timeout,
        args.bind_interface.as_deref(),
        args.insecure,
    );
    let proxy_status = if !attempt.tunnel_ok || attempt.error.is_some() {
        Status::Fail
    } else if attempt.status.is_none() {
        Status::Inconclusive
    } else if attempt.status.unwrap_or(0) >= 400 {
        Status::Warn
    } else {
        Status::Pass
    };
    let summary = format!(
        "proxy: {} ({})\ntunnel: {}\nstages: proxy_tcp {tcp_ms:.1} ms | negotiate {negotiation_ms:.1} ms | connect {connect_ms:.1} ms | tls {tls_ms:.1} ms | http {http_ms:.1} ms\nhttp_status: {}",
        spec.redacted(),
        spec.kind.label(),
        if attempt.tunnel_ok { "ok" } else { "failed" },
        attempt
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        tcp_ms = attempt.proxy_tcp_ms,
        negotiation_ms = attempt.negotiation_ms,
        connect_ms = attempt.connect_ms,
        tls_ms = attempt.tls_ms,
        http_ms = attempt.http_ms,
    );
    record_proxy_attempt(
        &mut recorder,
        &spec.redacted(),
        spec.kind.label(),
        &display_url,
        &attempt,
    );
    let mut report = CommandReport::new("proxy", &display_url, started_at)
        .with_status(proxy_status, summary)
        .with_probes(recorder.into_probes());
    report = report.with_limitation(
        "隧道建立成功不等于目标 HTTPS 可用；代理与直连可能使用不同的 DNS、出口与路由".to_string(),
    );
    if url.host.parse::<std::net::IpAddr>().is_err() {
        report = report.with_limitation(
            "域名已交给代理侧处理；这不能证明代理之外没有其他 DNS 解析或泄漏".to_string(),
        );
    }
    if let Some(error) = attempt.error {
        report = report.with_limitation(format!("proxy stage error: {error}"));
    }
    Ok(report.emit(args.format))
}

fn family_choice(family: AddressFamily) -> crate::probes::quic::FamilyChoice {
    match family {
        AddressFamily::Auto => crate::probes::quic::FamilyChoice::Auto,
        AddressFamily::Ipv4 => crate::probes::quic::FamilyChoice::Ipv4,
        AddressFamily::Ipv6 => crate::probes::quic::FamilyChoice::Ipv6,
    }
}

fn quic_status(outcome: &crate::probes::quic::QuicOutcome, wants_http3: bool) -> Status {
    if outcome.fake_ip_suspected() {
        Status::Inconclusive
    } else if outcome.protocol_unavailable() {
        Status::Skip
    } else if !outcome.handshake_ok || outcome.error.is_some() {
        Status::Fail
    } else if let Some(status) = outcome.http3_status {
        if status >= 400 {
            Status::Warn
        } else {
            Status::Pass
        }
    } else if wants_http3 {
        Status::Inconclusive
    } else {
        Status::Pass
    }
}

fn quic_summary(outcome: &crate::probes::quic::QuicOutcome) -> String {
    format!(
        "address: {}\nstage: {}\nhandshake: {} | {} ms\ntls_verified: {}\nalpn: {}\nhttp3_status: {}\nhttp3_bytes: {}\nhttp3_ttfb: {}\nhttp3_total: {}",
        outcome
            .address
            .map(|address| address.to_string())
            .unwrap_or_else(|| "unavailable".to_string()),
        outcome.stage,
        if outcome.handshake_ok { "ok" } else { "failed" },
        outcome
            .handshake_ms
            .map(|value| format!("{value:.1}"))
            .unwrap_or_else(|| "n/a".to_string()),
        outcome
            .tls_verified
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        outcome.alpn.as_deref().unwrap_or("none"),
        outcome
            .http3_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        outcome.http3_bytes,
        format_opt_ms(outcome.http3_ttfb_ms),
        format_opt_ms(outcome.http3_total_ms)
    )
}

fn quic_limits(report: CommandReport, outcome: &crate::probes::quic::QuicOutcome) -> CommandReport {
    let mut report = report.with_limitation(
        "QUIC 握手成功不等于 HTTP/3 可用；TLS 证书、ALPN 和 HTTP/3 阶段分开记录".to_string(),
    );
    report = report.with_limitation(
        "UDP 无响应可能来自服务未开放、防火墙或路径丢包；本工具不定位具体设备".to_string(),
    );
    if outcome.protocol_unavailable() {
        report = report.with_limitation(
            "目标未协商请求的 ALPN；这只能说明该协议未提供，不能判成整条网络异常".to_string(),
        );
    }
    if outcome.fake_ip_suspected() {
        report = report.with_limitation(
            "解析结果位于 198.18.0.0/15，疑似本地代理 Fake-IP；本次握手描述本地代理路径"
                .to_string(),
        );
    }
    report
}

/// `pathtrial quic HOST`
pub fn quic(args: &QuicArgs) -> Result<u8, String> {
    if args.timeout_ms == 0 || args.max_seconds == 0 {
        return Err("--timeout-ms and --max-seconds must be greater than zero".to_string());
    }
    crate::probes::quic::check_interface(args.bind_interface.as_deref())?;
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let request = crate::probes::quic::QuicRequest {
        host: &args.host,
        port: args.port,
        family: family_choice(args.family),
        alpn: &args.alpn,
        server_name: args.sni.as_deref(),
        timeout: std::time::Duration::from_millis(args.timeout_ms),
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(args.max_seconds),
        interface: args.bind_interface.as_deref(),
        ca_file: args.ca_file.as_deref(),
        insecure: args.insecure,
        http3: None,
    };
    let outcome = crate::probes::quic::run(&mut recorder, &request)?;
    let id = crate::probes::quic::record(&mut recorder, &request, &outcome);
    let status = quic_status(&outcome, false);
    let target = format!("{}:{}", args.host, args.port);
    let report = CommandReport::new("quic", &target, started_at)
        .with_status(status, quic_summary(&outcome))
        .with_probes(recorder.into_probes());
    let mut report = quic_limits(report, &outcome);
    if args.insecure {
        report = report.with_limitation("证书校验已关闭；该模式只能用于诊断或本地测试".to_string());
    }
    if let Some(error) = &outcome.error {
        report = report.with_limitation(format!("QUIC stage error: {error}"));
    }
    let _ = id;
    Ok(report.emit(args.format))
}

/// `pathtrial http3 URL`
pub fn http3(args: &Http3Args) -> Result<u8, String> {
    if args.timeout_ms == 0 || args.max_seconds == 0 {
        return Err("--timeout-ms and --max-seconds must be greater than zero".to_string());
    }
    crate::probes::quic::check_interface(args.bind_interface.as_deref())?;
    let url = crate::probes::http::parse_url(&args.url)?;
    if !url.is_tls() {
        return Err("http3 requires an https:// URL".to_string());
    }
    let display_url = url.redacted();
    let uri = format!("https://{}{}", url.host_header(), url.path);
    let started_at = crate::util::now_rfc3339();
    let mut recorder = Recorder::new();
    let request = crate::probes::quic::QuicRequest {
        host: &url.host,
        port: url.port,
        family: family_choice(args.family),
        alpn: "h3",
        server_name: args.sni.as_deref().or(Some(&url.host)),
        timeout: std::time::Duration::from_millis(args.timeout_ms),
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(args.max_seconds),
        interface: args.bind_interface.as_deref(),
        ca_file: args.ca_file.as_deref(),
        insecure: args.insecure,
        http3: Some(crate::probes::quic::Http3Target { uri: &uri }),
    };
    let outcome = crate::probes::quic::run(&mut recorder, &request)?;
    let id = crate::probes::quic::record(&mut recorder, &request, &outcome);
    let status = quic_status(&outcome, true);
    let report = CommandReport::new("http3", &display_url, started_at)
        .with_status(status, quic_summary(&outcome))
        .with_probes(recorder.into_probes());
    let mut report = quic_limits(report, &outcome);
    if args.insecure {
        report = report.with_limitation("证书校验已关闭；该模式只能用于诊断或本地测试".to_string());
    }
    if let Some(error) = &outcome.error {
        report = report.with_limitation(format!("HTTP/3 stage error: {error}"));
    }
    let _ = id;
    Ok(report.emit(args.format))
}

struct ProxyAttempt {
    proxy_tcp_ms: f64,
    negotiation_ms: f64,
    connect_ms: f64,
    tls_ms: f64,
    http_ms: f64,
    status: Option<u16>,
    tunnel_ok: bool,
    tls_verified: Option<bool>,
    error: Option<String>,
}

impl ProxyAttempt {
    fn total_ms(&self) -> f64 {
        round2(
            self.proxy_tcp_ms + self.negotiation_ms + self.connect_ms + self.tls_ms + self.http_ms,
        )
    }
}

fn record_proxy_attempt(
    recorder: &mut Recorder,
    proxy: &str,
    proxy_kind: &str,
    target: &str,
    attempt: &ProxyAttempt,
) -> String {
    record(
        recorder,
        ProbeKind::Proxy,
        target,
        ProbeDetail::ProxyExchange {
            proxy: proxy.to_string(),
            proxy_kind: proxy_kind.to_string(),
            target: target.to_string(),
            proxy_tcp_ms: attempt.proxy_tcp_ms,
            negotiation_ms: attempt.negotiation_ms,
            connect_ms: attempt.connect_ms,
            tls_ms: attempt.tls_ms,
            http_ms: attempt.http_ms,
            http_status: attempt.status,
            tunnel_ok: attempt.tunnel_ok,
            tls_verified: attempt.tls_verified,
            error: attempt.error.clone(),
        },
        attempt.error.is_none()
            && attempt.tunnel_ok
            && attempt.status.map(|code| code < 400).unwrap_or(false),
    )
}

fn proxy_once(
    spec: &crate::probes::proxy::ProxySpec,
    url: &crate::probes::http::Url,
    timeout: std::time::Duration,
    interface: Option<&str>,
    insecure: bool,
) -> ProxyAttempt {
    let mut attempt = ProxyAttempt {
        proxy_tcp_ms: 0.0,
        negotiation_ms: 0.0,
        connect_ms: 0.0,
        tls_ms: 0.0,
        http_ms: 0.0,
        status: None,
        tunnel_ok: false,
        tls_verified: None,
        error: None,
    };
    let (stream, timings) =
        match crate::probes::proxy::tunnel(spec, &url.host, url.port, timeout, interface) {
            Ok(value) => value,
            Err(failure) => {
                attempt.error = Some(failure.label());
                return attempt;
            }
        };
    attempt.tunnel_ok = true;
    attempt.proxy_tcp_ms = timings.proxy_tcp_ms;
    attempt.negotiation_ms = timings.negotiation_ms;
    attempt.connect_ms = timings.connect_ms;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;
    if url.is_tls() {
        let tls_started = std::time::Instant::now();
        match crate::probes::tls::handshake(stream, &url.host, insecure) {
            Ok(mut session) => {
                attempt.tls_ms = round2(tls_started.elapsed().as_secs_f64() * 1000.0);
                attempt.tls_verified = Some(!insecure);
                let http_started = std::time::Instant::now();
                match http_status(&mut session.stream, url) {
                    Ok(code) => {
                        attempt.status = Some(code);
                        attempt.http_ms = round2(http_started.elapsed().as_secs_f64() * 1000.0);
                    }
                    Err(message) => attempt.error = Some(message),
                }
            }
            Err(crate::probes::tls::TlsFailure::Certificate { message, .. }) => {
                attempt.tls_ms = round2(tls_started.elapsed().as_secs_f64() * 1000.0);
                attempt.tls_verified = Some(false);
                attempt.error = Some(format!("certificate: {message}"));
            }
            Err(crate::probes::tls::TlsFailure::Transport(message)) => {
                attempt.tls_ms = round2(tls_started.elapsed().as_secs_f64() * 1000.0);
                attempt.error = Some(format!("tls: {message}"));
            }
        }
    } else {
        let http_started = std::time::Instant::now();
        match http_status(&mut stream, url) {
            Ok(code) => {
                attempt.status = Some(code);
                attempt.http_ms = round2(http_started.elapsed().as_secs_f64() * 1000.0);
            }
            Err(message) => attempt.error = Some(message),
        }
    }
    attempt
}

fn compare_direct(
    args: &crate::cli::ProxyArgs,
    url: &crate::probes::http::Url,
    display_url: &str,
    spec: &crate::probes::proxy::ProxySpec,
    timeout: std::time::Duration,
    started_at: String,
    mut recorder: Recorder,
) -> Result<u8, String> {
    if args.rounds == 0 || args.rounds > 50 {
        return Err("--rounds must be between 1 and 50".to_string());
    }
    if args.max_seconds == 0 {
        return Err("--max-seconds must be greater than zero".to_string());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.max_seconds);
    let interval = std::time::Duration::from_millis(args.interval_ms);
    let mut direct_totals = Vec::new();
    let mut proxy_totals = Vec::new();
    let mut direct_errors = Vec::new();
    let mut proxy_errors = Vec::new();
    let mut direct_total = 0u32;
    let mut direct_success = 0u32;
    let mut proxy_total = 0u32;
    let mut proxy_success = 0u32;
    let mut completed = 0u32;

    for round in 1..=args.rounds {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let request = HttpRequest {
            url: &args.url,
            method: "GET",
            expected_status: None,
            timeout,
            interface: args.bind_interface.as_deref(),
            insecure: args.insecure,
            max_body: 16 * 1024,
        };
        let direct = crate::probes::http::run(&mut recorder, &request)?;
        direct_total += 1;
        if direct.error.is_none() && direct.status.map(|code| code < 400).unwrap_or(false) {
            direct_success += 1;
            direct_totals.push(direct.timings.total_ms);
        } else {
            direct_errors.push(format!(
                "round {round}: {}",
                direct
                    .error
                    .as_ref()
                    .map(|error| error.label())
                    .or_else(|| direct.status.map(|code| format!("http_status:{code}")))
                    .unwrap_or_else(|| "no HTTP status".to_string())
            ));
        }
        if !interval.is_zero() {
            std::thread::sleep(interval);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }

        let attempt = proxy_once(
            spec,
            url,
            timeout,
            args.bind_interface.as_deref(),
            args.insecure,
        );
        record_proxy_attempt(
            &mut recorder,
            &spec.redacted(),
            spec.kind.label(),
            display_url,
            &attempt,
        );
        proxy_total += 1;
        if attempt.error.is_none() && attempt.status.map(|code| code < 400).unwrap_or(false) {
            proxy_success += 1;
            proxy_totals.push(attempt.total_ms());
        } else {
            proxy_errors.push(format!(
                "round {round}: {}",
                attempt
                    .error
                    .clone()
                    .or_else(|| attempt.status.map(|code| format!("http_status:{code}")))
                    .unwrap_or_else(|| "no HTTP status".to_string())
            ));
        }
        completed += 1;
        if !interval.is_zero() {
            std::thread::sleep(interval);
        }
    }

    let direct_median = crate::util::median(&direct_totals);
    let proxy_median = crate::util::median(&proxy_totals);
    let direct_min = direct_totals.iter().copied().reduce(f64::min);
    let proxy_min = proxy_totals.iter().copied().reduce(f64::min);
    let direct_dns = if url.host.parse::<std::net::IpAddr>().is_ok() {
        "literal address (no DNS)".to_string()
    } else {
        "local resolver".to_string()
    };
    let proxy_dns = if url.host.parse::<std::net::IpAddr>().is_ok() {
        "literal address (no DNS)".to_string()
    } else {
        "proxy-side resolution requested".to_string()
    };
    let note = "Alternating requests share the URL and timeout, but the two paths can use different DNS, egress and routing".to_string();
    let detail = ProbeDetail::PathComparison {
        rounds_requested: args.rounds,
        rounds_completed: completed,
        direct_total,
        direct_success,
        proxy_total,
        proxy_success,
        direct_median_ms: direct_median.map(round2),
        proxy_median_ms: proxy_median.map(round2),
        direct_min_ms: direct_min.map(round2),
        proxy_min_ms: proxy_min.map(round2),
        direct_errors: direct_errors.clone(),
        proxy_errors: proxy_errors.clone(),
        direct_dns: direct_dns.clone(),
        proxy_dns: proxy_dns.clone(),
        note,
    };
    record(
        &mut recorder,
        ProbeKind::Proxy,
        display_url,
        detail,
        proxy_total > 0 && proxy_success == proxy_total,
    );

    let status = if proxy_total == 0 {
        Status::Inconclusive
    } else if proxy_success == 0 {
        Status::Fail
    } else if proxy_success < proxy_total || direct_success < direct_total {
        Status::Warn
    } else {
        Status::Pass
    };
    let summary = format!(
        "target: {display_url}\nproxy: {} ({})\nrounds: {completed}/{} completed\ndirect: {direct_success}/{direct_total} | median {} | min {}\nproxy path: {proxy_success}/{proxy_total} | median {} | min {}\ndns: direct={direct_dns}; proxy={proxy_dns}",
        spec.redacted(),
        spec.kind.label(),
        args.rounds,
        format_opt_ms(direct_median),
        format_opt_ms(direct_min),
        format_opt_ms(proxy_median),
        format_opt_ms(proxy_min),
    );
    let mut report = CommandReport::new("proxy", display_url, started_at)
        .with_status(status, summary)
        .with_probes(recorder.into_probes());
    report = report.with_limitation(
        "直连与代理可能经过不同的 DNS、出口和路由；性能差异不能单独证明运营商干预".to_string(),
    );
    report = report.with_limitation(
        "直连结果只描述直连路径；本地 Fake-IP 或 TUN 会改变直连观测值".to_string(),
    );
    if !direct_errors.is_empty() {
        report = report.with_limitation(format!("direct errors: {}", direct_errors.join("; ")));
    }
    if !proxy_errors.is_empty() {
        report = report.with_limitation(format!("proxy errors: {}", proxy_errors.join("; ")));
    }
    if direct_total != proxy_total {
        report = report.with_limitation(
            "time budget ended between the two paths; sample counts differ".to_string(),
        );
    }
    if completed < args.rounds {
        report = report.with_limitation(format!(
            "time budget stopped the run after {completed} of {} rounds",
            args.rounds
        ));
    }
    Ok(report.emit(args.format))
}

fn format_opt_ms(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1} ms"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn http_status<S: Read + Write>(
    stream: &mut S,
    url: &crate::probes::http::Url,
) -> Result<u16, String> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: pathtrial/{}\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header(),
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(request.as_bytes()).map_err(|error| {
        format!(
            "http_write:{}",
            crate::util::classify_io_error(&error).label()
        )
    })?;
    let mut buffer = [0u8; 2048];
    let mut head = Vec::new();
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => head.extend_from_slice(&buffer[..read]),
            Err(error) => {
                return Err(format!(
                    "http_read:{}",
                    crate::util::classify_io_error(&error).label()
                ))
            }
        }
        if head.len() > 16 * 1024 {
            return Err("http head too large".to_string());
        }
    }
    let text = String::from_utf8_lossy(&head);
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "http status unreadable".to_string())
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
