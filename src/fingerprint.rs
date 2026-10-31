//! Stable local-path fingerprints built from existing probes.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::cli::{FingerprintArgs, FingerprintDiffArgs, OutputFormat};
use crate::models::{Confidence, Finding, Probe, ProbeDetail, Status};
use crate::probes::{dns, http, system, tls, Recorder};
use crate::util::{new_run_id, now_rfc3339};

pub const FINGERPRINT_SCHEMA_VERSION: &str = "1.0.0";
const COMPONENT_VERSION: &str = "local-path-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitCapture {
    pub ip: Option<String>,
    pub probe_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsFingerprint {
    pub resolvers: Vec<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub cname_chain: Vec<String>,
    pub fake_ip_suspected: bool,
    pub probe_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsFingerprint {
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_sha256: Option<String>,
    pub issuer: Option<String>,
    pub transport_ok: bool,
    pub verified: bool,
    pub probe_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyHop {
    pub source: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintEnvironment {
    pub interface_count: usize,
    pub ipv4_local: bool,
    pub ipv6_local: bool,
    pub vpn_like_interfaces: Vec<String>,
    pub proxy_hops: Vec<ProxyHop>,
    pub system_probe_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintComponents {
    pub component_version: String,
    pub exit_ipv4: ExitCapture,
    pub exit_ipv6: ExitCapture,
    pub dns: DnsFingerprint,
    pub tls: Option<TlsFingerprint>,
    pub ip_fork: String,
    pub environment: FingerprintEnvironment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintReport {
    pub schema_version: String,
    pub tool_version: String,
    pub run_id: String,
    pub captured_at: String,
    pub target: String,
    pub fingerprint: String,
    pub components: FingerprintComponents,
    pub probes: Vec<Probe>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintChange {
    pub component: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintDiffReport {
    pub schema_version: String,
    pub tool_version: String,
    pub before_fingerprint: String,
    pub after_fingerprint: String,
    pub verdict: String,
    pub changes: Vec<FingerprintChange>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}

pub fn run(args: &FingerprintArgs) -> Result<u8, String> {
    if args.timeout_ms < 100 || args.timeout_ms > 30_000 {
        return Err("--timeout-ms must be between 100 and 30000".to_string());
    }
    if args.max_seconds < 5 || args.max_seconds > 300 {
        return Err("--max-seconds must be between 5 and 300".to_string());
    }
    let url = http::parse_url(&args.target)?;
    if !url.is_tls() {
        return Err("fingerprint target must be an HTTPS URL".to_string());
    }
    if let Some(proxy) = &args.proxy {
        crate::probes::proxy::parse_proxy(proxy)?;
    }
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    let timeout = Duration::from_millis(args.timeout_ms);
    let mut recorder = Recorder::new();

    let system_probe = system::collect(&mut recorder, None);
    let system_probe_id = system_probe.probe_ids.first().cloned();

    let dns_outcome = dns::resolve(
        &url.host,
        &mut recorder,
        timeout.min(Duration::from_secs(2)),
    );
    let dns_fingerprint = DnsFingerprint {
        resolvers: dns_outcome.resolvers.clone(),
        ipv4: dns_outcome.addresses_v4.clone(),
        ipv6: dns_outcome.addresses_v6.clone(),
        cname_chain: cname_chain(recorder.probes()),
        fake_ip_suspected: dns_outcome.fake_ip,
        probe_ids: dns_outcome.probe_ids.clone(),
    };

    let exit_ipv4 = capture_exit(
        &mut recorder,
        &url,
        dns_outcome
            .addresses_v4
            .first()
            .and_then(|ip| ip.parse().ok()),
        args,
        timeout,
        deadline,
    );
    let exit_ipv6 = capture_exit(
        &mut recorder,
        &url,
        dns_outcome
            .addresses_v6
            .first()
            .and_then(|ip| ip.parse().ok()),
        args,
        timeout,
        deadline,
    );

    let tls_target = dns_outcome
        .addresses_v4
        .first()
        .or_else(|| dns_outcome.addresses_v6.first())
        .and_then(|text| text.parse::<IpAddr>().ok());
    let tls_fingerprint = tls_target.and_then(|ip| {
        let family = if ip.is_ipv4() {
            crate::models::Family::Ipv4
        } else {
            crate::models::Family::Ipv6
        };
        let attempt = tls::probe(
            &mut recorder,
            family,
            ip,
            url.port,
            &url.host,
            timeout,
            false,
            args.bind_interface.as_deref(),
        );
        let detail = recorder
            .probes()
            .iter()
            .find(|probe| probe.id == attempt.probe_id)
            .and_then(|probe| match &probe.detail {
                ProbeDetail::TlsHandshake {
                    protocol,
                    cipher_suite,
                    cert,
                    transport_ok,
                    verification,
                    ..
                } => Some(TlsFingerprint {
                    protocol: protocol.clone(),
                    cipher_suite: cipher_suite.clone(),
                    cert_sha256: cert.as_ref().and_then(|cert| cert.cert_sha256.clone()),
                    issuer: cert.as_ref().and_then(|cert| cert.issuer.clone()),
                    transport_ok: *transport_ok,
                    verified: matches!(verification, crate::models::Verification::Verified),
                    probe_id: attempt.probe_id.clone(),
                }),
                _ => None,
            });
        detail
    });

    let mut proxy_hops = proxy_hops(args.proxy.as_deref());
    proxy_hops.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then(left.endpoint.cmp(&right.endpoint))
    });
    proxy_hops.dedup();
    let ip_fork = classify_ip_fork(&exit_ipv4.ip, &exit_ipv6.ip);
    let components = FingerprintComponents {
        component_version: COMPONENT_VERSION.to_string(),
        exit_ipv4,
        exit_ipv6,
        dns: dns_fingerprint,
        tls: tls_fingerprint,
        ip_fork,
        environment: FingerprintEnvironment {
            interface_count: system_probe.environment.interfaces.len(),
            ipv4_local: system_probe.environment.ipv4_local,
            ipv6_local: system_probe.environment.ipv6_local,
            vpn_like_interfaces: system_probe.environment.vpn_like_interfaces.clone(),
            proxy_hops,
            system_probe_id,
        },
    };
    let fingerprint = fingerprint_hash(&components)?;
    let findings = fingerprint_findings(&components, fingerprint.as_str());
    let probes = recorder.into_probes();
    let report = FingerprintReport {
        schema_version: FINGERPRINT_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        run_id: new_run_id(),
        captured_at: now_rfc3339(),
        target: url.redacted(),
        fingerprint,
        components,
        probes,
        findings,
        limitations: vec![
            "A fingerprint identifies this path at capture time; it is not a reputation or ownership claim."
                .to_string(),
            "Proxy hops describe locally configured endpoints and do not prove the remote proxy chain."
                .to_string(),
            "DNS and TLS identity can change with resolver, CDN, split-horizon or interception."
                .to_string(),
        ],
    };
    if let Some(path) = &args.out {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|error| format!("render fingerprint JSON: {error}"))?;
        std::fs::write(path, format!("{json}\n"))
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    emit_fingerprint(&report, args.format);
    Ok(
        match report
            .findings
            .iter()
            .map(|finding| finding.status)
            .fold(Status::Pass, worst_status)
        {
            Status::Fail | Status::Warn => 2,
            Status::Inconclusive => 3,
            _ => 0,
        },
    )
}

fn capture_exit(
    recorder: &mut Recorder,
    url: &http::Url,
    connect_ip: Option<IpAddr>,
    args: &FingerprintArgs,
    timeout: Duration,
    deadline: Instant,
) -> ExitCapture {
    let Some(connect_ip) = connect_ip else {
        return ExitCapture {
            ip: None,
            probe_id: None,
            error: Some("no address for this family".to_string()),
        };
    };
    if Instant::now() >= deadline {
        return ExitCapture {
            ip: None,
            probe_id: None,
            error: Some("fingerprint budget exhausted".to_string()),
        };
    }
    let request = http::HttpRequest {
        url: &args.target,
        method: "GET",
        expected_status: Some(200),
        timeout,
        interface: args.bind_interface.as_deref(),
        insecure: false,
        max_body: 256,
        server_name: Some(&url.host),
        host_header: None,
        connect_ip: Some(connect_ip),
    };
    match http::run(recorder, &request) {
        Ok(outcome) if outcome.error.is_none() => {
            let text = String::from_utf8_lossy(&outcome.body_preview)
                .trim()
                .to_string();
            match text.parse::<IpAddr>() {
                Ok(ip) => ExitCapture {
                    ip: Some(ip.to_string()),
                    probe_id: Some(outcome.probe_id),
                    error: None,
                },
                Err(_) => ExitCapture {
                    ip: None,
                    probe_id: Some(outcome.probe_id),
                    error: Some("response body was not an IP address".to_string()),
                },
            }
        }
        Ok(outcome) => ExitCapture {
            ip: None,
            probe_id: Some(outcome.probe_id),
            error: outcome.error.map(|error| error.label()),
        },
        Err(error) => ExitCapture {
            ip: None,
            probe_id: None,
            error: Some(error),
        },
    }
}

fn cname_chain(probes: &[Probe]) -> Vec<String> {
    let mut chain = Vec::new();
    for probe in probes {
        if let ProbeDetail::DnsQuery { cname_chain, .. } = &probe.detail {
            for name in cname_chain {
                if !chain.contains(name) {
                    chain.push(name.clone());
                }
            }
        }
    }
    chain
}

fn proxy_hops(explicit: Option<&str>) -> Vec<ProxyHop> {
    let mut hops = Vec::new();
    if let Some(proxy) = explicit {
        hops.push(ProxyHop {
            source: "explicit".to_string(),
            endpoint: sanitize_proxy(proxy),
        });
    }
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if let Ok(value) = std::env::var(name) {
            hops.push(ProxyHop {
                source: format!("env:{name}"),
                endpoint: sanitize_proxy(&value),
            });
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for (enable, host, port, label) in [
            ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "http"),
            ("HTTPEnable", "HTTPProxy", "HTTPPort", "http"),
            ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "socks5"),
        ] {
            if proxy_field(&text, enable).as_deref() == Some("1") {
                if let (Some(host), Some(port)) =
                    (proxy_field(&text, host), proxy_field(&text, port))
                {
                    hops.push(ProxyHop {
                        source: "system".to_string(),
                        endpoint: format!("{label}://{host}:{port}"),
                    });
                }
            }
        }
    }
    hops
}

#[cfg(target_os = "macos")]
fn proxy_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

fn sanitize_proxy(raw: &str) -> String {
    if let Ok(spec) = crate::probes::proxy::parse_proxy(raw) {
        let scheme = match spec.kind {
            crate::probes::proxy::ProxyKind::Socks5 => "socks5",
            crate::probes::proxy::ProxyKind::HttpConnect => "http",
        };
        let host = if spec.host.contains(':') {
            format!("[{}]", spec.host)
        } else {
            spec.host
        };
        format!("{scheme}://{host}:{}", spec.port)
    } else if raw.is_empty() {
        "<empty>".to_string()
    } else {
        "<unparsed-proxy>".to_string()
    }
}

fn classify_ip_fork(ipv4: &Option<String>, ipv6: &Option<String>) -> String {
    match (ipv4, ipv6) {
        (Some(v4), Some(v6)) if v4 == v6 => "same_exit".to_string(),
        (Some(v4), Some(v6)) => {
            let v4 = v4.parse::<IpAddr>();
            let v6 = v6.parse::<IpAddr>();
            if matches!(v4, Ok(IpAddr::V4(_))) && matches!(v6, Ok(IpAddr::V6(_))) {
                "dual_stack".to_string()
            } else {
                "cross_family".to_string()
            }
        }
        (Some(_), None) => "ipv4_only".to_string(),
        (None, Some(_)) => "ipv6_only".to_string(),
        (None, None) => "unavailable".to_string(),
    }
}

fn fingerprint_hash(components: &FingerprintComponents) -> Result<String, String> {
    let bytes = serde_json::to_vec(components)
        .map_err(|error| format!("serialize fingerprint components: {error}"))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn fingerprint_findings(components: &FingerprintComponents, fingerprint: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exit_evidence = [
        components.exit_ipv4.probe_id.clone(),
        components.exit_ipv6.probe_id.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    findings.push(make_finding(
        "F001",
        "R901",
        format!(
            "Exit identity IPv4={} IPv6={}",
            components.exit_ipv4.ip.as_deref().unwrap_or("unavailable"),
            components.exit_ipv6.ip.as_deref().unwrap_or("unavailable")
        ),
        if exit_evidence.is_empty() {
            Status::Inconclusive
        } else {
            Status::Pass
        },
        exit_evidence,
        vec![
            "Exit IP does not identify the access network, proxy operator or destination path."
                .to_string(),
        ],
        if components.ip_fork == "cross_family" {
            Confidence::High
        } else {
            Confidence::Moderate
        },
    ));
    findings.push(make_finding(
        "F002",
        "R902",
        format!("IPv4/IPv6 fork={}", components.ip_fork),
        match components.ip_fork.as_str() {
            "dual_stack" | "same_exit" | "ipv4_only" | "ipv6_only" => Status::Pass,
            "cross_family" => Status::Warn,
            _ => Status::Inconclusive,
        },
        components.dns.probe_ids.clone(),
        vec![
            "Address-family exit differences can come from CDN routing or split tunnels."
                .to_string(),
        ],
        Confidence::Moderate,
    ));
    findings.push(make_finding(
        "F003",
        "R903",
        format!(
            "DNS chain {} with {} IPv4 and {} IPv6 answer(s)",
            if components.dns.cname_chain.is_empty() {
                "has no observed CNAME"
            } else {
                "contains a CNAME chain"
            },
            components.dns.ipv4.len(),
            components.dns.ipv6.len()
        ),
        if components.dns.probe_ids.is_empty() {
            Status::Inconclusive
        } else {
            Status::Pass
        },
        components.dns.probe_ids.clone(),
        vec!["DNS answers do not prove the address used by an application.".to_string()],
        Confidence::Moderate,
    ));
    if let Some(tls) = &components.tls {
        findings.push(make_finding(
            "F004",
            "R904",
            format!(
                "TLS identity cert={} protocol={}",
                tls.cert_sha256.as_deref().unwrap_or("unavailable"),
                tls.protocol.as_deref().unwrap_or("unavailable")
            ),
            if tls.transport_ok && tls.verified {
                Status::Pass
            } else {
                Status::Fail
            },
            vec![tls.probe_id.clone()],
            vec!["A TLS certificate identity can be shared by many CDN endpoints.".to_string()],
            Confidence::High,
        ));
    }
    if let Some(probe_id) = &components.environment.system_probe_id {
        findings.push(make_finding(
            "F005",
            "R905",
            format!(
                "Local proxy hops={} fingerprint={fingerprint}",
                components.environment.proxy_hops.len()
            ),
            Status::Pass,
            vec![probe_id.clone()],
            vec![
                "Environment or system proxy settings do not reveal remote proxy hops.".to_string(),
            ],
            Confidence::Low,
        ));
    }
    findings
}

fn make_finding(
    id: &str,
    rule_id: &str,
    claim: String,
    status: Status,
    evidence: Vec<String>,
    not_established: Vec<String>,
    confidence: Confidence,
) -> Finding {
    Finding {
        id: id.to_string(),
        rule_id: rule_id.to_string(),
        claim,
        severity: match status {
            Status::Fail => crate::models::Severity::Fail,
            Status::Warn => crate::models::Severity::Warn,
            _ => crate::models::Severity::Info,
        },
        status,
        probe_id: evidence
            .first()
            .cloned()
            .unwrap_or_else(|| "none".to_string()),
        evidence,
        not_established,
        confidence,
        limits: vec![
            "This finding describes one fingerprint capture and does not claim a root cause."
                .to_string(),
        ],
    }
}

fn emit_fingerprint(report: &FingerprintReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        OutputFormat::Markdown => {
            println!("# PathTrial Path Fingerprint");
            println!();
            println!("- Target: `{}`", report.target);
            println!("- Fingerprint: `{}`", report.fingerprint);
            println!(
                "- IPv4 exit: `{}`",
                option_text(&report.components.exit_ipv4.ip)
            );
            println!(
                "- IPv6 exit: `{}`",
                option_text(&report.components.exit_ipv6.ip)
            );
            println!("- IP fork: `{}`", report.components.ip_fork);
            if let Some(tls) = &report.components.tls {
                println!(
                    "- TLS certificate: `{}`",
                    tls.cert_sha256.as_deref().unwrap_or("unavailable")
                );
            }
        }
        OutputFormat::Summary => {
            println!("PathTrial fingerprint");
            println!("target: {}", report.target);
            println!("fingerprint: {}", report.fingerprint);
            println!(
                "exit: ipv4={} ipv6={}",
                option_text(&report.components.exit_ipv4.ip),
                option_text(&report.components.exit_ipv6.ip)
            );
            println!("ip fork: {}", report.components.ip_fork);
            println!(
                "dns: {} v4 / {} v6, CNAME chain {}",
                report.components.dns.ipv4.len(),
                report.components.dns.ipv6.len(),
                report.components.dns.cname_chain.len()
            );
            if let Some(tls) = &report.components.tls {
                println!(
                    "tls: cert={} protocol={} verified={}",
                    tls.cert_sha256.as_deref().unwrap_or("unavailable"),
                    tls.protocol.as_deref().unwrap_or("unavailable"),
                    tls.verified
                );
            }
            println!(
                "proxy hops: {}",
                report.components.environment.proxy_hops.len()
            );
        }
    }
}

pub fn diff_run(args: &FingerprintDiffArgs) -> Result<u8, String> {
    let before = read_fingerprint(&args.before)?;
    let after = read_fingerprint(&args.after)?;
    let report = diff_reports(&before, &after);
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| format!("render fingerprint diff: {error}"))?
        ),
        OutputFormat::Markdown => {
            println!("# PathTrial Fingerprint Diff");
            println!();
            println!("- Verdict: **{}**", report.verdict);
            for change in &report.changes {
                println!(
                    "- `{}`: `{}` -> `{}`",
                    change.component, change.before, change.after
                );
            }
        }
        OutputFormat::Summary => {
            println!("fingerprint diff: {}", report.verdict);
            for change in &report.changes {
                println!(
                    "{}: {} -> {}",
                    change.component, change.before, change.after
                );
            }
        }
    }
    Ok(match report.verdict.as_str() {
        "IDENTICAL" => 0,
        "CHANGED" => 2,
        _ => 3,
    })
}

fn read_fingerprint(path: &std::path::Path) -> Result<FingerprintReport, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

pub fn diff_reports(
    before: &FingerprintReport,
    after: &FingerprintReport,
) -> FingerprintDiffReport {
    let mut changes = Vec::new();
    if before.schema_version != after.schema_version || before.target != after.target {
        changes.push(FingerprintChange {
            component: "identity".to_string(),
            before: json!(format!("{} {}", before.schema_version, before.target)),
            after: json!(format!("{} {}", after.schema_version, after.target)),
        });
    }
    compare_change(
        "exit_ipv4",
        &before.components.exit_ipv4.ip,
        &after.components.exit_ipv4.ip,
        &mut changes,
    );
    compare_change(
        "exit_ipv6",
        &before.components.exit_ipv6.ip,
        &after.components.exit_ipv6.ip,
        &mut changes,
    );
    compare_change(
        "dns_ipv4",
        &before.components.dns.ipv4,
        &after.components.dns.ipv4,
        &mut changes,
    );
    compare_change(
        "dns_ipv6",
        &before.components.dns.ipv6,
        &after.components.dns.ipv6,
        &mut changes,
    );
    compare_change(
        "dns_cname_chain",
        &before.components.dns.cname_chain,
        &after.components.dns.cname_chain,
        &mut changes,
    );
    compare_change(
        "ip_fork",
        &before.components.ip_fork,
        &after.components.ip_fork,
        &mut changes,
    );
    compare_change(
        "proxy_hops",
        &before.components.environment.proxy_hops,
        &after.components.environment.proxy_hops,
        &mut changes,
    );
    let before_tls = before.components.tls.as_ref().map(|tls| {
        (
            tls.cert_sha256.clone(),
            tls.protocol.clone(),
            tls.cipher_suite.clone(),
        )
    });
    let after_tls = after.components.tls.as_ref().map(|tls| {
        (
            tls.cert_sha256.clone(),
            tls.protocol.clone(),
            tls.cipher_suite.clone(),
        )
    });
    compare_change("tls_identity", &before_tls, &after_tls, &mut changes);

    let verdict = if before.schema_version != after.schema_version || before.target != after.target
    {
        "INCOMPARABLE"
    } else if changes.is_empty() && before.fingerprint == after.fingerprint {
        "IDENTICAL"
    } else {
        "CHANGED"
    }
    .to_string();
    let evidence = changes
        .iter()
        .take(5)
        .flat_map(|change| {
            [
                format!("fingerprint_before:{}", change.component),
                format!("fingerprint_after:{}", change.component),
            ]
        })
        .collect::<Vec<_>>();
    let status = match verdict.as_str() {
        "IDENTICAL" => Status::Pass,
        "CHANGED" => Status::Fail,
        _ => Status::Inconclusive,
    };
    let finding = make_finding(
        "F001",
        "R906",
        format!(
            "Fingerprint comparison verdict {verdict} with {} changed component(s)",
            changes.len()
        ),
        status,
        evidence,
        vec!["A fingerprint change does not prove which network component changed.".to_string()],
        if verdict == "IDENTICAL" {
            Confidence::High
        } else {
            Confidence::Moderate
        },
    );
    FingerprintDiffReport {
        schema_version: FINGERPRINT_SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        before_fingerprint: before.fingerprint.clone(),
        after_fingerprint: after.fingerprint.clone(),
        verdict,
        changes,
        findings: vec![finding],
        limitations: vec![
            "DNS, CDN and proxy assignments can change without local configuration changes."
                .to_string(),
        ],
    }
}

fn compare_change<T: Serialize + PartialEq>(
    component: &str,
    before: &T,
    after: &T,
    changes: &mut Vec<FingerprintChange>,
) {
    if before != after {
        changes.push(FingerprintChange {
            component: component.to_string(),
            before: serde_json::to_value(before).unwrap_or(Value::Null),
            after: serde_json::to_value(after).unwrap_or(Value::Null),
        });
    }
}

fn option_text(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("unavailable")
}

fn worst_status(left: Status, right: Status) -> Status {
    use Status::{Fail, Inconclusive, Pass, Skip, Warn};
    match (left, right) {
        (Fail, _) | (_, Fail) => Fail,
        (Warn, _) | (_, Warn) => Warn,
        (Inconclusive, _) | (_, Inconclusive) => Inconclusive,
        (Pass, _) | (_, Pass) => Pass,
        (Skip, Skip) => Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::classify_ip_fork;

    #[test]
    fn ip_fork_classification_keeps_native_dual_stack_separate_from_cross_family() {
        assert_eq!(
            classify_ip_fork(&Some("198.51.100.1".into()), &Some("2001:db8::1".into())),
            "dual_stack"
        );
        assert_eq!(
            classify_ip_fork(&Some("198.51.100.1".into()), &Some("198.51.100.1".into())),
            "same_exit"
        );
        assert_eq!(
            classify_ip_fork(&Some("198.51.100.1".into()), &Some("198.51.100.2".into())),
            "cross_family"
        );
        assert_eq!(
            classify_ip_fork(&Some("198.51.100.1".into()), &None),
            "ipv4_only"
        );
    }
}
