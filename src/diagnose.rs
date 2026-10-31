//! Guided, scenario-oriented diagnosis built on the existing probe commands.
//!
//! Each scenario composes the established JSON commands instead of duplicating
//! DNS, TCP, TLS, HTTP, UDP or QUIC protocol implementations. Sub-reports keep
//! their original probe IDs; diagnosis checks reference them as
//! `<source>:<probe_id>`.

use std::process::Command;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cli::{DiagnoseArgs, DiagnoseScenario, OutputFormat};
use crate::models::{Confidence, LocalLinkInfo, Status};
use crate::probes::{system, Recorder};
use crate::util::{mean, median, new_run_id, now_rfc3339, percentile, IpMasker};

pub const DIAGNOSE_SCHEMA_VERSION: &str = "1.1.0";
const MAX_CHILD_OUTPUT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseCheck {
    pub id: String,
    pub name: String,
    pub status: Status,
    pub summary: String,
    pub claim: String,
    pub evidence: Vec<String>,
    pub probe_id: Option<String>,
    pub observed: Vec<String>,
    pub possible: Vec<String>,
    pub not_established: Vec<String>,
    pub confidence: Confidence,
    pub limits: Vec<String>,
    pub next_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseSource {
    pub name: String,
    pub report: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseReport {
    pub schema_version: String,
    pub tool_version: String,
    pub run_id: String,
    pub scenario: String,
    pub target: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    pub status: Status,
    pub checks: Vec<DiagnoseCheck>,
    pub sources: Vec<DiagnoseSource>,
    pub limitations: Vec<String>,
    pub redaction: Value,
}

impl DiagnoseReport {
    fn new(args: &DiagnoseArgs, started_at: String) -> Self {
        Self {
            schema_version: DIAGNOSE_SCHEMA_VERSION.to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            run_id: new_run_id(),
            scenario: args.scenario.as_str().to_string(),
            target: args.requested_host.clone().or_else(|| args.target.clone()),
            started_at,
            finished_at: now_rfc3339(),
            status: Status::Skip,
            checks: Vec::new(),
            sources: Vec::new(),
            limitations: Vec::new(),
            redaction: json!({"applied": false, "ips_masked": 0}),
        }
    }

    fn add_source(&mut self, name: &str, report: Value) {
        self.sources.push(DiagnoseSource {
            name: name.to_string(),
            report,
        });
    }

    fn finalize(mut self, redact: bool) -> Self {
        self.normalize_evidence();
        self.status = self
            .checks
            .iter()
            .map(|check| check.status)
            .fold(Status::Skip, worst_status);
        if self.status == Status::Skip {
            self.status = Status::Inconclusive;
        }
        if redact {
            let mut masker = IpMasker::default();
            if let Some(target) = &self.target {
                self.target = Some(masker.mask_text(target));
            }
            for check in &mut self.checks {
                check.summary = masker.mask_text(&check.summary);
                mask_strings(&mut check.observed, &mut masker);
                mask_strings(&mut check.possible, &mut masker);
                mask_strings(&mut check.not_established, &mut masker);
                mask_strings(&mut check.next_checks, &mut masker);
            }
            for source in &mut self.sources {
                redact_value(&mut source.report, &mut masker);
            }
            mask_strings(&mut self.limitations, &mut masker);
            self.redaction = json!({"applied": true, "ips_masked": masker.masked});
        }
        self.finished_at = now_rfc3339();
        self
    }

    fn normalize_evidence(&mut self) {
        for check in &mut self.checks {
            if check.claim.trim().is_empty() {
                check.claim = check.summary.clone();
            }
            if check.probe_id.is_none() {
                check.probe_id = check.evidence.first().cloned();
            }
            if check.limits.is_empty() {
                check.limits = check.not_established.clone();
            }
            if check.limits.is_empty() {
                check.limits.push(
                    "Only the listed probes and their recorded samples were evaluated.".to_string(),
                );
            }
            check.confidence = match (check.evidence.len(), check.status) {
                (0, _) => Confidence::Low,
                (_, Status::Skip | Status::Inconclusive) => Confidence::Low,
                (1, _) => Confidence::Moderate,
                (_, _) => Confidence::High,
            };
        }
    }

    pub fn validate_evidence(&self) -> Result<(), String> {
        for check in &self.checks {
            if check.claim.trim().is_empty() {
                return Err(format!("check {} has an empty claim", check.id));
            }
            if check.limits.is_empty() {
                return Err(format!("check {} has no limits", check.id));
            }
            for evidence in &check.evidence {
                let (source, probe) = evidence.split_once(':').ok_or_else(|| {
                    format!("check {} evidence {evidence} lacks a source", check.id)
                })?;
                if source.is_empty() || probe.is_empty() {
                    return Err(format!(
                        "check {} evidence {evidence} is malformed",
                        check.id
                    ));
                }
            }
            if let Some(probe_id) = &check.probe_id {
                if !check.evidence.iter().any(|item| item == probe_id) {
                    return Err(format!(
                        "check {} probe_id {probe_id} is absent from evidence",
                        check.id
                    ));
                }
            } else if check.status != Status::Skip && !check.evidence.is_empty() {
                return Err(format!(
                    "check {} has evidence but no primary probe_id",
                    check.id
                ));
            }
        }
        Ok(())
    }

    pub fn emit(&self, format: OutputFormat) -> u8 {
        match format {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
                );
            }
            OutputFormat::Markdown => self.emit_markdown(),
            OutputFormat::Summary => self.emit_summary(),
        }
        match self.status {
            Status::Fail | Status::Warn => 2,
            Status::Pass => 0,
            Status::Skip | Status::Inconclusive => 3,
        }
    }

    fn emit_markdown(&self) {
        println!("# PathTrial Network Diagnosis");
        println!();
        println!("- Scenario: `{}`", self.scenario);
        if let Some(target) = &self.target {
            println!("- Target: `{target}`");
        }
        println!("- Overall: **{}**", self.status.label());
        println!();
        for check in &self.checks {
            println!("## {}: {}", check.name, check.status.label());
            println!();
            println!("{}", check.summary);
            if !check.evidence.is_empty() {
                println!();
                println!("Evidence: {}", check.evidence.join(", "));
            }
            print_list("Observed", &check.observed);
            print_list("Possible", &check.possible);
            print_list("Not established", &check.not_established);
            print_list("Next checks", &check.next_checks);
            println!();
        }
        print_list("Limits", &self.limitations);
    }

    fn emit_summary(&self) {
        println!(
            "PathTrial {}  diagnose --scenario {}",
            self.tool_version, self.scenario
        );
        if let Some(target) = &self.target {
            println!("target: {target}");
        }
        for check in &self.checks {
            println!(
                "{:<18} {:<14} {}",
                check.name,
                check.status.label(),
                check.summary
            );
            if !check.evidence.is_empty() {
                println!("  evidence: {}", check.evidence.join(", "));
            }
            for item in &check.possible {
                println!("  possible: {item}");
            }
            for item in &check.next_checks {
                println!("  next: {item}");
            }
            for item in &check.not_established {
                println!("  not established: {item}");
            }
        }
        for item in &self.limitations {
            println!("limit: {item}");
        }
        println!("overall: {}", self.status.label());
    }
}

pub fn run(args: &DiagnoseArgs) -> Result<u8, String> {
    args.validate()?;
    let started_at = now_rfc3339();
    let deadline = Instant::now() + std::time::Duration::from_secs(args.max_seconds);
    let mut report = DiagnoseReport::new(args, started_at);

    let outcome = match args.scenario {
        DiagnoseScenario::Web => run_web(args, &mut report, deadline),
        DiagnoseScenario::Vps => run_vps(args, &mut report, deadline),
        DiagnoseScenario::Latency => run_latency(args, &mut report, deadline),
        DiagnoseScenario::Proxy => run_proxy(args, &mut report, deadline),
        DiagnoseScenario::Local => run_local(&mut report),
        DiagnoseScenario::Dns => run_dns(args, &mut report, deadline),
        DiagnoseScenario::Tcp => run_scan_scenario(args, &mut report, deadline, "tcp", false),
        DiagnoseScenario::Tls => run_scan_scenario(args, &mut report, deadline, "web", true),
        DiagnoseScenario::Http => run_http(args, &mut report, deadline),
        DiagnoseScenario::DualStack => {
            if args.connect_ipv4.is_some() || args.connect_ipv6.is_some() {
                run_dual_stack_scans(args, &mut report, deadline)
            } else {
                let result = run_scan_scenario(args, &mut report, deadline, "tcp", false);
                add_dual_stack_check(&mut report);
                result
            }
        }
        DiagnoseScenario::UdpQuic => run_udp_quic(args, &mut report, deadline),
        DiagnoseScenario::VpsUnreachable => run_vps_unreachable(args, &mut report, deadline),
        DiagnoseScenario::ProxySplit => run_proxy_split(args, &mut report, deadline),
        DiagnoseScenario::Http3Fallback => run_http3_fallback(args, &mut report, deadline),
    };
    if let Err(error) = outcome {
        if !is_budget_error(&error) {
            return Err(error);
        }
        report.checks.push(budget_check(&error));
        report.limitations.push(
            "The wall-clock budget ended before every stage returned evidence; unfinished checks are not successful results."
                .to_string(),
        );
    }

    Ok(report.finalize(args.redact_ips).emit(args.format))
}

fn run_web(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    run_scan_scenario(args, report, deadline, "web", true)?;
    if Instant::now() < deadline {
        run_http(args, report, deadline)?;
    } else {
        report.checks.push(timeout_check("http"));
    }
    Ok(())
}

fn run_vps(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    run_scan_scenario(args, report, deadline, "tcp", false)?;
    if Instant::now() < deadline {
        run_ping(args, report, deadline)?;
    } else {
        report.checks.push(timeout_check("icmp"));
    }
    if Instant::now() < deadline {
        let trace = run_json(
            &[
                "trace".to_string(),
                target(args).to_string(),
                "--max-hops".to_string(),
                "15".to_string(),
                "--timeout-ms".to_string(),
                remaining_ms(deadline)
                    .min(args.timeout_ms.saturating_mul(10))
                    .to_string(),
                "--format".to_string(),
                "json".to_string(),
            ],
            deadline,
        )?;
        add_report_check(report, "trace", "Route path", &trace, "trace");
    }
    Ok(())
}

fn run_vps_unreachable(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    run_vps(args, report, deadline)?;
    let tcp = report
        .checks
        .iter()
        .find(|check| check.id == "scan-tcp_tls")
        .map(|check| (check.status, check.evidence.clone()));
    let icmp = report
        .checks
        .iter()
        .find(|check| check.id == "icmp")
        .map(|check| (check.status, check.evidence.clone()));
    let trace = report
        .checks
        .iter()
        .find(|check| check.id == "trace")
        .map(|check| (check.status, check.evidence.clone()));
    let mut evidence = Vec::new();
    for item in [&tcp, &icmp, &trace].into_iter().flatten() {
        evidence.extend(item.1.clone());
    }
    let (status, claim) = match (&tcp, &icmp) {
        (Some((Status::Pass, _)), _) => (
            Status::Pass,
            "The configured VPS TCP port accepted a connection.".to_string(),
        ),
        (Some((Status::Fail, _)), Some((Status::Pass, _))) => (
            Status::Fail,
            "The host answered ICMP, but the configured TCP port failed.".to_string(),
        ),
        (Some((Status::Fail, _)), _) => (
            Status::Inconclusive,
            "ICMP and TCP did not establish whether the VPS or only its service path is unavailable."
                .to_string(),
        ),
        _ => (
            Status::Inconclusive,
            "The scenario did not collect a complete TCP reachability result.".to_string(),
        ),
    };
    report.checks.push(DiagnoseCheck {
        id: "vps-reachability".to_string(),
        name: "VPS reachability".to_string(),
        status,
        summary: claim.clone(),
        claim,
        evidence,
        probe_id: None,
        observed: Vec::new(),
        possible: if status == Status::Fail {
            vec![
                "The host may be reachable while the selected service is stopped or filtered."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
        not_established: vec![
            "ICMP filtering and TCP service state are separate observations.".to_string(),
            "The exact failing network device is not established.".to_string(),
        ],
        confidence: Confidence::Moderate,
        limits: vec!["Only the configured TCP port and ICMP behavior were measured.".to_string()],
        next_checks: if status == Status::Fail {
            vec![
                "Confirm the service listener and provider firewall for the selected port."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
    });
    Ok(())
}

fn run_latency(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    run_scan_scenario(args, report, deadline, "tcp", false)?;
    add_latency_stats(args, report);
    if Instant::now() < deadline {
        run_ping(args, report, deadline)?;
    } else {
        report.checks.push(timeout_check("icmp"));
    }
    Ok(())
}

fn run_proxy(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    let url = scenario_url(args);
    let proxy = args.proxy.as_deref().unwrap_or_default();
    let mut command = vec![
        "proxy".to_string(),
        url,
        "--proxy".to_string(),
        proxy.to_string(),
        "--compare-direct".to_string(),
        "--rounds".to_string(),
        args.rounds.to_string(),
        "--timeout-ms".to_string(),
        args.timeout_ms.to_string(),
        "--max-seconds".to_string(),
        remaining_seconds(deadline).to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if let Some(target_ip) = &args.target_ip {
        command.push("--target-ip".to_string());
        command.push(target_ip.clone());
    }
    append_common_target_options(args, &mut command);
    let result = run_json(&command, deadline)?;
    add_report_check(report, "proxy", "Proxy comparison", &result, "proxy");
    if let Some(check) = report.checks.last_mut() {
        if check.status.is_problem() {
            check.next_checks.push(
                "Compare proxy endpoint reachability, authentication requirements and the direct path before changing proxy settings."
                    .to_string(),
            );
            check
                .not_established
                .push("The exact proxy or upstream fault is not established.".to_string());
        }
    }
    Ok(())
}

fn run_proxy_split(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    run_proxy(args, report, deadline)?;
    let Some(source) = report
        .sources
        .iter()
        .find(|source| source.name == "proxy")
        .map(|source| &source.report)
    else {
        return Ok(());
    };
    let comparison = source
        .get("probes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|probe| match probe.get("detail") {
            Some(detail)
                if detail.get("type").and_then(Value::as_str) == Some("path_comparison") =>
            {
                Some(detail)
            }
            _ => None,
        });
    let mut evidence = source
        .get("probes")
        .and_then(Value::as_array)
        .map(|probes| {
            probes
                .iter()
                .filter_map(|probe| probe.get("id").and_then(Value::as_str))
                .map(|id| format!("proxy:{id}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let Some(detail) = comparison else {
        report.checks.push(DiagnoseCheck {
            id: "proxy-split".to_string(),
            name: "Direct / proxy split".to_string(),
            status: Status::Inconclusive,
            summary: "No direct-versus-proxy comparison record was produced.".to_string(),
            claim: "A path split cannot be determined without both direct and proxied samples."
                .to_string(),
            evidence,
            probe_id: None,
            observed: Vec::new(),
            possible: Vec::new(),
            not_established: vec!["No comparison sample exists for at least one path.".to_string()],
            confidence: Confidence::Low,
            limits: vec!["Only the proxy command's recorded probes were inspected.".to_string()],
            next_checks: vec![
                "Run with a reachable target and authorized proxy endpoint.".to_string()
            ],
        });
        return Ok(());
    };
    let direct_success = detail
        .get("direct_success")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let direct_total = detail
        .get("direct_total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let proxy_success = detail
        .get("proxy_success")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let proxy_total = detail
        .get("proxy_total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let direct_rate = ratio(direct_success, direct_total);
    let proxy_rate = ratio(proxy_success, proxy_total);
    let (status, claim) = if direct_total == 0 || proxy_total == 0 {
        (
            Status::Inconclusive,
            "Direct and proxy samples were not both available.".to_string(),
        )
    } else if (direct_rate - proxy_rate).abs() < 0.25 {
        (
            Status::Pass,
            "Direct and proxy paths showed similar request success.".to_string(),
        )
    } else {
        (
            Status::Fail,
            format!(
                "Direct success {direct_success}/{direct_total} diverged from proxy success {proxy_success}/{proxy_total}."
            ),
        )
    };
    report.checks.push(DiagnoseCheck {
        id: "proxy-split".to_string(),
        name: "Direct / proxy split".to_string(),
        status,
        summary: claim.clone(),
        claim,
        evidence: std::mem::take(&mut evidence),
        probe_id: None,
        observed: vec![format!(
            "direct={direct_success}/{direct_total} proxy={proxy_success}/{proxy_total}"
        )],
        possible: if status == Status::Fail {
            vec![
                "DNS, egress, proxy authentication or upstream policy may differ between paths."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
        not_established: vec![
            "A split does not identify the responsible proxy or network device.".to_string(),
        ],
        confidence: if status == Status::Fail {
            Confidence::Moderate
        } else {
            Confidence::Low
        },
        limits: vec![
            "Direct and proxied requests can use different DNS and destination addresses."
                .to_string(),
        ],
        next_checks: if status == Status::Fail {
            vec![
                "Compare proxy endpoint reachability and authentication with the direct path."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
    });
    Ok(())
}

fn ratio(success: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        success as f64 / total as f64
    }
}

fn run_local(report: &mut DiagnoseReport) -> Result<(), String> {
    let mut recorder = Recorder::new();
    let system_probe = system::collect(&mut recorder, None);
    let interfaces = &system_probe.environment.interfaces;
    let links: Vec<LocalLinkInfo> = crate::platform::local_links(interfaces);
    let probes = recorder.into_probes();

    let interface_status = if interfaces.is_empty() {
        Status::Inconclusive
    } else {
        Status::Pass
    };
    report.checks.push(DiagnoseCheck {
        id: "local-interfaces".to_string(),
        name: "Interfaces".to_string(),
        status: interface_status,
        summary: format!(
            "{} interface(s), IPv4 local={}, IPv6 local={}",
            interfaces.len(),
            system_probe.environment.ipv4_local,
            system_probe.environment.ipv6_local
        ),
        claim: String::new(),
        evidence: local_evidence(&system_probe.probe_ids),
        probe_id: None,
        observed: interfaces
            .iter()
            .map(|interface| {
                format!(
                    "{} up={} ipv4={} ipv6={}",
                    interface.name,
                    interface.up,
                    interface.ipv4.len(),
                    interface.ipv6.len()
                )
            })
            .collect(),
        possible: Vec::new(),
        not_established: vec!["Interface presence does not prove upstream ISP health.".to_string()],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: vec![
            "If no interface is up, inspect physical link, Wi-Fi association or VM networking."
                .to_string(),
        ],
    });

    let route_ok = system_probe.environment.default_route_v4.is_some()
        || system_probe.environment.default_route_v6.is_some();
    report.checks.push(DiagnoseCheck {
        id: "local-default-route".to_string(),
        name: "Default route".to_string(),
        status: if route_ok { Status::Pass } else { Status::Warn },
        summary: if route_ok {
            "At least one default route is present.".to_string()
        } else {
            "No IPv4 or IPv6 default route was reported.".to_string()
        },
        claim: String::new(),
        evidence: local_evidence(
            &system_probe
                .probe_ids
                .iter()
                .filter(|id| id.starts_with("route_"))
                .cloned()
                .collect::<Vec<_>>(),
        ),
        probe_id: None,
        observed: vec![format!(
            "IPv4 default route present={}, IPv6 default route present={}",
            system_probe.environment.default_route_v4.is_some(),
            system_probe.environment.default_route_v6.is_some()
        )],
        possible: if route_ok {
            Vec::new()
        } else {
            vec!["Local link, DHCP or router configuration may be incomplete.".to_string()]
        },
        not_established: vec![
            "A missing route does not identify which local device or service failed.".to_string(),
        ],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: if route_ok {
            Vec::new()
        } else {
            vec!["Check the link state and router DHCP service from the OS UI.".to_string()]
        },
    });

    let wifi: Vec<&LocalLinkInfo> = links.iter().filter(|link| link.is_wifi).collect();
    let wifi_status = if wifi.is_empty() {
        Status::Skip
    } else if wifi
        .iter()
        .any(|link| link.ssid.is_some() || link.signal_dbm.is_some())
    {
        Status::Pass
    } else {
        Status::Inconclusive
    };
    report.checks.push(DiagnoseCheck {
        id: "local-wifi".to_string(),
        name: "Wi-Fi".to_string(),
        status: wifi_status,
        summary: if wifi.is_empty() {
            "No Wi-Fi interface was identified.".to_string()
        } else {
            wifi.iter()
                .map(|link| {
                    format!(
                        "{} ssid={} signal={} tx_rate={}",
                        link.interface,
                        link.ssid.as_deref().unwrap_or("unknown"),
                        link.signal_dbm
                            .map(|value| format!("{value} dBm"))
                            .unwrap_or_else(|| "unknown".to_string()),
                        link.tx_rate_mbps
                            .map(|value| format!("{value} Mbps"))
                            .unwrap_or_else(|| "unknown".to_string())
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        },
        claim: String::new(),
        evidence: local_evidence(&system_probe.probe_ids),
        probe_id: None,
        observed: wifi.iter().flat_map(|link| link.notes.clone()).collect(),
        possible: Vec::new(),
        not_established: vec![
            "Wi-Fi interference or router radio faults cannot be established from one snapshot."
                .to_string(),
        ],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: if wifi_status == Status::Pass {
            Vec::new()
        } else {
            vec![
                "Compare Wi-Fi and wired paths, or inspect the router's wireless status."
                    .to_string(),
            ]
        },
    });

    let dhcp: Vec<&str> = links
        .iter()
        .filter_map(|link| link.dhcp.as_deref())
        .collect();
    report.checks.push(DiagnoseCheck {
        id: "local-dhcp".to_string(),
        name: "DHCP / lease".to_string(),
        status: if dhcp.is_empty() {
            Status::Skip
        } else {
            Status::Pass
        },
        summary: if dhcp.is_empty() {
            "DHCP lease details were unavailable or not applicable.".to_string()
        } else {
            dhcp.join("; ")
        },
        claim: String::new(),
        evidence: local_evidence(&system_probe.probe_ids),
        probe_id: None,
        observed: links.iter().flat_map(|link| link.notes.clone()).collect(),
        possible: Vec::new(),
        not_established: vec![
            "DHCP server failure or lease expiry cannot be proven from missing read-only data."
                .to_string(),
        ],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: if dhcp.is_empty() {
            vec!["Inspect the router lease table or run the OS network diagnostic UI.".to_string()]
        } else {
            Vec::new()
        },
    });

    let local_value = json!({
        "environment": system_probe.environment,
        "links": links,
        "probes": probes,
    });
    report.add_source("local", local_value);
    report.limitations.push(
        "Local checks are read-only snapshots. DHCP, Wi-Fi and router faults require corroborating evidence."
            .to_string(),
    );
    Ok(())
}

fn local_evidence(ids: &[String]) -> Vec<String> {
    ids.iter().map(|id| format!("local:{id}")).collect()
}

fn run_dns(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    let mut command = vec![
        "dns".to_string(),
        target(args).to_string(),
        "--timeout-ms".to_string(),
        remaining_ms(deadline).min(args.timeout_ms).to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    for server in &args.servers {
        command.push("--server".to_string());
        command.push(server.clone());
    }
    let result = run_json(&command, deadline)?;
    add_report_check(report, "dns", "DNS", &result, "dns");
    classify_dns(report, &result);
    Ok(())
}

fn run_http(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    let mut command = vec![
        "http".to_string(),
        scenario_url(args),
        "--timeout-ms".to_string(),
        remaining_ms(deadline).min(args.timeout_ms).to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    append_common_target_options(args, &mut command);
    if let Some(host) = &args.http_host {
        command.push("--host".to_string());
        command.push(host.clone());
    }
    if let Some(target_ip) = &args.target_ip {
        command.push("--target-ip".to_string());
        command.push(target_ip.clone());
    }
    let result = run_json(&command, deadline)?;
    add_report_check(report, "http", "HTTP", &result, "http");
    classify_http(report, &result);
    Ok(())
}

fn run_http3_fallback(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    if Instant::now() < deadline {
        let mut command = vec![
            "http3".to_string(),
            scenario_url(args),
            "--family".to_string(),
            family_name(args.family).to_string(),
            "--timeout-ms".to_string(),
            args.timeout_ms.to_string(),
            "--max-seconds".to_string(),
            remaining_seconds(deadline).to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        append_common_target_options(args, &mut command);
        let result = run_json(&command, deadline)?;
        add_report_check(report, "http3", "HTTP/3", &result, "http3");
    } else {
        report.checks.push(timeout_check("http3"));
    }
    if Instant::now() < deadline {
        run_http(args, report, deadline)?;
    } else {
        report.checks.push(timeout_check("http"));
    }
    let http3 = report
        .checks
        .iter()
        .find(|check| check.id == "http3")
        .map(|check| (check.status, check.evidence.clone()));
    let https = report
        .checks
        .iter()
        .find(|check| check.id == "http")
        .map(|check| (check.status, check.evidence.clone()));
    let mut evidence = Vec::new();
    for item in [&http3, &https].into_iter().flatten() {
        evidence.extend(item.1.clone());
    }
    let (status, claim) = match (&http3, &https) {
        (Some((Status::Pass, _)), _) => (
            Status::Pass,
            "HTTP/3 completed without requiring the HTTPS fallback.".to_string(),
        ),
        (_, Some((Status::Pass, _))) => (
            Status::Warn,
            "HTTP/3 was unavailable, but HTTPS over TCP completed successfully.".to_string(),
        ),
        (Some((Status::Fail, _)), Some((Status::Fail, _))) => (
            Status::Fail,
            "Both HTTP/3 and the HTTPS fallback failed.".to_string(),
        ),
        _ => (
            Status::Inconclusive,
            "The scenario did not establish both HTTP/3 and HTTPS outcomes.".to_string(),
        ),
    };
    report.checks.push(DiagnoseCheck {
        id: "http3-fallback".to_string(),
        name: "HTTP/3 fallback".to_string(),
        status,
        summary: claim.clone(),
        claim,
        evidence,
        probe_id: None,
        observed: Vec::new(),
        possible: if status == Status::Warn {
            vec![
                "UDP/443 may be blocked, filtered, or the endpoint may not advertise h3."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
        not_established: vec![
            "HTTP/3 failure does not identify UDP blocking on a specific device.".to_string(),
        ],
        confidence: Confidence::Moderate,
        limits: vec!["The HTTPS fallback uses TCP and can follow a different path.".to_string()],
        next_checks: if status == Status::Warn {
            vec!["Compare UDP and TCP paths only when the endpoint advertises HTTP/3.".to_string()]
        } else {
            Vec::new()
        },
    });
    Ok(())
}

fn run_udp_quic(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    let port = args.effective_port();
    if Instant::now() < deadline {
        let udp = run_json(
            &[
                "udp".to_string(),
                "--target".to_string(),
                socket_target(args),
                "--rounds".to_string(),
                args.rounds.to_string(),
                "--timeout-ms".to_string(),
                args.timeout_ms.to_string(),
                "--max-seconds".to_string(),
                remaining_seconds(deadline).to_string(),
                "--format".to_string(),
                "json".to_string(),
            ],
            deadline,
        )?;
        add_report_check(report, "udp", "UDP Echo", &udp, "udp");
        if let Some(check) = report.checks.last_mut() {
            check.not_established.push(
                "Echo timeout does not prove UDP blocking; the target may not run an Echo service."
                    .to_string(),
            );
        }
    }
    if Instant::now() < deadline {
        let mut quic_args = vec![
            "quic".to_string(),
            target(args).to_string(),
            "--port".to_string(),
            port.to_string(),
            "--family".to_string(),
            family_name(args.family).to_string(),
            "--timeout-ms".to_string(),
            args.timeout_ms.to_string(),
            "--max-seconds".to_string(),
            remaining_seconds(deadline).to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        append_common_target_options(args, &mut quic_args);
        let quic = run_json(&quic_args, deadline)?;
        add_report_check(report, "quic", "QUIC", &quic, "quic");
    }
    if Instant::now() < deadline {
        let mut http3_args = vec![
            "http3".to_string(),
            scenario_url(args),
            "--family".to_string(),
            family_name(args.family).to_string(),
            "--timeout-ms".to_string(),
            args.timeout_ms.to_string(),
            "--max-seconds".to_string(),
            remaining_seconds(deadline).to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        append_common_target_options(args, &mut http3_args);
        let http3 = run_json(&http3_args, deadline)?;
        add_report_check(report, "http3", "HTTP/3", &http3, "http3");
    }
    Ok(())
}

fn run_scan_scenario(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
    profile: &str,
    tls: bool,
) -> Result<(), String> {
    let mut command = vec![
        "scan".to_string(),
        target(args).to_string(),
        "--profile".to_string(),
        profile.to_string(),
        "--port".to_string(),
        args.effective_port().to_string(),
        "--rounds".to_string(),
        args.rounds.to_string(),
        "--timeout-ms".to_string(),
        args.timeout_ms.to_string(),
        "--max-seconds".to_string(),
        remaining_seconds(deadline).to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--no-files".to_string(),
    ];
    if !tls {
        command.push("--no-tls".to_string());
    }
    append_common_target_options(args, &mut command);
    let result = run_json(&command, deadline)?;
    add_scan_checks(report, &result, tls);
    Ok(())
}

fn run_ping(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    let result = run_json(
        &[
            "ping".to_string(),
            target(args).to_string(),
            "--count".to_string(),
            args.rounds.to_string(),
            "--timeout-ms".to_string(),
            remaining_ms(deadline)
                .min(args.timeout_ms.saturating_mul(4))
                .to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
        deadline,
    )?;
    add_report_check(report, "ping", "ICMP latency and loss", &result, "ping");
    classify_icmp(report, &result);
    Ok(())
}

fn run_json(args: &[String], deadline: Instant) -> Result<Value, String> {
    if Instant::now() >= deadline {
        return Err("diagnosis budget exhausted before child probe started".to_string());
    }
    let exe =
        std::env::current_exe().map_err(|error| format!("locate PathTrial executable: {error}"))?;
    let mut command = Command::new(exe);
    command.args(args);
    let (status, stdout, stderr) =
        crate::process::run_limited(command, deadline, MAX_CHILD_OUTPUT, None)
            .map_err(|error| error.message())?;
    let text = String::from_utf8_lossy(&stdout);
    match serde_json::from_str(&text) {
        Ok(value) => Ok(value),
        Err(error) => Err(format!(
            "{} did not return JSON ({error}); status={}; stderr={}",
            args.first().map(String::as_str).unwrap_or("command"),
            status,
            String::from_utf8_lossy(&stderr).trim()
        )),
    }
}

fn add_scan_checks(report: &mut DiagnoseReport, scan: &Value, tls: bool) {
    report.add_source("scan", scan.clone());
    if let Some(stages) = scan.get("stages").and_then(Value::as_array) {
        for stage in stages {
            let id = stage.get("id").and_then(Value::as_str).unwrap_or("stage");
            if id == "report" {
                continue;
            }
            let status = status_from_value(stage.get("status"));
            let name = match id {
                "system" => "System",
                "dns" => "DNS",
                "tcp_tls" => {
                    if tls {
                        "TCP and TLS"
                    } else {
                        "TCP"
                    }
                }
                "compare" => "IPv4 / IPv6",
                other => other,
            };
            let summary = stage
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let evidence = stage
                .get("evidence")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|item| format!("scan:{item}"))
                        .collect()
                })
                .unwrap_or_default();
            let mut check = DiagnoseCheck {
                id: format!("scan-{id}"),
                name: name.to_string(),
                status,
                summary,
                claim: String::new(),
                evidence,
                probe_id: None,
                observed: Vec::new(),
                possible: Vec::new(),
                not_established: Vec::new(),
                confidence: Confidence::Low,
                limits: Vec::new(),
                next_checks: Vec::new(),
            };
            add_generic_guidance(&mut check);
            report.checks.push(check);
        }
    }
    if tls {
        classify_scan_tls(report, scan);
    }
}

fn classify_scan_tls(report: &mut DiagnoseReport, scan: &Value) {
    let Some(check) = report
        .checks
        .iter_mut()
        .find(|check| check.id == "scan-tcp_tls")
    else {
        return;
    };
    let mut total = 0usize;
    let mut transport_ok = 0usize;
    let mut verified = 0usize;
    for probe in scan
        .get("probes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if probe.get("kind").and_then(Value::as_str) != Some("tls") {
            continue;
        }
        let Some(detail) = probe.get("detail") else {
            continue;
        };
        total += 1;
        if detail
            .get("transport_ok")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            transport_ok += 1;
        }
        if detail.get("verification").and_then(Value::as_str) == Some("verified") {
            verified += 1;
        }
    }
    if total == 0 {
        return;
    }
    check.observed.push(format!(
        "TLS transport {transport_ok}/{total}, verified {verified}/{total}"
    ));
    if transport_ok == 0 {
        check.status = Status::Fail;
        check
            .possible
            .push("TLS may be absent, blocked, or the endpoint may not speak TLS.".to_string());
        check.next_checks.push(
            "Confirm the service port and TLS configuration before disabling certificate checks."
                .to_string(),
        );
    } else if verified < transport_ok {
        check.status = Status::Warn;
        check.possible.push(
            "The TLS transport worked but certificate or hostname verification failed.".to_string(),
        );
    }
    check.not_established.push(
        "A TLS failure does not by itself identify a middlebox or certificate owner.".to_string(),
    );
}

fn add_report_check(
    report: &mut DiagnoseReport,
    source: &str,
    name: &str,
    value: &Value,
    prefix: &str,
) {
    report.add_source(source, value.clone());
    let status = status_from_value(value.get("status"));
    let summary = value
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let evidence = value
        .get("probes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|probe| probe.get("id").and_then(Value::as_str))
                .map(|id| format!("{prefix}:{id}"))
                .collect()
        })
        .unwrap_or_default();
    let mut check = DiagnoseCheck {
        id: source.to_string(),
        name: name.to_string(),
        status,
        summary,
        claim: String::new(),
        evidence,
        probe_id: None,
        observed: Vec::new(),
        possible: Vec::new(),
        not_established: Vec::new(),
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: Vec::new(),
    };
    add_generic_guidance(&mut check);
    report.checks.push(check);
}

fn add_latency_stats(args: &DiagnoseArgs, report: &mut DiagnoseReport) {
    let Some(scan) = report
        .sources
        .iter()
        .find(|source| source.name == "scan")
        .map(|source| &source.report)
    else {
        return;
    };
    let mut samples: Vec<f64> = Vec::new();
    let mut total = 0usize;
    let mut success = 0usize;
    if let Some(summaries) = scan.get("summaries").and_then(Value::as_array) {
        for summary in summaries {
            total += summary
                .get("tcp_total")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            success += summary
                .get("tcp_success")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            if let Some(values) = summary.get("samples_ms").and_then(Value::as_array) {
                samples.extend(values.iter().filter_map(Value::as_f64));
            }
        }
    }
    if samples.is_empty() {
        let status = if total > 0 && success == 0 {
            Status::Fail
        } else if success < total {
            Status::Warn
        } else {
            Status::Inconclusive
        };
        report.checks.push(DiagnoseCheck {
            id: "latency-stats".to_string(),
            name: "Latency statistics".to_string(),
            status,
            summary: "No successful TCP timing samples were available.".to_string(),
            claim: String::new(),
            evidence: Vec::new(),
            probe_id: None,
            observed: vec![format!("TCP success {success}/{total}")],
            possible: Vec::new(),
            not_established: vec![
                "P50 and P95 are unavailable without successful samples.".to_string()
            ],
            confidence: Confidence::Low,
            limits: Vec::new(),
            next_checks: vec!["Confirm TCP reachability before interpreting latency.".to_string()],
        });
        return;
    }
    let p50 = median(&samples);
    let p95 = percentile(&samples, 0.95);
    let max = samples.iter().copied().reduce(f64::max);
    let average = mean(&samples);
    let status = latency_verdict(
        max,
        success,
        total,
        args.latency_warn_ms,
        args.latency_fail_ms,
    );
    let mut check = DiagnoseCheck {
        id: "latency-stats".to_string(),
        name: "Latency statistics".to_string(),
        status,
        summary: format!(
            "TCP {success}/{total}; avg={} ms p50={} ms p95={} ms max={} ms",
            fmt_opt(average),
            fmt_opt(p50),
            fmt_opt(p95),
            fmt_opt(max)
        ),
        claim: String::new(),
        evidence: Vec::new(),
        probe_id: None,
        observed: vec![format!("{} successful timing samples", samples.len())],
        possible: Vec::new(),
        not_established: Vec::new(),
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: Vec::new(),
    };
    if samples.len() < crate::util::MIN_SAMPLES_FOR_PERCENTILE {
        check.not_established.push(format!(
            "Only {} samples are available; P95 is descriptive and not a stable population estimate.",
            samples.len()
        ));
    }
    if status.is_problem() {
        check.next_checks.push(
            "Repeat the test over time and compare against another network path before attributing the latency to an ISP or remote host."
                .to_string(),
        );
    }
    report.checks.push(check);
}

/// Combine latency thresholds with connection outcomes so a high-severity
/// latency failure is never downgraded by a lower-severity partial failure.
fn latency_verdict(
    max_ms: Option<f64>,
    success: usize,
    total: usize,
    warn_ms: Option<f64>,
    fail_ms: Option<f64>,
) -> Status {
    if total > 0 && success == 0 {
        return Status::Fail;
    }
    let mut status = Status::Pass;
    if fail_ms.is_some_and(|threshold| max_ms.is_some_and(|value| value >= threshold)) {
        status = Status::Fail;
    } else if warn_ms.is_some_and(|threshold| max_ms.is_some_and(|value| value >= threshold)) {
        status = Status::Warn;
    }
    worst_status(
        status,
        if success < total {
            Status::Warn
        } else {
            Status::Pass
        },
    )
}

fn classify_icmp(report: &mut DiagnoseReport, value: &Value) {
    let Some(check) = report.checks.last_mut() else {
        return;
    };
    for probe in value
        .get("probes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(detail) = probe.get("detail") {
            if detail.get("type").and_then(Value::as_str) != Some("icmp") {
                continue;
            }
            if let Some(loss) = detail.get("loss_pct").and_then(Value::as_f64) {
                check.observed.push(format!("ICMP packet loss {loss:.1}%"));
                if loss > 0.0 {
                    check.status = Status::Warn;
                    check.not_established.push(
                        "ICMP loss is not equivalent to loss on TCP or application traffic."
                            .to_string(),
                    );
                }
            }
            if let Some(jitter) = detail.get("jitter").and_then(Value::as_f64) {
                check.observed.push(format!("ICMP jitter {jitter:.1} ms"));
            }
        }
    }
}

fn classify_dns(report: &mut DiagnoseReport, value: &Value) {
    let Some(check) = report.checks.last_mut() else {
        return;
    };
    let mut rcodes = Vec::new();
    let mut errors = Vec::new();
    for probe in value
        .get("probes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(detail) = probe.get("detail") else {
            continue;
        };
        if detail.get("type").and_then(Value::as_str) != Some("dns_query") {
            continue;
        }
        if let Some(rcode) = detail.get("rcode").and_then(Value::as_str) {
            rcodes.push(rcode.to_string());
        }
        if let Some(error) = detail.get("error").and_then(Value::as_str) {
            errors.push(error.to_string());
        }
    }
    if !rcodes.is_empty() {
        check
            .observed
            .push(format!("DNS rcodes: {}", rcodes.join(", ")));
    }
    if !errors.is_empty() {
        check
            .observed
            .push(format!("DNS errors: {}", errors.join("; ")));
    }
    if rcodes.iter().any(|rcode| rcode == "NXDOMAIN") {
        check.status = Status::Fail;
        check
            .possible
            .push("The queried name may not exist in one or more resolver scopes.".to_string());
        check.next_checks.push(
            "Verify the spelling and authoritative zone before considering DNS filtering."
                .to_string(),
        );
    }
    if rcodes.iter().any(|rcode| rcode == "SERVFAIL") {
        check.status = Status::Warn;
        check
            .possible
            .push("A resolver or upstream authoritative service may be failing.".to_string());
    }
    check
        .not_established
        .push("Resolver differences alone do not prove DNS poisoning or hijacking.".to_string());
}

fn classify_http(report: &mut DiagnoseReport, value: &Value) {
    let Some(check) = report.checks.last_mut() else {
        return;
    };
    for probe in value
        .get("probes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(detail) = probe.get("detail") else {
            continue;
        };
        if detail.get("type").and_then(Value::as_str) != Some("http") {
            continue;
        }
        let Some(status) = detail.get("status").and_then(Value::as_u64) else {
            continue;
        };
        check.observed.push(format!("HTTP {status}"));
        match status {
            200..=399 => {}
            401 | 403 => {
                check.status = Status::Warn;
                check
                    .possible
                    .push("Authentication or authorization may be required.".to_string());
                check
                    .next_checks
                    .push("Check credentials, access policy and reverse-proxy rules.".to_string());
            }
            404 => {
                check.status = Status::Warn;
                check.possible.push(
                    "The requested resource may not exist or the route may be wrong.".to_string(),
                );
            }
            429 => {
                check.status = Status::Warn;
                check
                    .possible
                    .push("The service may be rate limiting this client.".to_string());
            }
            502..=504 => {
                check.status = Status::Fail;
                check.possible.push(
                    "A reverse proxy or upstream service may be unavailable or timing out."
                        .to_string(),
                );
                check.next_checks.push(
                    "Inspect reverse-proxy and upstream-service logs; PathTrial cannot identify the exact upstream fault."
                        .to_string(),
                );
            }
            500..=599 => {
                check.status = Status::Warn;
                check
                    .possible
                    .push("The application returned a server-side error.".to_string());
            }
            _ => {}
        }
    }
    check.not_established.push(
        "An HTTP status does not by itself identify the failing server component.".to_string(),
    );
}

fn add_dual_stack_check(report: &mut DiagnoseReport) {
    let Some(scan) = report
        .sources
        .iter()
        .find(|source| source.name == "scan")
        .map(|source| &source.report)
    else {
        return;
    };
    let mut observed = Vec::new();
    let mut evidence = Vec::new();
    if let Some(summaries) = scan.get("summaries").and_then(Value::as_array) {
        for summary in summaries {
            let family = summary
                .get("family")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let total = summary
                .get("tcp_total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let success = summary
                .get("tcp_success")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let median = summary
                .get("tcp_median_ms")
                .and_then(Value::as_f64)
                .map(|value| format!("{value:.1} ms"))
                .unwrap_or_else(|| "unavailable".to_string());
            observed.push(format!("{family}: {success}/{total}, median {median}"));
            if let Some(ids) = summary.get("probe_ids").and_then(Value::as_array) {
                evidence.extend(
                    ids.iter()
                        .filter_map(Value::as_str)
                        .map(|id| format!("scan:{id}")),
                );
            }
        }
    }
    let status = if observed.len() < 2 {
        Status::Skip
    } else {
        Status::Pass
    };
    report.checks.push(DiagnoseCheck {
        id: "dual-stack".to_string(),
        name: "IPv4 / IPv6 comparison".to_string(),
        status,
        summary: if status == Status::Skip {
            "Only one address family was available; no direct comparison was made.".to_string()
        } else {
            "Both address families were measured under the same command budget.".to_string()
        },
        claim: String::new(),
        evidence,
        probe_id: None,
        observed,
        possible: Vec::new(),
        not_established: vec![
            "A difference between families does not prove the cause without route and server-side evidence."
                .to_string(),
        ],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: Vec::new(),
    });
}

fn run_dual_stack_scans(
    args: &DiagnoseArgs,
    report: &mut DiagnoseReport,
    deadline: Instant,
) -> Result<(), String> {
    let port = args.effective_port();
    let mut observed = Vec::new();
    let mut evidence = Vec::new();
    let mut successful_families = 0usize;
    let mut failed_families = 0usize;
    for (source, family, address) in [
        ("scan-v4", "ipv4", args.connect_ipv4.as_deref()),
        ("scan-v6", "ipv6", args.connect_ipv6.as_deref()),
    ] {
        let Some(address) = address else {
            observed.push(format!("{family}: SKIP (no authorized address)"));
            continue;
        };
        if Instant::now() >= deadline {
            return Err("diagnosis budget exhausted during dual-stack comparison".to_string());
        }
        let mut command = vec![
            "scan".to_string(),
            address.to_string(),
            "--profile".to_string(),
            "tcp".to_string(),
            "--port".to_string(),
            port.to_string(),
            "--rounds".to_string(),
            args.rounds.to_string(),
            "--timeout-ms".to_string(),
            args.timeout_ms.to_string(),
            "--max-seconds".to_string(),
            remaining_seconds(deadline).to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--no-files".to_string(),
            "--no-tls".to_string(),
        ];
        if let Some(interface) = &args.bind_interface {
            command.push("--bind-interface".to_string());
            command.push(interface.clone());
        }
        let scan = run_json(&command, deadline)?;
        report.add_source(source, scan.clone());
        if let Some(summaries) = scan.get("summaries").and_then(Value::as_array) {
            for summary in summaries {
                let total = summary
                    .get("tcp_total")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let success = summary
                    .get("tcp_success")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let median = summary
                    .get("tcp_median_ms")
                    .and_then(Value::as_f64)
                    .map(|value| format!("{value:.1} ms"))
                    .unwrap_or_else(|| "unavailable".to_string());
                observed.push(format!("{family}: {success}/{total}, median {median}"));
                if success == total && total > 0 {
                    successful_families += 1;
                } else {
                    failed_families += 1;
                }
                if let Some(ids) = summary.get("probe_ids").and_then(Value::as_array) {
                    evidence.extend(
                        ids.iter()
                            .filter_map(Value::as_str)
                            .map(|id| format!("{source}:{id}")),
                    );
                }
            }
        }
    }
    let measured_families = successful_families + failed_families;
    let status = if measured_families == 0 {
        Status::Inconclusive
    } else if failed_families > 0 {
        Status::Warn
    } else if measured_families == 1 {
        Status::Skip
    } else {
        Status::Pass
    };
    report.checks.push(DiagnoseCheck {
        id: "dual-stack".to_string(),
        name: "IPv4 / IPv6 comparison".to_string(),
        status,
        summary: if measured_families < 2 {
            "Only one address family had an authorized address; the other family was SKIP."
                .to_string()
        } else {
            "IPv4 and IPv6 used separately authorized literal addresses.".to_string()
        },
        claim: String::new(),
        evidence,
        probe_id: None,
        observed,
        possible: if failed_families > 0 {
            vec!["One family may be unreachable on this path.".to_string()]
        } else {
            Vec::new()
        },
        not_established: vec![
            "A difference between families does not prove the cause without route and server-side evidence."
                .to_string(),
        ],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: Vec::new(),
    });
    Ok(())
}

fn timeout_check(name: &str) -> DiagnoseCheck {
    DiagnoseCheck {
        id: format!("{name}-budget"),
        name: name.to_string(),
        status: Status::Skip,
        summary: "The scenario budget was exhausted before this check started.".to_string(),
        claim: String::new(),
        evidence: Vec::new(),
        probe_id: None,
        observed: Vec::new(),
        possible: Vec::new(),
        not_established: vec!["No measurement was collected for this check.".to_string()],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: vec!["Increase --max-seconds or reduce --rounds.".to_string()],
    }
}

fn is_budget_error(error: &str) -> bool {
    error.starts_with("timeout:") || error.contains("budget exhausted")
}

fn budget_check(error: &str) -> DiagnoseCheck {
    DiagnoseCheck {
        id: "scenario-budget".to_string(),
        name: "Scenario budget".to_string(),
        status: Status::Inconclusive,
        summary: "The wall-clock budget ended before this stage returned evidence.".to_string(),
        claim: String::new(),
        evidence: Vec::new(),
        probe_id: None,
        observed: vec![format!("stopped with: {error}")],
        possible: Vec::new(),
        not_established: vec![
            "Checks that did not finish carry no success or failure conclusion.".to_string(),
        ],
        confidence: Confidence::Low,
        limits: Vec::new(),
        next_checks: vec![
            "Increase --max-seconds, reduce --rounds, or lower --timeout-ms and re-run."
                .to_string(),
        ],
    }
}

fn add_generic_guidance(check: &mut DiagnoseCheck) {
    if check.status.is_problem() {
        check.next_checks.push(
            "Re-run the failed stage with a controlled target before changing system settings."
                .to_string(),
        );
        check
            .not_established
            .push("The available probes do not establish a unique root cause.".to_string());
    }
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

fn status_from_value(value: Option<&Value>) -> Status {
    match value.and_then(Value::as_str) {
        Some("PASS") => Status::Pass,
        Some("WARN") => Status::Warn,
        Some("FAIL") => Status::Fail,
        Some("INCONCLUSIVE") => Status::Inconclusive,
        _ => Status::Skip,
    }
}

fn target(args: &DiagnoseArgs) -> &str {
    args.target.as_deref().unwrap_or_default()
}

fn scenario_url(args: &DiagnoseArgs) -> String {
    if let Some(url) = &args.url {
        return url.clone();
    }
    let host = target(args);
    let authority = if host.starts_with('[') || !host.contains(':') {
        host.to_string()
    } else {
        format!("[{host}]")
    };
    format!("https://{authority}:{}/", args.effective_port())
}

fn socket_target(args: &DiagnoseArgs) -> String {
    let host = target(args);
    let host = if host.starts_with('[') || !host.contains(':') {
        host.to_string()
    } else {
        format!("[{host}]")
    };
    format!("{host}:{}", args.effective_port())
}

fn append_common_target_options(args: &DiagnoseArgs, command: &mut Vec<String>) {
    if let Some(interface) = &args.bind_interface {
        command.push("--bind-interface".to_string());
        command.push(interface.clone());
    }
    if let Some(sni) = &args.sni {
        command.push("--sni".to_string());
        command.push(sni.clone());
    }
}

fn family_name(family: crate::cli::AddressFamily) -> &'static str {
    match family {
        crate::cli::AddressFamily::Auto => "auto",
        crate::cli::AddressFamily::Ipv4 => "ipv4",
        crate::cli::AddressFamily::Ipv6 => "ipv6",
    }
}

fn remaining_seconds(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_secs()
        .max(5)
}

fn remaining_ms(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .max(100) as u64
}

fn fmt_opt(value: Option<f64>) -> String {
    value
        .map(|number| format!("{number:.2}"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn mask_strings(values: &mut [String], masker: &mut IpMasker) {
    for value in values {
        *value = masker.mask_text(value);
    }
}

fn redact_value(value: &mut Value, masker: &mut IpMasker) {
    match value {
        Value::String(text) => *text = masker.mask_text(text),
        Value::Array(items) => {
            for item in items {
                redact_value(item, masker);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                redact_value(item, masker);
            }
        }
        _ => {}
    }
}

fn print_list(title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    println!();
    println!("{title}:");
    for item in items {
        println!("- {item}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_status_preserves_failure_precedence() {
        assert_eq!(worst_status(Status::Pass, Status::Warn), Status::Warn);
        assert_eq!(worst_status(Status::Warn, Status::Fail), Status::Fail);
        assert_eq!(
            worst_status(Status::Skip, Status::Inconclusive),
            Status::Inconclusive
        );
    }

    #[test]
    fn scenario_url_brackets_ipv6() {
        let args = DiagnoseArgs {
            scenario: DiagnoseScenario::Http,
            target: Some("::1".to_string()),
            port: Some(8443),
            url: None,
            proxy: None,
            servers: Vec::new(),
            rounds: 1,
            timeout_ms: 1000,
            max_seconds: 10,
            family: crate::cli::AddressFamily::Auto,
            redact_ips: false,
            bind_interface: None,
            sni: None,
            requested_host: None,
            http_host: None,
            target_ip: None,
            connect_ipv4: None,
            connect_ipv6: None,
            latency_warn_ms: None,
            latency_fail_ms: None,
            format: OutputFormat::Summary,
        };
        assert_eq!(scenario_url(&args), "https://[::1]:8443/");
    }

    #[test]
    fn latency_verdict_keeps_fail_above_partial_warning() {
        assert_eq!(
            latency_verdict(Some(900.0), 9, 10, Some(200.0), Some(800.0)),
            Status::Fail
        );
        assert_eq!(
            latency_verdict(Some(900.0), 10, 10, Some(200.0), Some(800.0)),
            Status::Fail
        );
    }

    #[test]
    fn latency_verdict_warns_only_above_warn_threshold() {
        assert_eq!(
            latency_verdict(Some(250.0), 10, 10, Some(200.0), Some(800.0)),
            Status::Warn
        );
        assert_eq!(
            latency_verdict(Some(250.0), 9, 10, Some(200.0), Some(800.0)),
            Status::Warn
        );
    }

    #[test]
    fn latency_verdict_passes_when_all_samples_succeed() {
        assert_eq!(
            latency_verdict(Some(120.0), 10, 10, Some(200.0), Some(800.0)),
            Status::Pass
        );
        assert_eq!(
            latency_verdict(Some(120.0), 10, 10, None, None),
            Status::Pass
        );
    }

    #[test]
    fn latency_verdict_fails_without_successful_samples() {
        assert_eq!(
            latency_verdict(None, 0, 10, Some(200.0), Some(800.0)),
            Status::Fail
        );
    }

    #[test]
    fn only_budget_related_child_errors_become_incomplete_reports() {
        assert!(is_budget_error("timeout:child process"));
        assert!(is_budget_error(
            "diagnosis budget exhausted before child probe started"
        ));
        assert!(!is_budget_error("command did not return JSON"));
        assert!(!is_budget_error("start child process: no such file"));
        assert_eq!(
            budget_check("timeout:child process").status,
            Status::Inconclusive
        );
    }

    #[test]
    fn probe_detail_shape_is_publicly_serializable() {
        let detail = crate::models::ProbeDetail::TcpConnect {
            connect_ms: Some(1.0),
            error: None,
        };
        assert!(serde_json::to_value(detail).is_ok());
    }
}
