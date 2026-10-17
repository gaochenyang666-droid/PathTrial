//! Orchestration of the fixed five-stage scan.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::analysis;
use crate::cli::{OutputFormat, ScanArgs};
use crate::models::{
    Configuration, Family, FamilySummary, Probe, ProbeDetail, ProbeOutcome, Redaction, Report,
    Stage, Status, Target, SCHEMA_VERSION,
};
use crate::net::AddressScope;
use crate::platform;
use crate::probes::{dns, system, tcp, tls, Recorder};
use crate::report;
use crate::util::{as_literal_ip, mean, median, now_rfc3339};

/// Result of a completed scan.
pub struct ScanOutcome {
    /// Kept for callers that want the structured result in addition to the
    /// process exit code.
    #[allow(dead_code)]
    pub report: Report,
    pub worst_status: Status,
}

struct AddressSet {
    v4: Vec<IpAddr>,
    v6: Vec<IpAddr>,
}

fn parse_resolved(values: &[String]) -> Vec<IpAddr> {
    values
        .iter()
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .collect()
}

/// Run every stage in order and return the finished report.
pub fn run(args: &ScanArgs) -> Result<ScanOutcome, String> {
    let started_at = now_rfc3339();
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    let port = args.effective_port();
    let tls_enabled = args.tls_enabled();
    let rounds = args.effective_rounds();
    let timeout = Duration::from_millis(args.timeout_ms);
    let interval = Duration::from_millis(args.interval_ms);
    let literal = as_literal_ip(&args.target);

    let mut recorder = Recorder::new();
    let mut limitations: Vec<String> = Vec::new();
    let interface = args.bind_interface.as_deref();
    if rounds < args.rounds {
        limitations.push(format!(
            "请求的 {} 轮因 --max-seconds 预算被下调为 {} 轮",
            args.rounds, rounds
        ));
    }

    // ---- Stage 1: environment -------------------------------------------
    let stage1_start = now_rfc3339();
    let system_probe = system::collect(&mut recorder, None);
    let mut environment = system_probe.environment;
    let mut stage1_evidence = system_probe.probe_ids;
    let stage1_end = now_rfc3339();

    let interfaces_ok = !environment.interfaces.is_empty();
    let has_route =
        environment.default_route_v4.is_some() || environment.default_route_v6.is_some();
    let (system_status, system_summary, system_reason) = if !interfaces_ok {
        (
            Status::Inconclusive,
            "网卡信息未能读取".to_string(),
            Some("接口枚举失败，后续判断可能受影响".to_string()),
        )
    } else if !has_route {
        (Status::Warn, "网卡存在但未取得默认路由".to_string(), None)
    } else {
        (
            Status::Pass,
            format!(
                "{} 个网卡，IPv4 本地支持 {}，IPv6 本地支持 {}",
                environment.interfaces.len(),
                environment.ipv4_local,
                environment.ipv6_local
            ),
            None,
        )
    };

    // ---- Stage 2: DNS ----------------------------------------------------
    let stage2_start = now_rfc3339();
    let mut dns_outcome = dns::DnsOutcome::default();
    let mut addresses = AddressSet {
        v4: Vec::new(),
        v6: Vec::new(),
    };
    let (dns_status, dns_summary, dns_reason) = if let Some(ip) = literal {
        if ip.is_ipv4() {
            addresses.v4.push(ip);
        } else {
            addresses.v6.push(ip);
        }
        (
            Status::Skip,
            "目标是字面 IP 地址，无需 DNS 解析".to_string(),
            Some("字面 IP 跳过 DNS 验证".to_string()),
        )
    } else {
        dns_outcome = dns::resolve(
            &args.target,
            &mut recorder,
            timeout.min(Duration::from_secs(5)),
        );
        addresses.v4 = parse_resolved(&dns_outcome.addresses_v4);
        addresses.v6 = parse_resolved(&dns_outcome.addresses_v6);
        if addresses.v4.is_empty() && addresses.v6.is_empty() {
            (
                Status::Fail,
                "没有获得可用于连接的地址".to_string(),
                Some(
                    dns_outcome
                        .failures
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "解析失败".to_string()),
                ),
            )
        } else if addresses.v4.is_empty() || addresses.v6.is_empty() {
            let missing = if addresses.v4.is_empty() { "A" } else { "AAAA" };
            (
                Status::Pass,
                format!("已解析，缺少 {missing} 记录（不视为故障）"),
                None,
            )
        } else {
            (
                Status::Pass,
                format!(
                    "A 解析 {} 个地址，AAAA 解析 {} 个地址",
                    addresses.v4.len(),
                    addresses.v6.len()
                ),
                None,
            )
        }
    };
    let stage2_end = now_rfc3339();
    let used_addresses: Vec<IpAddr> = [addresses.v4.first(), addresses.v6.first()]
        .into_iter()
        .flatten()
        .copied()
        .collect();
    let scopes: Vec<AddressScope> = used_addresses
        .iter()
        .map(|ip| crate::net::scope_of(*ip))
        .collect();
    // Only the benchmark range from a hostname is treated as a local rewrite.
    // A private address is a legitimate target (LAN device, split DNS, hosts).
    let fake_ip = literal.is_none() && scopes.contains(&AddressScope::Benchmark);
    let target_scope = scopes.first().copied();
    if fake_ip {
        limitations.push(
            "域名解析到 198.18/15 基准网段，可能是本地代理的 Fake-IP 改写；本次 TCP 数据不能代表公网路径"
                .to_string(),
        );
    }

    // Target route is only knowable after address selection.
    let primary_ip = addresses
        .v4
        .first()
        .copied()
        .or_else(|| addresses.v6.first().copied());
    if let Some(ip) = primary_ip {
        let family = if ip.is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        };
        if let Some(route) = platform::route_to(ip) {
            environment.target_route = Some(route.clone());
            let id = recorder.next_id("route_target");
            recorder.record(Probe {
                id: id.clone(),
                kind: crate::models::ProbeKind::Route,
                outcome: ProbeOutcome::Ok,
                family: Some(family),
                target: Some(ip.to_string()),
                port: None,
                started_at: now_rfc3339(),
                duration_ms: None,
                detail: ProbeDetail::Route {
                    family: if family == Family::Ipv4 {
                        "ipv4"
                    } else {
                        "ipv6"
                    }
                    .to_string(),
                    purpose: "target".to_string(),
                    gateway: route.gateway.clone(),
                    interface: route.interface.clone(),
                    raw_error: None,
                },
            });
            stage1_evidence.push(id);
        } else {
            limitations.push("未能取得目标路由，出口网卡无法确认".to_string());
        }
    }

    // ---- Stage 3: TCP and TLS -------------------------------------------
    let stage3_start = now_rfc3339();
    let mut per_family: BTreeMap<Family, Vec<tcp::TcpSample>> = BTreeMap::new();
    let mut tls_attempts: BTreeMap<Family, Vec<tls::TlsAttempt>> = BTreeMap::new();
    let mut family_window: BTreeMap<Family, (String, String)> = BTreeMap::new();

    if !addresses.v4.is_empty() {
        per_family.insert(Family::Ipv4, Vec::new());
    }
    if !addresses.v6.is_empty() {
        per_family.insert(Family::Ipv6, Vec::new());
    }

    if per_family.is_empty() {
        limitations.push("没有可用地址，TCP 与 TLS 阶段未执行".to_string());
    } else {
        let mut budget_hit = false;
        'rounds: for _ in 0..rounds {
            for family in [Family::Ipv4, Family::Ipv6] {
                let Some(probe_ids) = per_family.get_mut(&family) else {
                    continue;
                };
                let list = if family == Family::Ipv4 {
                    &addresses.v4
                } else {
                    &addresses.v6
                };
                let Some(address) = list.first().copied() else {
                    continue;
                };
                if Instant::now() >= deadline {
                    budget_hit = true;
                    break 'rounds;
                }
                let sample =
                    tcp::probe_once(&mut recorder, family, address, port, timeout, interface);
                let entry = family_window
                    .entry(family)
                    .or_insert_with(|| (sample.probe_id.clone(), sample.probe_id.clone()));
                entry.1 = sample.probe_id.clone();
                probe_ids.push(sample);
                if !interval.is_zero() {
                    std::thread::sleep(interval.min(Duration::from_millis(500)));
                }
            }
        }
        if budget_hit {
            limitations.push("TCP 轮次因总时长预算提前结束".to_string());
        }

        if tls_enabled {
            let sni = args.sni.clone().unwrap_or_else(|| args.target.clone());
            for family in [Family::Ipv4, Family::Ipv6] {
                let Some(samples) = per_family.get(&family) else {
                    continue;
                };
                if samples.iter().all(|sample| !sample.ok) {
                    continue;
                }
                let list = if family == Family::Ipv4 {
                    &addresses.v4
                } else {
                    &addresses.v6
                };
                let Some(address) = list.first().copied() else {
                    continue;
                };
                let attempts = tls_attempts.entry(family).or_default();
                for _ in 0..2 {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let attempt = tls::probe(
                        &mut recorder,
                        family,
                        address,
                        port,
                        &sni,
                        timeout,
                        false,
                        interface,
                    );
                    let needs_insecure_retry =
                        matches!(attempt.error, Some(crate::models::NetError::Certificate));
                    attempts.push(attempt);
                    if needs_insecure_retry && args.allow_insecure_tls {
                        let retry = tls::probe(
                            &mut recorder,
                            family,
                            address,
                            port,
                            &sni,
                            timeout,
                            true,
                            interface,
                        );
                        attempts.push(retry);
                    }
                }
            }
        }
    }
    let stage3_end = now_rfc3339();
    for attempts in tls_attempts.values() {
        for attempt in attempts {
            if let Some(note) = &attempt.note {
                limitations.push(format!("{}: {}", attempt.probe_id, note));
            }
        }
    }

    // ---- Stage 4: comparison --------------------------------------------
    let stage4_start = now_rfc3339();
    let summaries = build_summaries(&per_family, &tls_attempts, &family_window, &addresses);
    let compare_status = if fake_ip {
        Status::Skip
    } else if summaries.len() == 2 {
        Status::Pass
    } else {
        Status::Skip
    };
    let compare_reason = if fake_ip {
        Some("目标地址为本地改写或私有地址，双栈对照不适用于公网诊断".to_string())
    } else if summaries.len() == 2 {
        None
    } else {
        Some("仅一种地址族参与测量，无法做双栈对照".to_string())
    };
    let compare_summary = if fake_ip {
        "未进行公网双栈对照".to_string()
    } else if summaries.len() == 2 {
        let mut parts = Vec::new();
        for summary in &summaries {
            parts.push(format!(
                "{} {}/{}",
                summary.family.label(),
                summary.tcp_success,
                summary.tcp_total
            ));
        }
        parts.join("，")
    } else {
        "未进行双栈对照".to_string()
    };
    let stage4_end = now_rfc3339();

    // ---- Stage 5: report ------------------------------------------------
    let stage5_start = now_rfc3339();
    let (tcp_status, tcp_reason) = if fake_ip {
        (
            Status::Inconclusive,
            Some("目标地址为本地改写或私有地址，无法据此判断公网路径".to_string()),
        )
    } else {
        (summarize_tcp_status(&summaries), None)
    };
    let tcp_summary = if summaries.is_empty() {
        "没有执行 TCP 探测".to_string()
    } else {
        summaries
            .iter()
            .map(|summary| {
                format!(
                    "{} {}/{}",
                    summary.family.label(),
                    summary.tcp_success,
                    summary.tcp_total
                )
            })
            .collect::<Vec<_>>()
            .join("，")
    };
    let tls_summary = if !tls_enabled {
        "配置未启用 TLS".to_string()
    } else {
        let total: usize = tls_attempts.values().map(|list| list.len()).sum();
        let ok: usize = tls_attempts
            .values()
            .flat_map(|list| list.iter())
            .filter(|attempt| attempt.transport_ok)
            .count();
        format!("TLS 传输握手 {ok}/{total}")
    };

    let stages = vec![
        Stage {
            id: "system".to_string(),
            name: "系统环境".to_string(),
            status: system_status,
            summary: system_summary,
            reason: system_reason,
            evidence: stage1_evidence,
            started_at: stage1_start,
            finished_at: stage1_end,
        },
        Stage {
            id: "dns".to_string(),
            name: "DNS".to_string(),
            status: dns_status,
            summary: dns_summary,
            reason: dns_reason,
            evidence: dns_outcome.probe_ids.clone(),
            started_at: stage2_start,
            finished_at: stage2_end,
        },
        Stage {
            id: "tcp_tls".to_string(),
            name: "TCP 与 TLS".to_string(),
            status: tcp_status,
            summary: format!("{tcp_summary}；{tls_summary}"),
            reason: tcp_reason,
            evidence: summaries
                .iter()
                .flat_map(|summary| summary.probe_ids.clone())
                .collect(),
            started_at: stage3_start,
            finished_at: stage3_end,
        },
        Stage {
            id: "compare".to_string(),
            name: "双栈对照".to_string(),
            status: compare_status,
            summary: compare_summary,
            reason: compare_reason,
            evidence: summaries
                .iter()
                .flat_map(|summary| summary.probe_ids.clone())
                .collect(),
            started_at: stage4_start,
            finished_at: stage4_end,
        },
    ];

    let probes = recorder.into_probes();
    let context = analysis::AnalysisContext {
        probes: &probes,
        summaries: &summaries,
        stages: &stages,
        tls_enabled,
        fake_ip_suspected: fake_ip,
        target_scope,
        literal_target: literal.is_some(),
        suppress_comparison: fake_ip,
    };
    let analysis = analysis::analyze(&context);
    limitations.extend(analysis.limitations);

    let mut stages = stages;
    stages.push(Stage {
        id: "report".to_string(),
        name: "报告".to_string(),
        status: Status::Pass,
        summary: format!(
            "{} 条结论，{} 条建议",
            analysis.findings.len(),
            analysis.recommendations.len()
        ),
        reason: None,
        evidence: Vec::new(),
        started_at: stage5_start,
        finished_at: now_rfc3339(),
    });

    let report = Report {
        schema_version: SCHEMA_VERSION.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        run_id: crate::util::new_run_id(),
        started_at,
        finished_at: now_rfc3339(),
        target: Target {
            input: args.target.clone(),
            host: if literal.is_some() {
                None
            } else {
                Some(args.target.clone())
            },
            port,
            profile: args.profile.as_str().to_string(),
            literal_ip: literal.is_some(),
        },
        configuration: Configuration {
            rounds,
            timeout_ms: args.timeout_ms,
            interval_ms: args.interval_ms,
            max_total_seconds: args.max_seconds,
            connect_budget: rounds * summaries.len().max(1),
            tls_enabled,
            allow_insecure_tls: args.allow_insecure_tls,
            output_format: args.format.as_str().to_string(),
            redact_ips: args.redact_ips,
            bind_interface: args.bind_interface.clone(),
        },
        environment,
        stages,
        probes,
        summaries,
        findings: analysis.findings,
        recommendations: analysis.recommendations,
        limitations,
        redaction: Redaction {
            applied: args.redact_ips,
            ips_masked: 0,
            notes: Vec::new(),
        },
    };

    emit(&report, args)?;
    let worst = report.worst_status();
    Ok(ScanOutcome {
        report,
        worst_status: worst,
    })
}

fn summarize_tcp_status(summaries: &[FamilySummary]) -> Status {
    if summaries.is_empty() {
        return Status::Skip;
    }
    let mut status = Status::Pass;
    for summary in summaries {
        if summary.tcp_total == 0 {
            continue;
        }
        if summary.tcp_success == 0 {
            let refused_only = summary.error_classes.len() == 1
                && summary.error_classes.contains_key("connection_refused");
            status = if refused_only {
                // The port answered with a refusal: the connection attempt
                // failed, even though something replied.
                Status::Fail
            } else if summary.tcp_total < analysis::MIN_SAMPLES_FOR_VERDICT {
                Status::Inconclusive
            } else {
                Status::Fail
            };
        } else if status == Status::Pass
            && (summary.tcp_success < summary.tcp_total
                || summary.tcp_mean_ms.unwrap_or(0.0) >= analysis::LATENCY_WARN_MS)
        {
            status = Status::Warn;
        }
    }
    status
}

fn build_summaries(
    per_family: &BTreeMap<Family, Vec<tcp::TcpSample>>,
    tls_attempts: &BTreeMap<Family, Vec<tls::TlsAttempt>>,
    windows: &BTreeMap<Family, (String, String)>,
    addresses: &AddressSet,
) -> Vec<FamilySummary> {
    let mut summaries = Vec::new();
    for family in [Family::Ipv4, Family::Ipv6] {
        let Some(samples) = per_family.get(&family) else {
            continue;
        };
        if samples.is_empty() {
            continue;
        }
        let list = if family == Family::Ipv4 {
            &addresses.v4
        } else {
            &addresses.v6
        };
        let address = list
            .first()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let total = samples.len();
        let success = samples.iter().filter(|sample| sample.ok).count();
        let mut durations: Vec<f64> = samples
            .iter()
            .filter_map(|sample| sample.connect_ms)
            .collect();
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mut errors: BTreeMap<String, usize> = BTreeMap::new();
        for sample in samples {
            if let Some(error) = &sample.error {
                *errors.entry(error.label()).or_insert(0) += 1;
            }
        }
        let tls_list = tls_attempts.get(&family).cloned().unwrap_or_default();
        let tls_total = tls_list.len();
        let tls_transport_ok = tls_list
            .iter()
            .filter(|attempt| attempt.transport_ok)
            .count();
        let tls_verified_ok = tls_list
            .iter()
            .filter(|attempt| matches!(attempt.verification, crate::models::Verification::Verified))
            .count();
        let (window_start, window_end) = windows
            .get(&family)
            .cloned()
            .unwrap_or_else(|| (now_rfc3339(), now_rfc3339()));
        summaries.push(FamilySummary {
            family,
            address,
            tcp_total: total,
            tcp_success: success,
            tcp_success_rate: if total == 0 {
                0.0
            } else {
                success as f64 / total as f64
            },
            tcp_mean_ms: mean(&durations),
            tcp_median_ms: median(&durations),
            tcp_max_ms: durations.last().copied(),
            error_classes: errors,
            samples_ms: durations,
            aggregate_only: false,
            tls_total,
            tls_transport_ok,
            tls_verified_ok,
            window_started_at: window_start,
            window_finished_at: window_end,
            probe_ids: samples
                .iter()
                .map(|sample| sample.probe_id.clone())
                .collect(),
        });
    }
    summaries
}

/// Render to the requested stream and persist report files.
fn emit(report: &Report, args: &ScanArgs) -> Result<(), String> {
    let redact = args.redact_ips;
    let rendered = report::render(report, redact)?;
    match args.format {
        OutputFormat::Json => println!("{}", rendered.json),
        OutputFormat::Markdown => println!("{}", rendered.markdown),
        OutputFormat::Summary => {
            print!("{}", rendered.terminal);
            if !report.summaries.is_empty() {
                println!("{}", "-".repeat(64));
            }
        }
    }
    if !args.no_files {
        let (json_path, markdown_path) = if let Some(prefix) = &args.out {
            if prefix.with_extension("json").exists() || prefix.with_extension("md").exists() {
                eprintln!(
                    "note: overwriting existing report files at {}",
                    prefix.display()
                );
            }
            report::write_at(prefix, &rendered)?
        } else {
            let dir: PathBuf = args
                .out_dir
                .clone()
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let stem = format!("pathtrial-report-{}", report.run_id);
            report::write_files(&dir, &stem, &rendered)?
        };
        match args.format {
            OutputFormat::Summary => {
                println!("Report: {}", json_path.display());
                println!("        {}", markdown_path.display());
            }
            _ => {
                eprintln!(
                    "report written to {} and {}",
                    json_path.display(),
                    markdown_path.display()
                );
            }
        }
    }
    Ok(())
}
