//! Deterministic analysis rules.
//!
//! Every rule is a pure function of recorded data. Rules produce findings that
//! cite probe IDs, state what is *not* established, and carry explicit limits.
//! Thresholds are constants here so the behaviour is auditable and testable.

use crate::models::{
    Confidence, FamilySummary, Finding, Probe, ProbeDetail, Recommendation, Severity, Stage,
    Status, UdpObservation,
};
use crate::net::AddressScope;
use crate::util::MIN_SAMPLES_FOR_PERCENTILE;

/// Latency thresholds in milliseconds for TCP connect time.
pub const LATENCY_WARN_MS: f64 = 500.0;
/// Above this the path is effectively unusable for interactive work.
pub const LATENCY_SEVERE_MS: f64 = 1500.0;
/// Minimum samples before a failure pattern is treated as more than anecdote.
pub const MIN_SAMPLES_FOR_VERDICT: usize = 5;
/// Success-rate gap (percentage points as a fraction) that counts as a family delta.
pub const FAMILY_SUCCESS_GAP: f64 = 0.20;
/// Median latency ratio that counts as a meaningful family difference.
pub const FAMILY_LATENCY_RATIO: f64 = 2.0;

pub struct Analysis {
    pub findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    pub limitations: Vec<String>,
}

/// Confidence is a deterministic bucket derived from sample size and whether
/// per-request data exists. It is not a statistical probability.
pub fn confidence_for(summary: &FamilySummary) -> Confidence {
    if summary.aggregate_only {
        return Confidence::Low;
    }
    if summary.tcp_total >= MIN_SAMPLES_FOR_PERCENTILE {
        Confidence::High
    } else if summary.tcp_total >= MIN_SAMPLES_FOR_VERDICT {
        Confidence::Moderate
    } else {
        Confidence::Low
    }
}

fn window_limit(summaries: &[FamilySummary]) -> String {
    match (summaries.first(), summaries.last()) {
        (Some(first), Some(last)) => format!(
            "结论仅适用于本次测试窗口（{} 至 {}）",
            first.window_started_at, last.window_finished_at
        ),
        _ => "结论仅适用于本次测试窗口".to_string(),
    }
}

fn sample_limit(summary: &FamilySummary) -> Option<String> {
    if summary.aggregate_only {
        Some(format!(
            "{} 的样本为汇总数据，没有保留逐次耗时，因此未计算中位数与 P95",
            summary.family.label()
        ))
    } else if summary.tcp_total < MIN_SAMPLES_FOR_PERCENTILE {
        Some(format!(
            "{} 样本量 {} 小于 {}，未计算 P95",
            summary.family.label(),
            summary.tcp_total,
            MIN_SAMPLES_FOR_PERCENTILE
        ))
    } else {
        None
    }
}

fn all_probe_ids(summary: &FamilySummary) -> Vec<String> {
    summary.probe_ids.clone()
}

#[allow(clippy::too_many_arguments)]
fn add_finding(
    findings: &mut Vec<Finding>,
    rule_id: &str,
    claim: String,
    severity: Severity,
    status: Status,
    evidence: Vec<String>,
    not_established: Vec<String>,
    confidence: Confidence,
    limits: Vec<String>,
) {
    let id = format!("F{:03}", findings.len() + 1);
    findings.push(Finding {
        id,
        rule_id: rule_id.to_string(),
        claim,
        severity,
        status,
        evidence,
        not_established,
        confidence,
        limits,
    });
}

/// Run all rules over the recorded data.
/// Everything the rules need. Passing a struct keeps the call sites readable
/// as more context is added.
pub struct AnalysisContext<'a> {
    pub probes: &'a [Probe],
    pub summaries: &'a [FamilySummary],
    pub stages: &'a [Stage],
    pub tls_enabled: bool,
    /// True when a hostname resolved into the 198.18/15 benchmark range, which
    /// local proxies commonly use for Fake-IP.
    pub fake_ip_suspected: bool,
    /// Scope of the address that was actually probed.
    pub target_scope: Option<AddressScope>,
    /// Whether the user supplied a literal IP instead of a hostname.
    pub literal_target: bool,
    /// Family comparison is meaningless when the addresses are local rewrites.
    pub suppress_comparison: bool,
}

fn scope_description(scope: AddressScope) -> &'static str {
    match scope {
        AddressScope::Public => "公网",
        AddressScope::Private => "私有",
        AddressScope::Shared => "运营商级 NAT",
        AddressScope::Loopback => "环回",
        AddressScope::LinkLocal => "链路本地",
        AddressScope::Benchmark => "基准测试/代理改写",
        AddressScope::Documentation => "文档示例",
        AddressScope::Unspecified => "未指定",
    }
}

pub fn analyze(ctx: &AnalysisContext<'_>) -> Analysis {
    let probes = ctx.probes;
    let summaries = ctx.summaries;
    let stages = ctx.stages;
    let tls_enabled = ctx.tls_enabled;
    let suppress_comparison = ctx.suppress_comparison;
    let mut findings: Vec<Finding> = Vec::new();
    let mut recommendations: Vec<Recommendation> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    limitations.push(window_limit(summaries));

    // ---- DNS rules -------------------------------------------------------
    let dns_probes: Vec<&Probe> = probes
        .iter()
        .filter(|probe| matches!(probe.detail, ProbeDetail::DnsQuery { .. }))
        .collect();
    let dns_stage = stages.iter().find(|stage| stage.id == "dns");
    if let Some(stage) = dns_stage {
        if stage.status == Status::Fail && !dns_probes.is_empty() {
            add_finding(
                &mut findings,
                "R001",
                "DNS 没有返回可用于连接的地址".to_string(),
                Severity::Fail,
                Status::Fail,
                dns_probes.iter().map(|probe| probe.id.clone()).collect(),
                vec![
                    "域名本身是否存在".to_string(),
                    "解析器是否被本地软件改写".to_string(),
                ],
                Confidence::Moderate,
                vec!["结论基于系统解析器的回答".to_string()],
            );
            recommendations.push(Recommendation {
                id: "S001".to_string(),
                action: "用浏览器或另一台设备确认域名解析结果".to_string(),
                rationale: "先区分域名问题与解析器问题".to_string(),
                evidence: dns_probes.iter().map(|probe| probe.id.clone()).collect(),
            });
        }
    }

    let fake_ip_probes: Vec<&Probe> = dns_probes
        .iter()
        .copied()
        .filter(|probe| {
            matches!(
                &probe.detail,
                ProbeDetail::DnsQuery {
                    fake_ip_suspected: true,
                    ..
                }
            )
        })
        .collect();
    if ctx.fake_ip_suspected || !fake_ip_probes.is_empty() {
        let mut evidence: Vec<String> = fake_ip_probes
            .iter()
            .map(|probe| probe.id.clone())
            .collect();
        if evidence.is_empty() {
            evidence = summaries
                .iter()
                .flat_map(|summary| summary.probe_ids.clone())
                .collect();
        }
        if !evidence.is_empty() {
            add_finding(
                &mut findings,
                "R002",
                "域名解析到 198.18/15 基准测试网段，疑似被本地代理改写（Fake-IP）".to_string(),
                Severity::Warn,
                Status::Warn,
                evidence.clone(),
                vec![
                    "改写来源是哪一个进程".to_string(),
                    "关闭本地代理后解析结果是否恢复".to_string(),
                ],
                Confidence::Moderate,
                vec!["检测依据仅为地址落入 198.18.0.0/15，这不构成改写的确证".to_string()],
            );
            recommendations.push(Recommendation {
                id: "S005".to_string(),
                action: "关闭本地代理后重测，或改用字面 IP 配合 --bind-interface 指定物理网卡"
                    .to_string(),
                rationale: "本地改写地址无法代表公网路径".to_string(),
                evidence,
            });
        } else {
            limitations.push("检测到疑似 Fake-IP 地址，但本次没有可用于引用的探测记录".to_string());
        }
    }

    // A non-public target is legitimate: a LAN device, an internal name, or a
    // hosts entry. Record what was measured without claiming anything about the
    // public internet.
    if !ctx.fake_ip_suspected {
        if let Some(scope) = ctx.target_scope {
            if !scope.is_public() {
                let evidence: Vec<String> = summaries
                    .iter()
                    .flat_map(|summary| summary.probe_ids.clone())
                    .collect();
                if !evidence.is_empty() {
                    add_finding(
                        &mut findings,
                        "R014",
                        format!(
                            "目标是{}地址（{}），本次结果描述的是本地或内网路径",
                            scope_description(scope),
                            scope.label()
                        ),
                        Severity::Info,
                        Status::Pass,
                        evidence,
                        vec!["公网路径是否正常".to_string()],
                        Confidence::Low,
                        vec![if ctx.literal_target {
                            "目标由用户以字面 IP 指定".to_string()
                        } else {
                            "目标由 DNS 解析得到，可能来自内网解析、hosts 文件或 Split DNS"
                                .to_string()
                        }],
                    );
                    limitations.push(format!(
                        "目标地址属于{}，结论不代表公网可达性",
                        scope_description(scope)
                    ));
                }
            }
        }
    }

    // ---- TCP rules -------------------------------------------------------
    // When a hostname resolved into the Fake-IP range, every downstream TCP/TLS
    // number describes the local proxy, not the target service. Interpreting
    // those numbers would produce confident but wrong claims, so the rules are
    // deliberately skipped and the raw data stays in the report.
    if ctx.fake_ip_suspected {
        limitations.push(
            "目标地址为本地改写时的 TCP/TLS 结论已被有意省略；原始探测数据仍保留，请关闭本地代理后重测"
                .to_string(),
        );
    }
    for summary in summaries.iter().filter(|_| !ctx.fake_ip_suspected) {
        let ids = all_probe_ids(summary);
        let confidence = confidence_for(summary);
        let limits: Vec<String> = sample_limit(summary).into_iter().collect();

        if summary.tcp_total == 0 {
            continue;
        }

        if summary.tcp_success == 0 {
            if summary.tcp_total < MIN_SAMPLES_FOR_VERDICT {
                add_finding(
                    &mut findings,
                    "R011",
                    format!(
                        "{} 仅有 {} 次连接尝试且全部失败，证据不足以判断故障是否持续",
                        summary.family.label(),
                        summary.tcp_total
                    ),
                    Severity::Warn,
                    Status::Inconclusive,
                    ids,
                    vec!["失败是偶发还是持续".to_string()],
                    Confidence::Low,
                    vec!["样本量低于判定阈值".to_string(), window_limit(summaries)],
                );
            } else {
                // A refusal proves the host answered: the path is fine and the
                // port is closed. The refusal itself is recorded, but the
                // requested port is not connectable, so this is a failed check.
                // PathTrial must not conclude that the remote host or its
                // service is healthy from a RST alone.
                let refused_only = summary.error_classes.len() == 1
                    && summary.error_classes.contains_key("connection_refused");
                if refused_only {
                    add_finding(
                        &mut findings,
                        "R015",
                        format!(
                            "{} 连接请求被明确拒绝（ECONNREFUSED，{}/{} 次），目标端口不可连接",
                            summary.family.label(),
                            summary.tcp_total,
                            summary.tcp_total
                        ),
                        Severity::Fail,
                        Status::Fail,
                        ids.clone(),
                        vec![
                            "拒绝响应由目标主机还是中间设备生成".to_string(),
                            "该端口是否本应开放".to_string(),
                            "远端服务本身的健康状态".to_string(),
                        ],
                        confidence,
                        limits.clone(),
                    );
                } else {
                    add_finding(
                        &mut findings,
                        "R004",
                        format!(
                            "{} TCP 连接全部失败（0/{}），错误类型：{}",
                            summary.family.label(),
                            summary.tcp_total,
                            summary
                                .error_classes
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        Severity::Fail,
                        Status::Fail,
                        ids,
                        vec![
                            "失败位于本机、运营商、服务端还是中间设备".to_string(),
                            "服务端是否在监听该端口".to_string(),
                            "是否存在按目的地进行的流量过滤".to_string(),
                        ],
                        confidence,
                        limits,
                    );
                    recommendations.push(Recommendation {
                        id: "S002".to_string(),
                        action: "在服务端确认服务在监听，并用另一条网络路径复测同一端口"
                            .to_string(),
                        rationale: "区分服务端问题、路径问题与过滤".to_string(),
                        evidence: vec![summary.probe_ids.first().cloned().unwrap_or_default()],
                    });
                }
            }
            continue;
        }

        if summary.tcp_success < summary.tcp_total {
            add_finding(
                &mut findings,
                "R005",
                format!(
                    "{} TCP 连接存在部分失败（{}/{}，成功率 {:.0}%）",
                    summary.family.label(),
                    summary.tcp_success,
                    summary.tcp_total,
                    summary.tcp_success_rate * 100.0
                ),
                Severity::Warn,
                Status::Warn,
                ids.clone(),
                vec!["丢失发生在哪一段路径".to_string()],
                confidence,
                limits.clone(),
            );
        }

        if let Some(mean_ms) = summary.tcp_mean_ms {
            if mean_ms >= LATENCY_WARN_MS {
                let severe = mean_ms >= LATENCY_SEVERE_MS;
                // Latency claims rest on successful samples, not on attempts.
                let latency_confidence = if summary.tcp_success >= MIN_SAMPLES_FOR_PERCENTILE {
                    Confidence::High
                } else if summary.tcp_success >= MIN_SAMPLES_FOR_VERDICT {
                    Confidence::Moderate
                } else {
                    Confidence::Low
                };
                let mut latency_limits = limits.clone();
                if summary.tcp_success < MIN_SAMPLES_FOR_VERDICT {
                    latency_limits
                        .push(format!("耗时结论仅基于 {} 个成功样本", summary.tcp_success));
                }
                add_finding(
                    &mut findings,
                    "R006",
                    format!(
                        "{} TCP 建连耗时偏高，平均 {:.0} 毫秒{}",
                        summary.family.label(),
                        mean_ms,
                        if severe {
                            "，已达到影响交互使用的程度"
                        } else {
                            ""
                        }
                    ),
                    Severity::Warn,
                    Status::Warn,
                    ids.clone(),
                    vec![
                        "高耗时的成因是排队、重传还是中间设备处理".to_string(),
                        "应用层在同样耗时下的成功率".to_string(),
                    ],
                    latency_confidence,
                    latency_limits,
                );
            }
        }
    }

    // ---- Family comparison ----------------------------------------------
    if summaries.len() == 2 && !suppress_comparison && !ctx.fake_ip_suspected {
        let (a, b) = (&summaries[0], &summaries[1]);
        if a.tcp_total > 0 && b.tcp_total > 0 {
            let gap = (a.tcp_success_rate - b.tcp_success_rate).abs();
            // Prefer medians when per-request samples exist, otherwise fall back
            // to the reported means and mark the finding as low confidence.
            let (left, right) = match (a.tcp_median_ms, b.tcp_median_ms) {
                (Some(left), Some(right)) => (Some(left), Some(right)),
                _ => (a.tcp_mean_ms, b.tcp_mean_ms),
            };
            let latency_ratio = match (left, right) {
                (Some(left), Some(right)) if left > 0.0 && right > 0.0 => {
                    Some((left / right).max(right / left))
                }
                _ => None,
            };
            let success_gap_hit = gap >= FAMILY_SUCCESS_GAP;
            let latency_hit = latency_ratio.is_some_and(|ratio| ratio >= FAMILY_LATENCY_RATIO)
                && a.tcp_success >= MIN_SAMPLES_FOR_VERDICT
                && b.tcp_success >= MIN_SAMPLES_FOR_VERDICT;

            if success_gap_hit || latency_hit {
                let better = if a.tcp_success_rate > b.tcp_success_rate
                    || (a.tcp_success_rate == b.tcp_success_rate
                        && a.tcp_median_ms.unwrap_or(f64::MAX)
                            < b.tcp_median_ms.unwrap_or(f64::MAX))
                {
                    a
                } else {
                    b
                };
                let worse = if std::ptr::eq(better, a) { b } else { a };
                let confidence = if a.aggregate_only || b.aggregate_only {
                    Confidence::Low
                } else if a.tcp_total >= MIN_SAMPLES_FOR_PERCENTILE
                    && b.tcp_total >= MIN_SAMPLES_FOR_PERCENTILE
                {
                    Confidence::High
                } else {
                    Confidence::Moderate
                };
                let mut evidence = a.probe_ids.clone();
                evidence.extend(b.probe_ids.clone());
                add_finding(
                    &mut findings,
                    "R007",
                    format!(
                        "{} 路径明显优于 {}（成功率 {}/{} 对 {}/{}，中位耗时 {} 对 {}）",
                        better.family.label(),
                        worse.family.label(),
                        better.tcp_success,
                        better.tcp_total,
                        worse.tcp_success,
                        worse.tcp_total,
                        better
                            .tcp_median_ms
                            .map(|value| format!("{value:.0} ms"))
                            .unwrap_or_else(|| "未知".to_string()),
                        worse
                            .tcp_median_ms
                            .map(|value| format!("{value:.0} ms"))
                            .unwrap_or_else(|| "未知".to_string())
                    ),
                    Severity::Warn,
                    Status::Warn,
                    evidence,
                    vec![
                        "具体丢包位置".to_string(),
                        "是否存在人为流量过滤".to_string(),
                        "UDP/QUIC 路径是否同样受影响".to_string(),
                    ],
                    confidence,
                    vec![
                        "两个地址族在同一轮窗口内交替测量".to_string(),
                        "该结论描述路径差异，不定位网元".to_string(),
                    ],
                );
                recommendations.push(Recommendation {
                    id: "S003".to_string(),
                    action: format!(
                        "让实际应用优先使用 {} 入口，并复测业务成功率",
                        better.family.label()
                    ),
                    rationale: "同窗口对照显示两个入口表现差异明显".to_string(),
                    evidence: vec![
                        better.probe_ids.first().cloned().unwrap_or_default(),
                        worse.probe_ids.first().cloned().unwrap_or_default(),
                    ],
                });
            }
        }
    }

    // ---- TLS rules -------------------------------------------------------
    // Counts come from the per-family summaries so aggregate fixtures and live
    // runs share one code path. Evidence prefers the TLS probes themselves.
    let tls_probe_ids: Vec<String> = probes
        .iter()
        .filter(|probe| matches!(probe.detail, ProbeDetail::TlsHandshake { .. }))
        .map(|probe| probe.id.clone())
        .collect();
    let tls_total: usize = summaries.iter().map(|summary| summary.tls_total).sum();
    let tls_transport_ok: usize = summaries
        .iter()
        .map(|summary| summary.tls_transport_ok)
        .sum();
    let tls_verified_ok: usize = summaries
        .iter()
        .map(|summary| summary.tls_verified_ok)
        .sum();
    let evidence_ids = if tls_probe_ids.is_empty() {
        summaries
            .iter()
            .flat_map(|summary| summary.probe_ids.clone())
            .collect::<Vec<_>>()
    } else {
        tls_probe_ids.clone()
    };

    if tls_enabled && tls_total == 0 {
        limitations.push("本次没有完成 TLS 检测（可能因为 TCP 未建立连接）".to_string());
    }
    if tls_total > 0 && !ctx.fake_ip_suspected {
        if tls_transport_ok == 0 {
            add_finding(
                &mut findings,
                "R008",
                format!("TLS 传输握手全部失败（0/{tls_total}）"),
                Severity::Fail,
                Status::Fail,
                evidence_ids.clone(),
                vec![
                    "失败发生在证书交换之前还是之后".to_string(),
                    "SNI 是否与目标服务匹配".to_string(),
                ],
                Confidence::Moderate,
                vec!["TLS 结果只代表本次尝试".to_string()],
            );
        } else if tls_verified_ok == 0 {
            add_finding(
                &mut findings,
                "R009",
                "TLS 传输可完成，但证书校验未通过".to_string(),
                Severity::Warn,
                Status::Warn,
                evidence_ids.clone(),
                vec![
                    "证书链缺失哪一级".to_string(),
                    "客户端信任库是否缺少对应的根证书".to_string(),
                    "SNI 与证书中的名称是否一致".to_string(),
                ],
                Confidence::Moderate,
                vec!["证书错误与传输错误在本报告中分开记录".to_string()],
            );
            recommendations.push(Recommendation {
                id: "S004".to_string(),
                action: "核对证书链、SNI 与系统时间".to_string(),
                rationale: "握手可达但信任链不成立".to_string(),
                evidence: evidence_ids.clone(),
            });
        } else if tls_verified_ok < tls_total {
            add_finding(
                &mut findings,
                "R009",
                format!("部分 TLS 尝试未通过证书校验（{tls_verified_ok}/{tls_total} 通过）"),
                Severity::Warn,
                Status::Warn,
                evidence_ids.clone(),
                vec!["失败样本的具体证书错误".to_string()],
                Confidence::Moderate,
                vec!["不同地址族的证书结果可能不同".to_string()],
            );
        } else {
            add_finding(
                &mut findings,
                "R010",
                "TLS 握手完成且证书校验通过".to_string(),
                Severity::Info,
                Status::Pass,
                evidence_ids.clone(),
                Vec::new(),
                Confidence::Moderate,
                vec!["仅代表握手阶段，未验证应用层请求".to_string()],
            );
        }
    }

    // ---- UDP evidence interpretation (fixtures and future probes) ---------
    for probe in probes {
        if let ProbeDetail::UdpObservation {
            observation,
            implies_udp_session,
            note,
        } = &probe.detail
        {
            let (claim, status, severity, not_established) = match observation {
                UdpObservation::IcmpPortUnreachable => (
                    "收到 ICMP 端口不可达，只能说明部分往返路径可达，不能证明 UDP 会话可用",
                    Status::Skip,
                    Severity::Info,
                    vec!["真实 UDP 载荷往返".to_string()],
                ),
                UdpObservation::NoResponseToInvalidPayload => (
                    "无效载荷没有响应，不能据此判断 QUIC 握手失败",
                    Status::Inconclusive,
                    Severity::Info,
                    vec!["有效 QUIC 握手是否可用".to_string()],
                ),
                UdpObservation::QuicHandshakeTimeout => (
                    "有效的 QUIC 握手超时",
                    Status::Warn,
                    Severity::Warn,
                    vec!["超时位于哪一段路径".to_string()],
                ),
                UdpObservation::ApplicationEchoReply => (
                    "真实 UDP 载荷完成往返",
                    Status::Pass,
                    Severity::Info,
                    Vec::new(),
                ),
                UdpObservation::QuicHandshakeComplete => (
                    "QUIC 握手完成",
                    Status::Pass,
                    Severity::Info,
                    vec!["应用层吞吐".to_string()],
                ),
            };
            add_finding(
                &mut findings,
                "R013",
                claim.to_string(),
                severity,
                status,
                vec![probe.id.clone()],
                not_established,
                Confidence::Low,
                vec![note.clone()],
            );
            if !*implies_udp_session {
                limitations.push(format!("{}：{}", probe.id, note));
            }
        }
    }

    // Deduplicate limits while preserving order.
    let mut seen = std::collections::BTreeSet::new();
    limitations.retain(|item| seen.insert(item.clone()));

    Analysis {
        findings,
        recommendations,
        limitations,
    }
}

/// Primary finding: highest severity, then the one with the most evidence.
pub fn primary_finding(findings: &[Finding]) -> Option<&Finding> {
    findings
        .iter()
        .filter(|finding| finding.status.is_notable())
        .max_by_key(|finding| {
            let rank = match finding.status {
                Status::Fail => 3,
                Status::Warn => 2,
                Status::Inconclusive => 1,
                _ => 0,
            };
            (rank, finding.evidence.len())
        })
        .or_else(|| {
            findings
                .iter()
                .find(|finding| finding.status == Status::Pass)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Family, ProbeKind, ProbeOutcome};
    use crate::net::AddressScope;
    use std::collections::BTreeMap;

    fn probe(id: &str) -> Probe {
        Probe {
            id: id.to_string(),
            kind: ProbeKind::Tcp,
            outcome: ProbeOutcome::Ok,
            family: Some(Family::Ipv4),
            target: Some("192.0.2.10".to_string()),
            port: Some(443),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            duration_ms: Some(100.0),
            detail: ProbeDetail::TcpConnect {
                connect_ms: Some(100.0),
                error: None,
            },
        }
    }

    fn summary(total: usize, success: usize, mean_ms: Option<f64>) -> FamilySummary {
        FamilySummary {
            family: Family::Ipv4,
            address: "192.0.2.10".to_string(),
            tcp_total: total,
            tcp_success: success,
            tcp_success_rate: if total == 0 {
                0.0
            } else {
                success as f64 / total as f64
            },
            tcp_mean_ms: mean_ms,
            tcp_median_ms: mean_ms,
            tcp_max_ms: mean_ms,
            error_classes: BTreeMap::new(),
            samples_ms: Vec::new(),
            aggregate_only: false,
            tls_total: 0,
            tls_transport_ok: 0,
            tls_verified_ok: 0,
            window_started_at: "2026-01-01T00:00:00.000Z".to_string(),
            window_finished_at: "2026-01-01T00:00:10.000Z".to_string(),
            probe_ids: vec!["tcp_ipv4_001".to_string()],
        }
    }

    fn context<'a>(
        probes: &'a [Probe],
        summaries: &'a [FamilySummary],
        stages: &'a [Stage],
        scope: Option<AddressScope>,
        literal: bool,
    ) -> AnalysisContext<'a> {
        AnalysisContext {
            probes,
            summaries,
            stages,
            tls_enabled: false,
            fake_ip_suspected: false,
            target_scope: scope,
            literal_target: literal,
            suppress_comparison: false,
        }
    }

    #[test]
    fn private_literal_target_is_measured_not_condemned() {
        let probes = vec![probe("tcp_ipv4_001")];
        let summaries = vec![summary(10, 10, Some(2.0))];
        let stages: Vec<Stage> = Vec::new();
        let ctx = context(
            &probes,
            &summaries,
            &stages,
            Some(AddressScope::Private),
            true,
        );
        let analysis = analyze(&ctx);
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.rule_id == "R014")
            .expect("R014 for a private target");
        assert_eq!(finding.status, Status::Pass);
        assert!(finding.claim.contains("私有"));
        assert!(analysis
            .limitations
            .iter()
            .any(|item| item.contains("不代表公网")));
        // A healthy private target must not be reported as a failure.
        assert!(!analysis
            .findings
            .iter()
            .any(|finding| finding.status == Status::Fail));
    }

    #[test]
    fn public_target_has_no_scope_finding() {
        let probes = vec![probe("tcp_ipv4_001")];
        let summaries = vec![summary(10, 10, Some(30.0))];
        let stages: Vec<Stage> = Vec::new();
        let ctx = context(
            &probes,
            &summaries,
            &stages,
            Some(AddressScope::Public),
            false,
        );
        let analysis = analyze(&ctx);
        assert!(analysis
            .findings
            .iter()
            .all(|finding| finding.rule_id != "R014"));
    }

    #[test]
    fn fake_ip_flag_produces_a_warning_with_evidence() {
        let probes = vec![probe("tcp_ipv4_001")];
        let summaries = vec![summary(10, 10, Some(1.0))];
        let stages: Vec<Stage> = Vec::new();
        let mut ctx = context(
            &probes,
            &summaries,
            &stages,
            Some(AddressScope::Benchmark),
            false,
        );
        ctx.fake_ip_suspected = true;
        ctx.suppress_comparison = true;
        let analysis = analyze(&ctx);
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.rule_id == "R002")
            .expect("fake ip finding");
        assert_eq!(finding.status, Status::Warn);
        assert!(!finding.evidence.is_empty());
        assert!(finding.limits.iter().any(|item| item.contains("198.18")));
        // Downstream numbers describe the local proxy, so no TCP/TLS verdicts
        // may be derived from them.
        assert!(
            analysis
                .findings
                .iter()
                .all(|finding| finding.rule_id == "R002"),
            "fake-ip runs must not emit TCP/TLS conclusions: {:?}",
            analysis
                .findings
                .iter()
                .map(|finding| finding.rule_id.clone())
                .collect::<Vec<_>>()
        );
        assert!(analysis
            .limitations
            .iter()
            .any(|item| item.contains("有意省略")));
    }

    #[test]
    fn latency_claim_uses_successful_sample_count() {
        let probes = vec![probe("tcp_ipv4_001")];
        let summaries = vec![summary(20, 1, Some(4800.0))];
        let stages: Vec<Stage> = Vec::new();
        let ctx = context(
            &probes,
            &summaries,
            &stages,
            Some(AddressScope::Public),
            false,
        );
        let analysis = analyze(&ctx);
        let latency = analysis
            .findings
            .iter()
            .find(|finding| finding.rule_id == "R006")
            .expect("latency finding");
        assert_eq!(latency.confidence, Confidence::Low);
        assert!(latency
            .limits
            .iter()
            .any(|item| item.contains("1 个成功样本")));
    }
}
