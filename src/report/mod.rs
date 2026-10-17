//! Rendering: JSON for machines, Markdown for tickets, plain text for people.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::analysis;
use crate::models::{FamilySummary, Report, Status};
use crate::util::IpMasker;

/// All rendered forms of one report.
pub struct Rendered {
    pub json: String,
    pub markdown: String,
    pub terminal: String,
}

fn mask_value(value: &mut Value, masker: &mut IpMasker) {
    match value {
        Value::String(text) => *text = masker.mask_text(text),
        Value::Array(items) => {
            for item in items {
                mask_value(item, masker);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                mask_value(item, masker);
            }
        }
        _ => {}
    }
}

fn status_cell(status: Status) -> &'static str {
    status.label()
}

fn family_line(summary: &FamilySummary) -> String {
    let latency = summary
        .tcp_median_ms
        .map(|value| format!("{value:.0} ms"))
        .unwrap_or_else(|| "无成功样本".to_string());
    format!(
        "{} {}/{}，中位 {}",
        summary.family.label(),
        summary.tcp_success,
        summary.tcp_total,
        latency
    )
}

fn markdown_body(report: &Report, masked: Option<usize>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# PathTrial 诊断报告\n");
    let _ = writeln!(
        out,
        "- 目标：`{}:{}`（profile: {}）",
        report.target.input, report.target.port, report.target.profile
    );
    let _ = writeln!(out, "- 运行 ID：`{}`", report.run_id);
    let _ = writeln!(
        out,
        "- 开始：{}　结束：{}",
        report.started_at, report.finished_at
    );
    let _ = writeln!(
        out,
        "- 工具版本：{}　报告 schema：{}\n",
        report.tool_version, report.schema_version
    );
    let _ = writeln!(
        out,
        "**总体判定：{}**（与退出码使用同一套优先级）\n",
        report.worst_status().label()
    );

    let _ = writeln!(out, "## 1. 系统与测试环境\n");
    let _ = writeln!(out, "| 项目 | 值 |\n| --- | --- |");
    let _ = writeln!(
        out,
        "| 操作系统 | {} / {} |",
        report.environment.os, report.environment.arch
    );
    let _ = writeln!(
        out,
        "| 内核 | {} |",
        report
            .environment
            .kernel
            .clone()
            .unwrap_or_else(|| "未知".to_string())
    );
    let _ = writeln!(
        out,
        "| 网卡数量 | {} |",
        report.environment.interfaces.len()
    );
    let _ = writeln!(out, "| 本机 IPv4 | {} |", report.environment.ipv4_local);
    let _ = writeln!(out, "| 本机 IPv6 | {} |", report.environment.ipv6_local);
    let _ = writeln!(
        out,
        "| 全局 IPv6 地址 | {} |",
        report.environment.has_global_ipv6
    );
    let _ = writeln!(
        out,
        "| 隧道类接口 | {} |",
        if report.environment.vpn_like_interfaces.is_empty() {
            "未发现".to_string()
        } else {
            report.environment.vpn_like_interfaces.join(", ")
        }
    );
    let _ = writeln!(
        out,
        "| 默认路由 IPv4 | {} |",
        report
            .environment
            .default_route_v4
            .as_ref()
            .map(crate::platform::describe_route)
            .unwrap_or_else(|| "未获取".to_string())
    );
    let _ = writeln!(
        out,
        "| 默认路由 IPv6 | {} |",
        report
            .environment
            .default_route_v6
            .as_ref()
            .map(crate::platform::describe_route)
            .unwrap_or_else(|| "未获取".to_string())
    );
    let _ = writeln!(
        out,
        "| 目标路由 | {} |",
        report
            .environment
            .target_route
            .as_ref()
            .map(crate::platform::describe_route)
            .unwrap_or_else(|| "未获取".to_string())
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## 2. 检测配置\n");
    let _ = writeln!(
        out,
        "| 配置 | 值 |\n| --- | --- |\n| 每协议族轮次 | {} |\n| 单次超时 | {} ms |\n| 探测间隔 | {} ms |\n| 总时长上限 | {} s |\n| TLS | {} |\n| 跳过证书校验 | {} |\n| IP 脱敏 | {} |",
        report.configuration.rounds,
        report.configuration.timeout_ms,
        report.configuration.interval_ms,
        report.configuration.max_total_seconds,
        report.configuration.tls_enabled,
        report.configuration.allow_insecure_tls,
        report.configuration.redact_ips
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## 3. 各阶段状态\n");
    let _ = writeln!(out, "| # | 阶段 | 状态 | 摘要 |\n| --- | --- | --- | --- |");
    for (index, stage) in report.stages.iter().enumerate() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            index + 1,
            stage.name,
            status_cell(stage.status),
            stage.summary.replace('|', "/")
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 4. 原始测试数据\n");
    for summary in &report.summaries {
        let _ = writeln!(out, "### {}\n", summary.family.label());
        let _ = writeln!(
            out,
            "- 地址：`{}`\n- TCP：{}/{}\n- 成功率：{:.0}%\n- 平均：{} ms\n- 中位：{} ms\n- 最大：{} ms\n- TLS 传输成功：{}/{}\n- TLS 证书校验通过：{}/{}",
            summary.address,
            summary.tcp_success,
            summary.tcp_total,
            summary.tcp_success_rate * 100.0,
            summary.tcp_mean_ms.map(|v| format!("{v:.0}")).unwrap_or_else(|| "无".to_string()),
            summary.tcp_median_ms.map(|v| format!("{v:.0}")).unwrap_or_else(|| "无".to_string()),
            summary.tcp_max_ms.map(|v| format!("{v:.0}")).unwrap_or_else(|| "无".to_string()),
            summary.tls_transport_ok,
            summary.tls_total,
            summary.tls_verified_ok,
            summary.tls_total
        );
        if !summary.error_classes.is_empty() {
            let errors = summary
                .error_classes
                .iter()
                .map(|(key, count)| format!("{key} × {count}"))
                .collect::<Vec<_>>()
                .join("，");
            let _ = writeln!(out, "- 错误分类：{errors}");
        }
        if !summary.samples_ms.is_empty() {
            let samples = summary
                .samples_ms
                .iter()
                .map(|value| format!("{value:.0}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "- 成功建连耗时（ms）：{samples}");
        }
        if summary.aggregate_only {
            let _ = writeln!(out, "- 备注：该组为汇总数据，没有逐次样本");
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## 5. 异常现象\n");
    let problems: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.status.is_notable())
        .collect();
    if problems.is_empty() {
        let _ = writeln!(out, "本次未发现 WARN/FAIL 级异常。\n");
    } else {
        for finding in &problems {
            let _ = writeln!(
                out,
                "- **{}** {}（{}）",
                finding.rule_id,
                finding.claim,
                status_cell(finding.status)
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## 6. 诊断结论\n");
    match analysis::primary_finding(&report.findings) {
        Some(finding) => {
            let _ = writeln!(
                out,
                "{}（规则 {}，置信度 {:?}）\n",
                finding.claim, finding.rule_id, finding.confidence
            );
        }
        None => {
            let _ = writeln!(out, "证据不足，无法给出结论。\n");
        }
    }

    let _ = writeln!(out, "## 7. 结论与证据\n");
    let _ = writeln!(
        out,
        "| 结论 | 状态 | 证据 | 尚未证实 |\n| --- | --- | --- | --- |"
    );
    for finding in &report.findings {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            finding.claim.replace('|', "/"),
            status_cell(finding.status),
            finding.evidence.join("<br>"),
            if finding.not_established.is_empty() {
                "—".to_string()
            } else {
                finding.not_established.join("<br>").replace('|', "/")
            }
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 8. 尚未证实的原因\n");
    let mut unknowns: Vec<&String> = report
        .findings
        .iter()
        .flat_map(|finding| finding.not_established.iter())
        .collect();
    unknowns.sort();
    unknowns.dedup();
    if unknowns.is_empty() {
        let _ = writeln!(out, "无。\n");
    } else {
        for item in unknowns {
            let _ = writeln!(out, "- {item}");
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## 9. 测试局限\n");
    if report.limitations.is_empty() {
        let _ = writeln!(out, "无。\n");
    } else {
        for item in &report.limitations {
            let _ = writeln!(out, "- {item}");
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## 10. 建议的人工验证\n");
    if report.recommendations.is_empty() {
        let _ = writeln!(out, "无需额外步骤。\n");
    } else {
        for recommendation in &report.recommendations {
            let _ = writeln!(
                out,
                "- **{}**：{}（理由：{}）",
                recommendation.id, recommendation.action, recommendation.rationale
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "---");
    let _ = writeln!(
        out,
        "PathTrial 只记录探测结果。本报告不修改任何系统配置，也不对无法证明的原因下结论。"
    );
    if let Some(count) = masked {
        let _ = writeln!(out, "\n> 已脱敏 IP 地址 {count} 个。");
    }
    out
}

fn terminal_body(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "PathTrial {}", report.tool_version);
    let _ = writeln!(
        out,
        "Target: {}:{}  profile={}  rounds={}",
        report.target.input, report.target.port, report.target.profile, report.configuration.rounds
    );
    let _ = writeln!(
        out,
        "Window: {} .. {}",
        report.started_at, report.finished_at
    );
    let _ = writeln!(out, "{}", "-".repeat(64));
    for (index, stage) in report.stages.iter().enumerate() {
        let _ = writeln!(
            out,
            "{:02}  {:<22} {:<12} {}",
            index + 1,
            stage.name,
            status_cell(stage.status),
            stage.summary
        );
        if let Some(reason) = &stage.reason {
            let _ = writeln!(out, "     ({reason})");
        }
    }
    let _ = writeln!(out, "{}", "-".repeat(64));
    let _ = writeln!(out, "Overall: {}", report.worst_status().label());
    let _ = writeln!(out, "{}", "-".repeat(64));
    for summary in &report.summaries {
        let _ = writeln!(out, "  {}", family_line(summary));
    }
    let _ = writeln!(out, "{}", "-".repeat(64));
    match analysis::primary_finding(&report.findings) {
        Some(finding) => {
            let _ = writeln!(out, "Primary finding: {}", finding.claim);
            if !finding.evidence.is_empty() {
                let shown = finding
                    .evidence
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "Evidence: {shown}");
            }
            for item in finding.not_established.iter().take(4) {
                let _ = writeln!(out, "Not established: {item}");
            }
            if let Some(recommendation) = report.recommendations.first() {
                let _ = writeln!(out, "Recommendation: {}", recommendation.action);
            }
        }
        None => {
            let _ = writeln!(out, "Primary finding: 证据不足，未形成结论");
        }
    }
    out
}

/// Render every output form. IP masking is applied to the rendered text so the
/// same placeholder mapping is used across JSON and Markdown.
pub fn render(report: &Report, redact: bool) -> Result<Rendered, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    // One masker is shared by every output so the same address always maps to
    // the same placeholder, even across JSON and Markdown.
    let mut masker = IpMasker::default();
    if redact {
        mask_value(&mut value, &mut masker);
        if let Some(redaction) = value.get_mut("redaction") {
            redaction["applied"] = Value::Bool(true);
            redaction["ips_masked"] = Value::Number(masker.masked.into());
        }
    }
    let json = serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;

    let mut markdown = markdown_body(report, if redact { Some(masker.masked) } else { None });
    let mut terminal = terminal_body(report);
    if redact {
        markdown = masker.mask_text(&markdown);
        terminal = masker.mask_text(&terminal);
    }
    Ok(Rendered {
        json,
        markdown,
        terminal,
    })
}

/// Write the JSON and Markdown reports into `dir` using `stem` as the base
/// name. The caller decides whether the stem is unique per run.
pub fn write_files(
    dir: &Path,
    stem: &str,
    rendered: &Rendered,
) -> Result<(PathBuf, PathBuf), String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("create {}: {error}", dir.display()))?;
    let json_path = dir.join(format!("{stem}.json"));
    let markdown_path = dir.join(format!("{stem}.md"));
    std::fs::write(&json_path, &rendered.json)
        .map_err(|error| format!("write {}: {error}", json_path.display()))?;
    std::fs::write(&markdown_path, &rendered.markdown)
        .map_err(|error| format!("write {}: {error}", markdown_path.display()))?;
    Ok((json_path, markdown_path))
}

/// Write to an explicit prefix, overwriting existing files. The caller must
/// tell the user about the overwrite.
pub fn write_at(prefix: &Path, rendered: &Rendered) -> Result<(PathBuf, PathBuf), String> {
    if let Some(parent) = prefix.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
    }
    let json_path = prefix.with_extension("json");
    let markdown_path = prefix.with_extension("md");
    std::fs::write(&json_path, &rendered.json)
        .map_err(|error| format!("write {}: {error}", json_path.display()))?;
    std::fs::write(&markdown_path, &rendered.markdown)
        .map_err(|error| format!("write {}: {error}", markdown_path.display()))?;
    Ok((json_path, markdown_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn minimal_report() -> Report {
        Report {
            schema_version: SCHEMA_VERSION.to_string(),
            tool_version: "0.1.0".to_string(),
            run_id: "run".to_string(),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            finished_at: "2026-01-01T00:00:01.000Z".to_string(),
            target: Target {
                input: "example.com".to_string(),
                host: Some("example.com".to_string()),
                port: 443,
                profile: "web".to_string(),
                literal_ip: false,
            },
            configuration: Configuration {
                rounds: 20,
                timeout_ms: 3000,
                interval_ms: 200,
                max_total_seconds: 180,
                connect_budget: 40,
                tls_enabled: true,
                allow_insecure_tls: false,
                output_format: "summary".to_string(),
                redact_ips: false,
                bind_interface: None,
            },
            environment: Environment {
                os: "macos".to_string(),
                arch: "aarch64".to_string(),
                kernel: None,
                interfaces: Vec::new(),
                ipv4_local: true,
                ipv6_local: false,
                has_global_ipv6: false,
                vpn_like_interfaces: Vec::new(),
                default_route_v4: None,
                default_route_v6: None,
                target_route: None,
                proxy_env_names: Vec::new(),
                notes: Vec::new(),
            },
            stages: vec![Stage {
                id: "system".to_string(),
                name: "系统环境".to_string(),
                status: Status::Pass,
                summary: "ok".to_string(),
                reason: None,
                evidence: vec!["system_001".to_string()],
                started_at: "2026-01-01T00:00:00.000Z".to_string(),
                finished_at: "2026-01-01T00:00:00.100Z".to_string(),
            }],
            probes: Vec::new(),
            summaries: Vec::new(),
            findings: Vec::new(),
            recommendations: Vec::new(),
            limitations: Vec::new(),
            redaction: Redaction {
                applied: false,
                ips_masked: 0,
                notes: Vec::new(),
            },
        }
    }

    #[test]
    fn json_round_trips_through_serde() {
        let report = minimal_report();
        let rendered = render(&report, false).unwrap();
        let parsed: Report = serde_json::from_str(&rendered.json).unwrap();
        assert_eq!(parsed.target.input, "example.com");
        assert_eq!(parsed.stages.len(), 1);
    }

    #[test]
    fn markdown_has_all_sections() {
        let report = minimal_report();
        let rendered = render(&report, false).unwrap();
        for index in 1..=10 {
            assert!(
                rendered.markdown.contains(&format!("## {index}.")),
                "missing section {index}"
            );
        }
    }

    #[test]
    fn redaction_masks_addresses_in_every_format() {
        let mut report = minimal_report();
        report.target.input = "192.0.2.55".to_string();
        let rendered = render(&report, true).unwrap();
        assert!(rendered.json.contains("<ipv4-1>"));
        assert!(rendered.markdown.contains("<ipv4-1>"));
        assert!(!rendered.terminal.contains("192.0.2.55"));
    }

    #[test]
    fn redaction_leaks_no_address_and_keeps_placeholders_stable() {
        let mut report = minimal_report();
        report.target.input = "203.0.113.9".to_string();
        report.target.host = Some("203.0.113.9".to_string());
        report.probes.push(Probe {
            id: "tcp_ipv4_001".to_string(),
            kind: ProbeKind::Tcp,
            outcome: ProbeOutcome::Fail,
            family: Some(Family::Ipv4),
            target: Some("203.0.113.9".to_string()),
            port: Some(443),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            duration_ms: Some(3.0),
            detail: ProbeDetail::TcpConnect {
                connect_ms: None,
                error: Some(NetError::Other(
                    "connect to 203.0.113.9:443 failed".to_string(),
                )),
            },
        });
        let rendered = render(&report, true).unwrap();
        for text in [&rendered.json, &rendered.markdown, &rendered.terminal] {
            assert!(!text.contains("203.0.113.9"), "raw address leaked");
            assert!(!text.contains("203.0.113"), "address prefix leaked");
        }
        // One masker is shared, so both formats must use the same placeholder.
        assert!(rendered.json.contains("<ipv4-1>"));
        assert!(rendered.markdown.contains("<ipv4-1>"));
        assert!(rendered.json.contains("\"ips_masked\": 1"));
    }
}
