//! Offline rendering of a saved PathTrial JSON report.
//!
//! The renderer reads one local file and writes HTML, SVG, or text. It does
//! not open sockets, and it does not add measurements that were not in the file.

use std::fs;

use serde_json::Value;

use crate::cli::{RenderArgs, RenderFormat};

pub fn run(args: &RenderArgs) -> Result<u8, String> {
    let text = fs::read_to_string(&args.input)
        .map_err(|error| format!("read {}: {error}", args.input.display()))?;
    let mut value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("parse {}: {error}", args.input.display()))?;
    if !value.is_object() {
        return Err("report JSON must be an object".to_string());
    }
    let mut masked = 0usize;
    if args.redact_ips {
        masked = crate::util::mask_json(&mut value);
    }
    let body = match args.format {
        RenderFormat::Html => render_html(&value, masked),
        RenderFormat::Svg => render_svg(&value),
        RenderFormat::Summary => render_summary(&value, masked),
    };
    if let Some(path) = &args.out {
        if path.exists() {
            return Err(format!(
                "refusing to overwrite {}; choose a new --out path",
                path.display()
            ));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("create {}: {error}", parent.display()))?;
            }
        }
        fs::write(path, &body).map_err(|error| format!("write {}: {error}", path.display()))?;
        eprintln!("wrote {}", path.display());
    } else {
        print!("{body}");
        if !body.ends_with('\n') {
            println!();
        }
    }
    Ok(0)
}

pub fn render_summary(value: &Value, masked: usize) -> String {
    let report = inner_report(value);
    let mut lines = Vec::new();
    lines.push("PathTrial report view".to_string());
    lines.push(
        "Rendered locally from the saved file. No network request was made and no sample was added."
            .to_string(),
    );
    if value.get("kind").and_then(Value::as_str) == Some("pathtrial_baseline") {
        lines.push("Source is a baseline envelope; the inner report is shown.".to_string());
    }
    if masked > 0 {
        lines.push(format!(
            "IP literals masked for this rendering: {masked}. The input file was not modified."
        ));
    } else if report
        .get("redaction")
        .and_then(|item| item.get("applied"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        lines.push("The saved report says IP redaction was already applied.".to_string());
    }
    lines.push(format!("Target: {}", target_label(report)));
    for row in rows(report) {
        let evidence = if row.evidence.is_empty() {
            "no evidence id recorded".to_string()
        } else {
            row.evidence.join(", ")
        };
        lines.push(format!(
            "{} {} — {} — {evidence}",
            row.status, row.title, row.detail
        ));
    }
    if let Some(limits) = report.get("limitations").and_then(Value::as_array) {
        for limit in limits {
            if let Some(text) = limit.as_str() {
                lines.push(format!("limit: {text}"));
            }
        }
    }
    lines.join("\n")
}

pub fn render_html(value: &Value, masked: usize) -> String {
    let report = inner_report(value);
    let mut body = String::new();
    body.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>PathTrial report</title><style>");
    body.push_str(
        "body{font-family:ui-sans-serif,sans-serif;margin:24px;background:#0f1419;color:#e7ecf3}",
    );
    body.push_str("h1{font-size:20px} .note{color:#a1a1aa} .row{display:flex;gap:12px;align-items:flex-start;margin:8px 0}");
    body.push_str(".mark{min-width:8.5em;font-weight:700} .PASS{color:#3dd68c}.WARN{color:#f5a524}.FAIL{color:#f31260}.SKIP{color:#a1a1aa}.INCONCLUSIVE{color:#7dd3fc}");
    body.push_str("code{color:#e7ecf3}</style></head><body>");
    body.push_str("<h1>PathTrial report</h1>");
    body.push_str("<p class=\"note\">Rendered locally from a saved report. This page does not load remote resources and does not add measurements.</p>");
    if masked > 0 {
        body.push_str(&format!(
            "<p class=\"note\">IP literals masked in this view: {masked}. The input file was not modified.</p>"
        ));
    }
    body.push_str("<p>Target: ");
    body.push_str(&escape(&target_label(report)));
    body.push_str("</p>");
    for row in rows(report) {
        let class = status_class(&row.status);
        body.push_str("<div class=\"row\"><div class=\"mark ");
        body.push_str(class);
        body.push_str("\">");
        body.push_str(&escape(&row.status));
        body.push_str("</div><div><div>");
        body.push_str(&escape(&row.title));
        body.push_str("</div><div class=\"note\">");
        body.push_str(&escape(&row.detail));
        body.push_str("</div><div class=\"note\">");
        if row.evidence.is_empty() {
            body.push_str("no evidence id recorded");
        } else {
            body.push_str("evidence ");
            body.push_str(&escape(&row.evidence.join(", ")));
        }
        body.push_str("</div></div></div>");
    }
    if let Some(limits) = report.get("limitations").and_then(Value::as_array) {
        body.push_str("<h2>Limits</h2><ul>");
        for limit in limits {
            if let Some(text) = limit.as_str() {
                body.push_str("<li>");
                body.push_str(&escape(text));
                body.push_str("</li>");
            }
        }
        body.push_str("</ul>");
    }
    body.push_str("</body></html>\n");
    body
}

pub fn render_svg(value: &Value) -> String {
    let report = inner_report(value);
    let rows = rows(report);
    let height = 56 + rows.len().max(1) * 36;
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"720\" height=\"{height}\" viewBox=\"0 0 720 {height}\">"
    );
    svg.push_str("<rect width=\"720\" height=\"100%\" fill=\"#0f1419\"/>");
    svg.push_str("<text x=\"16\" y=\"28\" fill=\"#e7ecf3\" font-family=\"sans-serif\" font-size=\"16\">PathTrial report</text>");
    for (index, row) in rows.iter().enumerate() {
        let y = 48 + index * 36;
        let color = status_color(&row.status);
        svg.push_str(&format!(
            "<rect x=\"16\" y=\"{y}\" width=\"120\" height=\"24\" rx=\"4\" fill=\"{color}\"/>"
        ));
        svg.push_str(&format!(
            "<text x=\"24\" y=\"{}\" fill=\"#0f1419\" font-family=\"sans-serif\" font-size=\"12\">{}</text>",
            y + 16,
            escape(&row.status)
        ));
        let label = format!("{} — {}", row.title, evidence_label(&row.evidence));
        svg.push_str(&format!(
            "<text x=\"148\" y=\"{}\" fill=\"#e7ecf3\" font-family=\"sans-serif\" font-size=\"13\">{}</text>",
            y + 16,
            escape(&label)
        ));
    }
    svg.push_str("</svg>\n");
    svg
}

struct Row {
    title: String,
    status: String,
    detail: String,
    evidence: Vec<String>,
}

fn inner_report(value: &Value) -> &Value {
    if value.get("kind").and_then(Value::as_str) == Some("pathtrial_baseline") {
        if let Some(report) = value.get("report") {
            if report.is_object() {
                return report;
            }
        }
    }
    value
}

fn rows(report: &Value) -> Vec<Row> {
    let mut rows = Vec::new();
    if let Some(stages) = report.get("stages").and_then(Value::as_array) {
        for stage in stages {
            rows.push(Row {
                title: format!(
                    "stage {}",
                    stage
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unnamed")
                ),
                status: stage
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                detail: stage
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("summary not recorded")
                    .to_string(),
                evidence: string_list(stage.get("evidence")),
            });
        }
    }
    if let Some(checks) = report.get("checks").and_then(Value::as_array) {
        for check in checks {
            rows.push(Row {
                title: format!(
                    "check {}",
                    check
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unnamed")
                ),
                status: check
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                detail: check
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("summary not recorded")
                    .to_string(),
                evidence: string_list(check.get("evidence")),
            });
        }
    }
    if let Some(probes) = report.get("probes").and_then(Value::as_array) {
        for probe in probes {
            let id = probe
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("missing-id");
            let kind = probe.get("kind").and_then(Value::as_str).unwrap_or("probe");
            let outcome = probe
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or("outcome not recorded");
            let detail = match probe.get("duration_ms").and_then(Value::as_f64) {
                Some(duration) => format!("{outcome}; duration_ms {duration}"),
                None => format!("{outcome}; duration not recorded"),
            };
            rows.push(Row {
                title: format!("probe {id} ({kind})"),
                status: outcome.to_ascii_uppercase(),
                detail,
                evidence: vec![id.to_string()],
            });
        }
    }
    if rows.is_empty() {
        rows.push(Row {
            title: "report".to_string(),
            status: "INCONCLUSIVE".to_string(),
            detail: "no stage, check, or probe array was present in this file".to_string(),
            evidence: Vec::new(),
        });
    }
    rows
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn target_label(report: &Value) -> String {
    if let Some(target) = report.get("target") {
        if let Some(text) = target.as_str() {
            return text.to_string();
        }
        if target.is_object() {
            let input = target.get("input").and_then(Value::as_str).unwrap_or("");
            let port = target
                .get("port")
                .and_then(Value::as_u64)
                .map(|port| port.to_string())
                .unwrap_or_else(|| "port not recorded".to_string());
            if input.is_empty() {
                return "target not recorded".to_string();
            }
            return format!("{input} port {port}");
        }
    }
    report
        .get("scenario")
        .and_then(Value::as_str)
        .unwrap_or("target not recorded")
        .to_string()
}

fn evidence_label(evidence: &[String]) -> String {
    if evidence.is_empty() {
        "no evidence id recorded".to_string()
    } else {
        evidence.join(", ")
    }
}

fn status_class(status: &str) -> &str {
    match status {
        "PASS" | "OK" => "PASS",
        "WARN" => "WARN",
        "FAIL" => "FAIL",
        "SKIP" | "NOT_APPLICABLE" => "SKIP",
        _ => "INCONCLUSIVE",
    }
}

fn status_color(status: &str) -> &'static str {
    match status_class(status) {
        "PASS" => "#3dd68c",
        "WARN" => "#f5a524",
        "FAIL" => "#f31260",
        "SKIP" => "#a1a1aa",
        _ => "#7dd3fc",
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "schema_version": "1.5.0",
            "tool_version": "1.5.0-rc.1",
            "run_id": "run-1",
            "target": {"input": "203.0.113.10", "port": 443, "profile": "tcp", "literal_ip": true},
            "stages": [{
                "id": "tcp",
                "name": "TCP",
                "status": "PASS",
                "summary": "connected to 203.0.113.10",
                "evidence": ["tcp_001"],
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:00:01Z"
            }],
            "probes": [{
                "id": "tcp_001",
                "kind": "tcp",
                "outcome": "ok",
                "duration_ms": 12.0,
                "started_at": "2026-01-01T00:00:00Z"
            }],
            "limitations": ["clock sync is not established"]
        })
    }

    #[test]
    fn html_is_offline_and_redacts_addresses() {
        let mut value = sample();
        let masked = crate::util::mask_json(&mut value);
        assert!(masked > 0);
        let html = render_html(&value, masked);
        assert!(!html.contains("203.0.113.10"));
        assert!(html.contains("tcp_001"));
        assert!(html.contains("PASS"));
        assert!(!html.contains("src="));
        assert!(!html.contains("<script"));
        assert!(!html.contains("href="));
        let svg = render_svg(&value);
        assert!(svg.contains("tcp_001"));
        assert!(!svg.contains("203.0.113.10"));
        assert!(!svg.contains("src="));
        assert!(!svg.contains("<script"));
    }

    #[test]
    fn summary_names_missing_evidence() {
        let value = json!({"schema_version": "1.5.0", "run_id": "x"});
        let text = render_summary(&value, 0);
        assert!(text.contains("no stage, check, or probe"));
        assert!(text.contains("No network request"));
    }
}
