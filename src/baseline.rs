//! Opt-in local baselines.
//!
//! A baseline is a report the user chose to store. Comparison reads that file
//! and the current report. It does not invent earlier samples, and it does not
//! upload either document.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};

use crate::cli::{
    BaselineAction, BaselineArgs, BaselineCompareArgs, BaselineSaveArgs, OutputFormat,
};

pub const BASELINE_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Identity {
    kind: String,
    target: String,
    port: Option<u64>,
    profile: Option<String>,
    scenario: Option<String>,
}

#[derive(Debug, Serialize)]
struct Comparison {
    schema_version: String,
    kind: String,
    generated_at: String,
    identity: Identity,
    baseline_file: String,
    baseline_saved_at: String,
    comparability: Comparability,
    items: Vec<Item>,
    not_established: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Comparability {
    verdict: String,
    issues: Vec<String>,
    limits: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Item {
    name: String,
    relation: String,
    before: Option<String>,
    after: Option<String>,
    evidence_ids: Vec<String>,
    limits: Vec<String>,
}

pub fn run(args: &BaselineArgs) -> Result<u8, String> {
    match &args.action {
        BaselineAction::Path => {
            println!("{}", default_dir()?.display());
            Ok(0)
        }
        BaselineAction::Save(save) => save_baseline(save),
        BaselineAction::Compare(compare) => compare_baseline(compare),
    }
}

fn save_baseline(args: &BaselineSaveArgs) -> Result<u8, String> {
    let mut report = read_json(&args.report)?;
    let identity = identity_of(&report)?;
    let masked = if args.redact_ips {
        crate::util::mask_json(&mut report)
    } else {
        0
    };
    let directory = args.dir.clone().unwrap_or(default_dir()?);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700));
    }
    let path = directory.join(format!("{}.json", file_key(&identity)));
    if path.exists() && !args.replace {
        return Err(format!(
            "baseline already exists at {}; pass --replace to overwrite it",
            path.display()
        ));
    }
    let source_name = args
        .report
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "report.json".to_string());
    let envelope = json!({
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": "pathtrial_baseline",
        "saved_at": crate::util::now_rfc3339(),
        "identity": identity,
        "source_name": source_name,
        "redaction": {
            "applied": args.redact_ips,
            "ips_masked": masked,
            "note": if args.redact_ips {
                "IP literals inside the stored report copy were masked. The identity key still uses the original target so a later compare can find this file."
            } else {
                "The report was stored as provided. Review it before copying this directory."
            }
        },
        "report": report
    });
    let text = serde_json::to_string_pretty(&envelope)
        .map_err(|error| format!("render baseline JSON: {error}"))?;
    fs::write(&path, text).map_err(|error| format!("write {}: {error}", path.display()))?;
    eprintln!(
        "saved baseline {} for {} {}",
        path.display(),
        identity.kind,
        identity.target
    );
    Ok(0)
}

fn compare_baseline(args: &BaselineCompareArgs) -> Result<u8, String> {
    let current = read_json(&args.report)?;
    let identity = identity_of(&current)?;
    let directory = args.dir.clone().unwrap_or(default_dir()?);
    let path = directory.join(format!("{}.json", file_key(&identity)));
    if !path.is_file() {
        return Err(format!(
            "no local baseline for {} {}; looked for {}",
            identity.kind,
            identity.target,
            path.display()
        ));
    }
    let envelope = read_json(&path)?;
    let stored_report = envelope
        .get("report")
        .cloned()
        .ok_or_else(|| format!("{} has no report object", path.display()))?;
    let stored_identity = identity_from_envelope(&envelope)?;
    let saved_at = envelope
        .get("saved_at")
        .and_then(Value::as_str)
        .unwrap_or("saved_at not recorded")
        .to_string();
    let baseline_file = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "baseline.json".to_string());
    let comparison = if stored_identity != identity {
        Comparison {
            schema_version: BASELINE_SCHEMA_VERSION.to_string(),
            kind: "baseline_comparison".to_string(),
            generated_at: crate::util::now_rfc3339(),
            identity,
            baseline_file,
            baseline_saved_at: saved_at,
            comparability: Comparability {
                verdict: "not_comparable".to_string(),
                issues: vec!["stored report identity does not match the current report".to_string()],
                limits: vec![
                    "no better/worse relation is reported when the identity does not match"
                        .to_string(),
                ],
            },
            items: Vec::new(),
            not_established: vec![
                "history was not invented; the stored file could not be compared".to_string(),
            ],
        }
    } else {
        let addresses_comparable = envelope
            .get("redaction")
            .and_then(|item| item.get("applied"))
            .and_then(Value::as_bool)
            != Some(true);
        build_comparison(
            &stored_report,
            &current,
            identity,
            baseline_file,
            saved_at,
            addresses_comparable,
        )?
    };
    let code = if comparison.comparability.verdict == "not_comparable" {
        3
    } else if comparison.items.iter().any(|item| item.relation == "worse") {
        2
    } else {
        0
    };
    match args.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&comparison)
                .map_err(|error| format!("render JSON: {error}"))?
        ),
        OutputFormat::Markdown | OutputFormat::Summary => print!("{}", render_text(&comparison)),
    }
    Ok(code)
}

fn build_comparison(
    before: &Value,
    after: &Value,
    identity: Identity,
    baseline_file: String,
    saved_at: String,
    addresses_comparable: bool,
) -> Result<Comparison, String> {
    let mut not_established =
        vec!["This comparison uses only the stored baseline and the current file.".to_string()];
    if !addresses_comparable {
        not_established.push(
            "the baseline copy masked IP literals, so address strings were not compared; status labels are compared for the saved identity"
                .to_string(),
        );
    }
    let compared = if addresses_comparable {
        match crate::compare::compare_values(before, after) {
            Ok(report) => Some(report),
            Err(error) => {
                not_established.push(format!("aggregate metric comparison was not run: {error}"));
                None
            }
        }
    } else {
        None
    };
    let directly = if addresses_comparable {
        compared
            .as_ref()
            .is_some_and(|report| report.comparability.verdict == "DIRECTLY COMPARABLE")
    } else {
        true
    };
    let mut issues = Vec::new();
    let mut limits = Vec::new();
    if let Some(report) = &compared {
        issues.extend(report.comparability.issues.clone());
        limits.extend(report.comparability.limits.clone());
        if !directly {
            not_established.push(
                "runs are not directly comparable, so metric changes are not labeled better or worse"
                    .to_string(),
            );
        }
    }
    let mut items = Vec::new();
    if let Some(report) = &compared {
        for metric in &report.metrics {
            let relation = if directly {
                match metric.change.as_str() {
                    "Improved" => "better",
                    "Regressed" => "worse",
                    "Unchanged" => "same",
                    _ => "not_established",
                }
            } else {
                "not_established"
            };
            let mut item_limits = Vec::new();
            let evidence_ids = evidence_for_metric(&metric.name, after);
            if evidence_ids.is_empty() {
                item_limits.push(
                    "no probe id in the current report matched this metric; the numbers come from aggregate fields"
                        .to_string(),
                );
            }
            if !directly {
                item_limits.push("comparability checks did not pass".to_string());
            }
            items.push(Item {
                name: metric.name.clone(),
                relation: relation.to_string(),
                before: metric.before.map(|value| value.to_string()),
                after: metric.after.map(|value| value.to_string()),
                evidence_ids,
                limits: item_limits,
            });
        }
    }
    items.extend(status_items(
        "stage",
        before.get("stages"),
        after.get("stages"),
        directly,
    ));
    items.extend(status_items(
        "check",
        before.get("checks"),
        after.get("checks"),
        directly,
    ));
    let verdict = if !directly {
        "not_comparable"
    } else if items.iter().any(|item| item.relation == "worse") {
        "worse"
    } else if items.iter().any(|item| item.relation == "better") {
        "better"
    } else if items.iter().any(|item| item.relation == "same") {
        "same"
    } else {
        "not_established"
    };
    Ok(Comparison {
        schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        kind: "baseline_comparison".to_string(),
        generated_at: crate::util::now_rfc3339(),
        identity,
        baseline_file,
        baseline_saved_at: saved_at,
        comparability: Comparability {
            verdict: verdict.to_string(),
            issues,
            limits,
        },
        items,
        not_established,
    })
}

fn status_items(
    prefix: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    directly: bool,
) -> Vec<Item> {
    let Some(before_items) = before.and_then(Value::as_array) else {
        return Vec::new();
    };
    let Some(after_items) = after.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut items = Vec::new();
    for (index, after_item) in after_items.iter().enumerate() {
        let name = after_item
            .get("name")
            .or_else(|| after_item.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let after_status = after_item.get("status").and_then(Value::as_str);
        let before_status = before_items
            .get(index)
            .and_then(|item| item.get("status"))
            .and_then(Value::as_str);
        let evidence_ids = string_list(after_item.get("evidence"));
        let (relation, mut limits) = relate_status(before_status, after_status, directly);
        if evidence_ids.is_empty() {
            limits.push("no evidence id was recorded on this item".to_string());
        }
        items.push(Item {
            name: format!("{prefix} {name}"),
            relation,
            before: before_status.map(str::to_string),
            after: after_status.map(str::to_string),
            evidence_ids,
            limits,
        });
    }
    items
}

fn relate_status(
    before: Option<&str>,
    after: Option<&str>,
    directly: bool,
) -> (String, Vec<String>) {
    if !directly {
        return (
            "not_established".to_string(),
            vec!["comparability checks did not pass".to_string()],
        );
    }
    let (Some(before), Some(after)) = (before, after) else {
        return (
            "not_established".to_string(),
            vec!["one side has no status".to_string()],
        );
    };
    if matches!(before, "SKIP" | "INCONCLUSIVE") || matches!(after, "SKIP" | "INCONCLUSIVE") {
        return (
            "not_established".to_string(),
            vec!["SKIP and INCONCLUSIVE are not treated as a quality change".to_string()],
        );
    }
    let rank = |status: &str| match status {
        "PASS" => Some(0),
        "WARN" => Some(1),
        "FAIL" => Some(2),
        _ => None,
    };
    match (rank(before), rank(after)) {
        (Some(first), Some(second)) if first == second => ("same".to_string(), Vec::new()),
        (Some(first), Some(second)) if second < first => ("better".to_string(), Vec::new()),
        (Some(first), Some(second)) if second > first => ("worse".to_string(), Vec::new()),
        _ => (
            "not_established".to_string(),
            vec![format!(
                "status pair {before} -> {after} has no better/worse rule"
            )],
        ),
    }
}

fn evidence_for_metric(name: &str, report: &Value) -> Vec<String> {
    let needle = if name.to_ascii_lowercase().contains("tcp") {
        "tcp"
    } else if name.to_ascii_lowercase().contains("tls") {
        "tls"
    } else if name.to_ascii_lowercase().contains("http") {
        "http"
    } else if name.to_ascii_lowercase().contains("icmp") {
        "icmp"
    } else if name.to_ascii_lowercase().contains("udp") {
        "udp"
    } else if name.to_ascii_lowercase().contains("proxy") {
        "proxy"
    } else {
        return Vec::new();
    };
    let Some(probes) = report.get("probes").and_then(Value::as_array) else {
        return Vec::new();
    };
    probes
        .iter()
        .filter(|probe| {
            probe
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.contains(needle))
        })
        .filter_map(|probe| probe.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
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

fn render_text(comparison: &Comparison) -> String {
    let mut lines = vec![
        format!(
            "Baseline {} for {} {}",
            comparison.comparability.verdict, comparison.identity.kind, comparison.identity.target
        ),
        format!(
            "Stored file {} saved at {}",
            comparison.baseline_file, comparison.baseline_saved_at
        ),
        "Relations use only the stored baseline and this report.".to_string(),
    ];
    for item in &comparison.items {
        let evidence = if item.evidence_ids.is_empty() {
            "no evidence id".to_string()
        } else {
            item.evidence_ids.join(", ")
        };
        lines.push(format!(
            "{} {} {:?} -> {:?} evidence {evidence}",
            item.relation, item.name, item.before, item.after
        ));
    }
    for note in &comparison.not_established {
        lines.push(format!("not_established: {note}"));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn identity_from_envelope(value: &Value) -> Result<Identity, String> {
    let identity = value
        .get("identity")
        .ok_or_else(|| "baseline envelope has no identity".to_string())?;
    let kind = identity
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let target = identity
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if kind.is_empty() || target.is_empty() {
        return Err("baseline identity is missing kind or target".to_string());
    }
    Ok(Identity {
        kind,
        target,
        port: identity.get("port").and_then(Value::as_u64),
        profile: identity
            .get("profile")
            .and_then(Value::as_str)
            .map(str::to_string),
        scenario: identity
            .get("scenario")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn identity_of(value: &Value) -> Result<Identity, String> {
    if let Some(scenario) = value.get("scenario").and_then(Value::as_str) {
        let target = match value.get("target").and_then(Value::as_str) {
            Some(target) if !target.is_empty() => target.to_string(),
            _ if scenario == "local" => "local".to_string(),
            _ => {
                return Err(
                    "this diagnose report has no target, so it cannot be stored as a baseline"
                        .to_string(),
                );
            }
        };
        return Ok(Identity {
            kind: "diagnose".to_string(),
            target,
            port: None,
            profile: None,
            scenario: Some(scenario.to_string()),
        });
    }
    if let Some(target) = value.get("target").filter(|target| target.is_object()) {
        let input = target
            .get("input")
            .and_then(Value::as_str)
            .filter(|input| !input.is_empty())
            .ok_or_else(|| "scan report is missing target.input".to_string())?;
        return Ok(Identity {
            kind: "scan".to_string(),
            target: input.to_string(),
            port: target.get("port").and_then(Value::as_u64),
            profile: target
                .get("profile")
                .and_then(Value::as_str)
                .map(str::to_string),
            scenario: None,
        });
    }
    if let Some(command) = value.get("command").and_then(Value::as_str) {
        let target = value
            .get("target")
            .and_then(Value::as_str)
            .filter(|target| !target.is_empty())
            .ok_or_else(|| "command report is missing a target string".to_string())?;
        return Ok(Identity {
            kind: command.to_string(),
            target: target.to_string(),
            port: value.get("port").and_then(Value::as_u64),
            profile: None,
            scenario: None,
        });
    }
    Err("this JSON has no scan target, diagnose scenario, or command target to use as a baseline identity".to_string())
}

fn file_key(identity: &Identity) -> String {
    let raw = format!(
        "{}|{}|{}|{}|{}",
        identity.kind,
        identity.target,
        identity
            .port
            .map(|port| port.to_string())
            .unwrap_or_default(),
        identity.profile.as_deref().unwrap_or(""),
        identity.scenario.as_deref().unwrap_or("")
    );
    format!("{:016x}", fnv64(raw.as_bytes()))
}

fn fnv64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn default_dir() -> Result<PathBuf, String> {
    crate::paths::baseline_dir()
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        BaselineAction, BaselineArgs, BaselineCompareArgs, BaselineSaveArgs, OutputFormat,
    };
    use serde_json::json;

    fn report(status: &str) -> Value {
        json!({
            "schema_version": "1.5.0",
            "tool_version": "1.5.0-rc.1",
            "run_id": "run",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "target": {"input": "203.0.113.10", "port": 443, "profile": "tcp", "literal_ip": true},
            "configuration": {"timeout_ms": 1000, "rounds": 1, "bind_interface": null},
            "environment": {"os": "test", "arch": "test"},
            "stages": [{
                "id": "tcp",
                "name": "TCP",
                "status": status,
                "summary": "stage",
                "evidence": ["tcp_001"]
            }],
            "probes": [{"id": "tcp_001", "kind": "tcp", "outcome": "ok"}],
            "findings": []
        })
    }

    #[test]
    fn save_and_compare_use_evidence_ids_and_do_not_invent_history() {
        let dir = std::env::temp_dir().join(format!(
            "pathtrial-baseline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let before = dir.join("before.json");
        let after = dir.join("after.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&before, serde_json::to_vec_pretty(&report("PASS")).unwrap()).unwrap();
        fs::write(&after, serde_json::to_vec_pretty(&report("FAIL")).unwrap()).unwrap();
        let code = run(&BaselineArgs {
            action: BaselineAction::Save(BaselineSaveArgs {
                report: before,
                dir: Some(dir.clone()),
                replace: false,
                redact_ips: true,
            }),
        })
        .unwrap();
        assert_eq!(code, 0);
        let stored = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".json") && name != "before.json" && name != "after.json"
            })
            .unwrap();
        let stored_value = read_json(&stored.path()).unwrap();
        let report_text = serde_json::to_string(stored_value.get("report").unwrap()).unwrap();
        assert!(!report_text.contains("203.0.113.10"), "{report_text}");
        assert!(report_text.contains("tcp_001"));
        assert_eq!(stored_value["identity"]["target"], "203.0.113.10");
        let current = read_json(&dir.join("after.json")).unwrap();
        let comparison = build_comparison(
            stored_value.get("report").unwrap(),
            &current,
            identity_of(&current).unwrap(),
            "baseline.json".to_string(),
            "saved".to_string(),
            false,
        )
        .unwrap();
        let stage = comparison
            .items
            .iter()
            .find(|item| item.name == "stage TCP")
            .unwrap();
        assert_eq!(stage.relation, "worse");
        assert_eq!(stage.evidence_ids, vec!["tcp_001".to_string()]);
        assert!(comparison
            .not_established
            .iter()
            .any(|note| note.contains("stored baseline")));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_baseline_is_an_error() {
        let dir =
            std::env::temp_dir().join(format!("pathtrial-baseline-missing-{}", std::process::id()));
        let report_path = dir.join("now.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&report("PASS")).unwrap(),
        )
        .unwrap();
        let error = run(&BaselineArgs {
            action: BaselineAction::Compare(BaselineCompareArgs {
                report: report_path,
                dir: Some(dir.clone()),
                format: OutputFormat::Summary,
            }),
        })
        .unwrap_err();
        assert!(error.contains("no local baseline"), "{error}");
        let _ = fs::remove_dir_all(dir);
    }
}
