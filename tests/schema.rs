//! The generated report must validate against the published JSON Schema, and
//! aggregate fixture reports must validate too.

mod common;

use common::{load, report_from_fixture};

fn validator() -> jsonschema::Validator {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/report.schema.json")).expect("schema parses");
    jsonschema::validator_for(&schema).expect("schema compiles")
}

fn assert_valid(value: &serde_json::Value) {
    let validator = validator();
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|error| format!("{} at {}", error, error.instance_path))
        .collect();
    assert!(errors.is_empty(), "schema violations: {errors:#?}");
}

#[test]
fn fixture_reports_validate() {
    for case in [
        "case_a_ipv4_slow",
        "case_b_tcp_ok_tls_fail",
        "case_c_tcp_all_fail",
        "case_d_udp_evidence",
        "case_e_single_timeout",
    ] {
        let report = report_from_fixture(&load(case));
        let value = serde_json::to_value(&report).expect("serializes");
        assert_valid(&value);
    }
}

#[test]
fn schema_rejects_reports_without_evidence() {
    let mut report = report_from_fixture(&load("case_c_tcp_all_fail"));
    let analysis = pathtrial::analysis::analyze(&pathtrial::analysis::AnalysisContext {
        probes: &report.probes,
        summaries: &report.summaries,
        stages: &report.stages,
        tls_enabled: true,
        fake_ip_suspected: false,
        target_scope: None,
        literal_target: true,
        suppress_comparison: false,
    });
    report.findings = analysis.findings;
    if let Some(finding) = report.findings.first_mut() {
        finding.evidence.clear();
    }
    let value = serde_json::to_value(&report).expect("serializes");
    assert!(!validator().is_valid(&value), "evidence must be required");
}
