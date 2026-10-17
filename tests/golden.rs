//! Golden regression tests built from real observations recorded during the
//! RackNerd troubleshooting session (2026-10-15 to 2026-10-17).

mod common;

use common::{load, report_from_fixture};
use pathtrial::analysis::{analyze, primary_finding, AnalysisContext};
use pathtrial::models::{Confidence, Status};

fn analyze_report(report: &pathtrial::models::Report) -> pathtrial::analysis::Analysis {
    analyze(&AnalysisContext {
        probes: &report.probes,
        summaries: &report.summaries,
        stages: &report.stages,
        tls_enabled: true,
        fake_ip_suspected: false,
        target_scope: None,
        literal_target: true,
        suppress_comparison: false,
    })
}

fn analyze_case(case: &str) -> (common::Fixture, pathtrial::analysis::Analysis) {
    let fixture = load(case);
    let report = report_from_fixture(&fixture);
    let analysis = analyze_report(&report);
    (fixture, analysis)
}

#[test]
fn case_a_slow_ipv4_is_reported_as_family_delta() {
    let (fixture, analysis) = analyze_case("case_a_ipv4_slow");
    for rule in &fixture.expected_rules {
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| &finding.rule_id == rule),
            "expected rule {rule} in {:?}",
            analysis
                .findings
                .iter()
                .map(|finding| &finding.rule_id)
                .collect::<Vec<_>>()
        );
    }
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R007")
        .expect("family delta finding");
    assert!(
        finding.claim.contains("IPv6"),
        "claim was {}",
        finding.claim
    );
    assert_eq!(finding.status, Status::Warn);
    // Aggregate input must lower confidence and never invent distributions.
    assert_eq!(finding.confidence, Confidence::Low);
    for expected in &fixture.must_be_uncertain {
        assert!(
            finding.not_established.iter().any(|item| item == expected),
            "missing not_established {expected}"
        );
    }
    assert!(!finding.claim.contains("封锁"), "must not assert blocking");
}

#[test]
fn case_b_tcp_ok_tls_fail_is_separate_from_tcp() {
    let (_, analysis) = analyze_case("case_b_tcp_ok_tls_fail");
    let tls = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R008")
        .expect("tls transport finding");
    assert_eq!(tls.status, Status::Fail);
    assert!(tls.claim.contains("TLS"));
    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.rule_id != "R010"),
        "TLS must not be reported as verified when it never completed"
    );
}

#[test]
fn case_c_total_failure_does_not_claim_blocking() {
    let (fixture, analysis) = analyze_case("case_c_tcp_all_fail");
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R004")
        .expect("tcp failure finding");
    assert_eq!(finding.status, Status::Fail);
    for expected in &fixture.must_be_uncertain {
        assert!(
            finding.not_established.iter().any(|item| item == expected),
            "missing not_established {expected}"
        );
    }
    let text = serde_json::to_string(&analysis.findings).unwrap();
    assert!(!text.contains("已被封锁"), "must not assert blocking");
}

#[test]
fn case_d_udp_evidence_kinds_are_never_conflated() {
    let (_, analysis) = analyze_case("case_d_udp_evidence");
    let udp_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "R013")
        .collect();
    assert_eq!(udp_findings.len(), 3);

    let icmp = udp_findings
        .iter()
        .find(|finding| finding.claim.contains("ICMP"))
        .expect("icmp finding");
    assert_eq!(icmp.status, Status::Skip);
    assert!(icmp.claim.contains("不能证明"));

    let invalid = udp_findings
        .iter()
        .find(|finding| finding.claim.contains("无效载荷"))
        .expect("invalid payload finding");
    assert_eq!(invalid.status, Status::Inconclusive);

    let echo = udp_findings
        .iter()
        .find(|finding| finding.claim.contains("真实 UDP"))
        .expect("echo finding");
    assert_eq!(echo.status, Status::Pass);

    let passes = udp_findings
        .iter()
        .filter(|finding| finding.status == Status::Pass)
        .count();
    assert_eq!(passes, 1, "only a real echo may count as success");
}

#[test]
fn case_e_single_timeout_stays_inconclusive() {
    let (_, analysis) = analyze_case("case_e_single_timeout");
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R011")
        .expect("inconclusive finding");
    assert_eq!(finding.status, Status::Inconclusive);
    assert_eq!(finding.confidence, Confidence::Low);
    assert!(primary_finding(&analysis.findings).is_some());
}

#[test]
fn case_f_transport_ok_but_certificate_failed() {
    let (_, analysis) = analyze_case("case_f_cert_invalid");
    let cert = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R009")
        .expect("certificate finding");
    assert_eq!(cert.status, Status::Warn);
    assert!(cert.claim.contains("证书"));
    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.rule_id != "R010"),
        "a failed verification must not be reported as verified"
    );
}

#[test]
fn case_g_single_success_keeps_latency_confidence_low() {
    let (fixture, analysis) = analyze_case("case_g_single_success");
    let loss = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R005")
        .expect("partial loss finding");
    assert_eq!(loss.status, Status::Warn);
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
    assert!(!fixture.expected_rules.is_empty());
}

#[test]
fn case_h_latency_gap_is_not_reported_as_loss() {
    let (_, analysis) = analyze_case("case_h_latency_gap");
    let delta = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R007")
        .expect("latency delta finding");
    assert_eq!(delta.status, Status::Warn);
    assert!(delta.claim.contains("IPv6"));
    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.rule_id != "R005"),
        "equal success rates must not produce a loss finding"
    );
}

#[test]
fn case_i_refused_is_not_a_path_failure() {
    let (_, analysis) = analyze_case("case_i_all_refused");
    let refused = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "R015")
        .expect("refused finding");
    assert_eq!(refused.status, Status::Pass);
    assert!(refused.claim.contains("可达"));
    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.rule_id != "R004"),
        "a refusal must not be reported as a connectivity failure"
    );
}

#[test]
fn every_finding_cites_existing_probes() {
    for case in [
        "case_a_ipv4_slow",
        "case_b_tcp_ok_tls_fail",
        "case_c_tcp_all_fail",
        "case_d_udp_evidence",
        "case_e_single_timeout",
        "case_f_cert_invalid",
        "case_g_single_success",
        "case_h_latency_gap",
        "case_i_all_refused",
    ] {
        let fixture = load(case);
        let report = report_from_fixture(&fixture);
        let analysis = analyze_report(&report);
        let ids: std::collections::BTreeSet<&str> = report
            .probes
            .iter()
            .map(|probe| probe.id.as_str())
            .collect();
        for finding in &analysis.findings {
            assert!(
                !finding.evidence.is_empty(),
                "{case}: finding {} has no evidence",
                finding.rule_id
            );
            for id in &finding.evidence {
                assert!(ids.contains(id.as_str()), "{case}: unknown probe id {id}");
            }
        }
    }
}
