use std::process::Command;

use pathtrial::fingerprint::{
    diff_reports, DnsFingerprint, ExitCapture, FingerprintComponents, FingerprintEnvironment,
    FingerprintReport, ProxyHop, TlsFingerprint, FINGERPRINT_SCHEMA_VERSION,
};
use pathtrial::models::{Confidence, Finding, Severity, Status};
use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

fn finding(claim: &str, evidence: Vec<&str>) -> Finding {
    Finding {
        id: "F001".to_string(),
        rule_id: "R901".to_string(),
        claim: claim.to_string(),
        severity: Severity::Info,
        status: Status::Pass,
        evidence: evidence.iter().map(|item| item.to_string()).collect(),
        probe_id: evidence.first().copied().unwrap_or("none").to_string(),
        not_established: vec!["synthetic test".to_string()],
        confidence: Confidence::Moderate,
        limits: vec!["synthetic test".to_string()],
    }
}

fn report(exit_v4: &str, proxy: &str) -> FingerprintReport {
    let components = FingerprintComponents {
        component_version: "local-path-v1".to_string(),
        exit_ipv4: ExitCapture {
            ip: Some(exit_v4.to_string()),
            probe_id: Some("http_ipv4_001".to_string()),
            error: None,
        },
        exit_ipv6: ExitCapture {
            ip: Some("2001:db8::2".to_string()),
            probe_id: Some("http_ipv6_001".to_string()),
            error: None,
        },
        dns: DnsFingerprint {
            resolvers: vec!["192.0.2.53".to_string()],
            ipv4: vec!["192.0.2.10".to_string()],
            ipv6: vec!["2001:db8::10".to_string()],
            cname_chain: vec!["edge.example".to_string()],
            fake_ip_suspected: false,
            probe_ids: vec!["dns_ipv4_001".to_string()],
        },
        tls: Some(TlsFingerprint {
            protocol: Some("TLSv1.3".to_string()),
            cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
            cert_sha256: Some("a".repeat(64)),
            issuer: Some("test".to_string()),
            transport_ok: true,
            verified: true,
            probe_id: "tls_ipv4_001".to_string(),
        }),
        ip_fork: "dual_stack".to_string(),
        environment: FingerprintEnvironment {
            interface_count: 1,
            ipv4_local: true,
            ipv6_local: true,
            vpn_like_interfaces: Vec::new(),
            proxy_hops: vec![ProxyHop {
                source: "explicit".to_string(),
                endpoint: proxy.to_string(),
            }],
            system_probe_id: Some("system_001".to_string()),
        },
    };
    FingerprintReport {
        schema_version: FINGERPRINT_SCHEMA_VERSION.to_string(),
        tool_version: "test".to_string(),
        run_id: format!("run-{exit_v4}-{proxy}"),
        captured_at: "2026-10-31T00:00:00.000Z".to_string(),
        target: "https://example.com/".to_string(),
        fingerprint: if exit_v4 == "198.51.100.1" {
            "a".repeat(64)
        } else {
            "b".repeat(64)
        },
        components,
        probes: Vec::new(),
        findings: vec![finding("synthetic", vec!["system_001"])],
        limitations: vec!["synthetic test".to_string()],
    }
}

#[test]
fn fingerprint_diff_detects_exit_and_proxy_changes() {
    let before = report("198.51.100.1", "socks5://127.0.0.1:1080");
    let after = report("198.51.100.2", "socks5://127.0.0.1:1081");
    let diff = diff_reports(&before, &after);
    assert_eq!(diff.verdict, "CHANGED");
    assert!(diff
        .changes
        .iter()
        .any(|change| change.component == "exit_ipv4"));
    assert!(diff
        .changes
        .iter()
        .any(|change| change.component == "proxy_hops"));
    assert_eq!(diff.findings[0].status, Status::Fail);
}

#[test]
fn fingerprint_diff_identical_reports_is_stable() {
    let before = report("198.51.100.1", "socks5://127.0.0.1:1080");
    let diff = diff_reports(&before, &before.clone());
    assert_eq!(diff.verdict, "IDENTICAL");
    assert!(diff.changes.is_empty());
    assert_eq!(diff.findings[0].status, Status::Pass);
}

#[test]
fn fingerprint_and_diff_schemas_validate_synthetic_reports() {
    let evidence = Command::new(binary())
        .args(["schema", "--evidence"])
        .output()
        .expect("evidence schema command");
    assert!(evidence.status.success());
    let evidence: Value = serde_json::from_slice(&evidence.stdout).expect("evidence schema JSON");
    assert!(evidence["$id"]
        .as_str()
        .unwrap()
        .ends_with("evidence-1.0.0.json"));

    for (flag, schema_name) in [
        ("--fingerprint", "fingerprint.schema.json"),
        ("--fingerprint-diff", "fingerprint-diff.schema.json"),
    ] {
        let output = Command::new(binary())
            .args(["schema", flag])
            .output()
            .expect("schema command");
        assert!(output.status.success(), "{flag}");
        let schema: Value = serde_json::from_slice(&output.stdout).expect("schema JSON");
        assert!(schema["$id"]
            .as_str()
            .unwrap()
            .ends_with(&schema_name.replace(".schema.json", "-1.0.0.json")));
    }

    let schema: Value = serde_json::from_slice(
        &Command::new(binary())
            .args(["schema", "--fingerprint"])
            .output()
            .expect("fingerprint schema")
            .stdout,
    )
    .expect("schema JSON");
    let report_value = serde_json::to_value(report("198.51.100.1", "socks5://127.0.0.1:1080"))
        .expect("report JSON");
    let validator = jsonschema::validator_for(&schema).expect("validator");
    let errors = validator
        .iter_errors(&report_value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "{errors:#?}");

    let diff_schema: Value = serde_json::from_slice(
        &Command::new(binary())
            .args(["schema", "--fingerprint-diff"])
            .output()
            .expect("diff schema")
            .stdout,
    )
    .expect("diff schema JSON");
    let diff = diff_reports(
        &report("198.51.100.1", "socks5://127.0.0.1:1080"),
        &report("198.51.100.2", "socks5://127.0.0.1:1081"),
    );
    let diff = serde_json::to_value(diff).expect("diff JSON");
    let validator = jsonschema::validator_for(&diff_schema).expect("diff validator");
    let errors = validator
        .iter_errors(&diff)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "{errors:#?}");
}

#[test]
fn fingerprint_rejects_non_https_targets_before_probing() {
    let output = Command::new(binary())
        .args(["fingerprint", "http://example.com/"])
        .output()
        .expect("fingerprint");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HTTPS"));
}
