//! Shared helpers for integration tests.

use std::collections::BTreeMap;

use pathtrial::models::{
    Configuration, Environment, Family, FamilySummary, Probe, ProbeDetail, ProbeKind, ProbeOutcome,
    Redaction, Report, Stage, Status, Target, UdpObservation, SCHEMA_VERSION,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TcpAggregate {
    pub family: String,
    pub total: usize,
    pub success: usize,
    #[serde(default)]
    pub mean_ms: Option<f64>,
    #[serde(default)]
    pub errors: BTreeMap<String, usize>,
}

#[derive(Debug, Deserialize)]
pub struct TlsAggregate {
    pub family: String,
    pub total: usize,
    pub transport_ok: usize,
    pub verified_ok: usize,
}

#[derive(Debug, Deserialize)]
pub struct UdpAggregate {
    pub observation: String,
    pub implies_udp_session: bool,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct Fixture {
    pub case: String,
    #[allow(dead_code)]
    pub description: String,
    #[allow(dead_code)]
    pub provenance: String,
    #[serde(default)]
    pub tcp: Vec<TcpAggregate>,
    #[serde(default)]
    pub tls: Vec<TlsAggregate>,
    #[serde(default)]
    pub udp: Vec<UdpAggregate>,
    #[allow(dead_code)]
    pub expected_rules: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub must_be_uncertain: Vec<String>,
}

pub fn load(case: &str) -> Fixture {
    let path = format!("{}/tests/fixtures/{case}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    serde_json::from_str(&text).expect("fixture parses")
}

fn family_of(text: &str) -> Family {
    if text.eq_ignore_ascii_case("ipv6") {
        Family::Ipv6
    } else {
        Family::Ipv4
    }
}

fn observation_of(text: &str) -> UdpObservation {
    match text {
        "icmp_port_unreachable" => UdpObservation::IcmpPortUnreachable,
        "application_echo_reply" => UdpObservation::ApplicationEchoReply,
        "no_response_to_invalid_payload" => UdpObservation::NoResponseToInvalidPayload,
        "quic_handshake_timeout" => UdpObservation::QuicHandshakeTimeout,
        "quic_handshake_complete" => UdpObservation::QuicHandshakeComplete,
        other => panic!("unknown observation {other}"),
    }
}

/// Build a report from aggregate fixture data. No per-request timings are
/// invented: `samples_ms` stays empty and `aggregate_only` is true.
pub fn report_from_fixture(fixture: &Fixture) -> Report {
    let mut probes: Vec<Probe> = Vec::new();
    let mut summaries: Vec<FamilySummary> = Vec::new();
    let stamp = "2026-01-01T00:00:00.000Z".to_string();

    for aggregate in &fixture.tcp {
        let family = family_of(&aggregate.family);
        let id = format!(
            "tcp_{}_agg",
            if family == Family::Ipv4 {
                "ipv4"
            } else {
                "ipv6"
            }
        );
        probes.push(Probe {
            id: id.clone(),
            kind: ProbeKind::Tcp,
            outcome: ProbeOutcome::Ok,
            family: Some(family),
            target: Some("192.0.2.10".to_string()),
            port: Some(443),
            started_at: stamp.clone(),
            duration_ms: None,
            detail: ProbeDetail::Aggregate {
                total: aggregate.total,
                success: aggregate.success,
                mean_ms: aggregate.mean_ms,
                aggregate_only: true,
            },
        });

        let tls = fixture
            .tls
            .iter()
            .find(|entry| family_of(&entry.family) == family);
        summaries.push(FamilySummary {
            family,
            address: "192.0.2.10".to_string(),
            tcp_total: aggregate.total,
            tcp_success: aggregate.success,
            tcp_success_rate: if aggregate.total == 0 {
                0.0
            } else {
                aggregate.success as f64 / aggregate.total as f64
            },
            tcp_mean_ms: aggregate.mean_ms,
            tcp_median_ms: None,
            tcp_max_ms: None,
            error_classes: aggregate.errors.clone(),
            samples_ms: Vec::new(),
            aggregate_only: true,
            tls_total: tls.map(|entry| entry.total).unwrap_or(0),
            tls_transport_ok: tls.map(|entry| entry.transport_ok).unwrap_or(0),
            tls_verified_ok: tls.map(|entry| entry.verified_ok).unwrap_or(0),
            window_started_at: stamp.clone(),
            window_finished_at: stamp.clone(),
            probe_ids: vec![id],
        });
    }

    for (index, observation) in fixture.udp.iter().enumerate() {
        probes.push(Probe {
            id: format!("udp_observation_{:03}", index + 1),
            kind: ProbeKind::UdpObservation,
            outcome: ProbeOutcome::NotApplicable,
            family: None,
            target: Some("192.0.2.10".to_string()),
            port: Some(39000),
            started_at: stamp.clone(),
            duration_ms: None,
            detail: ProbeDetail::UdpObservation {
                observation: observation_of(&observation.observation),
                implies_udp_session: observation.implies_udp_session,
                note: observation.note.clone(),
            },
        });
    }

    let stage = |id: &str, name: &str, status: Status| Stage {
        id: id.to_string(),
        name: name.to_string(),
        status,
        summary: "fixture".to_string(),
        reason: None,
        evidence: Vec::new(),
        started_at: stamp.clone(),
        finished_at: stamp.clone(),
    };

    Report {
        schema_version: SCHEMA_VERSION.to_string(),
        tool_version: "test".to_string(),
        run_id: format!("fixture-{}", fixture.case),
        started_at: stamp.clone(),
        finished_at: stamp.clone(),
        target: Target {
            input: "192.0.2.10".to_string(),
            host: None,
            port: 443,
            profile: "web".to_string(),
            literal_ip: true,
        },
        configuration: Configuration {
            rounds: 20,
            timeout_ms: 3000,
            interval_ms: 200,
            max_total_seconds: 180,
            connect_budget: 40,
            tls_enabled: true,
            allow_insecure_tls: false,
            output_format: "json".to_string(),
            redact_ips: false,
            bind_interface: None,
        },
        environment: Environment {
            os: "test".to_string(),
            arch: "test".to_string(),
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
        stages: vec![
            stage("system", "系统环境", Status::Pass),
            stage("dns", "DNS", Status::Pass),
            stage("tcp_tls", "TCP 与 TLS", Status::Pass),
            stage("compare", "双栈对照", Status::Pass),
            stage("report", "报告", Status::Pass),
        ],
        probes,
        summaries,
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
