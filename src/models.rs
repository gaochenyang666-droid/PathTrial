//! Core data model for PathTrial reports.
//!
//! The report is the product surface: every finding must point at real probe
//! identifiers, and every status must be explainable from recorded data.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Version of the report schema. 1.5.0 adds the `quic` probe kind and detail.
pub const SCHEMA_VERSION: &str = "1.5.0";

/// Uniform status vocabulary for stages and findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    /// The check reached its documented pass condition.
    Pass,
    /// The check completed but showed an abnormal signal.
    Warn,
    /// The check clearly violated its expected condition.
    Fail,
    /// Not applicable, or required preconditions were absent.
    Skip,
    /// Executed, but evidence is not sufficient for a verdict.
    Inconclusive,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
            Status::Inconclusive => "INCONCLUSIVE",
        }
    }

    pub fn is_problem(self) -> bool {
        matches!(self, Status::Warn | Status::Fail)
    }

    /// Anything worth surfacing to a reader: problems plus cases where the
    /// evidence was insufficient. SKIP is intentionally excluded.
    pub fn is_notable(self) -> bool {
        matches!(self, Status::Warn | Status::Fail | Status::Inconclusive)
    }
}

/// Address family under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::Ipv4 => "IPv4",
            Family::Ipv6 => "IPv6",
        }
    }
}

/// Deterministic confidence buckets. These are rule outputs, not statistical
/// probabilities, and the rules are documented in `analysis::confidence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Moderate,
    High,
}

/// Severity of a finding, independent of the stage status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Fail,
}

/// Kind of probe that produced a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    System,
    Route,
    Dns,
    Tcp,
    Tls,
    Http,
    Icmp,
    Trace,
    UdpObservation,
    Proxy,
    Quic,
}

/// Outcome of a single probe, describing that probe only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Ok,
    Fail,
    NotApplicable,
}

/// Network error categories used for aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetError {
    Timeout,
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionReset,
    DnsFailure,
    TlsTransport,
    Certificate,
    Other(String),
}

impl NetError {
    pub fn label(&self) -> String {
        match self {
            NetError::Timeout => "timeout".to_string(),
            NetError::ConnectionRefused => "connection_refused".to_string(),
            NetError::NetworkUnreachable => "network_unreachable".to_string(),
            NetError::HostUnreachable => "host_unreachable".to_string(),
            NetError::ConnectionReset => "connection_reset".to_string(),
            NetError::DnsFailure => "dns_failure".to_string(),
            NetError::TlsTransport => "tls_transport".to_string(),
            NetError::Certificate => "certificate".to_string(),
            NetError::Other(text) => format!("other:{text}"),
        }
    }
}

/// Certificate facts gathered during a TLS probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub days_remaining: Option<i64>,
    pub sans: Vec<String>,
    pub chain_len: usize,
}

/// Certificate verification result, kept separate from transport handshake
/// success so the two failure modes are never conflated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Verified,
    Failed(String),
    NotChecked,
}

/// Structured detail for every probe. `type` is the discriminant so the JSON
/// stays self-describing for downstream tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeDetail {
    TcpConnect {
        connect_ms: Option<f64>,
        error: Option<NetError>,
    },
    TlsHandshake {
        handshake_ms: Option<f64>,
        transport_ok: bool,
        verification: Verification,
        protocol: Option<String>,
        cipher_suite: Option<String>,
        sni: String,
        cert: Option<CertInfo>,
        error: Option<NetError>,
        insecure_retry: bool,
    },
    DnsQuery {
        resolver: String,
        record_type: String,
        answers: Vec<String>,
        cname_chain: Vec<String>,
        query_ms: f64,
        rcode: Option<String>,
        error: Option<String>,
        fake_ip_suspected: bool,
    },
    Route {
        family: String,
        purpose: String,
        gateway: Option<String>,
        interface: Option<String>,
        raw_error: Option<String>,
    },
    SystemInventory {
        interface_count: usize,
        vpn_like_interfaces: Vec<String>,
        has_global_ipv6: bool,
        notes: Vec<String>,
    },
    Http {
        url: String,
        method: String,
        status: Option<u16>,
        expected_status: Option<u16>,
        matches_expectation: Option<bool>,
        http_version: Option<String>,
        location: Option<String>,
        body_bytes: usize,
        dns_ms: f64,
        connect_ms: f64,
        tls_ms: f64,
        ttfb_ms: f64,
        total_ms: f64,
        tls_verified: Option<bool>,
        error: Option<NetError>,
    },
    Icmp {
        sent: u32,
        received: u32,
        loss_pct: f64,
        rtt_min: Option<f64>,
        rtt_avg: Option<f64>,
        rtt_max: Option<f64>,
        jitter: Option<f64>,
        error: Option<String>,
    },
    Trace {
        hops: Vec<TraceHop>,
        reached: bool,
        protocol: String,
        error: Option<String>,
    },
    UdpEcho {
        seq: u32,
        session: String,
        sent_bytes: usize,
        received_bytes: Option<usize>,
        result: String,
        rtt_ms: Option<f64>,
        note: String,
    },
    ProxyExchange {
        proxy: String,
        proxy_kind: String,
        target: String,
        proxy_tcp_ms: f64,
        negotiation_ms: f64,
        connect_ms: f64,
        tls_ms: f64,
        http_ms: f64,
        http_status: Option<u16>,
        tunnel_ok: bool,
        tls_verified: Option<bool>,
        error: Option<String>,
    },
    /// Aggregate of alternating direct and proxied requests. The two paths may
    /// use different DNS, egress and routing, so this record never asserts a
    /// cause for a difference.
    PathComparison {
        rounds_requested: u32,
        rounds_completed: u32,
        direct_total: u32,
        direct_success: u32,
        proxy_total: u32,
        proxy_success: u32,
        direct_median_ms: Option<f64>,
        proxy_median_ms: Option<f64>,
        direct_min_ms: Option<f64>,
        proxy_min_ms: Option<f64>,
        direct_errors: Vec<String>,
        proxy_errors: Vec<String>,
        direct_dns: String,
        proxy_dns: String,
        note: String,
    },
    /// Real QUIC handshake and optional HTTP/3 exchange. The stage field names
    /// the last completed or attempted phase so transport, TLS, ALPN and
    /// application failures stay separate.
    Quic {
        host: String,
        port: u16,
        family: String,
        server_name: String,
        alpn_requested: String,
        alpn: Option<String>,
        handshake_ms: Option<f64>,
        handshake_ok: bool,
        tls_verified: Option<bool>,
        http3_status: Option<u16>,
        http3_bytes: usize,
        http3_ttfb_ms: Option<f64>,
        http3_total_ms: Option<f64>,
        stage: String,
        error: Option<String>,
    },
    /// Evidence record for UDP observations. V1 does not probe UDP, but the
    /// model keeps the classification explicit so ICMP replies can never be
    /// counted as a successful UDP session.
    UdpObservation {
        observation: UdpObservation,
        implies_udp_session: bool,
        note: String,
    },
    /// Aggregate-only record used by golden fixtures and by reports imported
    /// from external measurements that lack per-request samples.
    Aggregate {
        total: usize,
        success: usize,
        mean_ms: Option<f64>,
        aggregate_only: bool,
    },
}

/// How a UDP-related observation was obtained. Ordering matters for the
/// classification rules in `analysis::udp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpObservation {
    IcmpPortUnreachable,
    ApplicationEchoReply,
    NoResponseToInvalidPayload,
    QuicHandshakeTimeout,
    QuicHandshakeComplete,
}

/// One hop in a traceroute run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop: u32,
    pub address: Option<String>,
    pub rtt_ms: Vec<f64>,
    pub timed_out: bool,
}

/// A single recorded probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub id: String,
    pub kind: ProbeKind,
    pub outcome: ProbeOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<Family>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    pub detail: ProbeDetail,
}

/// One fixed diagnostic stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub id: String,
    pub name: String,
    pub status: Status,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evidence: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
}

/// Per-family TCP/TLS aggregate for the comparison stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilySummary {
    pub family: Family,
    pub address: String,
    pub tcp_total: usize,
    pub tcp_success: usize,
    pub tcp_success_rate: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_median_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_max_ms: Option<f64>,
    pub error_classes: BTreeMap<String, usize>,
    /// Raw successful connect durations. Empty when the summary is aggregate
    /// only, in which case percentile statistics are intentionally omitted.
    pub samples_ms: Vec<f64>,
    pub aggregate_only: bool,
    pub tls_total: usize,
    pub tls_transport_ok: usize,
    pub tls_verified_ok: usize,
    pub window_started_at: String,
    pub window_finished_at: String,
    pub probe_ids: Vec<String>,
}

/// A claim with its evidence, confidence and explicit unknowns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub claim: String,
    pub severity: Severity,
    pub status: Status,
    pub evidence: Vec<String>,
    pub not_established: Vec<String>,
    pub confidence: Confidence,
    pub limits: Vec<String>,
}

/// A concrete, non-destructive next step for the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub action: String,
    pub rationale: String,
    pub evidence: Vec<String>,
}

/// Local network interface as observed at scan start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// Heuristic flag only: a TUN-like name is a hint, not proof of a VPN.
    pub vpn_like: bool,
}

/// A routing table entry relevant to the scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub family: String,
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub note: Option<String>,
}

/// Read-only local link facts available without elevated privileges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalLinkInfo {
    pub interface: String,
    pub up: bool,
    pub is_wifi: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_mbps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<String>,
    pub notes: Vec<String>,
}

/// Snapshot of the machine environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,
    pub interfaces: Vec<InterfaceInfo>,
    pub ipv4_local: bool,
    pub ipv6_local: bool,
    pub has_global_ipv6: bool,
    pub vpn_like_interfaces: Vec<String>,
    pub default_route_v4: Option<RouteInfo>,
    pub default_route_v6: Option<RouteInfo>,
    pub target_route: Option<RouteInfo>,
    /// Names of proxy-related environment variables that are set. Values are
    /// never recorded because they can embed credentials.
    pub proxy_env_names: Vec<String>,
    pub notes: Vec<String>,
}

/// What the user asked to scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub port: u16,
    pub profile: String,
    pub literal_ip: bool,
}

/// Effective configuration for the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    pub rounds: usize,
    pub timeout_ms: u64,
    pub interval_ms: u64,
    pub max_total_seconds: u64,
    pub connect_budget: usize,
    pub tls_enabled: bool,
    pub allow_insecure_tls: bool,
    pub output_format: String,
    pub redact_ips: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
}

/// What was redacted from the shared report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    pub applied: bool,
    pub ips_masked: usize,
    pub notes: Vec<String>,
}

/// The complete diagnostic report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub target: Target,
    pub configuration: Configuration,
    pub environment: Environment,
    pub stages: Vec<Stage>,
    pub probes: Vec<Probe>,
    pub summaries: Vec<FamilySummary>,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    pub limitations: Vec<String>,
    pub redaction: Redaction,
}

impl Report {
    /// Highest severity among findings, used for the process exit code.
    pub fn worst_status(&self) -> Status {
        // Stage statuses are included so a stage that failed without emitting a
        // finding cannot hide behind an unrelated PASS.
        worst_of(
            self.findings
                .iter()
                .map(|finding| finding.status)
                .chain(self.stages.iter().map(|stage| stage.status)),
        )
    }
}

/// Precedence used for exit codes: FAIL beats WARN, WARN beats INCONCLUSIVE.
/// SKIP never escalates, because it means "not applicable".
pub fn worst_of(statuses: impl Iterator<Item = Status>) -> Status {
    statuses.fold(Status::Pass, |worst, status| match (worst, status) {
        (Status::Fail, _) | (_, Status::Fail) => Status::Fail,
        (Status::Warn, _) | (_, Status::Warn) => Status::Warn,
        (Status::Inconclusive, _) | (_, Status::Inconclusive) => Status::Inconclusive,
        _ => worst,
    })
}

#[cfg(test)]
mod tests {
    use super::{worst_of, Status};

    #[test]
    fn fail_outranks_warn_and_inconclusive() {
        assert_eq!(
            worst_of([Status::Warn, Status::Inconclusive].into_iter()),
            Status::Warn
        );
        assert_eq!(
            worst_of([Status::Inconclusive, Status::Fail].into_iter()),
            Status::Fail
        );
        assert_eq!(
            worst_of([Status::Pass, Status::Fail, Status::Warn].into_iter()),
            Status::Fail
        );
    }

    #[test]
    fn skip_never_escalates() {
        assert_eq!(
            worst_of([Status::Pass, Status::Skip].into_iter()),
            Status::Pass
        );
        assert_eq!(worst_of([Status::Skip].into_iter()), Status::Pass);
    }

    #[test]
    fn inconclusive_alone_is_reported() {
        assert_eq!(
            worst_of([Status::Inconclusive].into_iter()),
            Status::Inconclusive
        );
    }
}
