//! Command line surface. Kept intentionally small for V1: one `scan` command
//! with stable flags, plus `schema` so automation can fetch the report schema.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Profile presets only decide which port and whether TLS applies. They never
/// change the order of the diagnostic stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// HTTPS-style target: TLS enabled, default port 443.
    Web,
    /// Raw TCP target: no TLS, port from --port (default 443).
    Tcp,
    /// SSH-style target: no TLS, default port 22.
    Ssh,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Web => "web",
            Profile::Tcp => "tcp",
            Profile::Ssh => "ssh",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Profile::Web | Profile::Tcp => 443,
            Profile::Ssh => 22,
        }
    }

    pub fn tls_by_default(self) -> bool {
        matches!(self, Profile::Web)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human readable terminal summary (default).
    Summary,
    /// Machine readable report on stdout.
    Json,
    /// Markdown report on stdout, suitable for issues and tickets.
    Markdown,
}

impl OutputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Summary => "summary",
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "markdown",
        }
    }
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Hostname or literal IP address to diagnose.
    pub target: String,

    /// TCP rounds per address family (1-200).
    #[arg(long, default_value_t = 20)]
    pub rounds: usize,

    /// Override the port implied by the profile.
    #[arg(long)]
    pub port: Option<u16>,

    /// Target profile preset.
    #[arg(long, value_enum, default_value_t = Profile::Web)]
    pub profile: Profile,

    /// Force TLS on top of the profile preset.
    #[arg(long)]
    pub tls: bool,

    /// Disable TLS even when the profile enables it.
    #[arg(long, conflicts_with = "tls")]
    pub no_tls: bool,

    /// Output format on stdout. Report files are always written unless --no-files.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,

    /// Per-connection timeout in milliseconds.
    #[arg(long, default_value_t = 3000)]
    pub timeout_ms: u64,

    /// Minimum delay between probes in milliseconds.
    #[arg(long, default_value_t = 200)]
    pub interval_ms: u64,

    /// Hard wall-clock budget for the whole scan in seconds.
    #[arg(long, default_value_t = 180)]
    pub max_seconds: u64,

    /// Directory for pathtrial-report.json/.md (defaults to the working directory).
    #[arg(long)]
    pub out_dir: Option<PathBuf>,

    /// Explicit output prefix, for example ./reports/run1 writes run1.json and
    /// run1.md. Existing files at that prefix are overwritten.
    #[arg(long, value_name = "PREFIX", conflicts_with = "no_files")]
    pub out: Option<PathBuf>,

    /// Do not write report files.
    #[arg(long)]
    pub no_files: bool,

    /// Diagnostic only: retry failed TLS handshakes without certificate
    /// verification to separate transport failure from trust failure.
    #[arg(long)]
    pub allow_insecure_tls: bool,

    /// Mask all IP literals in the generated reports.
    #[arg(long)]
    pub redact_ips: bool,

    /// Pin probe egress to a physical interface (for example en0) so a local
    /// TUN adapter cannot intercept the measurement. On Linux this requires
    /// root; on macOS it does not.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// TLS server name to use when the target is a literal IP address. Without
    /// it the IP itself is used and certificate verification will normally fail
    /// for public services.
    #[arg(long)]
    pub sni: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the fixed five-stage diagnostic scan.
    Scan(ScanArgs),
    /// Run a guided diagnosis for a common network problem scenario.
    Diagnose(DiagnoseArgs),
    /// Send one real HTTP/HTTPS request and report the timings per phase.
    Http(HttpArgs),
    /// ICMP echo with loss, RTT and jitter.
    Ping(PingArgs),
    /// Hop-by-hop route to the target.
    Trace(TraceArgs),
    /// Resolve a name against the system resolvers and optional extra servers.
    Dns(DnsArgs),
    /// Application-level UDP echo against a target you control.
    Udp(UdpArgs),
    /// Diagnose a SOCKS5 or HTTP CONNECT proxy path.
    Proxy(ProxyArgs),
    /// Perform a real QUIC handshake with an explicit ALPN.
    Quic(QuicArgs),
    /// Perform a real HTTP/3 GET over QUIC.
    Http3(Http3Args),
    /// Collect one side of an offline two-endpoint test.
    Collect(CollectArgs),
    /// Correlate independently collected client and server JSON reports.
    Correlate(CorrelateArgs),
    /// Run the local stdio MCP server for AI clients.
    Mcp(McpArgs),
    /// Compare two saved JSON reports with explicit comparability checks.
    Compare(CompareArgs),
    /// Render a saved JSON report offline.
    Report(ReportArgs),
    /// Store or compare a local baseline for one target.
    Baseline(BaselineArgs),
    /// Run a temporary local endpoint for repeatable tests.
    Endpoint(EndpointArgs),
    /// Print a JSON Schema to stdout.
    Schema(SchemaArgs),
}

#[derive(Debug, Args)]
pub struct SchemaArgs {
    /// Print the single-command envelope schema instead of the scan schema.
    #[arg(long)]
    pub command: bool,

    /// Print the guided diagnosis schema.
    #[arg(long, conflicts_with_all = ["command"])]
    pub diagnose: bool,

    /// Print the collect report schema.
    #[arg(long, conflicts_with_all = ["command", "diagnose"])]
    pub collect: bool,

    /// Print the correlation report schema.
    #[arg(long, conflicts_with_all = ["command", "diagnose", "collect"])]
    pub correlate: bool,
}

#[derive(Debug, Args)]
pub struct UdpArgs {
    /// Echo target as HOST:PORT (IPv6 needs brackets).
    #[arg(long)]
    pub target: String,

    /// Probe mode. Only `echo` is implemented.
    #[arg(long, default_value = "echo")]
    pub mode: String,

    /// Number of datagrams to send.
    #[arg(long, default_value_t = 10)]
    pub rounds: u32,

    /// Per-datagram timeout in milliseconds.
    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,

    /// Delay between datagrams in milliseconds.
    #[arg(long, default_value_t = 200)]
    pub interval_ms: u64,

    /// Wall-clock budget for the whole run in seconds.
    #[arg(long, default_value_t = 30)]
    pub max_seconds: u64,

    /// Payload size in bytes (17 minimum, 512 maximum).
    #[arg(long, default_value_t = 64)]
    pub payload: usize,

    /// Pin the socket to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Absolute target URL.
    pub url: String,

    /// Proxy URL: socks5://host:port or http://host:port.
    #[arg(long)]
    pub proxy: String,

    /// Timeout for one stage in milliseconds.
    #[arg(long, default_value_t = 8000)]
    pub timeout_ms: u64,

    /// Pin the proxy connection to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// Diagnostic only: accept any certificate.
    #[arg(long)]
    pub insecure: bool,

    /// Pre-authorized literal target IP. The URL host is retained for TLS SNI
    /// and the HTTP Host header.
    #[arg(long)]
    pub target_ip: Option<String>,

    /// TLS server name override for the proxied target.
    #[arg(long)]
    pub sni: Option<String>,

    /// Alternate direct and proxied requests against the same URL.
    #[arg(long)]
    pub compare_direct: bool,

    /// Rounds per path when --compare-direct is used (1-50).
    #[arg(long, default_value_t = 5)]
    pub rounds: u32,

    /// Delay between comparison requests in milliseconds.
    #[arg(long, default_value_t = 200)]
    pub interval_ms: u64,

    /// Wall-clock budget for --compare-direct in seconds.
    #[arg(long, default_value_t = 60)]
    pub max_seconds: u64,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct CompareArgs {
    /// Earlier report in JSON format.
    pub before: PathBuf,

    /// Later report in JSON format.
    pub after: PathBuf,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,

    /// Write <PREFIX>.json and <PREFIX>.md with the comparison.
    #[arg(long, value_name = "PREFIX")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AddressFamily {
    Auto,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiagnoseScenario {
    Web,
    Vps,
    Latency,
    Proxy,
    Local,
    Dns,
    Tcp,
    Tls,
    Http,
    DualStack,
    UdpQuic,
}

impl DiagnoseScenario {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnoseScenario::Web => "web",
            DiagnoseScenario::Vps => "vps",
            DiagnoseScenario::Latency => "latency",
            DiagnoseScenario::Proxy => "proxy",
            DiagnoseScenario::Local => "local",
            DiagnoseScenario::Dns => "dns",
            DiagnoseScenario::Tcp => "tcp",
            DiagnoseScenario::Tls => "tls",
            DiagnoseScenario::Http => "http",
            DiagnoseScenario::DualStack => "dual-stack",
            DiagnoseScenario::UdpQuic => "udp-quic",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            DiagnoseScenario::Vps | DiagnoseScenario::Tcp => 22,
            _ => 443,
        }
    }
}

#[derive(Debug, Args)]
pub struct DiagnoseArgs {
    /// Guided scenario to run.
    #[arg(long, value_enum, default_value_t = DiagnoseScenario::Web)]
    pub scenario: DiagnoseScenario,

    /// Hostname or literal IP. Not required for --scenario local.
    pub target: Option<String>,

    /// Target port. Defaults to 443, or 22 for vps/tcp scenarios.
    #[arg(long)]
    pub port: Option<u16>,

    /// Absolute URL for http/proxy scenarios. Built from target when omitted.
    #[arg(long)]
    pub url: Option<String>,

    /// Proxy URL for --scenario proxy.
    #[arg(long)]
    pub proxy: Option<String>,

    /// Extra DNS resolver to compare against.
    #[arg(long = "server")]
    pub servers: Vec<String>,

    /// Sampling rounds for TCP, ICMP or proxy checks.
    #[arg(long, default_value_t = 5)]
    pub rounds: u32,

    /// Per-stage timeout in milliseconds.
    #[arg(long, default_value_t = 3000)]
    pub timeout_ms: u64,

    /// Hard wall-clock budget for the whole diagnosis in seconds.
    #[arg(long, default_value_t = 60)]
    pub max_seconds: u64,

    /// Address family selection.
    #[arg(long, value_enum, default_value_t = AddressFamily::Auto)]
    pub family: AddressFamily,

    /// Mask IP literals in all rendered output.
    #[arg(long)]
    pub redact_ips: bool,

    /// Pin probe egress to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// TLS server name when target is a literal IP.
    #[arg(long)]
    pub sni: Option<String>,

    /// Original hostname retained for report identity.
    #[arg(long)]
    pub requested_host: Option<String>,

    /// HTTP Host header when the connection target is a literal IP.
    #[arg(long)]
    pub http_host: Option<String>,

    /// Authorized address for HTTP or proxy while the URL keeps its hostname.
    #[arg(long)]
    pub target_ip: Option<String>,

    /// Authorized IPv4 address for a deterministic dual-stack comparison.
    #[arg(long)]
    pub connect_ipv4: Option<String>,

    /// Authorized IPv6 address for a deterministic dual-stack comparison.
    #[arg(long)]
    pub connect_ipv6: Option<String>,

    /// Optional latency warning threshold in milliseconds.
    #[arg(long)]
    pub latency_warn_ms: Option<f64>,

    /// Optional latency failure threshold in milliseconds.
    #[arg(long)]
    pub latency_fail_ms: Option<f64>,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

impl DiagnoseArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.scenario != DiagnoseScenario::Local {
            if let Some(target) = self
                .target
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if target.len() > 2048 {
                    return Err("target is too long".to_string());
                }
                if target.contains(char::is_whitespace) {
                    return Err("target must not contain whitespace".to_string());
                }
            } else if self.url.as_deref().is_none_or(str::is_empty)
                || !matches!(
                    self.scenario,
                    DiagnoseScenario::Http | DiagnoseScenario::Proxy
                )
            {
                return Err("target is required, or --url for http/proxy scenarios".to_string());
            }
        }
        if self.scenario == DiagnoseScenario::Proxy
            && self.proxy.as_deref().is_none_or(str::is_empty)
        {
            return Err("--proxy is required for --scenario proxy".to_string());
        }
        if !(1..=50).contains(&self.rounds) {
            return Err("--rounds must be between 1 and 50".to_string());
        }
        if !(100..=30_000).contains(&self.timeout_ms) {
            return Err("--timeout-ms must be between 100 and 30000".to_string());
        }
        if !(5..=3600).contains(&self.max_seconds) {
            return Err("--max-seconds must be between 5 and 3600".to_string());
        }
        if self.port == Some(0) {
            return Err("--port must be between 1 and 65535".to_string());
        }
        for value in [self.latency_warn_ms, self.latency_fail_ms]
            .into_iter()
            .flatten()
        {
            if !value.is_finite() || value < 0.0 {
                return Err("latency thresholds must be finite and non-negative".to_string());
            }
        }
        for (label, value) in [
            ("--connect-ipv4", self.connect_ipv4.as_deref()),
            ("--connect-ipv6", self.connect_ipv6.as_deref()),
            ("--target-ip", self.target_ip.as_deref()),
        ] {
            if let Some(value) = value {
                value
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| format!("{label} must be a literal IP address"))?;
            }
        }
        for (label, value) in [
            ("--requested-host", self.requested_host.as_deref()),
            ("--http-host", self.http_host.as_deref()),
            ("--sni", self.sni.as_deref()),
        ] {
            if let Some(value) = value {
                crate::util::validate_host_token(label, value)?;
            }
        }
        if let (Some(warn), Some(fail)) = (self.latency_warn_ms, self.latency_fail_ms) {
            if warn > fail {
                return Err("--latency-warn-ms must not exceed --latency-fail-ms".to_string());
            }
        }
        Ok(())
    }

    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.scenario.default_port())
    }
}

#[derive(Debug, Args)]
pub struct QuicArgs {
    /// Hostname or literal IP address.
    pub host: String,

    /// UDP port for QUIC.
    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Address family selection.
    #[arg(long, value_enum, default_value_t = AddressFamily::Auto)]
    pub family: AddressFamily,

    /// ALPN protocol to require. Defaults to h3.
    #[arg(long, default_value = "h3")]
    pub alpn: String,

    /// Per-stage timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,

    /// Wall-clock budget for the whole probe in seconds.
    #[arg(long, default_value_t = 15)]
    pub max_seconds: u64,

    /// Pin the UDP socket to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// Additional PEM trust anchors for a local test server.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,

    /// TLS server name override, useful for a literal IP target.
    #[arg(long)]
    pub sni: Option<String>,

    /// Diagnostic only: accept any QUIC certificate.
    #[arg(long)]
    pub insecure: bool,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct Http3Args {
    /// Absolute https URL.
    pub url: String,

    /// Address family selection.
    #[arg(long, value_enum, default_value_t = AddressFamily::Auto)]
    pub family: AddressFamily,

    /// Per-stage timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,

    /// Wall-clock budget for the whole probe in seconds.
    #[arg(long, default_value_t = 15)]
    pub max_seconds: u64,

    /// Pin the UDP socket to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// Additional PEM trust anchors for a local test server.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,

    /// TLS server name override, useful for a literal IP target.
    #[arg(long)]
    pub sni: Option<String>,

    /// Diagnostic only: accept any QUIC certificate.
    #[arg(long)]
    pub insecure: bool,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CollectRole {
    Client,
    Server,
}

#[derive(Debug, Args)]
pub struct CollectArgs {
    /// Run as the connecting client or the listening server.
    #[arg(long, value_enum)]
    pub role: CollectRole,

    /// Shared identifier written into every client payload.
    #[arg(long)]
    pub task_id: String,

    /// Client target as HOST:PORT.
    #[arg(long)]
    pub target: Option<String>,

    /// Server listen address as IP:PORT.
    #[arg(long)]
    pub listen: Option<String>,

    /// Client connection attempts.
    #[arg(long, default_value_t = 10)]
    pub rounds: u32,

    /// Per-connection timeout in milliseconds.
    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,

    /// Delay between client attempts in milliseconds.
    #[arg(long, default_value_t = 200)]
    pub interval_ms: u64,

    /// Server collection window or client wall-clock budget in seconds.
    #[arg(long, default_value_t = 30)]
    pub max_seconds: u64,

    /// Pin client sockets to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// JSON output path.
    #[arg(long, default_value = "collect.json")]
    pub output: PathBuf,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct CorrelateArgs {
    /// Client-side collect JSON.
    pub client: PathBuf,

    /// Server-side collect JSON.
    pub server: PathBuf,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,

    /// Write <PREFIX>.json and <PREFIX>.md.
    #[arg(long, value_name = "PREFIX")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct McpArgs {
    /// Authorized probe target, repeatable. Use HOST or HOST:PORT.
    #[arg(long = "allow-target", value_name = "HOST[:PORT]")]
    pub allow_target: Vec<String>,

    /// Allowlist file with one explicit HOST or HOST:PORT per line.
    /// When omitted, an existing user config file is loaded if present.
    #[arg(long = "allow-file", value_name = "PATH")]
    pub allow_file: Option<PathBuf>,

    /// Print the allow-file path that would be read, then exit.
    #[arg(long)]
    pub print_allow_path: bool,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    #[command(subcommand)]
    pub action: ReportAction,
}

#[derive(Debug, Subcommand)]
pub enum ReportAction {
    /// Render a saved report as offline HTML, SVG, or a text timeline.
    Render(RenderArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RenderFormat {
    Html,
    Svg,
    Summary,
}

#[derive(Debug, Args)]
pub struct RenderArgs {
    /// Saved PathTrial JSON report.
    pub input: PathBuf,

    /// Output format. HTML and SVG contain no external resources.
    #[arg(long, value_enum, default_value_t = RenderFormat::Html)]
    pub format: RenderFormat,

    /// Write the rendering to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Mask IP literals in the rendering. This does not change the input file.
    #[arg(long)]
    pub redact_ips: bool,
}

#[derive(Debug, Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub action: BaselineAction,
}

#[derive(Debug, Subcommand)]
pub enum BaselineAction {
    /// Store a report as the local baseline for its target and scenario.
    Save(BaselineSaveArgs),
    /// Compare a report with the stored baseline for the same identity.
    Compare(BaselineCompareArgs),
    /// Print the local baseline directory.
    Path,
}

#[derive(Debug, Args)]
pub struct BaselineSaveArgs {
    /// Saved PathTrial JSON report.
    pub report: PathBuf,

    /// Baseline directory. Defaults to the user data directory.
    #[arg(long)]
    pub dir: Option<PathBuf>,

    /// Replace an existing baseline for this identity.
    #[arg(long)]
    pub replace: bool,

    /// Mask IP literals inside the stored report copy.
    #[arg(long)]
    pub redact_ips: bool,
}

#[derive(Debug, Args)]
pub struct BaselineCompareArgs {
    /// Current PathTrial JSON report.
    pub report: PathBuf,

    /// Baseline directory. Defaults to the user data directory.
    #[arg(long)]
    pub dir: Option<PathBuf>,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct EndpointArgs {
    /// Serve UDP echo on --bind until interrupted.
    #[arg(long)]
    pub udp_echo: bool,

    /// Serve the collect server on --listen for --max-seconds.
    #[arg(long)]
    pub collect: bool,

    /// Serve UDP echo and the collect server together for --max-seconds.
    #[arg(long)]
    pub peer: bool,

    /// UDP echo listen address. Defaults to loopback.
    #[arg(long, default_value = "127.0.0.1:39001")]
    pub bind: String,

    /// Collect listen address. Defaults to 127.0.0.1:39002 for --collect/--peer.
    #[arg(long)]
    pub listen: Option<String>,

    /// Shared collect task id. Required for --collect and --peer.
    #[arg(long)]
    pub task_id: Option<String>,

    /// Wall-clock window for --collect and --peer, in seconds (1-3600).
    #[arg(long, default_value_t = 120)]
    pub max_seconds: u64,

    /// Collect JSON path for --collect and --peer.
    #[arg(long, default_value = "pathtrial-peer-collect.json")]
    pub output: PathBuf,

    /// Allow binding a non-loopback address. Does not change firewall rules.
    #[arg(long)]
    pub allow_public_bind: bool,
}

#[derive(Debug, Args)]
pub struct PingArgs {
    /// Hostname or literal IP address.
    pub host: String,

    /// Number of echo requests.
    #[arg(long, default_value_t = 5)]
    pub count: u32,

    /// Wall-clock budget for the whole run in milliseconds.
    #[arg(long, default_value_t = 15000)]
    pub timeout_ms: u64,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct TraceArgs {
    /// Hostname or literal IP address.
    pub host: String,

    /// Maximum number of hops.
    #[arg(long, default_value_t = 15)]
    pub max_hops: u32,

    /// Wall-clock budget for the whole run in milliseconds.
    #[arg(long, default_value_t = 30000)]
    pub timeout_ms: u64,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct DnsArgs {
    /// Hostname to resolve.
    pub host: String,

    /// Extra resolver to compare against, for example --server 223.5.5.5.
    #[arg(long = "server")]
    pub servers: Vec<String>,

    /// Per-query timeout in milliseconds.
    #[arg(long, default_value_t = 3000)]
    pub timeout_ms: u64,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct HttpArgs {
    /// Absolute URL, for example https://example.com/path
    pub url: String,

    /// Expected HTTP status code. A mismatch fails the check.
    #[arg(long)]
    pub expect_status: Option<u16>,

    /// Total budget for the request in milliseconds.
    #[arg(long, default_value_t = 8000)]
    pub timeout_ms: u64,

    /// Pin the connection to a physical interface.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// Diagnostic only: accept any certificate.
    #[arg(long)]
    pub insecure: bool,

    /// TLS server name override when the URL uses a literal IP.
    #[arg(long)]
    pub sni: Option<String>,

    /// HTTP Host header override when the URL uses a literal IP.
    #[arg(long)]
    pub host: Option<String>,

    /// Pre-authorized address to connect to while the URL keeps its hostname.
    #[arg(long)]
    pub target_ip: Option<std::net::IpAddr>,

    /// Output format on stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
#[command(
    name = "pathtrial",
    version,
    about = "Evidence-first network diagnostics",
    long_about = "PathTrial runs a fixed, reproducible five-stage network check and writes a report \
where every conclusion is tied to recorded probe data. It never changes system \
configuration and never guesses a root cause without evidence.",
    after_help = "Exit codes:\n  0  scan completed, no WARN/FAIL findings\n  2  scan completed with WARN/FAIL findings\n  3  scan completed but evidence was inconclusive\n  1  the tool itself failed (invalid input, I/O error)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

impl ScanArgs {
    /// Validate and bound user input. Called before any network activity.
    pub fn validate(&self) -> Result<(), String> {
        let name = self.target.trim();
        if name.is_empty() {
            return Err("target must not be empty".to_string());
        }
        if name.len() > 253 {
            return Err("target is longer than 253 characters".to_string());
        }
        if name.contains(char::is_whitespace) {
            return Err("target must not contain whitespace".to_string());
        }
        if !(1..=200).contains(&self.rounds) {
            return Err("--rounds must be between 1 and 200".to_string());
        }
        if !(100..=30_000).contains(&self.timeout_ms) {
            return Err("--timeout-ms must be between 100 and 30000".to_string());
        }
        if self.interval_ms > 60_000 {
            return Err("--interval-ms must be at most 60000".to_string());
        }
        if !(5..=3600).contains(&self.max_seconds) {
            return Err("--max-seconds must be between 5 and 3600".to_string());
        }
        if let Some(port) = self.port {
            if port == 0 {
                return Err("--port must be between 1 and 65535".to_string());
            }
        }
        Ok(())
    }

    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.profile.default_port())
    }

    pub fn tls_enabled(&self) -> bool {
        if self.no_tls {
            return false;
        }
        if self.tls {
            return true;
        }
        self.profile.tls_by_default()
    }

    /// Hard cap on TCP probes per family, derived from the time budget so a
    /// pathological run can never exceed the wall clock.
    pub fn effective_rounds(&self) -> usize {
        let per_round_ms = self.timeout_ms + self.interval_ms;
        let budget_ms = self.max_seconds.saturating_mul(1000) / 2;
        let by_budget = (budget_ms / per_round_ms.max(1)) as usize;
        self.rounds.min(by_budget.max(1)).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(target: &str) -> ScanArgs {
        ScanArgs {
            target: target.to_string(),
            rounds: 20,
            port: None,
            profile: Profile::Web,
            tls: false,
            no_tls: false,
            format: OutputFormat::Summary,
            timeout_ms: 3000,
            interval_ms: 200,
            max_seconds: 180,
            out_dir: None,
            out: None,
            no_files: false,
            allow_insecure_tls: false,
            redact_ips: false,
            bind_interface: None,
            sni: None,
        }
    }

    #[test]
    fn rejects_empty_and_whitespace_targets() {
        assert!(args("").validate().is_err());
        assert!(args("two words").validate().is_err());
    }

    #[test]
    fn profile_presets_pick_ports_and_tls() {
        assert_eq!(args("example.com").effective_port(), 443);
        assert!(args("example.com").tls_enabled());
        let mut ssh = args("example.com");
        ssh.profile = Profile::Ssh;
        assert_eq!(ssh.effective_port(), 22);
        assert!(!ssh.tls_enabled());
    }

    #[test]
    fn round_cap_respects_time_budget() {
        let mut slow = args("example.com");
        slow.rounds = 200;
        slow.timeout_ms = 3000;
        slow.interval_ms = 200;
        slow.max_seconds = 10;
        assert!(slow.effective_rounds() < 200);
    }

    #[test]
    fn budget_shrinks_rounds_but_never_the_per_attempt_timeout() {
        let mut slow = args("example.com");
        slow.rounds = 200;
        slow.timeout_ms = 9000;
        slow.max_seconds = 10;
        let rounds = slow.effective_rounds();
        assert!(rounds >= 1, "at least one round is always attempted");
        assert_eq!(
            slow.timeout_ms, 9000,
            "the per-connect timeout is untouched"
        );
        // A single attempt may exceed the remaining budget; the contract is that
        // the budget is checked between attempts.
        assert!(slow.validate().is_ok());
    }
}
