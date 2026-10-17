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
    /// Send one real HTTP/HTTPS request and report the timings per phase.
    Http(HttpArgs),
    /// ICMP echo with loss, RTT and jitter.
    Ping(PingArgs),
    /// Hop-by-hop route to the target.
    Trace(TraceArgs),
    /// Resolve a name against the system resolvers and optional extra servers.
    Dns(DnsArgs),
    /// Print the JSON Schema of the report to stdout.
    Schema,
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
