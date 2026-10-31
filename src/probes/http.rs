//! M08: real HTTP/HTTPS request over a direct or proxied stream.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::models::{NetError, Probe, ProbeDetail, ProbeKind, ProbeOutcome};
use crate::probes::tls::{handshake, TlsFailure};
use crate::probes::Recorder;

/// Parsed target of an HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    pub fn host_header(&self) -> String {
        let default = if self.is_tls() { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// URL form safe for reports and terminal output: no userinfo and no query
    /// string, which may carry tokens or other credentials.
    pub fn redacted(&self) -> String {
        let default = if self.is_tls() { 443 } else { 80 };
        let authority = if self.port == default {
            if self.host.contains(':') {
                format!("[{}]", self.host)
            } else {
                self.host.clone()
            }
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let path = self.path.split('?').next().unwrap_or("/");
        format!("{}://{}{}", self.scheme, authority, path)
    }
}

/// Parse `http(s)://host[:port][/path][?query]`. IPv6 literals use brackets.
pub fn parse_url(input: &str) -> Result<Url, String> {
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| "URL must start with http:// or https://".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme {scheme}"));
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        return Err("credentials in URLs are not supported and are refused".to_string());
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let port = match tail.strip_prefix(':') {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {authority}"))?,
            None => {
                if tail.is_empty() {
                    default_port(&scheme)
                } else {
                    return Err("invalid URL authority".to_string());
                }
            }
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, value)) => {
                let port = value
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port in {authority}"))?;
                (host.to_string(), port)
            }
            None => (authority.to_string(), default_port(&scheme)),
        }
    };
    if host.is_empty() {
        return Err("URL has an empty host".to_string());
    }
    if host
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("URL host contains whitespace or control characters".to_string());
    }
    if path
        .chars()
        .any(|character| character == '\r' || character == '\n')
    {
        return Err("URL path contains a line break".to_string());
    }
    Ok(Url {
        scheme,
        host,
        port,
        path,
    })
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

/// Timings recorded for one request.
#[derive(Debug, Clone, Default)]
pub struct HttpTimings {
    pub dns_ms: f64,
    pub connect_ms: f64,
    pub tls_ms: f64,
    pub ttfb_ms: f64,
    pub total_ms: f64,
}

/// Result of one HTTP attempt.
pub struct HttpOutcome {
    pub probe_id: String,
    pub status: Option<u16>,
    pub expected_status: Option<u16>,
    pub matches_expectation: Option<bool>,
    pub http_version: Option<String>,
    pub redirect: Option<String>,
    pub body_bytes: usize,
    pub body_preview: Vec<u8>,
    pub tls_verified: Option<bool>,
    pub timings: HttpTimings,
    pub error: Option<NetError>,
}

impl HttpOutcome {
    /// A request "passed" when it produced the expected status. A 4xx/5xx is
    /// still an HTTP answer, so it is never reported as a transport failure.
    pub fn passed(&self) -> bool {
        self.error.is_none() && self.matches_expectation.unwrap_or(false)
    }
}

/// Parameters for one request.
pub struct HttpRequest<'a> {
    pub url: &'a str,
    pub method: &'a str,
    pub expected_status: Option<u16>,
    pub timeout: Duration,
    pub interface: Option<&'a str>,
    pub insecure: bool,
    /// Optional byte budget for the response body.
    pub max_body: usize,
    /// TLS server name override, useful when connecting to a pre-authorized IP.
    pub server_name: Option<&'a str>,
    /// HTTP Host header override, useful when connecting to a pre-authorized IP.
    pub host_header: Option<&'a str>,
    /// Pre-authorized address used for the connection. When set, the URL host
    /// is only used for SNI and the Host header, and no second resolution is
    /// performed for the connect target.
    pub connect_ip: Option<IpAddr>,
}

enum Channel {
    Plain(TcpStream),
    Tls(Box<crate::probes::tls::TlsSession>),
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

impl Channel {
    fn as_rw(&mut self) -> &mut (dyn ReadWrite + '_) {
        match self {
            Channel::Plain(stream) => stream,
            Channel::Tls(session) => &mut session.stream,
        }
    }
}

/// Run one request and record the probe.
pub fn run(recorder: &mut Recorder, request: &HttpRequest<'_>) -> Result<HttpOutcome, String> {
    let url = parse_url(request.url)?;
    let id = recorder.next_id("http");
    let started_at = crate::util::now_rfc3339();
    let started = Instant::now();
    let mut timings = HttpTimings::default();
    let mut status = None;
    let mut version = None;
    let mut redirect = None;
    let mut body_bytes = 0usize;
    let mut body_preview = Vec::new();
    let mut tls_verified = None;
    let mut error: Option<NetError> = None;
    let mut matches = None;

    // 1. Resolve.
    let dns_stage_start = Instant::now();
    let literal: Option<IpAddr> = url.host.parse().ok();
    let address = match request.connect_ip.or(literal) {
        Some(ip) => ip,
        None => {
            // The request budget must cover DNS too: give resolution at most a
            // third of it, capped at two seconds.
            let dns_budget =
                (request.timeout / 3).clamp(Duration::from_millis(400), Duration::from_secs(2));
            let resolved = crate::probes::dns::resolve(&url.host, recorder, dns_budget);
            let candidate = resolved
                .addresses_v4
                .first()
                .or_else(|| resolved.addresses_v6.first())
                .and_then(|text| text.parse::<IpAddr>().ok());
            match candidate {
                Some(ip) => {
                    // A Fake-IP answer describes the local proxy, so a request
                    // to it would not describe the real target.
                    if crate::net::scope_of(ip) == crate::net::AddressScope::Benchmark {
                        timings.dns_ms = round2(dns_stage_start.elapsed().as_secs_f64() * 1000.0);
                        error = Some(NetError::Other(
                            "resolved address is in 198.18.0.0/15 (local proxy rewrite)"
                                .to_string(),
                        ));
                        return Ok(finish(
                            recorder,
                            id,
                            started,
                            started_at,
                            url,
                            request,
                            timings,
                            status,
                            version,
                            redirect,
                            body_bytes,
                            body_preview.clone(),
                            tls_verified,
                            error,
                            matches,
                        ));
                    }
                    ip
                }
                None => {
                    timings.dns_ms = round2(dns_stage_start.elapsed().as_secs_f64() * 1000.0);
                    error = Some(NetError::DnsFailure);
                    let outcome = finish(
                        recorder,
                        id,
                        started,
                        started_at,
                        url,
                        request,
                        timings,
                        status,
                        version,
                        redirect,
                        body_bytes,
                        body_preview.clone(),
                        tls_verified,
                        error,
                        matches,
                    );
                    return Ok(outcome);
                }
            }
        }
    };
    timings.dns_ms = round2(dns_stage_start.elapsed().as_secs_f64() * 1000.0);

    // 2. Connect.
    let connect_started = Instant::now();
    let stream = match crate::net::connect(
        std::net::SocketAddr::new(address, url.port),
        request.timeout,
        request.interface,
    ) {
        Ok(stream) => stream,
        Err(err) => {
            timings.connect_ms = round2(connect_started.elapsed().as_secs_f64() * 1000.0);
            error = Some(crate::util::classify_io_error(&err));
            return Ok(finish(
                recorder,
                id,
                started,
                started_at,
                url,
                request,
                timings,
                status,
                version,
                redirect,
                body_bytes,
                body_preview.clone(),
                tls_verified,
                error,
                matches,
            ));
        }
    };
    timings.connect_ms = round2(connect_started.elapsed().as_secs_f64() * 1000.0);

    // 3. TLS.
    let mut channel = if url.is_tls() {
        let tls_started = Instant::now();
        let _ = stream.set_read_timeout(Some(request.timeout));
        let _ = stream.set_write_timeout(Some(request.timeout));
        let server_name = request.server_name.unwrap_or(&url.host);
        match handshake(stream, server_name, request.insecure) {
            Ok(session) => {
                timings.tls_ms = round2(tls_started.elapsed().as_secs_f64() * 1000.0);
                tls_verified = Some(!request.insecure);
                Channel::Tls(Box::new(session))
            }
            Err(TlsFailure::Certificate { message, .. }) => {
                timings.tls_ms = round2(tls_started.elapsed().as_secs_f64() * 1000.0);
                tls_verified = Some(false);
                error = Some(NetError::Certificate);
                let _ = message;
                return Ok(finish(
                    recorder,
                    id,
                    started,
                    started_at,
                    url,
                    request,
                    timings,
                    status,
                    version,
                    redirect,
                    body_bytes,
                    body_preview.clone(),
                    tls_verified,
                    error,
                    matches,
                ));
            }
            Err(TlsFailure::Transport(message)) => {
                timings.tls_ms = round2(tls_started.elapsed().as_secs_f64() * 1000.0);
                error = Some(NetError::TlsTransport);
                let _ = message;
                return Ok(finish(
                    recorder,
                    id,
                    started,
                    started_at,
                    url,
                    request,
                    timings,
                    status,
                    version,
                    redirect,
                    body_bytes,
                    body_preview.clone(),
                    tls_verified,
                    error,
                    matches,
                ));
            }
        }
    } else {
        let _ = stream.set_read_timeout(Some(request.timeout));
        let _ = stream.set_write_timeout(Some(request.timeout));
        Channel::Plain(stream)
    };

    // 4. Request and response.
    let host_header = request
        .host_header
        .map(str::to_string)
        .unwrap_or_else(|| url.host_header());
    let request_bytes = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: pathtrial/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        request.method,
        url.path,
        host_header,
        env!("CARGO_PKG_VERSION")
    );
    let write_started = Instant::now();
    let io = channel
        .as_rw()
        .write_all(request_bytes.as_bytes())
        .and_then(|_| channel.as_rw().flush());
    if let Err(err) = io {
        timings.total_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
        error = Some(crate::util::classify_io_error(&err));
        return Ok(finish(
            recorder,
            id,
            started,
            started_at,
            url,
            request,
            timings,
            status,
            version,
            redirect,
            body_bytes,
            body_preview,
            tls_verified,
            error,
            matches,
        ));
    }

    let mut buffer = vec![0u8; 8192];
    let mut head = Vec::new();
    let mut first_byte: Option<Instant> = None;
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match channel.as_rw().read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if first_byte.is_none() {
                    first_byte = Some(Instant::now());
                }
                head.extend_from_slice(&buffer[..read]);
                if head.len() > 64 * 1024 {
                    error = Some(NetError::Other("response head too large".to_string()));
                    break;
                }
            }
            Err(err) => {
                error = Some(crate::util::classify_io_error(&err));
                break;
            }
        }
    }
    if let Some(moment) = first_byte {
        timings.ttfb_ms = round2(moment.duration_since(write_started).as_secs_f64() * 1000.0);
    }

    if error.is_none() {
        match parse_head(&head) {
            Ok(parsed) => {
                status = Some(parsed.status);
                version = Some(parsed.version);
                redirect = parsed.location.map(|location| redact_location(&location));
                let body_start = head
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .unwrap_or(head.len());
                body_bytes = head.len().saturating_sub(body_start);
                body_preview.extend_from_slice(&head[body_start..]);
                body_preview.truncate(request.max_body);
                let mut remaining = request.max_body.saturating_sub(body_bytes);
                while remaining > 0 {
                    match channel.as_rw().read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => {
                            let room = request.max_body.saturating_sub(body_preview.len());
                            body_preview.extend_from_slice(&buffer[..read.min(room)]);
                            body_bytes += read;
                            remaining = remaining.saturating_sub(read);
                        }
                        Err(err) => {
                            // A read timeout after a complete head still leaves a
                            // usable HTTP answer; keep the status.
                            if err.kind() != std::io::ErrorKind::WouldBlock
                                && err.kind() != std::io::ErrorKind::TimedOut
                            {
                                error = Some(crate::util::classify_io_error(&err));
                            }
                            break;
                        }
                    }
                }
            }
            Err(message) => {
                error = Some(NetError::Other(format!("http: {message}")));
            }
        }
    }

    timings.total_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
    if let (Some(code), Some(expected)) = (status, request.expected_status) {
        matches = Some(code == expected);
    }
    Ok(finish(
        recorder,
        id,
        started,
        started_at,
        url,
        request,
        timings,
        status,
        version,
        redirect,
        body_bytes,
        body_preview,
        tls_verified,
        error,
        matches,
    ))
}

#[allow(clippy::too_many_arguments)]
fn finish(
    recorder: &mut Recorder,
    id: String,
    started: Instant,
    started_at: String,
    url: Url,
    request: &HttpRequest<'_>,
    mut timings: HttpTimings,
    status: Option<u16>,
    version: Option<String>,
    redirect: Option<String>,
    body_bytes: usize,
    body_preview: Vec<u8>,
    tls_verified: Option<bool>,
    error: Option<NetError>,
    matches: Option<bool>,
) -> HttpOutcome {
    if timings.total_ms == 0.0 {
        timings.total_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
    }
    let detail = ProbeDetail::Http {
        url: url.redacted(),
        method: request.method.to_string(),
        status,
        expected_status: request.expected_status,
        matches_expectation: matches,
        http_version: version.clone(),
        location: redirect
            .as_deref()
            .map(|value| value.split(['?', '#']).next().unwrap_or(value).to_string()),
        body_bytes,
        dns_ms: timings.dns_ms,
        connect_ms: timings.connect_ms,
        tls_ms: timings.tls_ms,
        ttfb_ms: timings.ttfb_ms,
        total_ms: timings.total_ms,
        tls_verified,
        error: error.clone(),
    };
    let passed = error.is_none() && matches.unwrap_or(true);
    recorder.record(Probe {
        id: id.clone(),
        kind: ProbeKind::Http,
        outcome: if passed {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::Fail
        },
        family: None,
        target: Some(format!("{}:{}", url.host, url.port)),
        port: Some(url.port),
        started_at,
        duration_ms: Some(timings.total_ms),
        detail,
    });
    HttpOutcome {
        probe_id: id,
        status,
        expected_status: request.expected_status,
        matches_expectation: matches,
        http_version: version,
        redirect,
        body_bytes,
        body_preview,
        tls_verified,
        timings,
        error,
    }
}

struct Head {
    status: u16,
    version: String,
    location: Option<String>,
}

fn parse_head(bytes: &[u8]) -> Result<Head, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines();
    let status_line = lines.next().ok_or_else(|| "empty response".to_string())?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default().to_string();
    if !version.starts_with("HTTP/") {
        return Err(format!("unexpected status line: {status_line}"));
    }
    let status = parts
        .next()
        .ok_or_else(|| "missing status code".to_string())?
        .parse::<u16>()
        .map_err(|_| format!("invalid status code: {status_line}"))?;
    let mut location = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            break;
        };
        if name.eq_ignore_ascii_case("location") {
            location = Some(value.trim().to_string());
        }
    }
    Ok(Head {
        status,
        version,
        location,
    })
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// Keep a redirect location useful without carrying credentials, a query
/// string or a fragment into the report.
pub fn redact_location(input: &str) -> String {
    let without_fragment = input.split('#').next().unwrap_or(input);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    let Some((scheme, rest)) = without_query.split_once("://") else {
        return without_query.to_string();
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let authority = authority
        .rsplit_once('@')
        .map(|(_, value)| value)
        .unwrap_or(authority);
    format!("{scheme}://{authority}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let url = parse_url("https://example.com/a?b=1").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/a?b=1");
        assert!(url.is_tls());

        let plain = parse_url("http://example.com").unwrap();
        assert_eq!(plain.port, 80);
        assert_eq!(plain.path, "/");
        assert!(!plain.is_tls());
    }

    #[test]
    fn parses_ipv6_and_ports() {
        let url = parse_url("https://[2001:db8::1]:8443/x").unwrap();
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 8443);
        assert_eq!(url.host_header(), "[2001:db8::1]:8443");
    }

    #[test]
    fn rejects_bad_urls() {
        assert!(parse_url("example.com").is_err());
        assert!(parse_url("ftp://example.com").is_err());
        assert!(parse_url("https://:443").is_err());
        assert!(parse_url("https://[2001:db8::1").is_err());
        assert!(parse_url("https://user:pass@example.com/").is_err());
        assert!(parse_url("https://exa mple.com/").is_err());
        assert!(parse_url("https://example.com/a\r\nX-Test: 1").is_err());
    }

    #[test]
    fn report_url_drops_credentials_and_query() {
        let url = parse_url("https://example.com:8443/a?token=secret#frag").unwrap();
        assert_eq!(url.redacted(), "https://example.com:8443/a");
    }

    #[test]
    fn redirect_location_drops_credentials_and_query() {
        assert_eq!(
            redact_location("https://user:pass@example.org/next?token=secret#frag"),
            "https://example.org/next"
        );
        assert_eq!(redact_location("/relative?token=secret"), "/relative");
    }

    #[test]
    fn parses_status_and_location() {
        let head = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.org/\r\n\r\n";
        let parsed = parse_head(head).unwrap();
        assert_eq!(parsed.status, 301);
        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.location.as_deref(), Some("https://example.org/"));
    }

    #[test]
    fn rejects_non_http_responses() {
        assert!(parse_head(b"SSH-2.0-OpenSSH\r\n").is_err());
        assert!(parse_head(b"").is_err());
    }
}
