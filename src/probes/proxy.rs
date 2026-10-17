//! M11: SOCKS5 (RFC 1928, no auth) and HTTP CONNECT tunnels.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::models::NetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    HttpConnect,
}

impl ProxyKind {
    pub fn label(self) -> &'static str {
        match self {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::HttpConnect => "http_connect",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxySpec {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
}

impl ProxySpec {
    /// Proxy address without any path or query that could carry a token.
    pub fn redacted(&self) -> String {
        let scheme = match self.kind {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::HttpConnect => "http",
        };
        if self.host.contains(':') {
            format!("{scheme}://[{}]:{}", self.host, self.port)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// Parse `socks5://host:port` or `http://host:port`. Credentials in the URL are
/// rejected rather than ignored, so the tool never pretends to support auth.
pub fn parse_proxy(input: &str) -> Result<ProxySpec, String> {
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| format!("proxy must look like socks5://host:port: {input}"))?;
    let kind = match scheme.to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" => ProxyKind::Socks5,
        "http" => ProxyKind::HttpConnect,
        other => return Err(format!("unsupported proxy scheme {other}")),
    };
    if rest.contains('@') {
        return Err(
            "proxy credentials are not supported and are refused instead of being ignored"
                .to_string(),
        );
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 proxy address".to_string())?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| "missing proxy port".to_string())?
            .parse::<u16>()
            .map_err(|_| "invalid proxy port".to_string())?;
        (host.to_string(), port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| "missing proxy port".to_string())?;
        (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| "invalid proxy port".to_string())?,
        )
    };
    Ok(ProxySpec { kind, host, port })
}

/// Why a tunnel could not be established.
#[derive(Debug, Clone)]
pub enum TunnelError {
    /// Could not reach the proxy itself.
    ProxyUnreachable(NetError),
    /// Protocol bytes were wrong or the peer closed early.
    Protocol(String),
    /// The proxy asked for authentication PathTrial does not implement.
    AuthRequired,
    /// SOCKS5 CONNECT reply code.
    SocksReply(u8),
    /// HTTP CONNECT status code.
    HttpStatus(u16),
    /// A stage ran out of its own wall-clock budget.
    Timeout(&'static str),
}

impl TunnelError {
    pub fn label(&self) -> String {
        match self {
            TunnelError::ProxyUnreachable(error) => format!("proxy_unreachable:{}", error.label()),
            TunnelError::Protocol(message) => format!("protocol:{message}"),
            TunnelError::AuthRequired => "auth_required".to_string(),
            TunnelError::SocksReply(code) => format!("socks_reply:{code}"),
            TunnelError::HttpStatus(code) => format!("http_status:{code}"),
            TunnelError::Timeout(stage) => format!("timeout:{stage}"),
        }
    }
}

/// Stage timings for the proxy path.
#[derive(Debug, Clone, Default)]
pub struct ProxyTimings {
    pub proxy_tcp_ms: f64,
    pub negotiation_ms: f64,
    pub connect_ms: f64,
}

/// Establish a tunnel to `target_host:target_port` through `spec`.
pub fn tunnel(
    spec: &ProxySpec,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
    interface: Option<&str>,
) -> Result<(TcpStream, ProxyTimings), TunnelError> {
    let mut timings = ProxyTimings::default();
    let started = Instant::now();
    let proxy_ip = resolve_proxy(&spec.host)?;
    let mut stream = crate::net::connect(SocketAddr::new(proxy_ip, spec.port), timeout, interface)
        .map_err(|error| TunnelError::ProxyUnreachable(crate::util::classify_io_error(&error)))?;
    timings.proxy_tcp_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    match spec.kind {
        ProxyKind::Socks5 => {
            let (negotiation_ms, connect_ms) =
                socks5_handshake(&mut stream, target_host, target_port)?;
            timings.negotiation_ms = negotiation_ms;
            timings.connect_ms = connect_ms;
        }
        ProxyKind::HttpConnect => {
            let connect_started = Instant::now();
            http_connect(&mut stream, target_host, target_port)?;
            timings.connect_ms = round2(connect_started.elapsed().as_secs_f64() * 1000.0);
        }
    }
    Ok((stream, timings))
}

fn resolve_proxy(host: &str) -> Result<IpAddr, TunnelError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut recorder = crate::probes::Recorder::new();
    let resolved = crate::probes::dns::resolve(host, &mut recorder, Duration::from_secs(3));
    resolved
        .addresses_v4
        .first()
        .or_else(|| resolved.addresses_v6.first())
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| TunnelError::Protocol(format!("cannot resolve proxy host {host}")))
}

fn socks5_handshake(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<(f64, f64), TunnelError> {
    let negotiation_started = Instant::now();
    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|error| io_failure("greeting_write", error))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .map_err(|error| io_failure("greeting_read", error))?;
    if reply[0] != 0x05 {
        return Err(TunnelError::Protocol(format!(
            "unexpected SOCKS version {}",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => {}
        0xFF => return Err(TunnelError::AuthRequired),
        other => {
            return Err(TunnelError::Protocol(format!(
                "proxy requires unsupported auth method {other:#04x}"
            )))
        }
    }
    let negotiation_ms = round2(negotiation_started.elapsed().as_secs_f64() * 1000.0);

    let connect_started = Instant::now();
    let (address_type, address_bytes) = encode_socks_target(target_host)?;
    let mut request = vec![0x05, 0x01, 0x00, address_type];
    if address_type == 0x03 {
        request.push(address_bytes.len() as u8);
    }
    request.extend_from_slice(&address_bytes);
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|error| io_failure("connect_write", error))?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|error| io_failure("connect_read", error))?;
    if head[0] != 0x05 {
        return Err(TunnelError::Protocol(format!(
            "unexpected SOCKS version {}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(TunnelError::SocksReply(head[1]));
    }
    let address_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .map_err(|error| io_failure("bound_addr", error))?;
            length[0] as usize
        }
        other => {
            return Err(TunnelError::Protocol(format!(
                "unsupported bound address type {other:#04x}"
            )))
        }
    };
    let mut bound = vec![0u8; address_len + 2];
    stream
        .read_exact(&mut bound)
        .map_err(|error| io_failure("bound_addr_read", error))?;
    let connect_ms = round2(connect_started.elapsed().as_secs_f64() * 1000.0);
    Ok((negotiation_ms, connect_ms))
}

/// Encode a SOCKS5 ATYP plus address bytes. Literal addresses keep their
/// family; names are passed to the proxy for remote resolution.
fn encode_socks_target(host: &str) -> Result<(u8, Vec<u8>), TunnelError> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Ok((0x01, ip.octets().to_vec()));
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return Ok((0x04, ip.octets().to_vec()));
    }
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > 255 {
        return Err(TunnelError::Protocol(
            "target host length invalid".to_string(),
        ));
    }
    Ok((0x03, host_bytes.to_vec()))
}

fn io_failure(stage: &'static str, error: std::io::Error) -> TunnelError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            TunnelError::Timeout(stage)
        }
        _ => TunnelError::Protocol(format!("{stage}: {error}")),
    }
}

fn http_connect(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<(), TunnelError> {
    let authority = if target_host.contains(':') {
        format!("[{target_host}]:{target_port}")
    } else {
        format!("{target_host}:{target_port}")
    };
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| io_failure("connect_write", error))?;

    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) => {
                return Err(TunnelError::Protocol(
                    "proxy closed during CONNECT".to_string(),
                ))
            }
            Ok(read) => {
                head.extend_from_slice(&buffer[..read]);
                if head.len() > 8 * 1024 {
                    return Err(TunnelError::Protocol("CONNECT head too large".to_string()));
                }
            }
            Err(error) => return Err(io_failure("connect_read", error)),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| TunnelError::Protocol("CONNECT status line unreadable".to_string()))?;
    match status {
        200 => Ok(()),
        407 => Err(TunnelError::AuthRequired),
        other => Err(TunnelError::HttpStatus(other)),
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_proxies() {
        let socks = parse_proxy("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(socks.kind, ProxyKind::Socks5);
        assert_eq!(socks.port, 1080);
        let http = parse_proxy("http://[::1]:8080").unwrap();
        assert_eq!(http.kind, ProxyKind::HttpConnect);
        assert_eq!(http.host, "::1");
    }

    #[test]
    fn rejects_credentials_and_bad_schemes() {
        assert!(parse_proxy("socks5://user:pass@127.0.0.1:1080").is_err());
        assert!(parse_proxy("https://127.0.0.1:443").is_err());
        assert!(parse_proxy("127.0.0.1:1080").is_err());
    }

    #[test]
    fn socks_target_preserves_literal_address_families() {
        assert_eq!(
            encode_socks_target("127.0.0.1").unwrap(),
            (0x01, vec![127, 0, 0, 1])
        );
        assert_eq!(encode_socks_target("::1").unwrap().0, 0x04);
        assert_eq!(
            encode_socks_target("example.com").unwrap(),
            (0x03, b"example.com".to_vec())
        );
    }
}
