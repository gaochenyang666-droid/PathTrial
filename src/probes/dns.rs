//! Stage 2: DNS resolution against the system resolvers.
//!
//! PathTrial talks DNS itself instead of using `getaddrinfo` so that resolver
//! selection, timing and rcode are observable. Only the system resolvers are
//! contacted; no public resolver is queried without an explicit user choice.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::models::{Family, Probe, ProbeDetail, ProbeKind, ProbeOutcome};
use crate::probes::Recorder;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const MAX_RESOLVERS: usize = 3;

/// Aggregated DNS outcome for one hostname.
#[derive(Debug, Default)]
pub struct DnsOutcome {
    pub addresses_v4: Vec<String>,
    pub addresses_v6: Vec<String>,
    pub probe_ids: Vec<String>,
    pub resolvers: Vec<String>,
    pub fake_ip: bool,
    pub notes: Vec<String>,
    pub failures: Vec<String>,
    pub total_ms: f64,
}

/// Read the resolver list from the OS.
pub fn system_resolvers() -> (Vec<String>, Vec<String>) {
    let mut notes = Vec::new();
    let mut resolvers: Vec<String> = Vec::new();

    if cfg!(target_os = "macos") {
        if let Ok(output) = std::process::Command::new("/usr/sbin/scutil")
            .args(["--dns"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if let Some((_, value)) = line.split_once("nameserver[") {
                    if let Some((_, address)) = value.split_once(':') {
                        let candidate = address.trim();
                        if !candidate.is_empty() {
                            resolvers.push(candidate.to_string());
                        }
                    }
                }
            }
        }
    }

    if resolvers.is_empty() {
        if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("nameserver") {
                    let candidate = rest.trim();
                    if !candidate.is_empty() {
                        resolvers.push(candidate.to_string());
                    }
                }
            }
        } else {
            notes.push("/etc/resolv.conf could not be read".to_string());
        }
    }

    resolvers.dedup();
    if resolvers.is_empty() {
        notes.push("no system resolver was discovered".to_string());
    }
    if resolvers
        .iter()
        .any(|value| value == "127.0.0.1" || value == "::1")
    {
        notes.push(
            "a loopback stub resolver is in use; answers may be rewritten by local software"
                .to_string(),
        );
    }
    resolvers.truncate(MAX_RESOLVERS);
    (resolvers, notes)
}

/// Resolve A and AAAA for `host`, recording one probe per resolver and family.
pub fn resolve(host: &str, recorder: &mut Recorder, timeout: Duration) -> DnsOutcome {
    let mut outcome = DnsOutcome::default();
    let (resolvers, notes) = system_resolvers();
    outcome.notes.extend(notes);
    outcome.resolvers = resolvers.clone();

    if resolvers.is_empty() {
        outcome
            .failures
            .push("no resolver available to query".to_string());
        return outcome;
    }

    let mut got_v4 = false;
    let mut got_v6 = false;

    for (index, resolver) in resolvers.iter().enumerate() {
        let Ok(server) = parse_resolver(resolver) else {
            outcome
                .failures
                .push(format!("resolver {resolver} is not a usable IP address"));
            continue;
        };

        for (record_type, qtype) in [("A", TYPE_A), ("AAAA", TYPE_AAAA)] {
            let family = if qtype == TYPE_A {
                Family::Ipv4
            } else {
                Family::Ipv6
            };
            let probe_id = recorder.next_id(&format!(
                "dns_{}",
                if family == Family::Ipv4 {
                    "ipv4"
                } else {
                    "ipv6"
                }
            ));
            let started_at = crate::util::now_rfc3339();
            let started = Instant::now();
            let result = query(server, host, qtype, timeout);
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            outcome.total_ms += elapsed;

            let mut answers: Vec<String> = Vec::new();
            let mut cnames: Vec<String> = Vec::new();
            let mut rcode = None;
            let mut error = None;
            let mut fake = false;

            match result {
                Ok(parsed) => {
                    rcode = Some(rcode_name(parsed.rcode).to_string());
                    if parsed.rcode != 0 {
                        error = Some(format!("rcode {}", rcode_name(parsed.rcode)));
                    }
                    cnames = parsed.cnames.clone();
                    for address in &parsed.answers {
                        let text = address.to_string();
                        fake |= looks_like_fake_ip(*address);
                        if crate::net::scope_of(*address) == crate::net::AddressScope::Private {
                            outcome.notes.push(format!(
                                "resolver {resolver} returned a private {record_type} address for {host}; this can be an internal name or split DNS"
                            ));
                        }
                        answers.push(text);
                    }
                    if parsed.answers.is_empty() && parsed.rcode == 0 {
                        outcome.notes.push(format!(
                            "resolver {resolver} returned NOERROR with no {record_type} records for {host}"
                        ));
                    }
                }
                Err(message) => {
                    error = Some(message.clone());
                    outcome
                        .failures
                        .push(format!("{resolver} {record_type} query failed: {message}"));
                }
            }

            if fake {
                outcome.fake_ip = true;
            }

            recorder.record(Probe {
                id: probe_id.clone(),
                kind: ProbeKind::Dns,
                outcome: if error.is_none() && !answers.is_empty() {
                    ProbeOutcome::Ok
                } else if error.is_some() {
                    ProbeOutcome::Fail
                } else {
                    ProbeOutcome::NotApplicable
                },
                family: Some(family),
                target: Some(host.to_string()),
                port: None,
                started_at,
                duration_ms: Some(round2(elapsed)),
                detail: ProbeDetail::DnsQuery {
                    resolver: resolver.clone(),
                    record_type: record_type.to_string(),
                    answers: answers.clone(),
                    cname_chain: cnames,
                    query_ms: round2(elapsed),
                    rcode,
                    error,
                    fake_ip_suspected: fake,
                },
            });
            outcome.probe_ids.push(probe_id);

            if family == Family::Ipv4 && !got_v4 && !answers.is_empty() {
                outcome.addresses_v4 = answers;
                got_v4 = true;
            } else if family == Family::Ipv6 && !got_v6 && !answers.is_empty() {
                outcome.addresses_v6 = answers;
                got_v6 = true;
            }

            let _ = index;
        }
    }

    outcome.addresses_v4.truncate(2);
    outcome.addresses_v6.truncate(2);
    outcome.total_ms = round2(outcome.total_ms);
    outcome
}

fn parse_resolver(value: &str) -> Result<SocketAddr, ()> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(())
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Addresses that strongly suggest local rewriting (Fake-IP) rather than a
/// genuine public answer.
pub fn looks_like_fake_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_unspecified() || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

#[derive(Debug, Clone)]
struct ParsedResponse {
    rcode: u8,
    truncated: bool,
    answers: Vec<IpAddr>,
    cnames: Vec<String>,
}

fn query(
    server: SocketAddr,
    host: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<ParsedResponse, String> {
    let id = next_id();
    let packet = build_query(id, host, qtype)?;
    let mut last_error = String::from("no attempt made");
    for _ in 0..2 {
        match udp_exchange(server, &packet, timeout) {
            Ok(response) => {
                let parsed = parse_response(&response, id)?;
                if parsed.truncated {
                    return tcp_exchange(server, &packet, timeout, id);
                }
                return Ok(parsed);
            }
            Err(message) => last_error = message,
        }
    }
    Err(last_error)
}

fn next_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((nanos ^ (std::process::id() << 8)) & 0xFFFF) as u16
}

fn build_query(id: u16, host: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err("empty hostname".to_string());
    }
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD set
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    let mut wire_len = 1;
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("invalid DNS label in {host}"));
        }
        wire_len += 1 + bytes.len();
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    if wire_len > 254 {
        return Err("hostname too long for DNS".to_string());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(packet)
}

fn udp_exchange(server: SocketAddr, packet: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).map_err(|error| format!("udp bind: {error}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("udp timeout: {error}"))?;
    socket
        .connect(server)
        .map_err(|error| format!("udp connect: {error}"))?;
    socket
        .send(packet)
        .map_err(|error| format!("udp send: {error}"))?;
    let mut buffer = vec![0u8; 4096];
    let read = socket
        .recv(&mut buffer)
        .map_err(|error| format!("udp recv: {error}"))?;
    buffer.truncate(read);
    Ok(buffer)
}

fn tcp_exchange(
    server: SocketAddr,
    packet: &[u8],
    timeout: Duration,
    expected_id: u16,
) -> Result<ParsedResponse, String> {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect_timeout(&server, timeout)
        .map_err(|error| format!("tcp connect: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("tcp timeout: {error}"))?;
    let length = (packet.len() as u16).to_be_bytes();
    stream
        .write_all(&length)
        .and_then(|_| stream.write_all(packet))
        .map_err(|error| format!("tcp send: {error}"))?;
    let mut size = [0u8; 2];
    stream
        .read_exact(&mut size)
        .map_err(|error| format!("tcp read length: {error}"))?;
    let mut response = vec![0u8; u16::from_be_bytes(size) as usize];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("tcp read body: {error}"))?;
    parse_response(&response, expected_id)
}

fn parse_response(buffer: &[u8], expected_id: u16) -> Result<ParsedResponse, String> {
    if buffer.len() < 12 {
        return Err("response shorter than DNS header".to_string());
    }
    let id = u16::from_be_bytes([buffer[0], buffer[1]]);
    if id != expected_id {
        return Err("transaction id mismatch".to_string());
    }
    let flags = u16::from_be_bytes([buffer[2], buffer[3]]);
    let rcode = (flags & 0x000F) as u8;
    let truncated = flags & 0x0200 != 0;
    let questions = u16::from_be_bytes([buffer[4], buffer[5]]) as usize;
    let answers = u16::from_be_bytes([buffer[6], buffer[7]]) as usize;

    let mut offset = 12;
    for _ in 0..questions {
        let (_, next) = read_name(buffer, offset)?;
        offset = next + 4;
        if offset > buffer.len() {
            return Err("truncated question section".to_string());
        }
    }

    let mut addresses = Vec::new();
    let mut cnames = Vec::new();
    for _ in 0..answers {
        let (_, next) = read_name(buffer, offset)?;
        offset = next;
        if offset + 10 > buffer.len() {
            return Err("truncated answer header".to_string());
        }
        let record_type = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
        let length = u16::from_be_bytes([buffer[offset + 8], buffer[offset + 9]]) as usize;
        offset += 10;
        if offset + length > buffer.len() {
            return Err("truncated rdata".to_string());
        }
        match record_type {
            TYPE_A if length == 4 => addresses.push(IpAddr::V4(Ipv4Addr::new(
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ))),
            TYPE_AAAA if length == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buffer[offset..offset + 16]);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            TYPE_CNAME => {
                if let Ok((name, _)) = read_name(buffer, offset) {
                    cnames.push(name);
                }
            }
            _ => {}
        }
        offset += length;
    }

    Ok(ParsedResponse {
        rcode,
        truncated,
        answers: addresses,
        cnames,
    })
}

/// Decode a (possibly compressed) DNS name. Returns the name and the offset
/// immediately after the name in the original byte stream.
fn read_name(buffer: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut position = start;
    let mut end = start;
    let mut jumped = false;
    let mut hops = 0;

    loop {
        if position >= buffer.len() {
            return Err("name runs past message".to_string());
        }
        let length = buffer[position];
        if length & 0xC0 == 0xC0 {
            if position + 1 >= buffer.len() {
                return Err("truncated compression pointer".to_string());
            }
            let target = (((length as usize) & 0x3F) << 8) | buffer[position + 1] as usize;
            if !jumped {
                end = position + 2;
                jumped = true;
            }
            hops += 1;
            if hops > 16 {
                return Err("compression pointer loop".to_string());
            }
            position = target;
            continue;
        }
        if length == 0 {
            position += 1;
            if !jumped {
                end = position;
            }
            break;
        }
        let length = length as usize;
        if position + 1 + length > buffer.len() {
            return Err("truncated label".to_string());
        }
        let label =
            String::from_utf8_lossy(&buffer[position + 1..position + 1 + length]).to_string();
        labels.push(label);
        position += 1 + length;
    }

    Ok((labels.join("."), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_query_with_correct_header() {
        let packet = build_query(0x1234, "example.com", TYPE_A).unwrap();
        assert_eq!(&packet[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1);
        // 7example3com0 + 4 bytes type/class
        assert_eq!(packet.len(), 12 + 13 + 4);
    }

    #[test]
    fn rejects_bad_labels() {
        assert!(build_query(1, "example..com", TYPE_A).is_err());
        assert!(build_query(1, "", TYPE_A).is_err());
    }

    #[test]
    fn parses_a_record_response() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00, 0x2A]); // id 42
        packet.extend_from_slice(&[0x81, 0x80]); // response, no error
        packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
        packet.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        packet.extend_from_slice(&[0, 0, 0, 60]); // ttl
        packet.extend_from_slice(&[0, 4]); // rdlength
        packet.extend_from_slice(&[192, 0, 2, 10]);

        let parsed = parse_response(&packet, 42).unwrap();
        assert_eq!(parsed.rcode, 0);
        assert_eq!(
            parsed.answers,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }

    #[test]
    fn follows_compression_pointers() {
        let mut buffer = vec![0u8; 12];
        buffer.extend_from_slice(&[7]);
        buffer.extend_from_slice(b"example");
        buffer.push(0);
        let pointer_offset = buffer.len();
        buffer.extend_from_slice(&[0xC0, 0x0C]);
        let (name, end) = read_name(&buffer, pointer_offset).unwrap();
        assert_eq!(name, "example");
        assert_eq!(end, pointer_offset + 2);
    }

    #[test]
    fn rejects_pointer_loops() {
        let mut buffer = vec![0u8; 12];
        buffer.extend_from_slice(&[0xC0, 0x0C]);
        assert!(read_name(&buffer, 12).is_err());
    }

    #[test]
    fn fake_ip_ranges_are_detected() {
        assert!(looks_like_fake_ip("198.18.0.17".parse().unwrap()));
        assert!(looks_like_fake_ip("0.0.0.0".parse().unwrap()));
        // RFC 1918 answers are not evidence of rewriting: internal names live
        // there legitimately.
        assert!(!looks_like_fake_ip("10.0.0.1".parse().unwrap()));
        assert!(!looks_like_fake_ip("192.168.1.1".parse().unwrap()));
        assert!(!looks_like_fake_ip("93.184.216.34".parse().unwrap()));
    }
}
