//! M09: application-level UDP echo.
//!
//! Every datagram carries a magic marker, a session id and a sequence number.
//! A reply only counts when the payload is byte-identical, so an ICMP error or
//! an unrelated datagram can never be reported as a successful echo.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::models::{NetError, Probe, ProbeDetail, ProbeKind, ProbeOutcome};
use crate::probes::Recorder;

pub const MAGIC: [u8; 4] = *b"PTRB";
pub const MAX_PAYLOAD: usize = 512;
pub const HEADER_LEN: usize = 17;

/// How one round ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoResult {
    Echo,
    Timeout,
    IcmpUnreachable,
    InvalidPayload,
    WrongSequence,
    UnexpectedSource,
    Duplicate,
}

impl EchoResult {
    pub fn label(self) -> &'static str {
        match self {
            EchoResult::Echo => "echo",
            EchoResult::Timeout => "timeout",
            EchoResult::IcmpUnreachable => "icmp_unreachable",
            EchoResult::InvalidPayload => "invalid_payload",
            EchoResult::WrongSequence => "wrong_sequence",
            EchoResult::UnexpectedSource => "unexpected_source",
            EchoResult::Duplicate => "duplicate",
        }
    }

    pub fn counts_as_echo(self) -> bool {
        matches!(self, EchoResult::Echo)
    }
}

#[derive(Debug, Clone)]
pub struct EchoSample {
    pub probe_id: String,
    pub seq: u32,
    pub result: EchoResult,
    pub rtt_ms: Option<f64>,
    pub sent_bytes: usize,
    pub received_bytes: Option<usize>,
}

/// Aggregate statistics for one run.
#[derive(Debug, Clone, Default)]
pub struct EchoStats {
    pub sent: u32,
    pub echoes: u32,
    pub failures: u32,
    pub success_rate: f64,
    pub rtt_min: Option<f64>,
    pub rtt_avg: Option<f64>,
    pub rtt_median: Option<f64>,
    pub rtt_max: Option<f64>,
    pub jitter: Option<f64>,
    pub classes: Vec<(String, u32)>,
}

pub struct EchoRequest<'a> {
    pub target: SocketAddr,
    pub rounds: u32,
    pub timeout: Duration,
    pub interval: Duration,
    pub interface: Option<&'a str>,
    pub payload: usize,
    pub deadline: Instant,
}

/// Build the datagram for one round.
pub fn payload(session: u64, seq: u32, size: usize) -> Vec<u8> {
    let size = size.clamp(HEADER_LEN, MAX_PAYLOAD);
    let mut buffer = vec![b'.'; size];
    buffer[..4].copy_from_slice(&MAGIC);
    buffer[4] = 1;
    buffer[5..13].copy_from_slice(&session.to_be_bytes());
    buffer[13..17].copy_from_slice(&seq.to_be_bytes());
    buffer
}

/// Validate a reply against the datagram that was sent.
pub fn classify_reply(
    sent: &[u8],
    reply: &[u8],
    expected_seq: u32,
    answered: &[u32],
) -> EchoResult {
    if reply.len() < HEADER_LEN || reply[..4] != MAGIC {
        return EchoResult::InvalidPayload;
    }
    let reply_seq = u32::from_be_bytes([reply[13], reply[14], reply[15], reply[16]]);
    if reply_seq != expected_seq && answered.contains(&reply_seq) {
        return EchoResult::Duplicate;
    }
    if reply[..HEADER_LEN] != sent[..HEADER_LEN] {
        if reply_seq != expected_seq {
            return EchoResult::WrongSequence;
        }
        return EchoResult::InvalidPayload;
    }
    if reply.len() != sent.len() || reply != sent {
        return EchoResult::InvalidPayload;
    }
    EchoResult::Echo
}

/// Run the echo rounds and record one probe per round.
pub fn run(recorder: &mut Recorder, request: &EchoRequest<'_>) -> (Vec<EchoSample>, EchoStats) {
    let bind: SocketAddr = if request.target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    let session = crate::util::new_run_id()
        .chars()
        .fold(0u64, |acc, ch| acc.wrapping_mul(31).wrapping_add(ch as u64));

    let socket = match crate::net::udp_socket(bind, request.interface) {
        Ok(socket) => socket,
        Err(error) => {
            let id = recorder.next_id("udp");
            recorder.record(Probe {
                id: id.clone(),
                kind: ProbeKind::UdpObservation,
                outcome: ProbeOutcome::Fail,
                family: None,
                target: Some(request.target.to_string()),
                port: Some(request.target.port()),
                started_at: crate::util::now_rfc3339(),
                duration_ms: None,
                detail: ProbeDetail::UdpObservation {
                    observation: crate::models::UdpObservation::NoResponseToInvalidPayload,
                    implies_udp_session: false,
                    note: format!("udp socket setup failed: {error}"),
                },
            });
            return (
                vec![EchoSample {
                    probe_id: id,
                    seq: 0,
                    result: EchoResult::Timeout,
                    rtt_ms: None,
                    sent_bytes: 0,
                    received_bytes: None,
                }],
                EchoStats::default(),
            );
        }
    };
    let _ = socket.connect(request.target);

    let mut samples = Vec::new();
    let mut answered: Vec<u32> = Vec::new();
    for round in 0..request.rounds {
        if Instant::now() >= request.deadline {
            break;
        }
        let seq = round + 1;
        let datagram = payload(session, seq, request.payload);
        let remaining = request.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let started = Instant::now();
        let result = send_and_receive(
            &socket,
            &datagram,
            seq,
            request.timeout.min(remaining),
            &answered,
            request.target,
        );
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        if result.0 == EchoResult::Echo {
            answered.push(seq);
        }
        let id = recorder.next_id("udp");
        let note = result.1.clone().unwrap_or_else(|| {
            if result.0 == EchoResult::Echo {
                "echo payload matched".to_string()
            } else {
                format!("round {}: {}", seq, result.0.label())
            }
        });
        recorder.record(Probe {
            id: id.clone(),
            kind: ProbeKind::UdpObservation,
            outcome: if result.0 == EchoResult::Echo {
                ProbeOutcome::Ok
            } else {
                ProbeOutcome::Fail
            },
            family: None,
            target: Some(request.target.to_string()),
            port: Some(request.target.port()),
            started_at: crate::util::now_rfc3339(),
            duration_ms: Some(round2(elapsed)),
            detail: ProbeDetail::UdpEcho {
                seq,
                session: format!("{session:016x}"),
                sent_bytes: datagram.len(),
                received_bytes: result.2,
                result: result.0.label().to_string(),
                rtt_ms: if result.0 == EchoResult::Echo {
                    Some(round2(elapsed))
                } else {
                    None
                },
                note,
            },
        });
        samples.push(EchoSample {
            probe_id: id,
            seq,
            result: result.0,
            rtt_ms: if result.0 == EchoResult::Echo {
                Some(round2(elapsed))
            } else {
                None
            },
            sent_bytes: datagram.len(),
            received_bytes: result.2,
        });
        if !request.interval.is_zero() {
            std::thread::sleep(request.interval);
        }
    }

    let stats = summarize(&samples);
    (samples, stats)
}

type RoundResult = (EchoResult, Option<String>, Option<usize>);

fn send_and_receive(
    socket: &UdpSocket,
    datagram: &[u8],
    seq: u32,
    timeout: Duration,
    answered: &[u32],
    expected_source: SocketAddr,
) -> RoundResult {
    if let Err(error) = socket.send(datagram) {
        return (classify_send(&error), Some(format!("send: {error}")), None);
    }
    let _ = socket.set_read_timeout(Some(timeout));
    let mut buffer = [0u8; MAX_PAYLOAD];
    match socket.recv_from(&mut buffer) {
        Ok((read, source)) => {
            let reply = &buffer[..read];
            if source != expected_source {
                return (EchoResult::UnexpectedSource, None, Some(read));
            }
            (
                classify_reply(datagram, reply, seq, answered),
                None,
                Some(read),
            )
        }
        Err(error) => {
            let kind = crate::util::classify_io_error(&error);
            let result = match kind {
                NetError::ConnectionRefused => EchoResult::IcmpUnreachable,
                NetError::Timeout => EchoResult::Timeout,
                _ => EchoResult::Timeout,
            };
            (result, Some(format!("recv: {error}")), None)
        }
    }
}

fn classify_send(error: &io::Error) -> EchoResult {
    match crate::util::classify_io_error(error) {
        NetError::NetworkUnreachable | NetError::HostUnreachable => EchoResult::IcmpUnreachable,
        _ => EchoResult::Timeout,
    }
}

/// Aggregate the per-round results.
pub fn summarize(samples: &[EchoSample]) -> EchoStats {
    let mut stats = EchoStats {
        sent: samples.len() as u32,
        ..Default::default()
    };
    let mut rtts: Vec<f64> = Vec::new();
    for sample in samples {
        if sample.result.counts_as_echo() {
            stats.echoes += 1;
            if let Some(rtt) = sample.rtt_ms {
                rtts.push(rtt);
            }
        } else {
            stats.failures += 1;
            match stats
                .classes
                .iter_mut()
                .find(|(name, _)| name == sample.result.label())
            {
                Some((_, count)) => *count += 1,
                None => stats.classes.push((sample.result.label().to_string(), 1)),
            }
        }
    }
    if stats.sent > 0 {
        stats.success_rate = stats.echoes as f64 / stats.sent as f64;
    }
    if !rtts.is_empty() {
        let mut sorted = rtts.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        stats.rtt_min = sorted.first().copied();
        stats.rtt_max = sorted.last().copied();
        stats.rtt_avg = Some(rtts.iter().sum::<f64>() / rtts.len() as f64);
        stats.rtt_median = Some(sorted[sorted.len() / 2]);
        if sorted.len() > 1 {
            let mean = stats.rtt_avg.unwrap_or(0.0);
            let variance = sorted
                .iter()
                .map(|value| (value - mean).powi(2))
                .sum::<f64>()
                / sorted.len() as f64;
            stats.jitter = Some(variance.sqrt());
        }
    }
    stats
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_carry_magic_session_and_sequence() {
        let datagram = payload(0x1234, 7, 64);
        assert_eq!(&datagram[..4], &MAGIC);
        assert_eq!(datagram[4], 1);
        assert_eq!(
            u32::from_be_bytes([datagram[13], datagram[14], datagram[15], datagram[16]]),
            7
        );
        assert_eq!(datagram.len(), 64);
    }

    #[test]
    fn payload_size_is_bounded() {
        assert_eq!(payload(1, 1, 10_000).len(), MAX_PAYLOAD);
        assert_eq!(payload(1, 1, 1).len(), HEADER_LEN);
    }

    #[test]
    fn exact_mirror_is_the_only_success() {
        let sent = payload(9, 3, 64);
        assert_eq!(classify_reply(&sent, &sent, 3, &[]), EchoResult::Echo);

        let mut truncated = sent.clone();
        truncated.pop();
        assert_eq!(
            classify_reply(&sent, &truncated, 3, &[]),
            EchoResult::InvalidPayload
        );

        let mut altered = sent.clone();
        altered[20] ^= 0xFF;
        assert_eq!(
            classify_reply(&sent, &altered, 3, &[]),
            EchoResult::InvalidPayload
        );

        let mut other_seq = payload(9, 4, 64);
        other_seq[20] = b'#';
        assert_eq!(
            classify_reply(&sent, &other_seq, 3, &[]),
            EchoResult::WrongSequence
        );

        assert_eq!(
            classify_reply(&sent, b"garbage", 3, &[]),
            EchoResult::InvalidPayload
        );
    }

    #[test]
    fn duplicate_and_foreign_magic_are_distinct() {
        let sent = payload(9, 3, 64);
        let stale = payload(9, 2, 64);
        assert_eq!(
            classify_reply(&sent, &stale, 3, &[2]),
            EchoResult::Duplicate
        );
        let mut foreign = sent.clone();
        foreign[..4].copy_from_slice(b"QUIC");
        assert_eq!(
            classify_reply(&sent, &foreign, 3, &[]),
            EchoResult::InvalidPayload
        );
    }

    #[test]
    fn statistics_reflect_only_echoes() {
        let samples = vec![
            EchoSample {
                probe_id: "a".into(),
                seq: 1,
                result: EchoResult::Echo,
                rtt_ms: Some(10.0),
                sent_bytes: 64,
                received_bytes: Some(64),
            },
            EchoSample {
                probe_id: "b".into(),
                seq: 2,
                result: EchoResult::Timeout,
                rtt_ms: None,
                sent_bytes: 64,
                received_bytes: None,
            },
            EchoSample {
                probe_id: "c".into(),
                seq: 3,
                result: EchoResult::IcmpUnreachable,
                rtt_ms: None,
                sent_bytes: 64,
                received_bytes: None,
            },
        ];
        let stats = summarize(&samples);
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.echoes, 1);
        assert_eq!(stats.failures, 2);
        assert!((stats.success_rate - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(stats.rtt_avg, Some(10.0));
        assert!(stats
            .classes
            .iter()
            .any(|(name, _)| name == "icmp_unreachable"));
    }
}
