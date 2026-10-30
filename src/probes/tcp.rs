//! TCP connect probes.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::models::{Family, NetError, Probe, ProbeDetail, ProbeKind, ProbeOutcome};
use crate::probes::Recorder;
use crate::util::classify_io_error;

/// Result of one TCP connect attempt.
#[derive(Debug, Clone)]
pub struct TcpSample {
    pub probe_id: String,
    pub ok: bool,
    pub connect_ms: Option<f64>,
    pub error: Option<NetError>,
}

/// Perform a single connect attempt and record it.
pub fn probe_once(
    recorder: &mut Recorder,
    family: Family,
    address: IpAddr,
    port: u16,
    timeout: Duration,
    interface: Option<&str>,
) -> TcpSample {
    let prefix = match family {
        Family::Ipv4 => "tcp_ipv4",
        Family::Ipv6 => "tcp_ipv6",
    };
    let id = recorder.next_id(prefix);
    let started_at = crate::util::now_rfc3339();
    let started = Instant::now();
    let socket = SocketAddr::new(address, port);
    let outcome = crate::net::connect(socket, timeout, interface);
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;

    let (ok, detail) = match outcome {
        Ok(stream) => {
            // Close immediately; PATH_MTU/keepalive tuning is out of scope.
            drop(stream);
            (
                true,
                ProbeDetail::TcpConnect {
                    connect_ms: Some(round2(elapsed)),
                    error: None,
                },
            )
        }
        Err(error) => {
            let classified = classify_io_error(&error);
            (
                false,
                ProbeDetail::TcpConnect {
                    connect_ms: None,
                    error: Some(classified),
                },
            )
        }
    };

    let (connect_ms, error) = match &detail {
        ProbeDetail::TcpConnect { connect_ms, error } => (*connect_ms, error.clone()),
        _ => (None, None),
    };
    let probe = Probe {
        id: id.clone(),
        kind: ProbeKind::Tcp,
        outcome: if ok {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::Fail
        },
        family: Some(family),
        target: Some(address.to_string()),
        port: Some(port),
        started_at,
        duration_ms: Some(round2(elapsed)),
        detail,
    };
    recorder.record(probe);
    TcpSample {
        probe_id: id,
        ok,
        connect_ms,
        error,
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn records_success_against_local_listener() {
        // A loopback listener is deterministic and needs no network access.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let accept = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let mut recorder = Recorder::new();
        let sample = probe_once(
            &mut recorder,
            Family::Ipv4,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
            None,
        );
        let _ = accept.join();
        assert!(sample.ok, "loopback connect should succeed");
        assert!(sample.connect_ms.is_some());
        assert_eq!(recorder.len(), 1);
    }

    #[test]
    fn records_refused_error_category() {
        // Bind then drop to obtain a port that is very likely closed.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut recorder = Recorder::new();
        let sample = probe_once(
            &mut recorder,
            Family::Ipv4,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            Duration::from_millis(800),
            None,
        );
        assert!(!sample.ok, "a closed port must not be stored as success");
        match sample.error {
            Some(NetError::ConnectionRefused) => {}
            // A Windows stack can time out or reset a just-closed loopback
            // port instead of returning WSAECONNREFUSED. Record that
            // observation; do not relabel it as a refusal.
            #[cfg(windows)]
            Some(NetError::Timeout) | Some(NetError::ConnectionReset) => {}
            other => panic!("closed loopback port classified as {other:?}"),
        }
    }
}
