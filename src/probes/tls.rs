//! Stage 3b: TLS handshake and certificate inspection.
//!
//! Transport success and certificate verification are recorded separately.
//! A verification failure is never reported as "TLS handshake failed".

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName as PkiServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use x509_parser::prelude::*;

use crate::models::{
    CertInfo, Family, NetError, Probe, ProbeDetail, ProbeKind, ProbeOutcome, Verification,
};
use crate::probes::Recorder;

/// One TLS attempt result.
#[derive(Debug, Clone)]
pub struct TlsAttempt {
    pub probe_id: String,
    pub transport_ok: bool,
    pub verification: Verification,
    pub error: Option<NetError>,
    /// Human readable note about the attempt (for example a missing trust
    /// store). Surfaced as a report limitation rather than a silent failure.
    pub note: Option<String>,
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn root_store() -> (RootCertStore, Option<String>) {
    let mut store = RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    let mut added = 0usize;
    for cert in result.certs {
        if store.add(cert).is_ok() {
            added += 1;
        }
    }
    let note = if added == 0 {
        Some(
            "no system trust anchors could be loaded; verification results are unreliable"
                .to_string(),
        )
    } else {
        None
    };
    (store, note)
}

/// Verify nothing. Only reachable through the explicit `--allow-insecure-tls`
/// diagnostic path, and every such probe is labelled in the report.
#[derive(Debug)]
struct NoVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &PkiServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn build_config(insecure: bool) -> (Arc<ClientConfig>, Option<String>) {
    if insecure {
        let provider = rustls::crypto::ring::default_provider();
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification(Arc::new(provider))))
            .with_no_client_auth();
        return (Arc::new(config), None);
    }
    let (store, note) = root_store();
    let config = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    (Arc::new(config), note)
}

fn server_name(sni: &str) -> Result<PkiServerName<'static>, String> {
    if let Ok(ip) = sni.parse::<IpAddr>() {
        return Ok(PkiServerName::IpAddress(ip.into()));
    }
    PkiServerName::try_from(sni.to_string()).map_err(|error| format!("invalid SNI {sni}: {error}"))
}

/// Classify a rustls error into transport versus certificate failure.
fn classify(error: &rustls::Error) -> (NetError, String) {
    match error {
        rustls::Error::InvalidCertificate(cert_error) => {
            (NetError::Certificate, format!("{cert_error:?}"))
        }
        other => (NetError::TlsTransport, other.to_string()),
    }
}

fn cert_info(chain: &[CertificateDer<'_>]) -> Option<CertInfo> {
    let leaf = chain.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    let sans = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some((*name).to_string()),
                    GeneralName::IPAddress(bytes) => Some(format_ip_san(bytes)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(CertInfo {
        subject: Some(parsed.subject().to_string()),
        issuer: Some(parsed.issuer().to_string()),
        not_before: Some(format_timestamp(not_before)),
        not_after: Some(format_timestamp(not_after)),
        days_remaining: Some((not_after - now) / 86_400),
        sans,
        chain_len: chain.len(),
    })
}

fn format_ip_san(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            IpAddr::from(octets).to_string()
        }
        _ => format!("<{}-byte SAN>", bytes.len()),
    }
}

fn format_timestamp(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| seconds.to_string())
}

/// Perform one TLS attempt and record it. `insecure` must only be true for the
/// explicit diagnostic retry.
#[allow(clippy::too_many_arguments)]
/// A completed TLS session plus the facts rustls can report about it.
pub(crate) struct TlsSession {
    pub stream: rustls::StreamOwned<ClientConnection, TcpStream>,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub cert: Option<CertInfo>,
}

/// Failure modes kept separate so callers never confuse transport problems
/// with trust problems.
pub(crate) enum TlsFailure {
    // The certificate variant carries parsed metadata, which makes it the large
    // variant; boxing keeps the Result small on the hot path.
    Certificate {
        message: String,
        cert: Option<Box<CertInfo>>,
    },
    Transport(String),
}

/// Drive a TLS handshake over an established stream.
pub(crate) fn handshake(
    mut stream: TcpStream,
    sni: &str,
    insecure: bool,
) -> Result<TlsSession, TlsFailure> {
    let (config, _note) = build_config(insecure);
    let name = server_name(sni).map_err(TlsFailure::Transport)?;
    let mut connection = ClientConnection::new(config, name)
        .map_err(|error| TlsFailure::Transport(format!("client setup: {error}")))?;
    while connection.is_handshaking() {
        if let Err(io_error) = connection.complete_io(&mut stream) {
            let inner = io_error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>());
            return match inner {
                Some(rustls::Error::InvalidCertificate(cert_error)) => {
                    let (_, message) =
                        classify(&rustls::Error::InvalidCertificate(cert_error.clone()));
                    Err(TlsFailure::Certificate {
                        message,
                        cert: connection
                            .peer_certificates()
                            .and_then(cert_info)
                            .map(Box::new),
                    })
                }
                Some(other) => Err(TlsFailure::Transport(other.to_string())),
                None => Err(TlsFailure::Transport(io_error.to_string())),
            };
        }
    }
    let protocol = connection
        .protocol_version()
        .map(|value| format!("{value:?}"));
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));
    let cert = connection.peer_certificates().and_then(cert_info);
    Ok(TlsSession {
        stream: rustls::StreamOwned::new(connection, stream),
        protocol,
        cipher,
        cert,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn probe(
    recorder: &mut Recorder,
    family: Family,
    ip: IpAddr,
    port: u16,
    sni: &str,
    timeout: Duration,
    insecure: bool,
    interface: Option<&str>,
) -> TlsAttempt {
    let prefix = match family {
        Family::Ipv4 => "tls_ipv4",
        Family::Ipv6 => "tls_ipv6",
    };
    let id = recorder.next_id(prefix);
    let started_at = crate::util::now_rfc3339();
    let started = Instant::now();

    let mut transport_ok = false;
    let mut verification = Verification::NotChecked;
    let mut protocol = None;
    let mut cipher = None;
    let mut cert = None;
    let mut error = None;
    let mut notes: Vec<String> = Vec::new();

    let connect = crate::net::connect(SocketAddr::new(ip, port), timeout, interface);
    let tcp_ms = started.elapsed().as_secs_f64() * 1000.0;
    let handshake_ms = match connect {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let handshake_started = Instant::now();
            let outcome = handshake(stream, sni, insecure);
            let elapsed = handshake_started.elapsed().as_secs_f64() * 1000.0;
            match outcome {
                Ok(session) => {
                    transport_ok = true;
                    verification = if insecure {
                        Verification::NotChecked
                    } else {
                        Verification::Verified
                    };
                    protocol = session.protocol.clone();
                    cipher = session.cipher.clone();
                    cert = session.cert.clone();
                }
                Err(TlsFailure::Certificate {
                    message,
                    cert: parsed,
                }) => {
                    verification = Verification::Failed(message.clone());
                    error = Some(NetError::Certificate);
                    cert = parsed.map(|value| *value);
                    notes.push(format!("certificate verification: {message}"));
                }
                Err(TlsFailure::Transport(message)) => {
                    error = Some(NetError::TlsTransport);
                    notes.push(format!("tls: {message}"));
                }
            }
            Some(elapsed)
        }
        Err(err) => {
            let classified = crate::util::classify_io_error(&err);
            notes.push(format!("tcp connect: {err}"));
            error = Some(classified);
            None
        }
    };

    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let detail = ProbeDetail::TlsHandshake {
        handshake_ms: handshake_ms.map(round2),
        transport_ok,
        verification: verification.clone(),
        protocol: protocol.clone(),
        cipher_suite: cipher.clone(),
        sni: sni.to_string(),
        cert: cert.clone(),
        error: error.clone(),
        insecure_retry: insecure,
    };

    let _ = tcp_ms;

    recorder.record(Probe {
        id: id.clone(),
        kind: ProbeKind::Tls,
        outcome: if transport_ok {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::Fail
        },
        family: Some(family),
        target: Some(ip.to_string()),
        port: Some(port),
        started_at,
        duration_ms: Some(round2(total_ms)),
        detail,
    });

    let note = if notes.is_empty() {
        None
    } else {
        Some(notes.join("; "))
    };
    TlsAttempt {
        probe_id: id,
        transport_ok,
        verification,
        error,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_accepts_dns_and_ip() {
        assert!(server_name("example.com").is_ok());
        assert!(server_name("192.0.2.10").is_ok());
        assert!(server_name("2001:db8::1").is_ok());
    }

    #[test]
    fn certificate_errors_are_not_transport_errors() {
        let error = rustls::Error::InvalidCertificate(rustls::CertificateError::Expired);
        let (classified, message) = classify(&error);
        assert_eq!(classified, NetError::Certificate);
        assert!(message.contains("Expired"));
    }

    #[test]
    fn timestamp_formatting_is_rfc3339() {
        let text = format_timestamp(1_700_000_000);
        assert!(text.ends_with('Z'));
        assert!(text.contains('T'));
    }
}
