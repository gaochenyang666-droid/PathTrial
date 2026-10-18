//! M10: real QUIC handshake and HTTP/3 request.
//!
//! Transport, certificate verification, ALPN and HTTP/3 are recorded as
//! separate stages. A successful QUIC handshake never implies that an HTTP/3
//! request succeeded.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Buf;
use futures_util::future;

use crate::models::{Probe, ProbeDetail, ProbeKind, ProbeOutcome};
use crate::probes::Recorder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyChoice {
    Auto,
    Ipv4,
    Ipv6,
}

pub struct Http3Target<'a> {
    pub uri: &'a str,
}

pub struct QuicRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub family: FamilyChoice,
    pub alpn: &'a str,
    pub server_name: Option<&'a str>,
    pub timeout: Duration,
    pub deadline: Instant,
    pub interface: Option<&'a str>,
    pub ca_file: Option<&'a Path>,
    pub insecure: bool,
    pub http3: Option<Http3Target<'a>>,
}

#[derive(Debug, Default)]
pub struct QuicOutcome {
    pub address: Option<SocketAddr>,
    pub handshake_ms: Option<f64>,
    pub handshake_ok: bool,
    pub tls_verified: Option<bool>,
    pub alpn: Option<String>,
    pub http3_status: Option<u16>,
    pub http3_bytes: usize,
    pub http3_ttfb_ms: Option<f64>,
    pub http3_total_ms: Option<f64>,
    pub stage: String,
    pub error: Option<String>,
}

impl QuicOutcome {
    pub fn fake_ip_suspected(&self) -> bool {
        self.error
            .as_deref()
            .map(|error| error.starts_with("fake_ip:"))
            .unwrap_or(false)
    }

    pub fn protocol_unavailable(&self) -> bool {
        self.error.is_some()
            && (self.stage == "alpn"
                || self
                    .error
                    .as_deref()
                    .map(|error| {
                        error.contains("no application protocol")
                            || error.contains("peer doesn't support")
                    })
                    .unwrap_or(false))
    }
}

pub fn run(recorder: &mut Recorder, request: &QuicRequest<'_>) -> Result<QuicOutcome, String> {
    let timeout = request
        .deadline
        .saturating_duration_since(Instant::now())
        .min(request.timeout);
    if timeout.is_zero() {
        return Err("QUIC budget exhausted before the probe started".to_string());
    }

    let address = resolve(recorder, request, timeout)?;
    let server_name = request
        .server_name
        .unwrap_or(request.host)
        .trim_matches(['[', ']'])
        .to_string();
    let mut outcome = QuicOutcome {
        address: Some(address),
        stage: "dns".to_string(),
        ..QuicOutcome::default()
    };
    if crate::net::scope_of(address.ip()) == crate::net::AddressScope::Benchmark {
        outcome.error = Some(format!(
            "fake_ip:{} is in 198.18.0.0/15 and was likely rewritten by a local proxy",
            address.ip()
        ));
        return Ok(outcome);
    }
    let alpn = request.alpn.as_bytes().to_vec();
    let mut tls = if request.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let roots = trust_store(request.ca_file)?;
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![alpn.clone()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| format!("QUIC TLS setup: {error}"))?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(timeout).map_err(|error| format!("idle timeout: {error}"))?,
    ));
    transport.keep_alive_interval(None);
    client_config.transport_config(Arc::new(transport));

    let bind: SocketAddr = if address.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = crate::net::udp_socket(bind, request.interface)
        .map_err(|error| format!("UDP socket setup: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("tokio runtime: {error}"))?;
    runtime.block_on(async {
        outcome.stage = "socket".to_string();
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| format!("QUIC endpoint: {error}"))?;
        endpoint.set_default_client_config(client_config);
        outcome.stage = "handshake".to_string();
        let handshake_started = Instant::now();
        let connecting = endpoint
            .connect(address, &server_name)
            .map_err(|error| format!("QUIC connect start: {error}"))?;
        let connection = match tokio::time::timeout(timeout, connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                outcome.error = Some(format!("handshake:{error}"));
                return Ok(outcome);
            }
            Err(_) => {
                outcome.error = Some("timeout:handshake".to_string());
                return Ok(outcome);
            }
        };
        outcome.handshake_ms = Some(round2(handshake_started.elapsed().as_secs_f64() * 1000.0));
        outcome.handshake_ok = true;
        outcome.tls_verified = Some(!request.insecure);
        outcome.alpn = connection
            .handshake_data()
            .and_then(|data| {
                data.downcast_ref::<quinn_proto::crypto::rustls::HandshakeData>()
                    .and_then(|data| data.protocol.clone())
            })
            .map(|value| String::from_utf8_lossy(&value).to_string());
        outcome.stage = "alpn".to_string();
        if outcome.alpn.as_deref() != Some(request.alpn) {
            outcome.error = Some(format!(
                "alpn_mismatch: requested {}, negotiated {}",
                request.alpn,
                outcome.alpn.as_deref().unwrap_or("none")
            ));
            connection.close(0u32.into(), b"alpn mismatch");
            let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
            return Ok(outcome);
        }

        if let Some(target) = &request.http3 {
            outcome.stage = "http3_request".to_string();
            let http_result = http3_exchange(&connection, target, timeout).await;
            match http_result {
                Ok(exchange) => {
                    outcome.stage = "http3_response".to_string();
                    outcome.http3_status = Some(exchange.status);
                    outcome.http3_bytes = exchange.bytes;
                    outcome.http3_ttfb_ms = Some(exchange.ttfb_ms);
                    outcome.http3_total_ms = Some(exchange.total_ms);
                }
                Err(error) => {
                    outcome.error = Some(format!("http3:{error}"));
                }
            }
        }
        connection.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
        Ok(outcome)
    })
}

fn resolve(
    recorder: &mut Recorder,
    request: &QuicRequest<'_>,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let literal = request.host.trim_matches(['[', ']']).parse::<IpAddr>().ok();
    let ip = match literal {
        Some(ip) => ip,
        None => {
            let resolved = crate::probes::dns::resolve(request.host, recorder, timeout / 3);
            let candidates = match request.family {
                FamilyChoice::Ipv4 => &resolved.addresses_v4,
                FamilyChoice::Ipv6 => &resolved.addresses_v6,
                FamilyChoice::Auto => {
                    if !resolved.addresses_v4.is_empty() {
                        &resolved.addresses_v4
                    } else {
                        &resolved.addresses_v6
                    }
                }
            };
            candidates
                .first()
                .and_then(|value| value.parse::<IpAddr>().ok())
                .ok_or_else(|| {
                    format!(
                        "no {} address for {}",
                        family_label(request.family),
                        request.host
                    )
                })?
        }
    };
    let mismatch = match request.family {
        FamilyChoice::Auto => false,
        FamilyChoice::Ipv4 => !ip.is_ipv4(),
        FamilyChoice::Ipv6 => !ip.is_ipv6(),
    };
    if mismatch {
        return Err(format!("{} is not {}", ip, family_label(request.family)));
    }
    Ok(SocketAddr::new(ip, request.port))
}

fn family_label(family: FamilyChoice) -> &'static str {
    match family {
        FamilyChoice::Auto => "usable",
        FamilyChoice::Ipv4 => "IPv4",
        FamilyChoice::Ipv6 => "IPv6",
    }
}

fn trust_store(ca_file: Option<&Path>) -> Result<rustls::RootCertStore, String> {
    let mut store = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = store.add(cert);
    }
    if let Some(path) = ca_file {
        let file = std::fs::File::open(path)
            .map_err(|error| format!("open CA file {}: {error}", path.display()))?;
        let mut reader = std::io::BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|error| format!("parse CA file: {error}"))?;
            store
                .add(cert)
                .map_err(|error| format!("add CA certificate: {error}"))?;
        }
    }
    if store.is_empty() && ca_file.is_none() {
        return Err(
            "no system trust anchors available; use --ca-file for a test server".to_string(),
        );
    }
    Ok(store)
}

struct Exchange {
    status: u16,
    bytes: usize,
    ttfb_ms: f64,
    total_ms: f64,
}

async fn http3_exchange(
    connection: &quinn::Connection,
    target: &Http3Target<'_>,
    timeout: Duration,
) -> Result<Exchange, String> {
    let started = Instant::now();
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|error| format!("client setup: {error}"))?;
    let request = http::Request::builder()
        .method("GET")
        .uri(target.uri)
        .header(
            "user-agent",
            format!("pathtrial/{}", env!("CARGO_PKG_VERSION")),
        )
        .body(())
        .map_err(|error| format!("request build: {error}"))?;
    let request_future = async {
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("send request: {error}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("recv response: {error}"))?;
        let ttfb_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
        let mut bytes = 0usize;
        while let Some(chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("recv body: {error}"))?
        {
            bytes = bytes.saturating_add(chunk.remaining()).min(64 * 1024);
            if bytes >= 64 * 1024 {
                break;
            }
        }
        Ok::<_, String>((
            response.status().as_u16(),
            bytes,
            ttfb_ms,
            round2(started.elapsed().as_secs_f64() * 1000.0),
        ))
    };
    let driver_task = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let result = tokio::time::timeout(timeout, request_future).await;
    driver_task.abort();
    match result {
        Ok(Ok((status, bytes, ttfb_ms, total_ms))) => Ok(Exchange {
            status,
            bytes,
            ttfb_ms,
            total_ms,
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("timeout:http3".to_string()),
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn record_outcome(
    recorder: &mut Recorder,
    request: &QuicRequest<'_>,
    outcome: &QuicOutcome,
) -> String {
    let id = recorder.next_id("quic");
    let family = outcome
        .address
        .map(|address| if address.is_ipv4() { "ipv4" } else { "ipv6" })
        .unwrap_or("unknown")
        .to_string();
    let ok = outcome.handshake_ok
        && outcome.error.is_none()
        && (outcome.http3_status.is_some() || request.http3.is_none());
    recorder.record(Probe {
        id: id.clone(),
        kind: ProbeKind::Quic,
        outcome: if ok {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::Fail
        },
        family: outcome.address.map(|address| {
            if address.is_ipv4() {
                crate::models::Family::Ipv4
            } else {
                crate::models::Family::Ipv6
            }
        }),
        target: Some(format!("{}:{}", request.host, request.port)),
        port: Some(request.port),
        started_at: crate::util::now_rfc3339(),
        duration_ms: outcome.handshake_ms,
        detail: ProbeDetail::Quic {
            host: request.host.to_string(),
            port: request.port,
            family,
            server_name: request.server_name.unwrap_or(request.host).to_string(),
            alpn_requested: request.alpn.to_string(),
            alpn: outcome.alpn.clone(),
            handshake_ms: outcome.handshake_ms,
            handshake_ok: outcome.handshake_ok,
            tls_verified: outcome.tls_verified,
            http3_status: outcome.http3_status,
            http3_bytes: outcome.http3_bytes,
            http3_ttfb_ms: outcome.http3_ttfb_ms,
            http3_total_ms: outcome.http3_total_ms,
            stage: outcome.stage.clone(),
            error: outcome.error.clone(),
        },
    })
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn check_interface(interface: Option<&str>) -> Result<(), String> {
    if let Some(name) = interface {
        if crate::net::interface_index(name).is_none() {
            return Err(format!(
                "interface {name} does not exist; check --bind-interface"
            ));
        }
    }
    Ok(())
}

pub fn record(recorder: &mut Recorder, request: &QuicRequest<'_>, outcome: &QuicOutcome) -> String {
    record_outcome(recorder, request, outcome)
}
