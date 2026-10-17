//! Local QUIC and HTTP/3 protocol tests. No public network is required.

use std::io::Write;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

#[derive(Clone, Copy)]
enum ServerMode {
    Http3(u16),
    QuicOnly,
}

struct TestServer {
    port: u16,
    ca_file: PathBuf,
}

static SERVER_ID: AtomicU64 = AtomicU64::new(1);

fn start_server(mode: ServerMode, alpn: &'static str, ipv6: bool) -> Option<TestServer> {
    let bind = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
    let probe = UdpSocket::bind(bind).ok()?;
    drop(probe);

    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).ok()?;
    let cert_pem = generated.cert.pem();
    let ca_path = std::env::temp_dir().join(format!(
        "pathtrial-quic-ca-{}-{}.pem",
        std::process::id(),
        SERVER_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::File::create(&ca_path)
        .ok()?
        .write_all(cert_pem.as_bytes())
        .ok()?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let cert = rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
            let key =
                rustls::pki_types::PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
            let mut tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server certificate");
            tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
            let quic_tls =
                quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC server config");
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
            let endpoint =
                quinn::Endpoint::server(server_config, bind.parse().unwrap()).expect("endpoint");
            tx.send(endpoint.local_addr().unwrap().port()).unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    match mode {
                        ServerMode::QuicOnly => {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            connection.close(0u32.into(), b"no http3");
                        }
                        ServerMode::Http3(status) => {
                            let Ok(mut h3_conn) =
                                h3::server::Connection::new(h3_quinn::Connection::new(connection))
                                    .await
                            else {
                                return;
                            };
                            while let Ok(Some(resolver)) = h3_conn.accept().await {
                                let Ok((_request, mut stream)) = resolver.resolve_request().await
                                else {
                                    continue;
                                };
                                let response = http::Response::builder()
                                    .status(status)
                                    .body(())
                                    .expect("response");
                                if stream.send_response(response).await.is_err() {
                                    continue;
                                }
                                let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
                                let _ = stream.finish().await;
                            }
                        }
                    }
                });
            }
        });
    });
    let port = rx.recv_timeout(Duration::from_secs(5)).ok()?;
    Some(TestServer {
        port,
        ca_file: ca_path,
    })
}

fn run(args: &[String]) -> (std::process::ExitStatus, serde_json::Value) {
    let output = Command::new(binary()).args(args).output().expect("run");
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON ({error}): {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status, value)
}

#[test]
fn quic_handshake_and_http3_request_succeed_against_local_server() {
    let Some(server) = start_server(ServerMode::Http3(200), "h3", false) else {
        return;
    };
    let args = vec![
        "http3".to_string(),
        format!("https://127.0.0.1:{}/", server.port),
        "--sni".to_string(),
        "localhost".to_string(),
        "--ca-file".to_string(),
        server.ca_file.display().to_string(),
        "--timeout-ms".to_string(),
        "3000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert!(status.success(), "http3 failed: {value}");
    let detail = value["probes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|probe| probe["kind"] == "quic")
        .map(|probe| &probe["detail"])
        .expect("quic probe");
    assert_eq!(detail["handshake_ok"], true);
    assert_eq!(detail["alpn"], "h3");
    assert_eq!(detail["tls_verified"], true);
    assert_eq!(detail["http3_status"], 200);
    assert!(detail["http3_bytes"].as_u64().unwrap() > 0);
    assert!(detail["handshake_ms"].as_f64().unwrap() >= 0.0);
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/command.schema.json")).unwrap();
    let errors: Vec<String> = jsonschema::validator_for(&schema)
        .unwrap()
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "schema: {errors:?}");
}

#[test]
fn quic_only_handshake_passes_without_http3() {
    let Some(server) = start_server(ServerMode::QuicOnly, "h3", false) else {
        return;
    };
    let args = vec![
        "quic".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        server.port.to_string(),
        "--alpn".to_string(),
        "h3".to_string(),
        "--sni".to_string(),
        "localhost".to_string(),
        "--ca-file".to_string(),
        server.ca_file.display().to_string(),
        "--timeout-ms".to_string(),
        "3000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert!(status.success(), "quic failed: {value}");
    let detail = value["probes"][0]["detail"].clone();
    assert_eq!(detail["handshake_ok"], true);
    assert_eq!(detail["http3_status"], serde_json::Value::Null);
}

#[test]
fn quic_certificate_failure_is_not_a_transport_success() {
    let Some(server) = start_server(ServerMode::QuicOnly, "h3", false) else {
        return;
    };
    let args = vec![
        "quic".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        server.port.to_string(),
        "--sni".to_string(),
        "localhost".to_string(),
        "--timeout-ms".to_string(),
        "2000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert_eq!(status.code(), Some(2));
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["handshake_ok"], false);
    let error = detail["error"].as_str().unwrap().to_lowercase();
    assert!(error.contains("certificate") || error.contains("invalid peer"));
}

#[test]
fn quic_alpn_mismatch_is_protocol_unavailable() {
    let Some(server) = start_server(ServerMode::QuicOnly, "not-h3", false) else {
        return;
    };
    let args = vec![
        "quic".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        server.port.to_string(),
        "--sni".to_string(),
        "localhost".to_string(),
        "--ca-file".to_string(),
        server.ca_file.display().to_string(),
        "--timeout-ms".to_string(),
        "2000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert_eq!(status.code(), Some(3), "value: {value}");
    assert_eq!(value["status"], "SKIP");
}

#[test]
fn quic_success_with_http3_failure_is_reported_separately() {
    let Some(server) = start_server(ServerMode::QuicOnly, "h3", false) else {
        return;
    };
    let args = vec![
        "http3".to_string(),
        format!("https://127.0.0.1:{}/", server.port),
        "--sni".to_string(),
        "localhost".to_string(),
        "--ca-file".to_string(),
        server.ca_file.display().to_string(),
        "--timeout-ms".to_string(),
        "1200".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert_eq!(status.code(), Some(2), "value: {value}");
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["handshake_ok"], true);
    assert_eq!(detail["alpn"], "h3");
    assert!(detail["http3_status"].is_null());
    assert!(detail["error"].as_str().unwrap().contains("http3"));
}

#[test]
fn http3_500_is_a_business_warning() {
    let Some(server) = start_server(ServerMode::Http3(500), "h3", false) else {
        return;
    };
    let args = vec![
        "http3".to_string(),
        format!("https://127.0.0.1:{}/", server.port),
        "--sni".to_string(),
        "localhost".to_string(),
        "--ca-file".to_string(),
        server.ca_file.display().to_string(),
        "--timeout-ms".to_string(),
        "3000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert_eq!(status.code(), Some(2));
    assert_eq!(value["status"], "WARN");
    assert_eq!(value["probes"][0]["detail"]["http3_status"], 500);
}

#[test]
fn http3_over_ipv6_loopback_when_available() {
    let Some(server) = start_server(ServerMode::Http3(200), "h3", true) else {
        eprintln!("IPv6 loopback unavailable; test not exercised");
        return;
    };
    let args = vec![
        "http3".to_string(),
        format!("https://[::1]:{}/", server.port),
        "--sni".to_string(),
        "localhost".to_string(),
        "--ca-file".to_string(),
        server.ca_file.display().to_string(),
        "--family".to_string(),
        "ipv6".to_string(),
        "--timeout-ms".to_string(),
        "3000".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert!(status.success(), "IPv6 http3 failed: {value}");
    assert_eq!(value["probes"][0]["detail"]["family"], "ipv6");
    assert_eq!(value["probes"][0]["detail"]["http3_status"], 200);
}

#[test]
fn quic_without_a_listener_times_out_without_fake_success() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let args = vec![
        "quic".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        port.to_string(),
        "--timeout-ms".to_string(),
        "700".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    let (status, value) = run(&args);
    assert_eq!(status.code(), Some(2));
    let detail = &value["probes"][0]["detail"];
    assert_eq!(detail["handshake_ok"], false);
    assert!(detail["error"].is_string());
}
