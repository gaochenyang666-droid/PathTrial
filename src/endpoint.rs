//! Temporary loopback endpoints for reproducible tests.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::cli::{CollectArgs, CollectRole, OutputFormat};

/// Run a UDP echo service until the process is interrupted.
///
/// The service is a test helper: it refuses non-loopback binds unless the user
/// explicitly allows them, never stores payloads and never amplifies traffic.
pub fn udp_echo(bind: &str, allow_public: bool, max_payload: usize) -> Result<(), String> {
    udp_echo_for(bind, allow_public, max_payload, None)
}

pub fn udp_echo_for(
    bind: &str,
    allow_public: bool,
    max_payload: usize,
    limit: Option<Duration>,
) -> Result<(), String> {
    let socket = bind_udp_echo(bind, allow_public)?;
    match limit {
        Some(limit) => println!("udp echo stops after {} seconds", limit.as_secs()),
        None => println!("press Ctrl+C to stop"),
    }
    serve_udp(socket, max_payload, limit)
}

fn bind_udp_echo(bind: &str, allow_public: bool) -> Result<UdpSocket, String> {
    let address = require_bind(bind, allow_public)?;
    let socket = UdpSocket::bind(address).map_err(|error| format!("bind {address}: {error}"))?;
    println!("pathtrial udp echo listening on {address}");
    if !address.ip().is_loopback() {
        println!(
            "warning: this endpoint is reachable from other hosts and is meant for short tests only"
        );
    }
    Ok(socket)
}

fn serve_udp(socket: UdpSocket, max_payload: usize, limit: Option<Duration>) -> Result<(), String> {
    if limit.is_some() {
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|error| format!("set udp read timeout: {error}"))?;
    }
    let started = Instant::now();

    let mut buffer = [0u8; 2048];
    let mut window_started = Instant::now();
    let mut window_count = 0u32;
    loop {
        if limit.is_some_and(|limit| started.elapsed() >= limit) {
            println!("udp echo stopped: time budget reached");
            return Ok(());
        }
        if window_started.elapsed() >= Duration::from_secs(1) {
            window_started = Instant::now();
            window_count = 0;
        }
        match socket.recv_from(&mut buffer) {
            Ok((read, peer)) => {
                if read > max_payload {
                    continue;
                }
                window_count += 1;
                if window_count > 500 {
                    continue;
                }
                let _ = socket.send_to(&buffer[..read], peer);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if limit.is_some()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                continue;
            }
            Err(_) => continue,
        }
    }
}

/// Run a bounded collect server, optionally with UDP echo on a second socket.
///
/// This does not change firewall, DNS, or routes. A non-loopback address is
/// refused unless `allow_public` is set.
pub fn peer(
    udp_bind: Option<&str>,
    listen: &str,
    allow_public: bool,
    task_id: &str,
    max_seconds: u64,
    output: &std::path::Path,
    max_payload: usize,
) -> Result<u8, String> {
    if task_id.trim().is_empty() {
        return Err("--task-id must not be empty".to_string());
    }
    if !(1..=3600).contains(&max_seconds) {
        return Err("--max-seconds must be between 1 and 3600".to_string());
    }
    let listen_address = require_bind(listen, allow_public)?;
    println!("pathtrial peer");
    println!("collect listen: {listen_address}");
    println!("task: {task_id}");
    println!("window: {max_seconds} seconds");
    println!("this process does not change firewall, DNS, or routes");
    println!("UDP echo does not store payloads");
    let udp_thread = if let Some(bind) = udp_bind {
        let socket = bind_udp_echo(bind, allow_public)?;
        let limit = Duration::from_secs(max_seconds);
        Some(std::thread::spawn(move || {
            println!("udp echo stops after {} seconds", limit.as_secs());
            serve_udp(socket, max_payload, Some(limit))
        }))
    } else {
        None
    };
    let code = crate::collect::collect(&CollectArgs {
        role: CollectRole::Server,
        task_id: task_id.to_string(),
        target: None,
        listen: Some(listen_address.to_string()),
        rounds: 1,
        timeout_ms: 1500,
        interval_ms: 200,
        max_seconds,
        bind_interface: None,
        output: output.to_path_buf(),
        format: OutputFormat::Summary,
    })?;
    if let Some(thread) = udp_thread {
        match thread.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err("udp echo thread stopped unexpectedly".to_string()),
        }
    }
    Ok(code)
}

fn require_bind(bind: &str, allow_public: bool) -> Result<SocketAddr, String> {
    let address: SocketAddr = bind
        .parse()
        .map_err(|_| format!("invalid address {bind}, expected IP:PORT"))?;
    if !address.ip().is_loopback() && !allow_public {
        return Err(format!(
            "refusing to bind {address}: it is not a loopback address. Re-run with \
             --allow-public-bind only if you understand the exposure. PathTrial will not \
             change firewall, DNS, or routes"
        ));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::require_bind;

    #[test]
    fn public_bind_requires_an_explicit_flag() {
        let error = require_bind("0.0.0.0:39001", false).unwrap_err();
        assert!(error.contains("allow-public-bind"), "{error}");
        assert!(error.contains("firewall"));
        assert!(require_bind("127.0.0.1:39001", false).is_ok());
    }
}
