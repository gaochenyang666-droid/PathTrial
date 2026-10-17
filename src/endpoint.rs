//! Temporary loopback endpoints for reproducible tests.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Run a UDP echo service until the process is interrupted.
///
/// The service is a test helper: it refuses non-loopback binds unless the user
/// explicitly allows them, never stores payloads and never amplifies traffic.
pub fn udp_echo(bind: &str, allow_public: bool, max_payload: usize) -> Result<(), String> {
    let address: SocketAddr = bind
        .parse()
        .map_err(|_| format!("invalid --bind value {bind}, expected IP:PORT"))?;
    if !address.ip().is_loopback() && !allow_public {
        return Err(format!(
            "refusing to bind {address}: it is not a loopback address. Re-run with \
             --allow-public-bind only if you understand the exposure"
        ));
    }
    let socket = UdpSocket::bind(address).map_err(|error| format!("bind {address}: {error}"))?;
    println!("pathtrial udp echo listening on {address}");
    if !address.ip().is_loopback() {
        println!(
            "warning: this endpoint is reachable from other hosts and is meant for short tests only"
        );
    }
    println!("press Ctrl+C to stop");

    let mut buffer = [0u8; 2048];
    let mut window_started = Instant::now();
    let mut window_count = 0u32;
    loop {
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
            Err(_) => continue,
        }
    }
}
