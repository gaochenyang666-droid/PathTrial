//! M04: hop-by-hop path via the system `traceroute`.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Hop {
    pub hop: u32,
    pub address: Option<String>,
    pub rtt_ms: Vec<f64>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TraceOutcome {
    pub hops: Vec<Hop>,
    pub reached: bool,
    pub error: Option<String>,
    pub protocol: String,
}

/// Run `traceroute -n` and parse the hops.
pub fn trace(host: &str, max_hops: u32, timeout: Duration) -> TraceOutcome {
    let candidates = ["/usr/sbin/traceroute", "/usr/bin/traceroute", "traceroute"];
    let mut missing = None;
    for program in candidates {
        let mut child = match Command::new(program)
            .args(["-n", "-m", &max_hops.to_string(), "-w", "1", host])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                missing = Some(format!("{program}: {error}"));
                continue;
            }
        };
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return TraceOutcome {
                        error: Some("traceroute exceeded the time budget".to_string()),
                        protocol: default_protocol().to_string(),
                        ..Default::default()
                    };
                }
                Err(error) => {
                    return TraceOutcome {
                        error: Some(format!("traceroute wait failed: {error}")),
                        protocol: default_protocol().to_string(),
                        ..Default::default()
                    };
                }
            }
        }
        let output = match child.wait_with_output() {
            Ok(output) => output,
            Err(error) => {
                return TraceOutcome {
                    error: Some(format!("traceroute output failed: {error}")),
                    protocol: default_protocol().to_string(),
                    ..Default::default()
                };
            }
        };
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let mut outcome = parse_trace(&text);
        outcome.protocol = default_protocol().to_string();
        if outcome.hops.is_empty() {
            outcome.error = Some(
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("traceroute produced no hops")
                    .trim()
                    .to_string(),
            );
        }
        return outcome;
    }
    TraceOutcome {
        error: Some(format!(
            "traceroute is not available ({})",
            missing.unwrap_or_default()
        )),
        protocol: default_protocol().to_string(),
        ..Default::default()
    }
}

fn default_protocol() -> &'static str {
    // macOS uses UDP probes by default; Linux traceroute defaults to ICMP when
    // run unprivileged (or UDP with CAP_NET_RAW). Reported per platform.
    if cfg!(target_os = "macos") {
        "udp"
    } else {
        "icmp-or-udp"
    }
}

/// Parse `traceroute -n` output.
pub fn parse_trace(text: &str) -> TraceOutcome {
    let mut outcome = TraceOutcome::default();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some((hop_text, rest)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(hop) = hop_text.parse::<u32>() else {
            continue;
        };
        let mut address = None;
        let mut rtts = Vec::new();
        let mut timed_out = true;
        for token in rest.split_whitespace() {
            if token == "*" {
                continue;
            }
            if let Ok(value) = token.parse::<f64>() {
                rtts.push(value);
                continue;
            }
            if token.eq_ignore_ascii_case("ms") {
                continue;
            }
            if address.is_none() && (token.contains('.') || token.contains(':') || token == "(no") {
                address = Some(token.to_string());
                timed_out = false;
            }
        }
        if !address.is_some() {
            timed_out = true;
        }
        outcome.hops.push(Hop {
            hop,
            address,
            rtt_ms: rtts,
            timed_out,
        });
    }
    if let Some(last) = outcome.hops.last() {
        outcome.reached = last.address.is_some() && !last.timed_out;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::parse_trace;

    #[test]
    fn parses_hops_and_timeouts() {
        let text = "traceroute to example.com (192.0.2.10), 30 hops max, 60 byte packets\n 1  192.168.1.1  2.123 ms  1.998 ms  2.010 ms\n 2  * * *\n 3  10.0.0.1  5.001 ms\n";
        let parsed = parse_trace(text);
        assert_eq!(parsed.hops.len(), 3);
        assert_eq!(parsed.hops[0].address.as_deref(), Some("192.168.1.1"));
        assert_eq!(parsed.hops[0].rtt_ms.len(), 3);
        assert!(parsed.hops[1].timed_out);
        assert!(parsed.reached, "last hop answered, so reached must be set");
    }

    #[test]
    fn detects_unanswered_tail() {
        let text = " 1  192.168.1.1  2.0 ms\n 2  * * *\n";
        let parsed = parse_trace(text);
        assert_eq!(parsed.hops.len(), 2);
        assert!(parsed.hops[1].timed_out);
        assert!(
            !parsed.reached,
            "an unanswered tail must not count as reached"
        );
    }
}
