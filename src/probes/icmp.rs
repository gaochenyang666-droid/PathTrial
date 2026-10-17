//! M05: ICMP echo via the system `ping` binary.
//!
//! A raw socket would need root on macOS, so PathTrial drives the vendor
//! `ping` (setuid or file-capability, unprivileged for the user) and parses its
//! summary. If the binary is missing the probe is SKIPped with a reason.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Parsed ping result.
#[derive(Debug, Clone, Default)]
pub struct IcmpOutcome {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub rtt_min: Option<f64>,
    pub rtt_avg: Option<f64>,
    pub rtt_max: Option<f64>,
    pub jitter: Option<f64>,
    pub error: Option<String>,
}

impl IcmpOutcome {
    pub fn usable(&self) -> bool {
        self.error.is_none() && self.received > 0
    }
}

/// Run `ping -c <count>` with a hard wall-clock limit.
pub fn ping(host: &str, count: u32, timeout: Duration) -> IcmpOutcome {
    let candidates = ["/sbin/ping", "/bin/ping", "ping"];
    let mut last_error = None;
    for program in candidates {
        // Bound the child itself: macOS uses -t, Linux uses -w, both in
        // seconds. Without it an unreachable target can hang for a long time.
        let seconds = timeout.as_secs().clamp(1, 60).to_string();
        let deadline_flag = if cfg!(target_os = "macos") {
            "-t"
        } else {
            "-w"
        };
        let mut child = match Command::new(program)
            .args(["-c", &count.to_string(), deadline_flag, &seconds, host])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                last_error = Some(format!("{program}: {error}"));
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
                    return IcmpOutcome {
                        error: Some("ping did not finish within the budget".to_string()),
                        ..Default::default()
                    };
                }
                Err(error) => {
                    return IcmpOutcome {
                        error: Some(format!("ping wait failed: {error}")),
                        ..Default::default()
                    };
                }
            }
        }
        let output = match child.wait_with_output() {
            Ok(output) => output,
            Err(error) => {
                return IcmpOutcome {
                    error: Some(format!("ping output failed: {error}")),
                    ..Default::default()
                };
            }
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let mut parsed = parse_ping(&text);
        if parsed.sent == 0 && !output.status.success() {
            parsed.error = Some(first_error_line(&text));
        }
        return parsed;
    }
    IcmpOutcome {
        error: Some(format!(
            "no ping binary available ({})",
            last_error.unwrap_or_default()
        )),
        ..Default::default()
    }
}

fn first_error_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("ping failed")
        .trim()
        .to_string()
}

/// Parse the summary block of macOS or Linux `ping` output.
pub fn parse_ping(text: &str) -> IcmpOutcome {
    let mut outcome = IcmpOutcome::default();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("packets transmitted") {
            let numbers: Vec<u32> = line
                .split(|ch: char| !ch.is_ascii_digit())
                .filter(|part| !part.is_empty())
                .filter_map(|part| part.parse::<u32>().ok())
                .collect();
            if numbers.len() >= 2 {
                outcome.sent = numbers[0];
                outcome.received = numbers[1];
            }
            if let Some(token) = line.split_whitespace().find(|token| token.ends_with('%')) {
                outcome.loss_pct = token
                    .trim_end_matches('%')
                    .trim_end_matches(',')
                    .parse::<f64>()
                    .unwrap_or(0.0);
            }
        } else if lower.contains("min/avg/max") {
            if let Some((_, values)) = line.split_once('=') {
                let parsed: Vec<f64> = values
                    .split('/')
                    .filter_map(|part| {
                        part.trim()
                            .trim_end_matches(" ms")
                            .trim()
                            .parse::<f64>()
                            .ok()
                    })
                    .collect();
                if parsed.len() >= 4 {
                    outcome.rtt_min = Some(parsed[0]);
                    outcome.rtt_avg = Some(parsed[1]);
                    outcome.rtt_max = Some(parsed[2]);
                    outcome.jitter = Some(parsed[3]);
                }
            }
        }
    }
    // The packet counts are authoritative; recompute loss from them so a
    // missing or unparsable percentage cannot silently report 0%.
    if outcome.sent > 0 {
        outcome.loss_pct = ((outcome.sent - outcome.received) as f64 / outcome.sent as f64) * 100.0;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::parse_ping;

    #[test]
    fn parses_macos_summary() {
        let text = "--- 1.1.1.1 ping statistics ---\n10 packets transmitted, 8 packets received, 20.0% packet loss\nround-trip min/avg/max/stddev = 12.1/13.4/15.0/0.8 ms\n";
        let parsed = parse_ping(text);
        assert_eq!(parsed.sent, 10);
        assert_eq!(parsed.received, 8);
        assert!((parsed.loss_pct - 20.0).abs() < 0.01);
        assert_eq!(parsed.rtt_avg, Some(13.4));
        assert_eq!(parsed.jitter, Some(0.8));
    }

    #[test]
    fn parses_linux_summary() {
        let text = "5 packets transmitted, 5 received, 0% packet loss, time 4004ms\nrtt min/avg/max/mdev = 20.1/21.2/22.3/0.7 ms\n";
        let parsed = parse_ping(text);
        assert_eq!(parsed.sent, 5);
        assert_eq!(parsed.received, 5);
        assert_eq!(parsed.loss_pct, 0.0);
        assert_eq!(parsed.rtt_avg, Some(21.2));
    }

    #[test]
    fn detects_total_loss() {
        let text = "--- 192.0.2.1 ping statistics ---\n3 packets transmitted, 0 packets received, 100.0% packet loss\n";
        let parsed = parse_ping(text);
        assert_eq!(parsed.received, 0);
        assert!((parsed.loss_pct - 100.0).abs() < 0.01);
        assert!(parsed.rtt_avg.is_none());
    }
}
