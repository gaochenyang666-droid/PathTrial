//! Small helpers shared by probes, analysis and reporting.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{SecondsFormat, Utc};

use crate::models::NetError;

/// RFC 3339 timestamp with millisecond precision, always UTC.
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Short, collision-resistant identifier for a single run.
pub fn new_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{nanos:x}{pid:x}")
}

/// Map a connect error to a stable category. Categories drive aggregation and
/// are part of the public report, so they must not change casually.
pub fn classify_io_error(error: &io::Error) -> NetError {
    if let Some(code) = error.raw_os_error() {
        if let Some(mapped) = classify_raw_os_error(code) {
            return mapped;
        }
    }
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => NetError::Timeout,
        io::ErrorKind::ConnectionRefused => NetError::ConnectionRefused,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
            NetError::ConnectionReset
        }
        io::ErrorKind::NetworkUnreachable => NetError::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => NetError::HostUnreachable,
        _ => {
            let text = error.to_string();
            let lower = text.to_ascii_lowercase();
            if lower.contains("timed out") || lower.contains("timeout") {
                NetError::Timeout
            } else if lower.contains("no route to host") {
                NetError::HostUnreachable
            } else if lower.contains("network is unreachable") {
                NetError::NetworkUnreachable
            } else if lower.contains("connection refused") || lower.contains("actively refused") {
                NetError::ConnectionRefused
            } else {
                NetError::Other(text)
            }
        }
    }
}

/// Stable OS codes for the categories above.
///
/// 61/111 are `ECONNREFUSED` on macOS/Linux. 10061 is `WSAECONNREFUSED`.
/// The timeout, reset, and unreachable codes are the matching platform values.
fn classify_raw_os_error(code: i32) -> Option<NetError> {
    match code {
        61 | 111 | 10061 => Some(NetError::ConnectionRefused),
        60 | 110 | 10060 => Some(NetError::Timeout),
        54 | 104 | 10054 => Some(NetError::ConnectionReset),
        51 | 101 | 10051 => Some(NetError::NetworkUnreachable),
        65 | 113 | 10065 => Some(NetError::HostUnreachable),
        _ => None,
    }
}

pub fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

/// Median of unsorted values. Returns `None` for empty input.
pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        Some((sorted[middle - 1] + sorted[middle]) / 2.0)
    } else {
        Some(sorted[middle])
    }
}

/// Percentile with linear interpolation. Only meaningful with enough samples;
/// callers must check `MIN_SAMPLES_FOR_PERCENTILE` before publishing it.
#[allow(dead_code)] // reserved until a report publishes P95 with enough samples
pub fn percentile(values: &[f64], fraction: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let position = fraction.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        Some(sorted[lower])
    } else {
        let weight = position - lower as f64;
        Some(sorted[lower] * (1.0 - weight) + sorted[upper] * weight)
    }
}

/// Below this sample count percentile statistics are not reported, because
/// small-sample P95 is effectively the maximum and misleads readers.
pub const MIN_SAMPLES_FOR_PERCENTILE: usize = 20;

/// Replace IP literals with stable placeholders. The same address always maps
/// to the same placeholder so evidence stays traceable within one report.
#[derive(Debug, Default)]
pub struct IpMasker {
    map: BTreeMap<String, String>,
    pub masked: usize,
}

impl IpMasker {
    pub fn mask_text(&mut self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut token = String::new();
        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == ':' || ch == '%' || ch == '_' {
                token.push(ch);
                continue;
            }
            result.push_str(&self.mask_token(&token));
            token.clear();
            result.push(ch);
        }
        result.push_str(&self.mask_token(&token));
        result
    }

    fn mask_token(&mut self, token: &str) -> String {
        if token.is_empty() {
            return String::new();
        }
        if let Some(masked) = self.try_mask(token) {
            return masked;
        }
        // Bracketed IPv6, optionally followed by a port: [2001:db8::1]:443
        if let Some(inner) = token
            .strip_prefix('[')
            .and_then(|rest| rest.split(']').next())
        {
            if let Some(masked) = self.try_mask(inner) {
                let suffix = &token[inner.len() + 2..];
                return format!("{masked}{suffix}");
            }
        }
        // IPv4:port pairs.
        if let Some((host, port)) = token.rsplit_once(':') {
            if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
                if let Some(masked) = self.try_mask(host) {
                    return format!("{masked}:{port}");
                }
            }
        }
        token.to_string()
    }

    fn try_mask(&mut self, candidate: &str) -> Option<String> {
        let (base, zone) = match candidate.split_once('%') {
            Some((base, zone)) => (base, Some(zone)),
            None => (candidate, None),
        };
        let ip = base.parse::<IpAddr>().ok()?;
        if let Some(existing) = self.map.get(candidate) {
            return Some(existing.clone());
        }
        let placeholder = match ip {
            IpAddr::V4(_) => format!("<ipv4-{}>", self.masked + 1),
            IpAddr::V6(_) => format!("<ipv6-{}>", self.masked + 1),
        };
        self.masked += 1;
        let stored = match zone {
            Some(zone) => format!("{placeholder}%{zone}"),
            None => placeholder.clone(),
        };
        self.map.insert(candidate.to_string(), stored.clone());
        Some(stored)
    }
}

/// Mask IP literals inside every string of a JSON value. The input file is not
/// modified unless the caller writes `value` back out.
pub fn mask_json(value: &mut serde_json::Value) -> usize {
    let mut masker = IpMasker::default();
    mask_json_with(value, &mut masker);
    masker.masked
}

fn mask_json_with(value: &mut serde_json::Value, masker: &mut IpMasker) {
    match value {
        serde_json::Value::String(text) => *text = masker.mask_text(text),
        serde_json::Value::Array(items) => {
            for item in items {
                mask_json_with(item, masker);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                mask_json_with(item, masker);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod masker_tests {
    use super::IpMasker;

    #[test]
    fn masks_host_port_pairs() {
        let mut masker = IpMasker::default();
        let text = masker.mask_text("connect 198.51.100.7:443 ok");
        assert!(text.contains("<ipv4-1>:443"), "got {text}");
    }

    #[test]
    fn masks_bracketed_ipv6() {
        let mut masker = IpMasker::default();
        let text = masker.mask_text("[2001:db8::1]:8443");
        assert!(text.contains("<ipv6-1>"), "got {text}");
        assert!(text.ends_with(":8443"), "got {text}");
    }

    #[test]
    fn leaves_versions_and_numbers_alone() {
        let mut masker = IpMasker::default();
        let text = masker.mask_text("version 1.0.0 latency 2476.5 ms at 2026-10-16T12:00:00Z");
        assert_eq!(
            text,
            "version 1.0.0 latency 2476.5 ms at 2026-10-16T12:00:00Z"
        );
    }
}

/// True when the string looks like a literal IP address, optionally wrapped in
/// brackets as used in URLs.
pub fn as_literal_ip(text: &str) -> Option<IpAddr> {
    let trimmed = text.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.parse::<IpAddr>().ok()
}

/// Reject values that would break an HTTP header line or a host authority.
pub fn validate_host_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 255 {
        return Err(format!("{label} must be between 1 and 255 characters"));
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control() || character == '/')
    {
        return Err(format!(
            "{label} must not contain whitespace, control characters or '/'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_refused_codes_stay_connection_refused() {
        for code in [61, 111, 10061] {
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(
                classify_io_error(&error),
                NetError::ConnectionRefused,
                "code {code}"
            );
        }
        let message = io::Error::other(
            "No connection could be made because the target machine actively refused it.",
        );
        assert_eq!(classify_io_error(&message), NetError::ConnectionRefused);
    }

    #[test]
    fn median_handles_even_and_odd_lengths() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn percentile_interpolates() {
        let values = [10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(percentile(&values, 0.5), Some(30.0));
        assert_eq!(percentile(&values, 1.0), Some(50.0));
    }

    #[test]
    fn literal_ip_parsing_accepts_brackets() {
        assert!(as_literal_ip("192.0.2.1").is_some());
        assert!(as_literal_ip("[2001:db8::1]").is_some());
        assert!(as_literal_ip("example.com").is_none());
    }

    #[test]
    fn host_tokens_reject_header_injection() {
        assert!(validate_host_token("--host", "example.com:443").is_ok());
        assert!(validate_host_token("--host", "[::1]:8443").is_ok());
        assert!(validate_host_token("--host", "example.com\r\nX-Test: 1").is_err());
        assert!(validate_host_token("--host", "example.com /").is_err());
        assert!(validate_host_token("--host", "").is_err());
    }

    #[test]
    fn masker_is_stable_and_counts_unique_addresses() {
        let mut masker = IpMasker::default();
        let first = masker.mask_text("connect 198.51.100.7:443 failed");
        let second = masker.mask_text("retry 198.51.100.7:443");
        assert!(first.contains("<ipv4-1>"));
        assert!(second.contains("<ipv4-1>"));
        assert_eq!(masker.masked, 1);
        assert!(!second.contains("198.51.100.7"));
    }
}
