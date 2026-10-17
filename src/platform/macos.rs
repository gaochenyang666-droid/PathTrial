//! macOS route lookups via the `route` command.

use std::net::IpAddr;
use std::process::Command;

use crate::models::{Family, RouteInfo};

fn run(args: &[&str]) -> Option<String> {
    let output = Command::new("/sbin/route").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse `route -n get ...` output for gateway and interface lines.
pub fn parse_route_get(text: &str) -> (Option<String>, Option<String>) {
    let mut gateway = None;
    let mut interface = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            gateway = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("interface:") {
            interface = Some(rest.trim().to_string());
        }
    }
    (gateway, interface)
}

pub fn default_route(family: Family) -> Option<RouteInfo> {
    let raw = match family {
        Family::Ipv4 => run(&["-n", "get", "default"]),
        Family::Ipv6 => run(&["-n", "get", "-inet6", "default"]),
    };
    let parsed = raw
        .map(|text| parse_route_get(&text))
        .unwrap_or((None, None));
    // With several default routes `route get` can fail, while netstat still
    // lists them, so fall back to the first matching row.
    let (gateway, interface) = if parsed.0.is_none() && parsed.1.is_none() {
        netstat_default(family)
    } else {
        parsed
    };
    Some(RouteInfo {
        family: if family == Family::Ipv4 {
            "ipv4"
        } else {
            "ipv6"
        }
        .to_string(),
        gateway,
        interface,
        note: None,
    })
}

/// Parse `netstat -rn -f inet|inet6` for the first default row.
pub fn parse_netstat_default(text: &str) -> (Option<String>, Option<String>) {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"default") || fields.len() < 3 {
            continue;
        }
        return (
            Some(fields[1].to_string()),
            fields.get(3).map(|value| (*value).to_string()),
        );
    }
    (None, None)
}

fn netstat_default(family: Family) -> (Option<String>, Option<String>) {
    let flag = if family == Family::Ipv4 {
        "inet"
    } else {
        "inet6"
    };
    let output = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", flag])
        .output()
        .ok();
    match output {
        Some(output) if output.status.success() => {
            parse_netstat_default(&String::from_utf8_lossy(&output.stdout))
        }
        _ => (None, None),
    }
}

pub fn route_to(ip: IpAddr) -> Option<RouteInfo> {
    let mut args = vec!["-n", "get"];
    if ip.is_ipv6() {
        args.push("-inet6");
    }
    let text = ip.to_string();
    args.push(&text);
    let raw = run(&args)?;
    let (gateway, interface) = parse_route_get(&raw);
    Some(RouteInfo {
        family: if ip.is_ipv4() { "ipv4" } else { "ipv6" }.to_string(),
        gateway,
        interface,
        note: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_netstat_default, parse_route_get};

    #[test]
    fn parses_route_get_output() {
        let sample = "   route to: 192.0.2.10\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,DONE>\n";
        let (gateway, interface) = parse_route_get(sample);
        assert_eq!(gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(interface.as_deref(), Some("en0"));
    }

    #[test]
    fn missing_fields_stay_none() {
        let (gateway, interface) = parse_route_get("no useful lines here");
        assert!(gateway.is_none());
        assert!(interface.is_none());
    }

    #[test]
    fn parses_netstat_default_rows() {
        let sample = "Destination        Gateway            Flags        Netif Expire\ndefault            fe80::1%en0        UGcg          en0\n";
        let (gateway, interface) = parse_netstat_default(sample);
        assert_eq!(gateway.as_deref(), Some("fe80::1%en0"));
        assert_eq!(interface.as_deref(), Some("en0"));
    }
}
