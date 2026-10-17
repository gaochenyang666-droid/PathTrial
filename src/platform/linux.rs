//! Linux route lookups via `ip route`, with `/proc/net/route` as a fallback for
//! the IPv4 default route on minimal systems without iproute2.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use crate::models::{Family, RouteInfo};

fn run(args: &[&str]) -> Option<String> {
    let output = Command::new("ip").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse `ip route show default`: `default via 10.0.0.1 dev eth0 ...`
pub fn parse_default(text: &str) -> Option<(Option<String>, Option<String>)> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("default"))?;
    let mut gateway = None;
    let mut interface = None;
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        match part {
            "via" => gateway = parts.next().map(str::to_string),
            "dev" => interface = parts.next().map(str::to_string),
            _ => {}
        }
    }
    Some((gateway, interface))
}

/// Parse `ip route get <ip>`: the first line contains `dev <if>` and usually
/// `via <gw>` for routed destinations.
pub fn parse_route_get(text: &str) -> (Option<String>, Option<String>) {
    let mut gateway = None;
    let mut interface = None;
    if let Some(line) = text.lines().next() {
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            match part {
                "via" => gateway = parts.next().map(str::to_string),
                "dev" => interface = parts.next().map(str::to_string),
                _ => {}
            }
        }
    }
    (gateway, interface)
}

fn parse_proc_net_route(text: &str) -> Option<(Option<String>, Option<String>)> {
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        if fields[1] != "00000000" {
            continue;
        }
        let gateway = u32::from_str_radix(fields[2], 16).ok()?;
        let gateway = Ipv4Addr::from(u32::from_le(gateway));
        return Some((Some(gateway.to_string()), Some(fields[0].to_string())));
    }
    None
}

pub fn default_route(family: Family) -> Option<RouteInfo> {
    let parsed = match family {
        Family::Ipv4 => run(&["route", "show", "default"])
            .and_then(|text| parse_default(&text))
            .or_else(|| {
                std::fs::read_to_string("/proc/net/route")
                    .ok()
                    .and_then(|text| parse_proc_net_route(&text))
            }),
        Family::Ipv6 => {
            run(&["-6", "route", "show", "default"]).and_then(|text| parse_default(&text))
        }
    };
    let (gateway, interface) = parsed?;
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

pub fn route_to(ip: IpAddr) -> Option<RouteInfo> {
    let text = ip.to_string();
    let output = if ip.is_ipv6() {
        run(&["-6", "route", "get", &text])
    } else {
        run(&["route", "get", &text])
    }?;
    let (gateway, interface) = parse_route_get(&output);
    Some(RouteInfo {
        family: if ip.is_ipv4() { "ipv4" } else { "ipv6" }.to_string(),
        gateway,
        interface,
        note: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_default, parse_proc_net_route, parse_route_get};

    #[test]
    fn parses_default_route_line() {
        let text = "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n";
        let (gateway, interface) = parse_default(text).unwrap();
        assert_eq!(gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_route_get_line() {
        let text = "192.0.2.10 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0\n";
        let (gateway, interface) = parse_route_get(text);
        assert_eq!(gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_proc_net_route_fallback() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let (gateway, interface) = parse_proc_net_route(text).unwrap();
        assert_eq!(gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(interface.as_deref(), Some("eth0"));
    }
}
