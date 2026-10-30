#![cfg_attr(not(windows), allow(dead_code))]
//! Pure parsers for Windows command output.
//!
//! The parsers do not run commands. Localized `ipconfig` text that does not
//! contain the English labels below yields no addresses; callers must say so
//! instead of inventing interfaces.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::Value;

use crate::models::InterfaceInfo;

#[derive(Debug, Clone, PartialEq)]
pub struct WlanFacts {
    pub name: String,
    pub ssid: Option<String>,
    pub signal_percent: Option<u8>,
    pub receive_mbps: Option<f64>,
}

pub fn looks_like_wifi(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("wi-fi")
        || lower.contains("wifi")
        || lower.contains("wlan")
        || lower.contains("wireless")
}

pub fn vpn_hint(name: &str) -> bool {
    if super::looks_like_tunnel(name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    [
        "wintun",
        "tailscale",
        "zerotier",
        "wireguard",
        "openvpn",
        "vpn",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

/// Parse `Get-NetIPAddress | ConvertTo-Json` output.
///
/// An empty array is a successful observation of no addresses. Malformed JSON
/// is an error so the caller can try another source.
pub fn parse_net_ip_address_json(text: &str) -> Result<Vec<InterfaceInfo>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("Get-NetIPAddress returned an empty document".to_string());
    }
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|error| format!("Get-NetIPAddress JSON was not parsed: {error}"))?;
    let items: Vec<&Value> = match &value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![&value],
        Value::Null => Vec::new(),
        _ => {
            return Err("Get-NetIPAddress JSON was neither an object nor an array".to_string());
        }
    };
    let mut by_name: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
    for item in items {
        let Some(name) = item.get("InterfaceAlias").and_then(Value::as_str) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let index = item
            .get("InterfaceIndex")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let family = item.get("AddressFamily").and_then(Value::as_u64);
        let address = item
            .get("IPAddress")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if address.is_empty() {
            continue;
        }
        let info = by_name
            .entry(name.to_string())
            .or_insert_with(|| InterfaceInfo {
                name: name.to_string(),
                index,
                up: true,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                vpn_like: vpn_hint(name),
            });
        info.index = info.index.max(index);
        match family {
            Some(23) => info.ipv6.push(address),
            Some(2) => info.ipv4.push(address),
            _ => {
                if address.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
                    info.ipv6.push(address);
                } else {
                    info.ipv4.push(address);
                }
            }
        }
    }
    Ok(by_name.into_values().collect())
}

/// Parse English `ipconfig /all` adapter blocks.
///
/// `index` is 0 because this text does not include an interface index. `up`
/// means an address was printed, not a separate link-state reading.
pub fn parse_ipconfig(text: &str) -> Vec<InterfaceInfo> {
    let mut by_name: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(name) = adapter_name(line) {
            current = Some(name.clone());
            by_name
                .entry(name.clone())
                .or_insert_with(|| InterfaceInfo {
                    name,
                    index: 0,
                    up: false,
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    vpn_like: false,
                });
            if let Some(info) = current.as_ref().and_then(|name| by_name.get_mut(name)) {
                info.vpn_like = vpn_hint(&info.name);
            }
            continue;
        }
        let Some(name) = current.clone() else {
            continue;
        };
        let lower = line.to_ascii_lowercase();
        let Some(info) = by_name.get_mut(&name) else {
            continue;
        };
        if lower.contains("ipv4 address") {
            if let Some(address) = value_after_colon(line) {
                info.ipv4.push(address);
                info.up = true;
            }
        } else if lower.contains("ipv6 address") {
            if let Some(address) = value_after_colon(line) {
                info.ipv6.push(address);
                info.up = true;
            }
        }
    }
    by_name.into_values().collect()
}

pub fn parse_ipv4_route_print(text: &str) -> Option<(Option<String>, Option<String>)> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            let gateway = if parts[2].eq_ignore_ascii_case("on-link") {
                None
            } else {
                Some(parts[2].to_string())
            };
            return Some((gateway, Some(parts[3].to_string())));
        }
    }
    None
}

pub fn parse_ipv6_route_print(text: &str) -> Option<(Option<String>, Option<String>)> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(index) = parts.iter().position(|part| *part == "::/0") else {
            continue;
        };
        let gateway = parts.get(index + 1).map(|value| (*value).to_string());
        let interface = parts
            .first()
            .filter(|value| value.parse::<u32>().is_ok())
            .map(|value| format!("ifindex {value}"));
        return Some((gateway, interface));
    }
    None
}

pub fn parse_netsh_wlan(text: &str) -> Vec<WlanFacts> {
    let mut facts = Vec::new();
    let mut current: Option<WlanFacts> = None;
    for line in text.lines() {
        let Some((key, value)) = netsh_field(line) else {
            continue;
        };
        if key.eq_ignore_ascii_case("Name") {
            if let Some(done) = current.take() {
                facts.push(done);
            }
            current = Some(WlanFacts {
                name: value.to_string(),
                ssid: None,
                signal_percent: None,
                receive_mbps: None,
            });
            continue;
        }
        let Some(item) = current.as_mut() else {
            continue;
        };
        if key.eq_ignore_ascii_case("SSID") && !value.is_empty() {
            item.ssid = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("Signal") {
            item.signal_percent = value.trim_end_matches('%').trim().parse().ok();
        } else if key.to_ascii_lowercase().contains("receive rate") {
            item.receive_mbps = value
                .split_whitespace()
                .next()
                .and_then(|part| part.parse().ok());
        }
    }
    if let Some(done) = current {
        facts.push(done);
    }
    facts
}

pub fn parse_dhcp_enabled(text: &str) -> Option<bool> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("dhcp enabled") {
            continue;
        }
        if lower.contains("yes") {
            return Some(true);
        }
        if lower.contains("no") {
            return Some(false);
        }
    }
    None
}

pub fn parse_windows_dns_servers(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let mut in_dns = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("dns servers") {
            in_dns = true;
            if let Some(value) = value_after_colon(trimmed) {
                push_dns(&mut servers, &value);
            }
            continue;
        }
        if !in_dns {
            continue;
        }
        if trimmed.contains(':') {
            in_dns = false;
            continue;
        }
        let candidate = trimmed.split_whitespace().next().unwrap_or("");
        if !push_dns(&mut servers, candidate) {
            in_dns = false;
        }
    }
    servers
}

fn push_dns(servers: &mut Vec<String>, candidate: &str) -> bool {
    let candidate = candidate.trim().trim_end_matches('%');
    if candidate.parse::<IpAddr>().is_err() {
        return false;
    }
    if !servers.iter().any(|existing| existing == candidate) {
        servers.push(candidate.to_string());
    }
    true
}

fn adapter_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.ends_with(':') {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let index = lower.rfind("adapter ")?;
    let name = trimmed[index + "adapter ".len()..]
        .trim_end_matches(':')
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn value_after_colon(line: &str) -> Option<String> {
    let (_, value) = line.split_once(':')?;
    let value = value.split('(').next()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn netsh_field(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some((key, value.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_powershell_address_json() {
        let text = r#"[{"InterfaceAlias":"Ethernet","InterfaceIndex":5,"IPAddress":"192.168.1.10","AddressFamily":2},{"InterfaceAlias":"Ethernet","InterfaceIndex":5,"IPAddress":"2001:db8::10","AddressFamily":23},{"InterfaceAlias":"Tailscale","InterfaceIndex":12,"IPAddress":"100.64.0.2","AddressFamily":2}]"#;
        let parsed = parse_net_ip_address_json(text).unwrap();
        assert_eq!(parsed.len(), 2);
        let ethernet = parsed.iter().find(|item| item.name == "Ethernet").unwrap();
        assert_eq!(ethernet.index, 5);
        assert_eq!(ethernet.ipv4, vec!["192.168.1.10".to_string()]);
        assert_eq!(ethernet.ipv6, vec!["2001:db8::10".to_string()]);
        assert!(!ethernet.vpn_like);
        let tunnel = parsed.iter().find(|item| item.name == "Tailscale").unwrap();
        assert!(tunnel.vpn_like);
    }

    #[test]
    fn empty_powershell_array_is_an_observation() {
        let parsed = parse_net_ip_address_json("[]").unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parses_english_ipconfig_blocks() {
        let text = "\
Ethernet adapter Ethernet:\n\
\n\
   IPv4 Address. . . . . . . . . . . : 192.168.1.10\n\
   IPv6 Address. . . . . . . . . . . : 2001:db8::10(Preferred)\n\
\n\
Wireless LAN adapter Wi-Fi:\n\
\n\
   Media State . . . . . . . . . . . : Media disconnected\n\
";
        let parsed = parse_ipconfig(text);
        let ethernet = parsed.iter().find(|item| item.name == "Ethernet").unwrap();
        assert!(ethernet.up);
        assert_eq!(ethernet.ipv4, vec!["192.168.1.10".to_string()]);
        assert_eq!(ethernet.ipv6, vec!["2001:db8::10".to_string()]);
        assert_eq!(ethernet.index, 0);
        let wifi = parsed.iter().find(|item| item.name == "Wi-Fi").unwrap();
        assert!(looks_like_wifi(&wifi.name));
        assert!(!wifi.up);
    }

    #[test]
    fn parses_default_routes() {
        let ipv4 = "\
Active Routes:\n\
Network Destination        Netmask          Gateway       Interface  Metric\n\
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.10     25\n\
";
        assert_eq!(
            parse_ipv4_route_print(ipv4),
            Some((
                Some("192.168.1.1".to_string()),
                Some("192.168.1.10".to_string())
            ))
        );
        let ipv6 = "  5    256 ::/0                     fe80::1\n";
        assert_eq!(
            parse_ipv6_route_print(ipv6),
            Some((Some("fe80::1".to_string()), Some("ifindex 5".to_string())))
        );
    }

    #[test]
    fn parses_wlan_without_converting_percent_to_dbm() {
        let text = "\
    Name                   : Wi-Fi\n\
    SSID                   : Cafe\n\
    Signal                 : 84%\n\
    Receive rate (Mbps)    : 144.5\n\
";
        let parsed = parse_netsh_wlan(text);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ssid.as_deref(), Some("Cafe"));
        assert_eq!(parsed[0].signal_percent, Some(84));
        assert_eq!(parsed[0].receive_mbps, Some(144.5));
    }

    #[test]
    fn parses_dhcp_and_dns_servers() {
        assert_eq!(
            parse_dhcp_enabled("   DHCP enabled:                         Yes\n"),
            Some(true)
        );
        let text = "\
   DNS Servers . . . . . . . . . . . : 192.168.1.1\n\
                                       1.1.1.1\n\
   NetBIOS over Tcpip  . . . . . . . : Enabled\n\
";
        assert_eq!(
            parse_windows_dns_servers(text),
            vec!["192.168.1.1".to_string(), "1.1.1.1".to_string()]
        );
    }
}
