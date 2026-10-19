//! Platform specific plumbing.
//!
//! Interface enumeration uses `getifaddrs` on both supported platforms, so no
//! external command or elevated privilege is needed. Route lookups shell out to
//! the OS tooling (`route` on macOS, `ip` on Linux) because both expose the
//! resolved route, not just the table, which is what a diagnostic needs.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt::Write as _;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use crate::models::{Family, InterfaceInfo, LocalLinkInfo, RouteInfo};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::{default_route, route_to};
#[cfg(target_os = "macos")]
pub use macos::{default_route, route_to};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("PathTrial V1 supports macOS and Linux only");

/// Heuristic: names used by common tunnel adapters. This is a hint for the
/// report, never a conclusion.
pub fn looks_like_tunnel(name: &str) -> bool {
    const PREFIXES: [&str; 8] = [
        "utun", "tun", "tap", "wg", "ppp", "ipsec", "gpd", "nordlynx",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Enumerate interfaces and their assigned addresses.
pub fn interfaces() -> Result<Vec<InterfaceInfo>, String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list owned by us; it is released
    // with freeifaddrs at the end of this function, including on early return
    // through the `result` value.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    let mut by_name: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor points into the list allocated above; each node stays
        // valid until freeifaddrs.
        let entry = unsafe { &*cursor };
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .to_string();
        let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
        let up = entry.ifa_flags & libc::IFF_UP as libc::c_uint != 0;

        let info = by_name
            .entry(name.clone())
            .or_insert_with(|| InterfaceInfo {
                name: name.clone(),
                index,
                up: false,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                vpn_like: looks_like_tunnel(&name),
            });
        info.up |= up;

        if !entry.ifa_addr.is_null() {
            // SAFETY: non-null ifa_addr points at a sockaddr whose family field
            // decides which concrete layout may be read.
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                // SAFETY: family is AF_INET, so the sockaddr is a sockaddr_in.
                let sockaddr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                let address = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
                info.ipv4.push(address.to_string());
            } else if family == libc::AF_INET6 {
                // SAFETY: family is AF_INET6, so the sockaddr is a sockaddr_in6.
                let sockaddr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                let address = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
                if address.is_unicast_link_local() {
                    info.ipv6.push(format!("{address}%{}", name));
                } else {
                    info.ipv6.push(address.to_string());
                }
            }
        }

        cursor = entry.ifa_next;
    }
    // SAFETY: head came from getifaddrs and is released exactly once here.
    unsafe { libc::freeifaddrs(head) };

    Ok(by_name.into_values().collect())
}

/// Kernel release string, when the platform exposes it.
pub fn kernel_version() -> Option<String> {
    // SAFETY: uname writes into a zeroed utsname owned by this stack frame.
    let mut info: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is valid for writes for the duration of the call.
    let rc = unsafe { libc::uname(&mut info) };
    if rc != 0 {
        return None;
    }
    // SAFETY: release is a NUL-terminated array inside utsname.
    let release = unsafe { CStr::from_ptr(info.release.as_ptr()) };
    Some(release.to_string_lossy().to_string())
}

/// Render a route for human summaries.
pub fn describe_route(route: &RouteInfo) -> String {
    let mut text = String::new();
    match (&route.gateway, &route.interface) {
        (Some(gateway), Some(interface)) => {
            let _ = write!(text, "via {gateway} dev {interface}");
        }
        (Some(gateway), None) => {
            let _ = write!(text, "via {gateway}");
        }
        (None, Some(interface)) => {
            let _ = write!(text, "dev {interface}");
        }
        (None, None) => text.push_str("unknown"),
    }
    text
}

/// Whether any interface carries a globally routable IPv6 address.
pub fn has_global_ipv6(interfaces: &[InterfaceInfo]) -> bool {
    interfaces.iter().any(|interface| {
        interface.ipv6.iter().any(|text| {
            text.split('%')
                .next()
                .and_then(|value| value.parse::<Ipv6Addr>().ok())
                .is_some_and(|address| !address.is_loopback() && !address.is_unicast_link_local())
        })
    })
}

/// Best-effort local family availability, derived from assigned addresses.
pub fn local_family_support(interfaces: &[InterfaceInfo], family: Family) -> bool {
    match family {
        Family::Ipv4 => interfaces
            .iter()
            .any(|interface| interface.ipv4.iter().any(|text| !text.starts_with("127."))),
        Family::Ipv6 => interfaces.iter().any(|interface| {
            interface.ipv6.iter().any(|text| {
                text.split('%')
                    .next()
                    .and_then(|value| value.parse::<Ipv6Addr>().ok())
                    .is_some_and(|address| !address.is_loopback())
            })
        }),
    }
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn mac_wifi_names() -> Vec<String> {
    let Some(text) = command_text("/usr/sbin/networksetup", &["-listallhardwareports"]) else {
        return Vec::new();
    };
    parse_macos_wifi_devices(&text)
}

#[cfg(target_os = "macos")]
fn parse_macos_wifi_devices(text: &str) -> Vec<String> {
    let mut wifi = Vec::new();
    let mut in_wifi = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(port) = trimmed.strip_prefix("Hardware Port:") {
            in_wifi = matches!(port.trim(), "Wi-Fi" | "AirPort");
        } else if in_wifi {
            if let Some(device) = trimmed.strip_prefix("Device:") {
                wifi.push(device.trim().to_string());
                in_wifi = false;
            }
        }
    }
    wifi
}

#[cfg(target_os = "macos")]
fn parse_macos_airport(text: &str) -> (Option<i32>, Option<f64>) {
    let mut signal = None;
    let mut rate = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("agrCtlRSSI:") {
            signal = value.trim().parse::<i32>().ok();
        } else if let Some(value) = trimmed.strip_prefix("lastTxRate:") {
            rate = value.trim().parse::<f64>().ok();
        }
    }
    (signal, rate)
}

#[cfg(target_os = "macos")]
fn parse_macos_dhcp(text: &str) -> Option<String> {
    let mut server = None;
    let mut lease = None;
    let value_after = |line: &str| {
        line.rsplit_once('=')
            .or_else(|| line.rsplit_once(':'))
            .map(|(_, value)| value.trim().to_string())
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("server_identifier") {
            server = value_after(trimmed);
        } else if trimmed.starts_with("lease_time") {
            lease = value_after(trimmed);
        }
    }
    if server.is_none() && lease.is_none() {
        None
    } else {
        Some(format!(
            "DHCP lease observed; server={} lease_seconds={}",
            server.unwrap_or_else(|| "unknown".to_string()),
            lease.unwrap_or_else(|| "unknown".to_string())
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_wifi_link(text: &str) -> (Option<String>, Option<i32>, Option<f64>) {
    let mut ssid = None;
    let mut signal = None;
    let mut rate = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("SSID:") {
            ssid = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("signal:") {
            signal = value
                .split_whitespace()
                .next()
                .and_then(|number| number.parse::<i32>().ok());
        } else if let Some(value) = trimmed.strip_prefix("tx bitrate:") {
            rate = value
                .split_whitespace()
                .next()
                .and_then(|number| number.parse::<f64>().ok());
        }
    }
    (ssid, signal, rate)
}

/// Best-effort, read-only Wi-Fi and DHCP facts. Missing tools or privileges
/// produce notes, never a fatal error.
pub fn local_links(interfaces: &[InterfaceInfo]) -> Vec<LocalLinkInfo> {
    #[cfg(target_os = "macos")]
    let wifi_names = mac_wifi_names();
    #[cfg(target_os = "macos")]
    let airport = command_text(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        &["-I"],
    );

    interfaces
        .iter()
        .filter(|interface| {
            interface.up
                && !interface.name.starts_with("lo")
                && (!interface.ipv4.is_empty() || !interface.ipv6.is_empty())
        })
        .map(|interface| {
            let mut notes = Vec::new();
            let name = interface.name.clone();
            #[cfg(target_os = "macos")]
            let is_wifi = wifi_names.iter().any(|candidate| candidate == &name);
            #[cfg(target_os = "linux")]
            let is_wifi = std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists();

            let mut ssid = None;
            let mut signal_dbm = None;
            let mut tx_rate_mbps = None;
            if is_wifi {
                #[cfg(target_os = "macos")]
                {
                    if let Some(text) =
                        command_text("/usr/sbin/networksetup", &["-getairportnetwork", &name])
                    {
                        if let Some(value) = text.trim().strip_prefix("Current Wi-Fi Network:") {
                            ssid = Some(value.trim().to_string());
                        }
                    }
                    if let Some(text) = &airport {
                        (signal_dbm, tx_rate_mbps) = parse_macos_airport(text);
                    }
                    if signal_dbm.is_none() {
                        notes.push(
                            "Wi-Fi link quality is unavailable from the built-in read-only tools"
                                .to_string(),
                        );
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    if let Some(text) = command_text("iw", &["dev", &name, "link"]) {
                        (ssid, signal_dbm, tx_rate_mbps) = parse_linux_wifi_link(&text);
                    } else {
                        notes
                            .push("iw is unavailable; Wi-Fi link metrics were skipped".to_string());
                    }
                }
            }

            let mut dhcp = None;
            #[cfg(target_os = "macos")]
            if let Some(text) = command_text("/usr/sbin/ipconfig", &["getpacket", &name]) {
                dhcp = parse_macos_dhcp(&text);
            }
            #[cfg(target_os = "linux")]
            {
                if let Some(text) = command_text("ip", &["route", "show", "default", "dev", &name])
                {
                    if text.contains("proto dhcp") {
                        dhcp = Some("default route is marked proto dhcp".to_string());
                    }
                }
                if dhcp.is_none()
                    && (std::path::Path::new("/var/lib/dhcp").exists()
                        || std::path::Path::new("/var/lib/NetworkManager").exists())
                {
                    notes.push(
                        "DHCP state directories exist, but no active lease was safely readable"
                            .to_string(),
                    );
                }
            }

            if !is_wifi {
                notes.push(
                    "interface is not identified as Wi-Fi; wireless metrics are SKIP".to_string(),
                );
            }

            LocalLinkInfo {
                interface: name,
                up: interface.up,
                is_wifi,
                ssid,
                signal_dbm,
                tx_rate_mbps,
                dhcp,
                notes,
            }
        })
        .collect()
}

#[cfg(test)]
mod local_tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_wifi_hardware_port() {
        let text = "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: Ethernet\nDevice: en5\n";
        assert_eq!(super::parse_macos_wifi_devices(text), vec!["en0"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_airport_signal_and_rate() {
        let text = "     agrCtlRSSI: -48\n     lastTxRate: 867\n";
        assert_eq!(super::parse_macos_airport(text), (Some(-48), Some(867.0)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_dhcp_lease() {
        let text = "server_identifier (ip): 192.168.1.1\nlease_time (uint32): 86400\n";
        let parsed = super::parse_macos_dhcp(text).unwrap();
        assert!(parsed.contains("192.168.1.1"));
        assert!(parsed.contains("86400"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_wifi_link() {
        let text = "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: Home\n\tsignal: -55 dBm\n\ttx bitrate: 433.3 MBit/s\n";
        assert_eq!(
            super::parse_linux_wifi_link(text),
            (Some("Home".to_string()), Some(-55), Some(433.3))
        );
    }
}
