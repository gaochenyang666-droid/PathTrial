//! Windows route and interface lookups.
//!
//! Interface binding is intentionally absent: a failed bind must not fall back
//! to another NIC. Per-target route lookup is also absent; only `route print`
//! default routes are recorded, and a missing target route is not evidence
//! that no route exists.

use std::net::IpAddr;
use std::process::Command;

use crate::models::{Family, InterfaceInfo, RouteInfo};

use super::winparse;

pub fn interfaces() -> Result<Vec<InterfaceInfo>, String> {
    if let Some(text) = command_text(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,AddressFamily | ConvertTo-Json -Compress",
        ],
    ) {
        match winparse::parse_net_ip_address_json(&text) {
            Ok(list) => return Ok(list),
            Err(error) => {
                if let Some(fallback) = ipconfig_interfaces() {
                    return Ok(fallback);
                }
                return Err(error);
            }
        }
    }
    ipconfig_interfaces().ok_or_else(|| {
        "could not enumerate interfaces with Get-NetIPAddress or ipconfig /all".to_string()
    })
}

fn ipconfig_interfaces() -> Option<Vec<InterfaceInfo>> {
    let text = command_text("ipconfig", &["/all"])?;
    let parsed = winparse::parse_ipconfig(&text);
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

pub fn kernel_version() -> Option<String> {
    let text = command_text("cmd", &["/C", "ver"])?;
    text.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

pub fn default_route(family: Family) -> Option<RouteInfo> {
    let parsed = match family {
        Family::Ipv4 => command_text("route", &["print", "-4"])
            .and_then(|text| winparse::parse_ipv4_route_print(&text)),
        Family::Ipv6 => command_text("route", &["print", "-6"])
            .and_then(|text| winparse::parse_ipv6_route_print(&text)),
    };
    let (gateway, interface) = parsed?;
    let note = if family == Family::Ipv4 {
        "parsed from route print -4; the interface field is the address printed there, not an adapter name"
    } else {
        "parsed from route print -6; the interface field is an ifindex when the text included one"
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
        note: Some(note.to_string()),
    })
}

pub fn route_to(_ip: IpAddr) -> Option<RouteInfo> {
    None
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}
