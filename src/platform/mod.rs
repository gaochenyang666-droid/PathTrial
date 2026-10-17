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

use crate::models::{Family, InterfaceInfo, RouteInfo};

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
