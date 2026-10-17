//! Stage 1: operating system, interfaces, routes and tunnel hints.

use std::net::IpAddr;

use crate::models::{
    Environment, Family, InterfaceInfo, Probe, ProbeDetail, ProbeKind, ProbeOutcome, RouteInfo,
};
use crate::platform;
use crate::probes::Recorder;

/// Environment snapshot plus the identifiers of the probes that produced it.
pub struct SystemProbe {
    pub environment: Environment,
    pub probe_ids: Vec<String>,
}

fn record_route(
    recorder: &mut Recorder,
    family: Family,
    purpose: &str,
    route: Option<&RouteInfo>,
    error: Option<String>,
) -> String {
    let id = match purpose {
        "target" => recorder.next_id("route_target"),
        "default" => match family {
            Family::Ipv4 => recorder.next_id("route_v4"),
            Family::Ipv6 => recorder.next_id("route_v6"),
        },
        _ => recorder.next_id("route"),
    };
    let detail = ProbeDetail::Route {
        family: if family == Family::Ipv4 {
            "ipv4"
        } else {
            "ipv6"
        }
        .to_string(),
        purpose: purpose.to_string(),
        gateway: route.and_then(|route| route.gateway.clone()),
        interface: route.and_then(|route| route.interface.clone()),
        raw_error: error,
    };
    recorder.record(Probe {
        id: id.clone(),
        kind: ProbeKind::Route,
        outcome: if route.is_some() {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::NotApplicable
        },
        family: Some(family),
        target: None,
        port: None,
        started_at: crate::util::now_rfc3339(),
        duration_ms: None,
        detail,
    });
    id
}

/// Collect the environment and record the probes backing it.
pub fn collect(recorder: &mut Recorder, target_ip: Option<IpAddr>) -> SystemProbe {
    let mut notes = Vec::new();
    let mut probe_ids = Vec::new();

    let interfaces: Vec<InterfaceInfo> = match platform::interfaces() {
        Ok(list) => list,
        Err(error) => {
            notes.push(format!("interface enumeration failed: {error}"));
            Vec::new()
        }
    };

    let ipv4_local = platform::local_family_support(&interfaces, Family::Ipv4);
    let ipv6_local = platform::local_family_support(&interfaces, Family::Ipv6);
    let has_global_ipv6 = platform::has_global_ipv6(&interfaces);
    let vpn_like_interfaces: Vec<String> = interfaces
        .iter()
        .filter(|interface| interface.vpn_like)
        .map(|interface| interface.name.clone())
        .collect();

    if !vpn_like_interfaces.is_empty() {
        notes.push(
            "tunnel-like interface names detected; this is a hint only and does not prove a VPN is active"
                .to_string(),
        );
    }

    let inventory_id = recorder.next_id("system");
    recorder.record(Probe {
        id: inventory_id.clone(),
        kind: ProbeKind::System,
        outcome: ProbeOutcome::Ok,
        family: None,
        target: None,
        port: None,
        started_at: crate::util::now_rfc3339(),
        duration_ms: None,
        detail: ProbeDetail::SystemInventory {
            interface_count: interfaces.len(),
            vpn_like_interfaces: vpn_like_interfaces.clone(),
            has_global_ipv6,
            notes: notes.clone(),
        },
    });
    probe_ids.push(inventory_id);

    let default_route_v4 = platform::default_route(Family::Ipv4);
    let default_route_v6 = platform::default_route(Family::Ipv6);
    if default_route_v4.is_none() {
        notes.push("no IPv4 default route reported by the OS".to_string());
    }
    if default_route_v6.is_none() {
        notes.push("no IPv6 default route reported by the OS".to_string());
    }
    probe_ids.push(record_route(
        recorder,
        Family::Ipv4,
        "default",
        default_route_v4.as_ref(),
        None,
    ));
    probe_ids.push(record_route(
        recorder,
        Family::Ipv6,
        "default",
        default_route_v6.as_ref(),
        None,
    ));

    let target_route = target_ip.and_then(|ip| {
        let family = if ip.is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        };
        platform::route_to(ip).map(|route| (family, route))
    });
    if let Some((family, route)) = &target_route {
        probe_ids.push(record_route(recorder, *family, "target", Some(route), None));
    } else if target_ip.is_some() {
        notes.push("target route could not be resolved by the OS".to_string());
    }

    let proxy_env_names = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
        .iter()
        .filter(|name| {
            std::env::var(name).is_ok() || std::env::var(name.to_ascii_lowercase()).is_ok()
        })
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    if !proxy_env_names.is_empty() {
        notes.push(
            "proxy environment variables are set; PathTrial does not apply them to its own probes"
                .to_string(),
        );
    }

    let environment = Environment {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: platform::kernel_version(),
        interfaces,
        ipv4_local,
        ipv6_local,
        has_global_ipv6,
        vpn_like_interfaces,
        default_route_v4,
        default_route_v6,
        target_route: target_route.map(|(_, route)| route),
        proxy_env_names,
        notes,
    };

    SystemProbe {
        environment,
        probe_ids,
    }
}
