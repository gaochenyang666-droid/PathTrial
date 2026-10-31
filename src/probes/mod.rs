//! Probe implementations and the recorder that gives every measurement a
//! stable identifier.

pub mod dns;
pub mod http;
pub mod icmp;
pub mod proxy;
pub mod quic;
pub mod system;
pub mod tcp;
pub mod tls;
pub mod trace;
pub mod udp;

use std::collections::BTreeMap;

use crate::models::Probe;

/// Collects probes and allocates deterministic identifiers such as
/// `tcp_ipv4_003`. Identifiers are part of the public report and are what
/// findings cite, so they never change shape within a run.
#[derive(Debug, Default)]
pub struct Recorder {
    probes: Vec<Probe>,
    counters: BTreeMap<String, usize>,
}

impl Recorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_id(&mut self, prefix: &str) -> String {
        let counter = self.counters.entry(prefix.to_string()).or_insert(0);
        *counter += 1;
        format!("{prefix}_{:03}", *counter)
    }

    pub fn record(&mut self, probe: Probe) -> String {
        let id = probe.id.clone();
        self.probes.push(probe);
        id
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    pub fn into_probes(self) -> Vec<Probe> {
        self.probes
    }

    pub fn probes(&self) -> &[Probe] {
        &self.probes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_sequential_per_prefix() {
        let mut recorder = Recorder::new();
        assert_eq!(recorder.next_id("tcp_ipv4"), "tcp_ipv4_001");
        assert_eq!(recorder.next_id("tcp_ipv4"), "tcp_ipv4_002");
        assert_eq!(recorder.next_id("tcp_ipv6"), "tcp_ipv6_001");
    }
}
