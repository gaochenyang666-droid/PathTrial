//! PathTrial: evidence-first network diagnostics.
//!
//! The library exposes the probe pipeline, the deterministic analysis rules and
//! the report renderer so they can be tested without invoking the binary.

pub mod allow;
pub mod analysis;
pub mod baseline;
pub mod cli;
pub mod collect;
pub mod commands;
pub mod compare;
pub mod diagnose;
pub mod endpoint;
pub mod mcp;
pub mod models;
pub mod net;
pub mod paths;
pub mod platform;
pub mod probes;
pub mod process;
pub mod render;
pub mod report;
pub mod scan;
pub mod single;
pub mod util;
