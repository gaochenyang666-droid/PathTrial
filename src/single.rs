//! Result envelope for the single-purpose subcommands (`http`, `ping`, ...).

use serde::Serialize;

use crate::cli::OutputFormat;
use crate::models::{Probe, Status, SCHEMA_VERSION};

#[derive(Serialize)]
pub struct CommandReport {
    pub schema_version: String,
    pub tool_version: String,
    pub command: String,
    pub target: String,
    pub started_at: String,
    pub finished_at: String,
    pub status: Status,
    pub summary: String,
    pub probes: Vec<Probe>,
    pub limitations: Vec<String>,
}

impl CommandReport {
    pub fn new(command: &str, target: &str, started_at: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            command: command.to_string(),
            target: target.to_string(),
            started_at,
            finished_at: crate::util::now_rfc3339(),
            status: Status::Inconclusive,
            summary: String::new(),
            probes: Vec::new(),
            limitations: Vec::new(),
        }
    }

    pub fn with_status(mut self, status: Status, summary: impl Into<String>) -> Self {
        self.status = status;
        self.summary = summary.into();
        self
    }

    pub fn with_probes(mut self, probes: Vec<Probe>) -> Self {
        self.probes = probes;
        self
    }

    pub fn with_limitation(mut self, item: impl Into<String>) -> Self {
        self.limitations.push(item.into());
        self
    }

    /// Print in the requested format and return the process exit code.
    pub fn emit(&self, format: OutputFormat) -> u8 {
        match format {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
                );
            }
            OutputFormat::Markdown => {
                println!("# PathTrial {} `{}`", self.tool_version, self.command);
                println!();
                println!("- Target: `{}`", self.target);
                println!("- Started: {}", self.started_at);
                println!("- Finished: {}", self.finished_at);
                println!("- Verdict: **{}**", self.status.label());
                println!();
                println!("```text");
                for line in self.summary.lines() {
                    println!("{line}");
                }
                println!("```");
                if !self.limitations.is_empty() {
                    println!();
                    println!("## Limits");
                    println!();
                    for item in &self.limitations {
                        println!("- {item}");
                    }
                }
                println!();
                println!("Probes: {}", self.probes.len());
            }
            OutputFormat::Summary => {
                println!("PathTrial {}  {}", self.tool_version, self.command);
                println!("target: {}", self.target);
                for line in self.summary.lines() {
                    println!("{line}");
                }
                for item in &self.limitations {
                    println!("limit: {item}");
                }
                println!("verdict: {}", self.status.label());
            }
        }
        match self.status {
            Status::Fail | Status::Warn => 2,
            Status::Inconclusive | Status::Skip => 3,
            Status::Pass => 0,
        }
    }
}
