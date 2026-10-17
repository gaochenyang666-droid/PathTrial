//! PathTrial: evidence-first network diagnostics.
//!
//! The binary is deliberately synchronous and single-process: probes run in a
//! fixed order, each result is recorded, and the report is derived from the
//! recorded data only.

use std::process::ExitCode;

use clap::Parser;

use pathtrial::cli::{Cli, Command};
use pathtrial::models::Status;
use pathtrial::scan;

const EXIT_OK: u8 = 0;
const EXIT_TOOL_ERROR: u8 = 1;
const EXIT_FINDINGS: u8 = 2;
const EXIT_INCONCLUSIVE: u8 = 3;

fn main() -> ExitCode {
    // rustls 0.23 requires an explicitly installed crypto provider. Installing
    // it once here keeps probe code free of global state.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    match cli.command {
        Command::Schema => {
            print!("{}", include_str!("../schemas/report.schema.json"));
            ExitCode::from(EXIT_OK)
        }
        Command::Scan(args) => {
            if let Err(message) = args.validate() {
                eprintln!("error: {message}");
                eprintln!("hint: run `pathtrial scan --help` for valid ranges");
                return ExitCode::from(EXIT_TOOL_ERROR);
            }
            match scan::run(&args) {
                Ok(outcome) => ExitCode::from(match outcome.worst_status {
                    Status::Fail | Status::Warn => EXIT_FINDINGS,
                    Status::Inconclusive => EXIT_INCONCLUSIVE,
                    _ => EXIT_OK,
                }),
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(EXIT_TOOL_ERROR)
                }
            }
        }
    }
}
