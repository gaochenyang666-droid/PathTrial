//! End to end CLI checks that do not depend on the public internet.

use std::net::TcpListener;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

#[test]
fn version_and_help_are_available() {
    let version = Command::new(binary())
        .arg("--version")
        .output()
        .expect("run");
    assert!(version.status.success());
    let text = String::from_utf8_lossy(&version.stdout);
    assert!(
        text.contains("pathtrial"),
        "unexpected version output: {text}"
    );

    let help = Command::new(binary()).arg("--help").output().expect("run");
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("scan"));
    assert!(help_text.contains("Exit codes"));
}

#[test]
fn invalid_arguments_exit_with_tool_error() {
    let output = Command::new(binary())
        .args(["scan", "example.com", "--rounds", "0"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"), "stderr was {stderr}");
}

#[test]
fn scan_against_loopback_listener_emits_valid_json() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let _ = listener.accept();
        }
    });

    let output = Command::new(binary())
        .args([
            "scan",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--profile",
            "tcp",
            "--rounds",
            "2",
            "--timeout-ms",
            "1000",
            "--interval-ms",
            "50",
            "--format",
            "json",
            "--no-files",
        ])
        .output()
        .expect("run scan");

    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(value["schema_version"], "1.1.0");
    assert_eq!(value["stages"].as_array().unwrap().len(), 5);
    assert_eq!(value["summaries"][0]["tcp_success"], 2);
    assert_eq!(value["configuration"]["tls_enabled"], false);

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/report.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|error| format!("{} at {}", error, error.instance_path))
        .collect();
    assert!(errors.is_empty(), "schema violations: {errors:#?}");
}

/// Start a loopback listener that serves `accepts` connections.
fn loopback(accepts: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for _ in 0..accepts {
            let _ = listener.accept();
        }
    });
    port
}

fn scan_args(port: u16) -> Vec<String> {
    [
        "scan",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--profile",
        "tcp",
        "--rounds",
        "1",
        "--timeout-ms",
        "1000",
        "--interval-ms",
        "20",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    std::env::temp_dir().join(format!("pathtrial-{tag}-{}-{nanos}", std::process::id()))
}

#[test]
fn report_files_use_unique_names_and_do_not_collide() {
    let dir = unique_dir("files");
    std::fs::create_dir_all(&dir).unwrap();
    for _ in 0..2 {
        let port = loopback(2);
        let mut args = scan_args(port);
        args.push("--out-dir".to_string());
        args.push(dir.to_str().unwrap().to_string());
        let status = Command::new(binary()).args(&args).status().expect("run");
        assert!(status.success());
    }
    let jsons: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with("pathtrial-report-"))
        .collect();
    let json_count = jsons.iter().filter(|name| name.ends_with(".json")).count();
    let md_count = jsons.iter().filter(|name| name.ends_with(".md")).count();
    assert_eq!(json_count, 2, "two runs must not overwrite each other");
    assert_eq!(md_count, 2);
}

#[test]
fn no_files_writes_nothing() {
    let dir = unique_dir("nofiles");
    std::fs::create_dir_all(&dir).unwrap();
    let port = loopback(2);
    let mut args = scan_args(port);
    args.push("--no-files".to_string());
    args.push("--format".to_string());
    args.push("json".to_string());
    let output = Command::new(binary())
        .args(&args)
        .current_dir(&dir)
        .output()
        .expect("run");
    assert!(output.status.success());
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(entries.is_empty(), "--no-files must not create files");
}

#[test]
fn json_stdout_is_pure() {
    let port = loopback(2);
    let mut args = scan_args(port);
    args.push("--format".to_string());
    args.push("json".to_string());
    args.push("--no-files".to_string());
    let output = Command::new(binary()).args(&args).output().expect("run");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.trim_start().starts_with('{'), "stdout: {stdout:.80}");
    assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_ok());
    assert!(!stdout.contains("Report:"));
}

#[test]
fn explicit_out_prefix_overwrites_on_purpose() {
    let dir = unique_dir("outprefix");
    std::fs::create_dir_all(&dir).unwrap();
    let prefix = dir.join("fixed");
    for _ in 0..2 {
        let port = loopback(2);
        let mut args = scan_args(port);
        args.push("--out".to_string());
        args.push(prefix.to_str().unwrap().to_string());
        let output = Command::new(binary()).args(&args).output().expect("run");
        assert!(output.status.success());
    }
    assert!(dir.join("fixed.json").exists());
    assert!(dir.join("fixed.md").exists());
    let count = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(count, 2, "explicit prefix writes exactly two files");
}
