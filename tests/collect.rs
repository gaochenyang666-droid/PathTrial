//! Offline dual-end collection and correlation tests.

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pathtrial")
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "pathtrial-collect-{tag}-{}-{id}.json",
        std::process::id(),
    ))
}

enum PairError {
    Transient(String),
    Invalid(String),
}

fn collect_pair(rounds: u32) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut last_error = String::new();
    for attempt in 1..=2 {
        match collect_pair_once(rounds) {
            Ok(paths) => return paths,
            Err(PairError::Transient(error)) => {
                eprintln!("collect pair attempt {attempt} failed: {error}");
                last_error = error;
            }
            Err(PairError::Invalid(error)) => {
                panic!("baseline collection is invalid: {error}");
            }
        }
    }
    panic!("collect pair failed twice; last error: {last_error}");
}

fn collect_pair_once(rounds: u32) -> Result<(std::path::PathBuf, std::path::PathBuf), PairError> {
    let server_path = temp_path("server");
    let client_path = temp_path("client");
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| PairError::Transient(error.to_string()))?;
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut server = Command::new(binary())
        .args([
            "collect",
            "--role",
            "server",
            "--task-id",
            "task-a",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--max-seconds",
            "4",
            "--output",
            server_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| PairError::Transient(format!("start collect server: {error}")))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !ready {
        let _ = server.kill();
        let _ = server.wait();
        return Err(PairError::Transient(format!(
            "collect server did not listen on 127.0.0.1:{port} within 8s"
        )));
    }
    let client = Command::new(binary())
        .args([
            "collect",
            "--role",
            "client",
            "--task-id",
            "task-a",
            "--target",
            &format!("127.0.0.1:{port}"),
            "--rounds",
            &rounds.to_string(),
            "--interval-ms",
            "50",
            "--max-seconds",
            "3",
            "--output",
            client_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|error| PairError::Transient(format!("run collect client: {error}")))?;
    if !client.status.success() {
        let _ = server.kill();
        let _ = server.wait();
        return Err(PairError::Transient(format!(
            "collect client failed: {}",
            String::from_utf8_lossy(&client.stderr)
        )));
    }
    let status = server
        .wait()
        .map_err(|error| PairError::Transient(format!("wait for collect server: {error}")))?;
    if !status.success() {
        return Err(PairError::Transient(format!(
            "collect server exited with {status}"
        )));
    }
    let (status, value) = correlate(&client_path, &server_path);
    if !status.success() {
        return Err(PairError::Invalid(format!(
            "baseline collection did not correlate: status={status}; finding={}; issues={}",
            value["finding"]["status"], value["comparability"]["issues"]
        )));
    }
    Ok((client_path, server_path))
}

fn correlate(
    client: &std::path::Path,
    server: &std::path::Path,
) -> (std::process::ExitStatus, serde_json::Value) {
    let output = Command::new(binary())
        .args([
            "correlate",
            client.to_str().unwrap(),
            server.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("correlate");
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "bad JSON: {error}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status, value)
}

fn validate(schema_text: &str, value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(schema_text).expect("schema");
    let errors: Vec<String> = jsonschema::validator_for(&schema)
        .expect("validator")
        .iter_errors(value)
        .map(|error| format!("{} at {}", error, error.instance_path))
        .collect();
    assert!(errors.is_empty(), "schema violations: {errors:#?}");
}

#[test]
fn matching_client_and_server_are_correlated() {
    let (client, server) = collect_pair(3);
    for path in [&client, &server] {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        validate(include_str!("../schemas/collect.schema.json"), &value);
    }
    let (status, value) = correlate(&client, &server);
    assert!(status.success(), "value: {value}");
    assert_eq!(value["comparability"]["verdict"], "DIRECTLY COMPARABLE");
    assert_eq!(value["client"]["success"], 3);
    assert_eq!(value["server"]["task_matched"], 3);
    assert_eq!(value["finding"]["status"], "PASS");
    assert!(value["finding"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .all(|id| id.as_str().unwrap().starts_with("client_")
            || id.as_str().unwrap().starts_with("server_")));
    assert!(value["finding"]["not_established"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("hop")));
    validate(include_str!("../schemas/correlate.schema.json"), &value);
}

fn edit(path: &std::path::Path, edit: impl FnOnce(&mut serde_json::Value)) -> std::path::PathBuf {
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    edit(&mut value);
    let output = temp_path("edited");
    std::fs::write(&output, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    output
}

#[test]
fn task_port_schema_and_time_mismatches_are_visible() {
    let (client, server) = collect_pair(2);

    let other_task = edit(&server, |value| {
        value["task_id"] = serde_json::json!("task-b");
    });
    let (status, value) = correlate(&client, &other_task);
    assert_eq!(status.code(), Some(3));
    assert_eq!(value["comparability"]["verdict"], "NOT DIRECTLY COMPARABLE");

    let old_window = edit(&server, |value| {
        value["window"]["started_at"] = serde_json::json!("2020-01-01T00:00:00Z");
        value["window"]["finished_at"] = serde_json::json!("2020-01-01T00:00:01Z");
    });
    let (status, value) = correlate(&client, &old_window);
    assert_eq!(status.code(), Some(3));
    assert!(value["comparability"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("windows")));

    let other_port = edit(&server, |value| {
        value["listen"] = serde_json::json!("127.0.0.1:65000");
    });
    let (status, value) = correlate(&client, &other_port);
    assert_eq!(status.code(), Some(3));
    assert!(value["comparability"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("ports differ")));

    let other_ip = edit(&server, |value| {
        let port = value["listen"]
            .as_str()
            .unwrap()
            .rsplit_once(':')
            .unwrap()
            .1
            .to_string();
        value["listen"] = serde_json::json!(format!("127.0.0.2:{port}"));
    });
    let (status, value) = correlate(&client, &other_ip);
    assert_eq!(status.code(), Some(3));
    assert!(value["comparability"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("target address differs")));

    let other_schema = edit(&server, |value| {
        value["schema_version"] = serde_json::json!("0.9.0");
    });
    let (status, value) = correlate(&client, &other_schema);
    assert!(status.success(), "schema difference should remain readable");
    assert!(value["comparability"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("schema versions differ")));
}

#[test]
fn partial_server_observation_is_a_failure_without_packet_claims() {
    let (client, server) = collect_pair(3);
    let truncated = edit(&server, |value| {
        value["events"].as_array_mut().unwrap().pop();
    });
    let (status, value) = correlate(&client, &truncated);
    assert_eq!(status.code(), Some(2));
    assert_eq!(value["finding"]["status"], "FAIL");
    assert!(value["finding"]["claim"]
        .as_str()
        .unwrap()
        .contains("server observed"));
    assert!(value["finding"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("packet capture")));
}

#[test]
fn missing_report_is_a_tool_error() {
    let missing = temp_path("missing");
    let (_, server) = collect_pair(1);
    let output = Command::new(binary())
        .args([
            "correlate",
            missing.to_str().unwrap(),
            server.to_str().unwrap(),
        ])
        .output()
        .expect("correlate");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("read"));
}

#[test]
fn no_success_on_either_side_is_inconclusive() {
    let (client, server) = collect_pair(2);
    let failed_client = edit(&client, |value| {
        for event in value["events"].as_array_mut().unwrap() {
            event["kind"] = serde_json::json!("connect_fail");
        }
    });
    let no_task_server = edit(&server, |value| {
        for event in value["events"].as_array_mut().unwrap() {
            event["task_id_seen"] = serde_json::Value::Null;
        }
    });
    let (status, value) = correlate(&failed_client, &no_task_server);
    assert_eq!(status.code(), Some(3));
    assert_eq!(value["finding"]["status"], "INCONCLUSIVE");
}
