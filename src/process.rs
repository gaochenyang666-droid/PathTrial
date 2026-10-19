//! Bounded child-process execution with descendant cleanup.

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[derive(Debug)]
pub enum ProcessError {
    Spawn(String),
    Wait(String),
    Timeout,
    Cancelled,
    OutputLimit(usize),
}

impl ProcessError {
    pub fn message(&self) -> String {
        match self {
            ProcessError::Spawn(error) => format!("start child process: {error}"),
            ProcessError::Wait(error) => format!("wait for child: {error}"),
            ProcessError::Timeout => "timeout:child process".to_string(),
            ProcessError::Cancelled => "cancelled:client disconnected".to_string(),
            ProcessError::OutputLimit(limit) => {
                format!("child output exceeded {limit} bytes")
            }
        }
    }
}

/// Put the direct child in its own process group so a timeout can terminate it
/// and any tool it spawned. Descendant enumeration remains a fallback where a
/// process changed groups itself.
pub fn isolate_process_group(command: &mut Command) {
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

pub fn run_limited(
    mut command: Command,
    deadline: Instant,
    max_output: usize,
    cancelled: Option<&AtomicBool>,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), ProcessError> {
    isolate_process_group(&mut command);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| ProcessError::Spawn(error.to_string()))?;
    let pid = child.id();
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let stdout_overflow = overflow.clone();
    let stderr_overflow = overflow.clone();
    let stdout_reader =
        std::thread::spawn(move || read_limited(stdout, max_output, stdout_overflow));
    let stderr_reader =
        std::thread::spawn(move || read_limited(stderr, max_output, stderr_overflow));

    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if cancelled.is_some_and(|flag| flag.load(Ordering::SeqCst)) => {
                kill_tree(pid, &mut child);
                break Err(ProcessError::Cancelled);
            }
            Ok(None) if overflow.load(Ordering::Relaxed) => {
                kill_tree(pid, &mut child);
                break Err(ProcessError::OutputLimit(max_output));
            }
            Ok(None) if Instant::now() >= deadline => {
                kill_tree(pid, &mut child);
                break Err(ProcessError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                kill_tree(pid, &mut child);
                break Err(ProcessError::Wait(error.to_string()));
            }
        }
    };

    // A descendant can outlive the direct child while still holding the pipe
    // open. Give the readers a short grace period, then terminate the process
    // group so joining them cannot block past the budget.
    let drain_deadline = Instant::now() + Duration::from_millis(200);
    while (!stdout_reader.is_finished() || !stderr_reader.is_finished())
        && Instant::now() < drain_deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !stdout_reader.is_finished() || !stderr_reader.is_finished() {
        kill_group(pid);
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| ProcessError::Wait("stdout reader panicked".to_string()))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ProcessError::Wait("stderr reader panicked".to_string()))?;
    if overflow.load(Ordering::Relaxed) {
        return Err(ProcessError::OutputLimit(max_output));
    }
    outcome.map(|status| (status, stdout, stderr))
}

fn read_limited<R: Read>(mut reader: R, limit: usize, overflow: Arc<AtomicBool>) -> Vec<u8> {
    let mut collected = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if collected.len() < limit {
                    let remaining = limit - collected.len();
                    collected.extend_from_slice(&buffer[..read.min(remaining)]);
                    if read > remaining {
                        overflow.store(true, Ordering::Relaxed);
                        break;
                    }
                } else {
                    overflow.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    collected
}

fn kill_tree(pid: u32, child: &mut std::process::Child) {
    kill_group(pid);
    for descendant in descendants(pid).into_iter().rev() {
        #[cfg(unix)]
        unsafe {
            let _ = libc::kill(descendant as i32, libc::SIGKILL);
        }
        #[cfg(not(unix))]
        let _ = descendant;
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn kill_group(pid: u32) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(-(pid as i32), libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = pid;
}

fn descendants(root: u32) -> Vec<u32> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid="])
        .output()
        .ok();
    let Some(output) = output else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(parent)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(pid), Ok(parent)) = (pid.parse::<u32>(), parent.parse::<u32>()) else {
            continue;
        };
        pairs.push((pid, parent));
    }
    let mut result = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for (pid, ppid) in &pairs {
            if *ppid == parent && !result.contains(pid) {
                result.push(*pid);
                frontier.push(*pid);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn times_out_and_reaps() {
        let mut command = Command::new("sleep");
        command.arg("5");
        let error = run_limited(
            command,
            Instant::now() + Duration::from_millis(100),
            1024,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ProcessError::Timeout));
    }

    #[test]
    fn bounds_large_output() {
        let error = run_limited(
            Command::new("yes"),
            Instant::now() + Duration::from_secs(2),
            1024,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ProcessError::OutputLimit(1024)));
    }

    #[test]
    fn large_stderr_is_bounded() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("yes >&2");
        let error =
            run_limited(command, Instant::now() + Duration::from_secs(2), 2048, None).unwrap_err();
        assert!(matches!(error, ProcessError::OutputLimit(2048)));
    }

    #[test]
    fn output_at_the_limit_is_not_an_overflow() {
        let mut command = Command::new("sh");
        command.arg("-c").arg(r#"printf '%0100d' 0"#);
        let (status, stdout, stderr) =
            run_limited(command, Instant::now() + Duration::from_secs(2), 100, None)
                .expect("exactly-at-limit output should be accepted");
        assert!(status.success());
        assert_eq!(stdout.len(), 100);
        assert!(stderr.is_empty());
    }

    #[test]
    fn cancellation_stops_the_process_group() {
        let marker = temp_marker("cancel");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("echo $$ > {}; sleep 30", marker.display()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(120));
            flag.store(true, Ordering::SeqCst);
        });
        let error = run_limited(
            command,
            Instant::now() + Duration::from_secs(10),
            1024,
            Some(&cancelled),
        )
        .unwrap_err();
        assert!(matches!(error, ProcessError::Cancelled));
        let pid = read_pid(&marker);
        assert_process_gone(pid);
        let _ = std::fs::remove_file(marker);
    }

    #[test]
    fn timeout_kills_grandchildren() {
        let marker = temp_marker("grandchild");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("sleep 30 & echo $! > {}; wait", marker.display()));
        let error = run_limited(
            command,
            Instant::now() + Duration::from_millis(150),
            1024,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ProcessError::Timeout));
        let pid = read_pid(&marker);
        assert_process_gone(pid);
        let _ = std::fs::remove_file(marker);
    }

    #[test]
    fn lingering_descendant_does_not_block_pipe_readers() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 30 & exit 0");
        let started = Instant::now();
        let result = run_limited(command, Instant::now() + Duration::from_secs(2), 1024, None);
        assert!(result.is_ok(), "child exit should stay bounded");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "pipe drain exceeded the budget"
        );
    }

    fn temp_marker(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pathtrial-{label}-{}-{nanos}", std::process::id()))
    }

    fn read_pid(path: &std::path::Path) -> u32 {
        for _ in 0..40 {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(pid) = text.trim().parse() {
                    return pid;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("child did not record its pid");
    }

    fn assert_process_gone(pid: u32) {
        for _ in 0..40 {
            #[cfg(unix)]
            unsafe {
                if libc::kill(pid as i32, 0) != 0 {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("process {pid} survived cleanup");
    }
}
