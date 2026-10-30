//! Local config and data directories.
//!
//! These paths are for opt-in files the user creates. PathTrial does not create
//! an allowlist on its own, and it does not upload either directory.

use std::path::PathBuf;

pub fn allow_targets_file() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("pathtrial").join("allow-targets"))
}

pub fn baseline_dir() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("pathtrial").join("baselines"))
}

fn config_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Some(path) = env_path("APPDATA") {
            return Ok(path);
        }
        home().map(|path| path.join("AppData").join("Roaming"))
    }
    #[cfg(not(windows))]
    {
        if let Some(path) = env_path("XDG_CONFIG_HOME") {
            return Ok(path);
        }
        home().map(|path| path.join(".config"))
    }
}

fn data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Some(path) = env_path("LOCALAPPDATA") {
            return Ok(path);
        }
        home().map(|path| path.join("AppData").join("Local"))
    }
    #[cfg(not(windows))]
    {
        if let Some(path) = env_path("XDG_DATA_HOME") {
            return Ok(path);
        }
        home().map(|path| path.join(".local").join("share"))
    }
}

fn home() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    env_path(key).ok_or_else(|| format!("cannot locate a home directory; set {key}"))
}

fn env_path(key: &str) -> Option<PathBuf> {
    let value = std::env::var_os(key)?;
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}
