//! MCP target allowlist loading.
//!
//! Rules come from `--allow-target`, `PATHTRIAL_MCP_ALLOW_TARGETS`, and an
//! optional local file. The file is how a desktop client can authorize targets
//! without inheriting a shell environment and without editing a marketplace
//! cache. Missing files stay default-deny. Wildcards and CIDR prefixes are
//! rejected.

use std::path::{Path, PathBuf};

use crate::cli::McpArgs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedAllow {
    pub rules: Vec<AllowRule>,
    pub file_loaded: bool,
}

pub fn load_for_mcp(args: &McpArgs) -> Result<LoadedAllow, String> {
    let mut rules = Vec::new();
    for value in &args.allow_target {
        push_token(&mut rules, value)?;
    }
    if let Ok(env) = std::env::var("PATHTRIAL_MCP_ALLOW_TARGETS") {
        for value in env.split(',').flat_map(str::split_whitespace) {
            push_token(&mut rules, value)?;
        }
    }
    let file = allow_file_path(args)?;
    let file_loaded = if let Some(path) = file {
        let text = read_allow_file(&path)?;
        for rule in parse_allow_file(&text)? {
            rules.push(rule);
        }
        true
    } else {
        false
    };
    Ok(LoadedAllow { rules, file_loaded })
}

pub fn path_to_print(args: &McpArgs) -> Result<PathBuf, String> {
    if let Some(path) = &args.allow_file {
        return Ok(path.clone());
    }
    if let Ok(value) = std::env::var("PATHTRIAL_MCP_ALLOW_FILE") {
        let value = value.trim();
        if !value.is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    crate::paths::allow_targets_file()
}

fn allow_file_path(args: &McpArgs) -> Result<Option<PathBuf>, String> {
    if let Some(path) = &args.allow_file {
        if !path.is_file() {
            return Err(format!("allow file {} does not exist", path.display()));
        }
        return Ok(Some(path.clone()));
    }
    if let Ok(value) = std::env::var("PATHTRIAL_MCP_ALLOW_FILE") {
        let value = value.trim();
        if !value.is_empty() {
            let path = PathBuf::from(value);
            if !path.is_file() {
                return Err(format!(
                    "PATHTRIAL_MCP_ALLOW_FILE {} does not exist",
                    path.display()
                ));
            }
            return Ok(Some(path));
        }
    }
    match crate::paths::allow_targets_file() {
        Ok(path) if path.is_file() => Ok(Some(path)),
        _ => Ok(None),
    }
}

pub fn read_allow_file(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|error| format!("read allow file {}: {error}", path.display()))?;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "allow file {} is writable by group or others; refusing to load it",
                path.display()
            ));
        }
    }
    std::fs::read_to_string(path)
        .map_err(|error| format!("read allow file {}: {error}", path.display()))
}

pub fn parse_allow_file(text: &str) -> Result<Vec<AllowRule>, String> {
    let mut rules = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains(',') {
            return Err(format!(
                "allow file line {} contains a comma; put one explicit target on each line",
                index + 1
            ));
        }
        push_token(&mut rules, line)
            .map_err(|error| format!("allow file line {}: {error}", index + 1))?;
    }
    Ok(rules)
}

fn push_token(rules: &mut Vec<AllowRule>, value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    reject_wildcard(value)?;
    let (host, port) = split_host_port(value)?;
    if host.is_empty() || host.contains('*') || host.contains('/') {
        return Err(format!("invalid allow rule {value}"));
    }
    rules.push(AllowRule {
        host: normalize_host(&host),
        port,
    });
    Ok(())
}

fn reject_wildcard(value: &str) -> Result<(), String> {
    if value.contains('*') || value.contains('/') {
        return Err(
            "wildcard and CIDR target authorization are not supported; use an explicit host or IP"
                .to_string(),
        );
    }
    Ok(())
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 allow rule {value}"))?;
        let port = if let Some(port) = tail.strip_prefix(':') {
            Some(
                port.parse::<u16>()
                    .map_err(|_| format!("invalid port in allow rule {value}"))?,
            )
        } else if tail.is_empty() {
            None
        } else {
            return Err(format!("invalid allow rule {value}"));
        };
        return Ok((host.to_string(), port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((
            host.to_string(),
            Some(
                port.parse::<u16>()
                    .map_err(|_| format!("invalid port in allow rule {value}"))?,
            ),
        )),
        Some(_) => Ok((value.to_string(), None)),
        None => Ok((value.to_string(), None)),
    }
}

pub(crate) fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_accepts_comments_and_exact_targets() {
        let rules =
            parse_allow_file("# comment\n\nexample.com:443\n203.0.113.10:22\n[2001:db8::1]:443\n")
                .unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].host, "example.com");
        assert_eq!(rules[0].port, Some(443));
        assert_eq!(rules[2].host, "2001:db8::1");
    }

    #[test]
    fn file_rejects_wildcards_cidr_and_commas() {
        assert!(parse_allow_file("*\n").is_err());
        assert!(parse_allow_file("*.example.com:443\n").is_err());
        assert!(parse_allow_file("10.0.0.0/8\n").is_err());
        assert!(parse_allow_file("example.com:443, other.example:443\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_allow_file_is_refused() {
        let path = std::env::temp_dir().join(format!(
            "pathtrial-allow-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "example.com:443\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = read_allow_file(&path).unwrap_err();
        assert!(error.contains("writable"), "{error}");
        let _ = std::fs::remove_file(path);
    }
}
