//! Structural checks for the Codex and Claude Code plugin packages.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    });
    serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("parse {}: {error}", path.display());
    })
}

fn files_under(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(base: &Path, current: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(base, &path, out);
            } else {
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.insert(relative, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(path, path, &mut out);
    out
}

#[test]
fn codex_manifest_matches_package_and_mcp() {
    let plugin = root().join("plugins/codex/pathtrial");
    let manifest = read_json(&plugin.join("plugin.json"));
    assert_eq!(manifest["name"], "pathtrial");
    assert_eq!(manifest["version"], "0.4.0");
    assert_eq!(
        manifest["extensions"]["com.openai"]["interface"]["displayName"],
        "PathTrial Network Diagnostics"
    );
    let onboarding = manifest["extensions"]["com.openai"]["onboardingSkill"]
        .as_str()
        .expect("onboarding skill");
    assert!(plugin.join(onboarding.trim_start_matches("./")).exists());

    let mcp = read_json(&plugin.join("mcp.json"));
    assert_eq!(mcp["mcpServers"]["pathtrial"]["type"], "stdio");
    assert_eq!(mcp["mcpServers"]["pathtrial"]["command"], "pathtrial");
    assert_eq!(mcp["mcpServers"]["pathtrial"]["args"][0], "mcp");
    for skill in [
        "network-diagnostics",
        "ipv4-ipv6-comparison",
        "explain-report",
        "setup",
    ] {
        assert!(
            plugin.join("skills").join(skill).join("SKILL.md").exists(),
            "missing Codex skill {skill}"
        );
    }
}

#[test]
fn claude_manifest_matches_package_and_mcp() {
    let plugin = root().join("plugins/claude-code/pathtrial");
    let manifest = read_json(&plugin.join(".claude-plugin/plugin.json"));
    assert_eq!(manifest["name"], "pathtrial");
    assert_eq!(manifest["version"], "0.4.0");
    let mcp = read_json(&plugin.join(".mcp.json"));
    assert_eq!(mcp["mcpServers"]["pathtrial"]["command"], "pathtrial");
    assert_eq!(mcp["mcpServers"]["pathtrial"]["args"][0], "mcp");
    for skill in [
        "network-diagnostics",
        "ipv4-ipv6-comparison",
        "explain-report",
        "setup",
    ] {
        assert!(
            plugin.join("skills").join(skill).join("SKILL.md").exists(),
            "missing Claude Code skill {skill}"
        );
    }
}

#[test]
fn shared_skills_match_both_generated_copies() {
    let shared = files_under(&root().join("plugins/shared/skills"));
    assert_eq!(shared.len(), 4);
    for generated in [
        "plugins/codex/pathtrial/skills",
        "plugins/claude-code/pathtrial/skills",
        "plugins/cursor/pathtrial/skills",
    ] {
        assert_eq!(
            shared,
            files_under(&root().join(generated)),
            "{generated} differs from the authoritative shared skills"
        );
    }
}

#[test]
fn diagnostic_skills_require_capabilities_allowlist_and_evidence() {
    let network =
        std::fs::read_to_string(root().join("plugins/shared/skills/network-diagnostics/SKILL.md"))
            .expect("network skill");
    assert!(network.contains("Call `pathtrial_capabilities` before any probe"));
    assert!(network.contains("classify the attempt as `FAIL`"));
    assert!(network.contains("Raw command output"));
    assert!(network.contains("pathtrial_fingerprint_diff"));

    let setup = std::fs::read_to_string(root().join("plugins/shared/skills/setup/SKILL.md"))
        .expect("setup skill");
    assert!(setup.contains("Call `pathtrial_capabilities` first"));
    assert!(setup.contains("exact target allowlist"));
}

#[test]
fn marketplaces_point_to_existing_plugin_directories() {
    let codex = read_json(&root().join(".agents/plugins/marketplace.json"));
    assert_eq!(codex["name"], "pathtrial");
    assert_eq!(
        codex["plugins"][0]["source"]["path"],
        "./plugins/codex/pathtrial"
    );
    assert!(root()
        .join("plugins/codex/pathtrial")
        .join("plugin.json")
        .exists());

    let claude = read_json(&root().join(".claude-plugin/marketplace.json"));
    assert_eq!(claude["name"], "pathtrial");
    assert_eq!(
        claude["plugins"][0]["source"],
        "./plugins/claude-code/pathtrial"
    );
    assert!(root()
        .join("plugins/claude-code/pathtrial")
        .join(".claude-plugin/plugin.json")
        .exists());

    let cursor = read_json(&root().join(".cursor-plugin/marketplace.json"));
    assert_eq!(cursor["name"], "pathtrial");
    assert_eq!(cursor["metadata"]["pluginRoot"], "plugins/cursor");
    assert_eq!(cursor["plugins"][0]["source"], "pathtrial");
    assert!(root()
        .join("plugins/cursor/pathtrial")
        .join(".cursor-plugin/plugin.json")
        .exists());
}

#[test]
fn cursor_package_keeps_default_deny_mcp_and_rule() {
    let plugin = root().join("plugins/cursor/pathtrial");
    let manifest = read_json(&plugin.join(".cursor-plugin/plugin.json"));
    assert_eq!(manifest["name"], "pathtrial");
    assert_eq!(manifest["version"], "0.4.0");
    assert!(manifest.get("mcpServers").is_none());

    let mcp = read_json(&plugin.join("mcp.json"));
    let server = &mcp["mcpServers"]["pathtrial"];
    assert_eq!(server["type"], "stdio");
    assert_eq!(server["command"], "pathtrial");
    assert_eq!(server["args"].as_array().map(Vec::len), Some(1));
    assert_eq!(server["args"][0], "mcp");
    let serialized = serde_json::to_string(&mcp).unwrap();
    assert!(!serialized.contains("allow-target"));
    assert!(!serialized.contains('*'));

    let rule = std::fs::read_to_string(plugin.join("rules/pathtrial-evidence.mdc")).unwrap();
    let rule = rule.replace("\r\n", "\n");
    assert!(rule.starts_with("---\n"), "Cursor rule lacks frontmatter");
    assert!(rule.contains("alwaysApply: false"));
    assert!(rule.contains("allow-targets"));
    for skill in [
        "network-diagnostics",
        "ipv4-ipv6-comparison",
        "explain-report",
        "setup",
    ] {
        assert!(plugin.join("skills").join(skill).join("SKILL.md").exists());
    }
}

#[cfg(unix)]
#[test]
fn cursor_install_script_merges_stdio_server_without_allowlist() {
    let python = ["python3", "python"]
        .into_iter()
        .find(|name| {
            std::process::Command::new(name)
                .arg("--version")
                .output()
                .is_ok()
        })
        .expect("python3 or python");
    let dir = std::env::temp_dir().join(format!(
        "pathtrial-cursor-mcp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let script = root().join("scripts/install-cursor-mcp.sh");
    let first = std::process::Command::new("sh")
        .arg(&script)
        .arg(&dir)
        .output()
        .expect("run installer");
    assert!(
        first.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let path = dir.join(".cursor/mcp.json");
    let value = read_json(&path);
    assert_eq!(value["mcpServers"]["pathtrial"]["args"][0], "mcp");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("allow-target"));
    assert!(!text.contains('*'));

    let again = std::process::Command::new("sh")
        .arg(&script)
        .arg(&dir)
        .output()
        .expect("rerun installer");
    assert!(again.status.success());
    let _ = python;
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn every_skill_has_name_and_description_frontmatter() {
    for skill in files_under(&root().join("plugins/shared/skills")) {
        if !skill.0.ends_with("SKILL.md") {
            continue;
        }
        let text = String::from_utf8(skill.1).expect("UTF-8 skill");
        // Windows checkouts may use CRLF. The frontmatter marker is still `---`.
        let text = text.replace("\r\n", "\n");
        assert!(text.starts_with("---\n"), "{} lacks frontmatter", skill.0);
        let frontmatter = text.split("---").nth(1).unwrap_or_default();
        assert!(frontmatter.contains("name:"), "{} lacks name", skill.0);
        assert!(
            frontmatter.contains("description:"),
            "{} lacks description",
            skill.0
        );
    }
}
