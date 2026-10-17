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
    assert_eq!(manifest["version"], "0.1.0");
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
    assert_eq!(manifest["version"], "0.1.0");
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
    ] {
        assert_eq!(
            shared,
            files_under(&root().join(generated)),
            "{generated} differs from the authoritative shared skills"
        );
    }
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
}

#[test]
fn every_skill_has_name_and_description_frontmatter() {
    for skill in files_under(&root().join("plugins/shared/skills")) {
        if !skill.0.ends_with("SKILL.md") {
            continue;
        }
        let text = String::from_utf8(skill.1).expect("UTF-8 skill");
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
