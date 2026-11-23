//! Curated MCP tool-server catalog.
//!
//! These are *templates* for common security MCP servers. They are merged into
//! the agent's `.mcp.json` only when the operator selects them (`--mcp` plus
//! `--mcp-server`, or `neurosploit tools mcp add`), so a normal run is
//! unchanged. Custom servers remain possible through `mcp.servers.json`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSpec {
    pub name: String,
    pub description: String,
    /// `stdio` (default) or `http`.
    #[serde(default = "stdio")]
    pub transport: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub url: String,
    /// Installer → package, same keys as the toolbox catalog.
    #[serde(default)]
    pub install: BTreeMap<String, String>,
    #[serde(default)]
    pub notes: String,
}

fn stdio() -> String {
    "stdio".into()
}

impl McpServerSpec {
    pub fn config(&self) -> Value {
        if self.transport == "http" {
            let mut v = json!({ "url": self.url, "transport": "http" });
            if !self.env.is_empty() {
                v["headers"] = json!(self.env);
            }
            return v;
        }
        let mut v = json!({ "command": self.command, "args": self.args });
        if !self.env.is_empty() {
            v["env"] = json!(self.env);
        }
        v
    }
}

pub fn all() -> Vec<McpServerSpec> {
    vec![
        McpServerSpec {
            name: "nmap".into(),
            description: "Nmap MCP server (gc-nmap-mcp): scan profiles, service detection, NSE.".into(),
            transport: "stdio".into(),
            command: "npx".into(),
            args: vec!["-y".into(), "gc-nmap-mcp".into()],
            env: BTreeMap::from([("NMAP_PATH".into(), nmap_path())]),
            url: String::new(),
            install: BTreeMap::from([("npm".into(), "gc-nmap-mcp".into())]),
            notes: "Requires Node 18+ and nmap on PATH. Alternative: mcp-nmap-server (Windows).".into(),
        },
        McpServerSpec {
            name: "kali".into(),
            description: "Kali Linux MCP server (kali-mcp): 80+ Kali tools over stdio/HTTP.".into(),
            transport: "stdio".into(),
            command: "kali-mcp".into(),
            args: vec![],
            env: BTreeMap::new(),
            url: String::new(),
            install: BTreeMap::from([("pipx".into(), "kali-mcp".into())]),
            notes: "Install with `pipx install kali-mcp`, or use the official Docker image. The Python package does not install the underlying Kali binaries.".into(),
        },
        McpServerSpec {
            name: "playwright".into(),
            description: "Playwright MCP: drive a real browser for JS-heavy targets.".into(),
            transport: "stdio".into(),
            command: "npx".into(),
            args: vec![
                "-y".into(),
                "@playwright/mcp@latest".into(),
                "--headless".into(),
                "--isolated".into(),
            ],
            env: BTreeMap::new(),
            url: String::new(),
            install: BTreeMap::from([("npm".into(), "@playwright/mcp".into())]),
            notes: "Run `npx playwright install chromium` once.".into(),
        },
        McpServerSpec {
            name: "burp".into(),
            description: "Burp Suite MCP / REST bridge for scanner and proxy history.".into(),
            transport: "http".into(),
            command: String::new(),
            args: vec![],
            env: BTreeMap::new(),
            url: "http://127.0.0.1:1337/v0.1".into(),
            install: BTreeMap::new(),
            notes: "Enable the Burp MCP/REST extension and adjust the URL/key in mcp.servers.json.".into(),
        },
        McpServerSpec {
            name: "turtlec2".into(),
            description: "TurtleC2 teamserver MCP: sessions, commands, listeners, tunnels, BOFs, workspace.".into(),
            transport: "stdio".into(),
            command: "uv".into(),
            args: vec![
                "--directory".into(),
                crate::mcp_profiles::turtlec2_dir(),
                "run".into(),
                "server.py".into(),
            ],
            env: BTreeMap::new(),
            url: String::new(),
            install: BTreeMap::new(),
            notes: "Needs uv + the TurtleC2-MCP-Server checkout with its .env (teamserver host/port/creds). Override the dir with TURTLEC2_MCP_DIR.".into(),
        },
        McpServerSpec {
            name: "rea".into(),
            description: "REA MCP: reverse engineering for mobile and native binaries.".into(),
            transport: "stdio".into(),
            command: "rea".into(),
            args: vec!["--mode".into(), "binary".into()],
            env: BTreeMap::new(),
            url: String::new(),
            install: BTreeMap::new(),
            notes: "Use --mode android / ios / binary in mcp.servers.json.".into(),
        },
        McpServerSpec {
            name: "neurosploit".into(),
            description: "NeuroSploit's own MCP tools (runs, findings, graphs, C2, toolbox).".into(),
            transport: "stdio".into(),
            command: std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "neurosploit".into()),
            args: vec!["mcp".into()],
            env: BTreeMap::new(),
            url: String::new(),
            install: BTreeMap::new(),
            notes: "Exposes C2/WebShell and toolbox tools to any MCP client.".into(),
        },
    ]
}

fn nmap_path() -> String {
    for p in ["/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"] {
        if Path::new(p).is_file() {
            return p.to_string();
        }
    }
    "nmap".into()
}

pub fn find(name: &str) -> Option<McpServerSpec> {
    all()
        .into_iter()
        .find(|s| s.name.eq_ignore_ascii_case(name.trim()))
}

/// Names selected by `NEUROSPLOIT_MCP_SERVERS` (comma/space separated).
pub fn selected_from_env() -> Vec<McpServerSpec> {
    let raw = std::env::var("NEUROSPLOIT_MCP_SERVERS").unwrap_or_default();
    let mut out = Vec::new();
    for name in raw.split([',', ';', ' ']).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some(spec) = find(name) {
            if !out.iter().any(|s: &McpServerSpec| s.name == spec.name) {
                out.push(spec);
            }
        }
    }
    out
}

/// Merge the selected catalog servers into an `mcpServers` object.
pub fn merge_selected(servers: &mut serde_json::Map<String, Value>) {
    for spec in selected_from_env() {
        servers.insert(spec.name.clone(), spec.config());
    }
}

pub fn servers_path(base: &Path) -> PathBuf {
    base.join("mcp.servers.json")
}

/// Add/update a catalog server in `mcp.servers.json` (the file the harness
/// merges into `.mcp.json` for every run in this checkout).
pub fn add_to_file(base: &Path, name: &str) -> Result<PathBuf, String> {
    let spec = find(name).ok_or_else(|| format!("unknown MCP server '{name}' (try `neurosploit tools mcp list`)"))?;
    let path = servers_path(base);
    let mut root = if path.exists() {
        serde_json::from_str::<Value>(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !root.is_object() {
        root = json!({});
    }
    let dst = root.as_object_mut().unwrap();
    // Accept both flat and {"mcpServers": {...}} files.
    let servers = if let Some(existing) = dst.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        existing
    } else {
        dst
    };
    servers.insert(spec.name.clone(), spec.config());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&root).unwrap_or_default())
        .map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn remove_from_file(base: &Path, name: &str) -> Result<bool, String> {
    let path = servers_path(base);
    if !path.exists() {
        return Ok(false);
    }
    let mut root = serde_json::from_str::<Value>(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let removed = if let Some(servers) = root.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        servers.remove(name).is_some()
    } else {
        root.as_object_mut().map(|o| o.remove(name).is_some()).unwrap_or(false)
    };
    if removed {
        std::fs::write(&path, serde_json::to_string_pretty(&root).unwrap_or_default())
            .map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_nmap_and_kali() {
        assert!(find("nmap").is_some());
        assert!(find("kali").is_some());
        let nmap = find("nmap").unwrap().config();
        assert_eq!(nmap["command"], "npx");
        assert!(nmap["args"].as_array().unwrap().iter().any(|v| v == "gc-nmap-mcp"));
    }

    #[test]
    fn add_and_remove_server_file() {
        let dir = std::env::temp_dir().join(format!(
            "ns_mcp_catalog_{}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        add_to_file(&dir, "nmap").unwrap();
        let text = std::fs::read_to_string(servers_path(&dir)).unwrap();
        assert!(text.contains("gc-nmap-mcp"));
        assert!(remove_from_file(&dir, "nmap").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
