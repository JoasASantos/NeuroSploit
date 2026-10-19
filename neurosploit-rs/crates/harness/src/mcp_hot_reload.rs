use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Watches `mcp.servers.json` for changes and rewrites `.mcp.json` so the
/// next agent spawn picks up newly added (or removed) MCP servers mid-run.
///
/// Each agent gets a fresh CLI subprocess that reads `.mcp.json` from disk,
/// so rewriting the file is enough — no in-process state needs updating.
pub struct McpReloader {
    config_dir: PathBuf,
    watch_path: PathBuf,
    last_mtime: AtomicU64,
    generation: Arc<AtomicU64>,
}

impl McpReloader {
    pub fn new(config_dir: PathBuf, watch_path: PathBuf) -> Self {
        let mtime = file_mtime(&watch_path).unwrap_or(0);
        Self {
            config_dir,
            watch_path,
            last_mtime: AtomicU64::new(mtime),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Spawn a background polling task that checks `mcp.servers.json` every
    /// 3 seconds. When the file changes (or appears for the first time),
    /// `.mcp.json` is rewritten so subsequent agents pick up the new servers.
    pub fn spawn(
        self: Arc<Self>,
        progress: Option<tokio::sync::mpsc::Sender<String>>,
        cancel: Arc<std::sync::atomic::AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let current = file_mtime(&self.watch_path).unwrap_or(0);
                let prev = self.last_mtime.load(Ordering::Relaxed);
                if current != prev && current != 0 {
                    self.last_mtime.store(current, Ordering::Relaxed);
                    match self.reload() {
                        Ok(servers) => {
                            let gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
                            if let Some(tx) = &progress {
                                let _ = tx.send(format!(
                                    "notify: 🔌 MCP hot-reload (gen {gen}): reloaded {servers} server(s) from {}",
                                    self.watch_path.display()
                                )).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = &progress {
                                let _ = tx.send(format!(
                                    "notify: ⚠ MCP hot-reload failed: {e}"
                                )).await;
                            }
                        }
                    }
                }
            }
        })
    }

    /// Rewrite `.mcp.json` with current contents of `mcp.servers.json`.
    /// Returns the number of MCP servers in the resulting config.
    fn reload(&self) -> anyhow::Result<usize> {
        let extra = if self.watch_path.exists() {
            Some(self.watch_path.as_path())
        } else {
            None
        };
        crate::models::write_mcp_config(&self.config_dir, extra)?;
        let count = server_count(&self.config_dir.join(".mcp.json"));
        Ok(count)
    }
}

fn file_mtime(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn server_count(mcp_json: &Path) -> usize {
    let Ok(txt) = std::fs::read_to_string(mcp_json) else { return 0 };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) else { return 0 };
    v.get("mcpServers")
        .and_then(|s| s.as_object())
        .map(|o| o.len())
        .unwrap_or(0)
}

/// Convenience: add a single MCP server to `mcp.servers.json` at runtime
/// (e.g. from a REPL command). Creates the file if it doesn't exist.
pub fn add_server(
    servers_path: &Path,
    name: &str,
    command: &str,
    args: &[&str],
) -> anyhow::Result<()> {
    let mut obj = if servers_path.exists() {
        let txt = std::fs::read_to_string(servers_path)?;
        serde_json::from_str::<serde_json::Value>(&txt)
            .unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let servers = obj
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("mcp.servers.json is not a JSON object"))?;

    servers.insert(
        name.to_string(),
        serde_json::json!({ "command": command, "args": args }),
    );

    if let Some(parent) = servers_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(servers_path, serde_json::to_string_pretty(&obj)?)?;
    Ok(())
}

/// Remove a server from `mcp.servers.json`.
pub fn remove_server(servers_path: &Path, name: &str) -> anyhow::Result<bool> {
    if !servers_path.exists() {
        return Ok(false);
    }
    let txt = std::fs::read_to_string(servers_path)?;
    let mut obj: serde_json::Value = serde_json::from_str(&txt)?;
    let removed = obj
        .as_object_mut()
        .map(|o| o.remove(name).is_some())
        .unwrap_or(false);
    if removed {
        std::fs::write(servers_path, serde_json::to_string_pretty(&obj)?)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(suffix: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ns_mcp_test_{}_{suffix}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn add_and_remove_server() {
        let dir = test_dir("add_rm");
        let path = dir.join("mcp.servers.json");
        add_server(&path, "test-server", "node", &["server.js"]).unwrap();
        let txt = std::fs::read_to_string(&path).unwrap();
        assert!(txt.contains("test-server"));
        assert!(txt.contains("node"));
        assert!(remove_server(&path, "test-server").unwrap());
        let txt2 = std::fs::read_to_string(&path).unwrap();
        assert!(!txt2.contains("test-server"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_mtime_works() {
        let dir = test_dir("mtime");
        let path = dir.join("test_mtime.json");
        assert!(file_mtime(&path).is_none());
        std::fs::write(&path, b"{}").unwrap();
        assert!(file_mtime(&path).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_count_empty() {
        let path = std::env::temp_dir().join("ns_nonexistent_12345.json");
        assert_eq!(server_count(&path), 0);
    }
}
