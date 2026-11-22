//! Universal completion cache — spend a token once.
//!
//! Agents ask the same questions constantly: the same recon page, the same
//! validator prompt, the same "is this reflected?" follow-up across chain
//! rounds and across runs of the same target. Each repeat costs money and time
//! and returns the same answer. This cache keys a completion by the exact
//! (provider, model, backend, system, user, output-budget, temperature) tuple
//! and serves it from memory, then from disk.
//!
//! Safety properties:
//!
//! - **Content-addressed, never fuzzy.** A near-match is not a cache hit; an
//!   agent's prompt is its context, and a stale answer to a different prompt is
//!   worse than paying again.
//! - **Scoped to a project.** `NEUROSPLOIT_CACHE_SCOPE` (default: the working
//!   directory) namespaces the store, so two engagements never share answers.
//! - **Bounded and expirable.** `NEUROSPLOIT_CACHE_TTL_SECS` (default 7 days)
//!   and `NEUROSPLOIT_CACHE=off` to disable. Entries are small JSON files;
//!   deleting the directory is always safe.
//! - **Does not mask failures.** Only successful completions are stored.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct Entry {
    created: u64,
    model: String,
    text: String,
}

fn mem() -> &'static Mutex<HashMap<String, String>> {
    static M: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn enabled() -> bool {
    !matches!(
        std::env::var("NEUROSPLOIT_CACHE").ok().as_deref().map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("0") | Some("false") | Some("off") | Some("no")
    )
}

fn ttl_secs() -> u64 {
    std::env::var("NEUROSPLOIT_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(7 * 24 * 3600)
}

fn root() -> PathBuf {
    let scope = std::env::var("NEUROSPLOIT_CACHE_SCOPE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    scope.join(".neurosploit").join("cache").join("llm")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Stable key for one completion request.
pub fn key(provider: &str, model: &str, cli: bool, system: &str, user: &str) -> String {
    let budget = std::env::var("NEUROSPLOIT_MAX_TOKENS").unwrap_or_default();
    let temp = std::env::var("NEUROSPLOIT_TEMPERATURE").unwrap_or_default();
    let mut h = Sha256::new();
    for part in [provider, model, if cli { "cli" } else { "api" }, &budget, &temp] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    h.update(system.as_bytes());
    h.update([0u8]);
    h.update(user.as_bytes());
    format!("{:x}", h.finalize())
}

pub fn get(k: &str) -> Option<String> {
    if !enabled() {
        return None;
    }
    if let Ok(m) = mem().lock() {
        if let Some(v) = m.get(k) {
            return Some(v.clone());
        }
    }
    let path = path_for(k);
    let text = std::fs::read_to_string(&path).ok()?;
    let entry: Entry = serde_json::from_str(&text).ok()?;
    if now().saturating_sub(entry.created) > ttl_secs() {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    if let Ok(mut m) = mem().lock() {
        m.insert(k.to_string(), entry.text.clone());
        if m.len() > 4096 {
            m.clear();
        }
    }
    Some(entry.text)
}

pub fn put(k: &str, model: &str, text: &str) {
    if !enabled() || text.is_empty() {
        return;
    }
    if let Ok(mut m) = mem().lock() {
        if m.len() > 4096 {
            m.clear();
        }
        m.insert(k.to_string(), text.to_string());
    }
    let path = path_for(k);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let entry = Entry { created: now(), model: model.to_string(), text: text.to_string() };
    if let Ok(json) = serde_json::to_string(&entry) {
        let _ = std::fs::write(path, json);
    }
}

fn path_for(k: &str) -> PathBuf {
    let shard = &k[..2.min(k.len())];
    root().join(shard).join(format!("{k}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_and_sensitive_to_every_input() {
        let a = key("p", "m", false, "sys", "user");
        assert_eq!(a, key("p", "m", false, "sys", "user"));
        assert_ne!(a, key("p", "m", true, "sys", "user"));
        assert_ne!(a, key("p", "m2", false, "sys", "user"));
        assert_ne!(a, key("p", "m", false, "sys", "other"));
    }

    #[test]
    fn roundtrips_in_memory() {
        std::env::set_var("NEUROSPLOIT_CACHE", "on");
        let k = key("test", "roundtrip", false, "s", "u");
        put(&k, "test", "hello");
        assert_eq!(get(&k).as_deref(), Some("hello"));
    }
}
