//! Command & Control (C2) and WebShell management.
//!
//! Opt-in, auditable post-exploitation tooling for **authorized internal
//! network engagements**, modelled on the C2 surface of CyberStrikeAI
//! (listener → session → task → payload) and its WebShell manager (saved
//! connections, command exec, file operations).
//!
//! Safety model:
//!  * disabled by default; enabling requires an authorization reference;
//!  * WebShell targets must resolve to private/loopback space unless the host
//!    is explicitly allow-listed;
//!  * persistence and lateral-movement task types require their own opt-in;
//!  * every mutation is appended to `<dir>/audit.jsonl`;
//!  * state and payloads are written with 0600 permissions.
//!
//! The CLI/MCP/REPL/web console all drive the same local control daemon, so
//! there is exactly one implementation of listener sockets, sessions and
//! tasks.

mod client;
mod daemon;
mod http;
mod manager;
mod store;
mod templates;
mod types;

pub use client::{control_request, ensure_daemon};
pub use daemon::run_daemon;
pub use manager::C2Manager;
pub use types::{
    C2Policy, C2State, Event, Listener, PayloadRecord, Session, Task, WebshellConnection,
};

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use sha2::{Digest, Sha256};

pub(crate) const STATE_VERSION: u32 = 1;
pub(crate) const EVENT_CAP: usize = 1000;
pub(crate) const TASK_CAP: usize = 5000;
pub(crate) const OUTPUT_CAP: usize = 128 * 1024;
pub(crate) const BODY_CAP: usize = 32 * 1024 * 1024;
pub(crate) const BEACON_PULL_LIMIT: usize = 16;

static ID_SEQ: AtomicU64 = AtomicU64::new(1);

/// Root directory for C2 state. Mirrors the console's `.neurosploit/` layout;
/// override with `NEUROSPLOIT_C2_DIR`.
pub fn c2_dir() -> PathBuf {
    if let Ok(p) = std::env::var("NEUROSPLOIT_C2_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".neurosploit")
        .join("c2")
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn new_id(prefix: &str) -> String {
    let n = ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}_{t:x}{n:x}")
}

pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    let mut ok = false;
    if let Ok(mut f) = File::open("/dev/urandom") {
        ok = f.read_exact(&mut bytes).is_ok();
    }
    if !ok {
        let mut h = Sha256::new();
        h.update(now_ms().to_le_bytes());
        h.update(std::process::id().to_le_bytes());
        h.update(ID_SEQ.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        let d = h.finalize();
        bytes[..32].copy_from_slice(&d[..32]);
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

pub(crate) fn clip(mut s: String) -> String {
    if s.len() > OUTPUT_CAP {
        s.truncate(OUTPUT_CAP);
        s.push_str("\n[truncated by NeuroSploit C2]");
    }
    s
}

/// Post-exploitation doctrine injected into agent prompts when `--c2` is on.
/// It explains the *available verbs* and the boundary, so the model plans
/// with the same guardrails the daemon enforces.
pub fn doctrine() -> &'static str {
    "C2 / POST-EXPLOITATION (authorized internal engagement, opt-in): a local \
NeuroSploit C2 daemon is available for this run. Use it only against hosts in \
scope and only on assets you own or are explicitly authorized to test.\n\
  • Inspect: `neurosploit c2 status --json`; sessions: `neurosploit c2 session list --json`.\n\
  • Remote command: `neurosploit c2 task exec --session <s_id> --command '<cmd>' --wait --json`.\n\
  • Persistence (only if allowed): `neurosploit c2 task persist --session <s_id> --method auto --wait --json`.\n\
  • Lateral movement (only if allowed): `neurosploit c2 task lateral --session <s_id> --command '<cmd>' --wait --json`;\n\
    reuse credentials/tokens already proven in the engagement, and verify every hop.\n\
  • Webshells: `neurosploit webshell add ...` then `neurosploit webshell exec --id <ws_id> --command '<cmd>' --json`.\n\
  • New listeners/payloads: `neurosploit c2 listener list --json`, `neurosploit c2 payload beacon --listener <l_id> --kind bash --json`.\n\
Rules: never touch out-of-scope hosts; never run destructive/DoS commands; persistence and \
lateral tasks fail unless the operator enabled them; report C2 actions as evidence (task id, \
session, output) in findings and the attack graph. Prefer the MCP tools (neurosploit_c2_*, \
neurosploit_webshell) when they are available; otherwise the CLI verbs above are equivalent."
}

/// A compact session snapshot for agent prompts. Returns an empty string when
/// C2 is disabled or unavailable — C2 must never break a normal run.
pub async fn agent_context() -> String {
    if std::env::var("NEUROSPLOIT_C2").ok().as_deref() != Some("1") {
        return String::new();
    }
    let status = match control_request("GET", "/api/status", None).await {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let enabled = status
        .pointer("/policy/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enabled {
        return String::new();
    }
    let sessions = status.get("sessions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let active: Vec<String> = sessions
        .iter()
        .filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("active"))
        .take(12)
        .map(|s| {
            format!(
                "- {} @ {} ({}/{}) user={} ip={} sleep={}s",
                s.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("hostname").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("os").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("arch").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("username").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("?"),
                s.get("sleep_seconds").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        })
        .collect();
    let webshells = status
        .get("webshells")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if active.is_empty() && webshells == 0 {
        format!("\n\nC2 STATUS: enabled, no active sessions yet.\n{}\n", doctrine())
    } else {
        format!(
            "\n\nC2 STATUS: enabled · {} active session(s) · {} webshell connection(s).\n{}\n{}\n",
            active.len(),
            webshells,
            active.join("\n"),
            doctrine()
        )
    }
}

/// CLI entrypoint used by `neurosploit run --c2 ...` to make the daemon and
/// policy match the operator's launch flags. Fails closed: a C2 run cannot
/// start without an authorization reference.
pub async fn bootstrap(
    authorization: &str,
    persistence: bool,
    lateral: bool,
    allow_public: bool,
) -> Result<C2Policy, String> {
    if authorization.trim().is_empty() {
        return Err(
            "--c2 requires an authorization reference: --c2-authorization \"SOW/ticket/URL\"".into(),
        );
    }
    let body = serde_json::json!({
        "authorization": authorization,
        "persistence": persistence,
        "lateral": lateral,
        "allow_public": allow_public,
    });
    let out = control_request("POST", "/api/enable", Some(body)).await?;
    let policy = out
        .get("policy")
        .cloned()
        .ok_or_else(|| "daemon did not return a policy".to_string())?;
    serde_json::from_value(policy).map_err(|e| format!("policy decode: {e}"))
}
