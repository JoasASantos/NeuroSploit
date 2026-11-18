use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{now_ms, EVENT_CAP, STATE_VERSION};

/// Operator authorization and guardrails. Persisted so every restarted daemon
/// enforces the same boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Policy {
    pub enabled: bool,
    /// Free-text reference to the engagement authorization (SOW / ticket /
    /// bug-bounty URL). Required to enable.
    pub authorized_by: String,
    /// Prefer private/loopback targets. Public targets require an allow-list
    /// match or an explicit `allow_public_targets`.
    pub internal_only: bool,
    /// Explicit opt-in: `persist` tasks are accepted.
    pub allow_persistence: bool,
    /// Explicit opt-in: `upload` and `lateral` tasks are accepted.
    pub allow_lateral: bool,
    /// Explicit opt-in for public targets.
    pub allow_public_targets: bool,
    /// Hosts / domains explicitly authorized (exact, `*.dom` or `.dom`).
    pub allowed_hosts: Vec<String>,
    /// Per-command OPSEC deny-list (regex) for exec/lateral tasks.
    pub command_deny_regex: Vec<String>,
    pub max_sessions: usize,
}

impl Default for C2Policy {
    fn default() -> Self {
        Self {
            enabled: false,
            authorized_by: String::new(),
            internal_only: true,
            allow_persistence: false,
            allow_lateral: false,
            allow_public_targets: false,
            allowed_hosts: Vec::new(),
            command_deny_regex: Vec::new(),
            max_sessions: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub id: String,
    pub name: String,
    /// `http_beacon` is the built-in transport. String field so future
    /// transports do not break stored state.
    pub kind: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub callback_host: String,
    pub token: String,
    pub status: String,
    pub sleep_seconds: u32,
    pub jitter_percent: u32,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub last_error: Option<String>,
}

impl Listener {
    /// Public projection for the web console / API responses.
    pub fn safe(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "callback_host": self.callback_host,
            "status": self.status,
            "sleep_seconds": self.sleep_seconds,
            "jitter_percent": self.jitter_percent,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "last_error": self.last_error,
            "token_set": !self.token.is_empty(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub listener_id: String,
    pub implant_uuid: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: i64,
    pub process_name: String,
    pub is_admin: bool,
    pub internal_ip: String,
    pub status: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub sleep_seconds: u32,
    pub jitter_percent: u32,
    pub note: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub session_id: String,
    pub task_type: String,
    pub payload: Value,
    pub status: String,
    pub source: String,
    pub created_at: i64,
    pub sent_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub output: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebshellConnection {
    pub id: String,
    pub name: String,
    pub url: String,
    pub password: String,
    pub shell_type: String,
    pub method: String,
    pub cmd_param: String,
    pub pass_param: String,
    pub encoding: String,
    pub os: String,
    pub note: String,
    pub created_at: i64,
    pub last_seen: Option<i64>,
}

impl WebshellConnection {
    /// Password is never sent back over the API — only whether one is set.
    pub fn safe(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "shell_type": self.shell_type,
            "method": self.method,
            "cmd_param": self.cmd_param,
            "pass_param": self.pass_param,
            "encoding": self.encoding,
            "os": self.os,
            "note": self.note,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "password_set": !self.password.is_empty(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: i64,
    pub level: String,
    pub kind: String,
    pub message: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRecord {
    pub name: String,
    pub kind: String,
    pub created_at: i64,
    pub size: usize,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2State {
    pub version: u32,
    pub policy: C2Policy,
    pub listeners: Vec<Listener>,
    pub sessions: Vec<Session>,
    pub tasks: Vec<Task>,
    pub webshells: Vec<WebshellConnection>,
    pub events: Vec<Event>,
    pub payloads: Vec<PayloadRecord>,
}

impl Default for C2State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            policy: C2Policy::default(),
            listeners: Vec::new(),
            sessions: Vec::new(),
            tasks: Vec::new(),
            webshells: Vec::new(),
            events: Vec::new(),
            payloads: Vec::new(),
        }
    }
}

pub fn push_event(
    state: &mut C2State,
    level: &str,
    kind: &str,
    message: impl Into<String>,
    data: Value,
) {
    state.events.push(Event {
        ts: now_ms(),
        level: level.into(),
        kind: kind.into(),
        message: message.into(),
        data,
    });
    if state.events.len() > EVENT_CAP {
        let drop = state.events.len() - EVENT_CAP;
        state.events.drain(0..drop);
    }
}
