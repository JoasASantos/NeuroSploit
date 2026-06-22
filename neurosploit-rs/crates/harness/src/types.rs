use serde::{Deserialize, Serialize};

/// A validated (or candidate) security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub agent: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub cwe: String,
    #[serde(default)]
    pub cvss: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub validated: bool,
    /// Per-model vote summary, e.g. "3/4 confirmed".
    #[serde(default)]
    pub votes: String,
}

impl Default for Finding {
    fn default() -> Self {
        Finding {
            id: String::new(),
            agent: String::new(),
            title: String::new(),
            severity: "Info".into(),
            cwe: String::new(),
            cvss: String::new(),
            endpoint: String::new(),
            payload: String::new(),
            evidence: String::new(),
            impact: String::new(),
            remediation: String::new(),
            confidence: 0.0,
            validated: false,
            votes: String::new(),
        }
    }
}

/// Configuration for a single engagement run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub target: String,
    /// Model references in `provider:model` form. The first is primary; the
    /// rest are failover candidates and also the voting panel.
    pub models: Vec<String>,
    /// Number of models that cross-check each candidate finding.
    #[serde(default = "default_vote")]
    pub vote_n: usize,
    /// Max concurrent model calls.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Cap on specialist agents to run (0 = all).
    #[serde(default)]
    pub max_agents: usize,
    /// Offline mode: exercise the full pipeline without calling any model API.
    #[serde(default)]
    pub offline: bool,
    /// Use local agentic CLI subscriptions (Claude Code / Codex / Grok) instead
    /// of HTTP API keys.
    #[serde(default)]
    pub subscription: bool,
}

fn default_vote() -> usize {
    3
}
fn default_concurrency() -> usize {
    8
}

impl RunConfig {
    pub fn new(target: impl Into<String>) -> Self {
        RunConfig {
            target: target.into(),
            models: vec!["anthropic:claude-opus-4-8".into()],
            vote_n: 3,
            concurrency: 8,
            max_agents: 0,
            offline: false,
            subscription: false,
        }
    }
}
