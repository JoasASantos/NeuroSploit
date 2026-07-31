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
    // --- attack-graph / kill-chain mapping (best-effort, optional) ---
    /// OWASP Top 10 category, e.g. "A03:2021-Injection".
    #[serde(default)]
    pub owasp: String,
    /// MITRE ATT&CK technique id, e.g. "T1190".
    #[serde(default)]
    pub mitre: String,
    /// Kill-chain stage: recon|initial-access|execution|privesc|lateral|exfil|impact.
    #[serde(default)]
    pub stage: String,
    /// Exploitability: trivial|moderate|hard.
    #[serde(default)]
    pub exploitability: String,
    /// Business impact, one line.
    #[serde(default)]
    pub business_impact: String,
    /// IDs of findings this one chains from (attack-path edges).
    #[serde(default)]
    pub chains_from: Vec<String>,
    /// Auth context in which this was proven: "authenticated" | "unauthenticated"
    /// | "" (unknown). Lets a report distinguish pre- and post-login findings —
    /// important in grey/black-box where the agent self-registered to test.
    #[serde(default)]
    pub auth_context: String,
    /// The test account/role used to prove this finding (e.g. "user1 · nrsplt_x@example.test"
    /// or "admin"). Empty when the finding needed no account.
    #[serde(default)]
    pub account: String,
    /// A credential generated during the run (password/token) for a created test
    /// account. Captured here transiently, moved to the run's vault, and MASKED in
    /// the human report. Only set on "test account created" capability findings.
    #[serde(default)]
    pub secret: String,
    /// Human-in-the-loop triage state: "confirmed" (passed vote + grounding +
    /// refute), "needs-review" (uncertain — partial vote, ungrounded, or refuted:
    /// KEPT and flagged for a human instead of silently dropped), or "" (unset).
    #[serde(default)]
    pub review_status: String,
    /// Why it needs review, when `review_status == "needs-review"` (e.g.
    /// "below vote quorum", "no receipt", "failed adversarial refute").
    #[serde(default)]
    pub review_reason: String,
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
            owasp: String::new(),
            mitre: String::new(),
            stage: String::new(),
            exploitability: String::new(),
            business_impact: String::new(),
            chains_from: Vec::new(),
            auth_context: String::new(),
            account: String::new(),
            secret: String::new(),
            review_status: String::new(),
            review_reason: String::new(),
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
    /// Directory to persist run artifacts (recon/exploit/findings json+md).
    #[serde(default)]
    pub workdir: Option<String>,
    /// Path to the RL reward state file.
    #[serde(default)]
    pub rl_path: Option<String>,
    /// Verbose: log each agent as it launches, recon snippet, and votes.
    #[serde(default)]
    pub verbose: bool,
    /// Free-text instructions from the operator that steer agent selection and
    /// execution (e.g. "focus on injection and broken access control").
    #[serde(default)]
    pub instructions: Option<String>,
    /// Engagement objective / rules-of-engagement context: WHY this test is run
    /// and WHAT matters (e.g. "pre-launch review of the checkout flow; prove any
    /// path to unauthorized order access"). Prepended to prompts as high-priority
    /// context so agents understand the goal, not just the surface.
    #[serde(default)]
    pub objective: Option<String>,
    /// Explicit out-of-scope exclusions the agents MUST NOT touch (e.g. hosts,
    /// paths, techniques, or actions). Rendered as a hard constraint in every
    /// recon/exploit prompt. Optional; empty means "nothing excluded".
    #[serde(default)]
    pub out_of_scope: Option<String>,
    /// Authentication material to use against the target so agents test as an
    /// authenticated user (e.g. "Authorization: Bearer <jwt>" or "Cookie: session=...").
    #[serde(default)]
    pub auth: Option<String>,
    /// Greybox: a source repository to review alongside the live `target` URL.
    #[serde(default)]
    pub repo: Option<String>,
    /// Explicit agent allowlist. When non-empty, the pipeline runs exactly these
    /// agents (skipping recon-based selection) — used by the category picker.
    #[serde(default)]
    pub pinned: Vec<String>,
    /// Attack-chaining depth: how many post-exploitation pivot rounds to run
    /// from confirmed findings (0 disables chaining). Each round expands the
    /// newest footholds in new directions, carrying discovered loot forward.
    #[serde(default = "default_chain_depth")]
    pub chain_depth: usize,
    /// Optional local intercepting proxy (Burp/ZAP), e.g. http://127.0.0.1:8080.
    /// When set, agents route HTTP through it so the operator can inspect/replay
    /// traffic in Burp Suite.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Custom User-Agent for identifying NeuroSploit traffic (attribution).
    /// Defaults to the NeuroSploit UA when unset.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Recon intensity (1=quick, 2=standard, 3=deep, 4=exhaustive). Higher =
    /// more recon rounds, more active enumeration, and auto-installing tools.
    #[serde(default = "default_recon")]
    pub recon_intensity: usize,
    /// Opt-in: when the app requires email confirmation to register, allow the
    /// agent to use a free disposable-inbox API (mail.tm) to read the code/link.
    /// Off by default. Account creation is still capped by the safety guardrail.
    #[serde(default)]
    pub temp_email: bool,
    /// Directory for the credential vault (created test-account secrets). Set by
    /// the app to `<cwd>/.neurosploit/vault`; falls back to the run workdir.
    #[serde(default)]
    pub vault_dir: Option<String>,
}

fn default_vote() -> usize {
    3
}

fn default_recon() -> usize {
    3
}

fn default_chain_depth() -> usize {
    2
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
            workdir: None,
            rl_path: None,
            verbose: false,
            instructions: None,
            objective: None,
            out_of_scope: None,
            auth: None,
            repo: None,
            pinned: Vec::new(),
            chain_depth: 2,
            proxy: None,
            user_agent: None,
            recon_intensity: 3,
            temp_email: false,
            vault_dir: None,
        }
    }
}
