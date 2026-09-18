//! Scope policy guard — hard scope (authorization) and soft scope (guardrails).
//!
//! Before this module, scope existed only as a sentence in the prompt:
//! `out_of_scope` was rendered as "HARD CONSTRAINT — do NOT test…" and nothing
//! checked it. That is a *request*, not a control. An agent that decides a
//! discovered subdomain is interesting, or that follows a redirect off-target,
//! was free to act, and the operator found out by reading the report. In an
//! authorized engagement the boundary is the one thing that must not depend on
//! a model's cooperation.
//!
//! Two layers, because they answer different questions:
//!
//! - **Hard scope** — *are we allowed to touch this at all?* An allowlist of
//!   hosts, wildcards, IPv4 CIDRs and URL prefixes, plus exclusions that always
//!   win. Anything not matched is [`Decision::Deny`]. It defaults to the
//!   engagement's own target, so discovery can never silently widen the
//!   engagement: finding a host is not authorization to attack it.
//! - **Soft scope** — *we may touch it, but how?* Guardrails that shape
//!   behaviour inside authorized territory: read-only zones, destructive HTTP
//!   methods, account creation, request rate, and payload classes that are
//!   never acceptable (data destruction, DoS). These produce [`Decision::Warn`]
//!   where the action is merely discouraged and [`Decision::Deny`] where it is
//!   forbidden.
//!
//! The guard is deterministic and independent of the LLM: [`ScopePolicy::check`]
//! is called at the point of action (probe, validator replay, evidence
//! collection), and [`ScopePolicy::audit_findings`] runs afterwards so anything
//! that reached a host outside the boundary is quarantined instead of shipped
//! in a report.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

/// What an interaction intends to do. The same URL can be fine to look at and
/// forbidden to attack, so authorization is per (target, intent), never per
/// target alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Passive: read a page, resolve DNS, look at a response already captured.
    Observe,
    /// Active but non-mutating: fingerprinting, enumeration, a GET with a probe
    /// parameter.
    Probe,
    /// Sends a payload intended to prove a weakness.
    Exploit,
    /// Mutates or removes state: DELETE/PUT, account creation, file write.
    Destructive,
}

impl Action {
    fn rank(self) -> u8 {
        match self {
            Action::Observe => 0,
            Action::Probe => 1,
            Action::Exploit => 2,
            Action::Destructive => 3,
        }
    }
}

/// The guard's answer. `Warn` still permits the action — it is the honest
/// outcome for "allowed, but the operator should know", and collapsing it into
/// Allow or Deny would either hide the signal or block legitimate testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn(String),
    Deny(String),
}

impl Decision {
    pub fn allowed(&self) -> bool {
        !matches!(self, Decision::Deny(_))
    }
    pub fn reason(&self) -> &str {
        match self {
            Decision::Allow => "",
            Decision::Warn(r) | Decision::Deny(r) => r,
        }
    }
}

/// One scope entry. Written by the operator as text and parsed with
/// [`Pattern::parse`], so the config file, the CLI flag and the web form all
/// accept the same spellings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum Pattern {
    /// Exact host match, case-insensitive (`app.example.com`).
    Host(String),
    /// Wildcard host (`*.example.com`) — matches sub-domains, and the apex too.
    Wildcard(String),
    /// IPv4 network (`10.0.0.0/8`).
    Cidr { base: u32, bits: u8 },
    /// URL prefix (`https://example.com/api/v2`) — narrower than a whole host.
    UrlPrefix(String),
}

impl Pattern {
    pub fn parse(raw: &str) -> Option<Pattern> {
        let s = raw.trim().trim_end_matches('.').to_lowercase();
        if s.is_empty() {
            return None;
        }
        if s.contains("://") {
            return Some(Pattern::UrlPrefix(s.trim_end_matches('/').to_string()));
        }
        if let Some((net, bits)) = s.split_once('/') {
            if let (Some(base), Ok(bits)) = (ipv4_to_u32(net), bits.parse::<u8>()) {
                if bits <= 32 {
                    return Some(Pattern::Cidr { base: base & mask(bits), bits });
                }
            }
            // A "/" that isn't a CIDR is a path — treat the whole thing as a
            // host-relative prefix so `example.com/admin` works as written.
            return Some(Pattern::UrlPrefix(format!("https://{s}")));
        }
        if let Some(rest) = s.strip_prefix("*.") {
            return Some(Pattern::Wildcard(rest.to_string()));
        }
        Some(Pattern::Host(s))
    }

    pub fn matches(&self, url: &str) -> bool {
        let host = host_of(url);
        match self {
            Pattern::Host(h) => host == *h,
            Pattern::Wildcard(root) => host == *root || host.ends_with(&format!(".{root}")),
            Pattern::Cidr { base, bits } => ipv4_to_u32(&host).map(|ip| ip & mask(*bits) == *base).unwrap_or(false),
            Pattern::UrlPrefix(p) => {
                let n = normalize_url(url);
                let p = normalize_url(p);
                // Prefix on a path boundary: `/api` must not match `/apikeys`.
                n == p || n.starts_with(&format!("{p}/")) || n.starts_with(&format!("{p}?"))
            }
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            Pattern::Host(h) => h.clone(),
            Pattern::Wildcard(r) => format!("*.{r}"),
            Pattern::Cidr { base, bits } => format!("{}/{}", u32_to_ipv4(*base), bits),
            Pattern::UrlPrefix(p) => p.clone(),
        }
    }
}

fn mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits.min(32))
    }
}

fn ipv4_to_u32(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out: u32 = 0;
    for p in parts {
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        out = (out << 8) | n;
    }
    Some(out)
}

fn u32_to_ipv4(v: u32) -> String {
    format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255)
}

/// Host of a URL or bare authority, lowercased, without port or userinfo.
pub fn host_of(url: &str) -> String {
    let s = url.trim().to_lowercase();
    let s = s.split_once("://").map(|(_, r)| r).unwrap_or(&s);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    let s = s.rsplit_once('@').map(|(_, h)| h).unwrap_or(s);
    // IPv6 literals keep their brackets; for anything else a colon is a port.
    if s.starts_with('[') {
        return s.split(']').next().unwrap_or(s).trim_start_matches('[').to_string();
    }
    s.split(':').next().unwrap_or(s).trim_start_matches("www.").to_string()
}

fn normalize_url(url: &str) -> String {
    let s = url.trim().to_lowercase();
    let s = s.split_once("://").map(|(_, r)| r).unwrap_or(&s);
    s.trim_end_matches('/').trim_start_matches("www.").to_string()
}

/// Guardrails that apply *inside* authorized scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftScope {
    /// Hosts/prefixes that may be looked at but never attacked.
    #[serde(default)]
    pub observe_only: Vec<Pattern>,
    /// Allow DELETE/PUT/PATCH and other state-mutating verbs.
    #[serde(default)]
    pub allow_destructive_methods: bool,
    /// Allow the agent to register test accounts.
    #[serde(default = "yes")]
    pub allow_account_creation: bool,
    /// Cap on accounts created during the engagement (0 = unlimited).
    #[serde(default = "default_max_accounts")]
    pub max_accounts: u32,
    /// Requests per minute across the engagement (0 = unlimited).
    #[serde(default = "default_rate")]
    pub max_requests_per_minute: u32,
    /// Payload substrings that are never acceptable, whatever the finding.
    /// Defaults cover data destruction and resource exhaustion — the two
    /// classes that damage a production target rather than demonstrate a bug.
    #[serde(default = "default_forbidden_payloads")]
    pub forbidden_payloads: Vec<String>,
    /// Free-text notes from the operator, passed to prompts as context. Not
    /// enforceable — kept separate from the rules precisely so nobody mistakes
    /// prose for a control.
    #[serde(default)]
    pub notes: Vec<String>,
}

fn yes() -> bool {
    true
}
fn default_max_accounts() -> u32 {
    3
}
fn default_rate() -> u32 {
    240
}
fn default_forbidden_payloads() -> Vec<String> {
    [
        "drop table", "drop database", "truncate table", "delete from users",
        "rm -rf /", "mkfs", "shutdown -h", "format c:", ":(){:|:&};:",
        "while(true)", "sleep(100)", "benchmark(10000000",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for SoftScope {
    fn default() -> Self {
        SoftScope {
            observe_only: Vec::new(),
            allow_destructive_methods: false,
            allow_account_creation: true,
            max_accounts: default_max_accounts(),
            max_requests_per_minute: default_rate(),
            forbidden_payloads: default_forbidden_payloads(),
            notes: Vec::new(),
        }
    }
}

/// The engagement's authorization boundary plus its guardrails.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScopePolicy {
    /// Allowlist. Empty means "nothing is authorized" — see [`ScopePolicy::for_target`].
    #[serde(default)]
    pub hard: Vec<Pattern>,
    /// Exclusions. Always beat the allowlist.
    #[serde(default)]
    pub exclude: Vec<Pattern>,
    #[serde(default)]
    pub soft: SoftScope,
    /// Rolling request timestamps for the rate guard.
    #[serde(skip)]
    ledger: Mutex<VecDeque<std::time::Instant>>,
    #[serde(skip)]
    accounts: std::sync::atomic::AtomicU32,
}

impl Clone for ScopePolicy {
    fn clone(&self) -> Self {
        ScopePolicy {
            hard: self.hard.clone(),
            exclude: self.exclude.clone(),
            soft: self.soft.clone(),
            ledger: Mutex::new(VecDeque::new()),
            accounts: std::sync::atomic::AtomicU32::new(self.accounts.load(std::sync::atomic::Ordering::Relaxed)),
        }
    }
}

impl ScopePolicy {
    /// The default policy for an engagement: exactly the target, nothing else.
    ///
    /// Starting from the target rather than from "everything" is the whole
    /// point. Recon finds subdomains, third-party CDNs, SSO providers and
    /// internal hosts referenced in JavaScript; none of that is authorized, and
    /// an agent that treats discovery as permission is how an engagement ends
    /// up touching someone else's asset.
    pub fn for_target(target: &str) -> ScopePolicy {
        let mut p = ScopePolicy::default();
        if let Some(pat) = Pattern::parse(&host_of(target)) {
            p.hard.push(pat);
        }
        p
    }

    /// Add allowlist entries from operator text (comma/space/newline separated).
    pub fn allow(&mut self, raw: &str) -> usize {
        let before = self.hard.len();
        for tok in split_list(raw) {
            if let Some(p) = Pattern::parse(&tok) {
                if !self.hard.contains(&p) {
                    self.hard.push(p);
                }
            }
        }
        self.hard.len() - before
    }

    /// Add exclusions from operator text. Exclusions beat the allowlist, so an
    /// operator can authorize `*.example.com` and still carve out `payments.`.
    pub fn deny(&mut self, raw: &str) -> usize {
        let before = self.exclude.len();
        for tok in split_list(raw) {
            if let Some(p) = Pattern::parse(&tok) {
                if !self.exclude.contains(&p) {
                    self.exclude.push(p);
                }
            }
        }
        self.exclude.len() - before
    }

    /// Mark hosts/prefixes as look-but-don't-touch.
    pub fn observe_only(&mut self, raw: &str) -> usize {
        let before = self.soft.observe_only.len();
        for tok in split_list(raw) {
            if let Some(p) = Pattern::parse(&tok) {
                if !self.soft.observe_only.contains(&p) {
                    self.soft.observe_only.push(p);
                }
            }
        }
        self.soft.observe_only.len() - before
    }

    /// Load a scope from a YAML file (the operator-facing format).
    ///
    /// The friendly string form — `app.example.com`, `*.example.com`,
    /// `10.0.0.0/24`, `https://example.com/api` — the SAME strings the CLI flag
    /// and the web form take, parsed through [`Pattern::parse`]. NOT the raw
    /// serde shape (`{kind, value}`), which is faithful but unwritable by hand.
    ///
    /// This is a hard boundary, so parsing is strict in one direction: an
    /// unreadable file is an error, never a silently-empty policy. An empty
    /// policy authorizes nothing, and "nothing" is a safe failure — but it must
    /// be the operator's choice, not a typo swallowed here.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<ScopePolicy> {
        let text = std::fs::read_to_string(path)?;
        Ok(ScopePolicy::from_yaml(&text))
    }

    /// Parse the friendly scope YAML subset. Dependency-free, matching the
    /// house style of `creds.rs` — the schema is small and known:
    ///
    /// ```yaml
    /// hard:    [ - <pattern> ... ]
    /// exclude: [ - <pattern> ... ]
    /// soft:
    ///   observe_only: [ - <pattern> ... ]
    ///   allow_destructive_methods: <bool>
    ///   allow_account_creation:    <bool>
    ///   max_accounts:              <int>
    ///   max_requests_per_minute:   <int>
    ///   forbidden_payloads: [ - <string> ... ]
    ///   notes:              [ - <string> ... ]
    /// ```
    pub fn from_yaml(text: &str) -> ScopePolicy {
        let mut p = ScopePolicy::default();
        // Section state: which list a `- item` currently belongs to.
        #[derive(PartialEq)]
        enum Sect { None, Hard, Exclude, Observe, Forbidden, Notes }
        let mut sect = Sect::None;
        // Track whether we are inside the `soft:` block (deeper indent), so a
        // top-level `notes:` (there is none today, but be robust) is not
        // confused with `soft.notes`.
        for raw in text.lines() {
            let line = strip_comment(raw);
            if line.trim().is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let t = line.trim();

            if let Some(item) = t.strip_prefix("- ") {
                let val = unquote(item.trim());
                if val.is_empty() {
                    continue;
                }
                match sect {
                    Sect::Hard => { p.allow(&val); }
                    Sect::Exclude => { p.deny(&val); }
                    Sect::Observe => { p.observe_only(&val); }
                    Sect::Forbidden => p.soft.forbidden_payloads.push(val.to_lowercase()),
                    Sect::Notes => p.soft.notes.push(val),
                    Sect::None => {}
                }
                continue;
            }

            // A `key:` or `key: value` line. Indent 0 = top level; deeper =
            // inside `soft:`.
            let (key, value) = match t.split_once(':') {
                Some((k, v)) => (k.trim(), unquote(v.trim())),
                None => continue,
            };
            let top = indent == 0;
            // An inline list on the key line (`hard: [a, b]`) is routed by key
            // regardless of depth, before the section-header handling.
            if value.starts_with('[') {
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                for tok in inner.split(',') {
                    let v = unquote(tok.trim());
                    if v.is_empty() { continue; }
                    match key {
                        "hard" => { p.allow(&v); }
                        "exclude" => { p.deny(&v); }
                        "observe_only" => { p.observe_only(&v); }
                        "forbidden_payloads" => p.soft.forbidden_payloads.push(v.to_lowercase()),
                        "notes" => p.soft.notes.push(v),
                        _ => {}
                    }
                }
                sect = Sect::None;
                continue;
            }
            match (top, key) {
                (true, "hard") => sect = Sect::Hard,
                (true, "exclude") => sect = Sect::Exclude,
                (true, "soft") => sect = Sect::None,
                // soft.* children
                (false, "observe_only") => sect = Sect::Observe,
                (false, "forbidden_payloads") => sect = Sect::Forbidden,
                (false, "notes") => sect = Sect::Notes,
                (false, "allow_destructive_methods") => { p.soft.allow_destructive_methods = truthy(&value); sect = Sect::None; }
                (false, "allow_account_creation") => { p.soft.allow_account_creation = truthy(&value); sect = Sect::None; }
                (false, "max_accounts") => { if let Ok(n) = value.parse() { p.soft.max_accounts = n; } sect = Sect::None; }
                (false, "max_requests_per_minute") => { if let Ok(n) = value.parse() { p.soft.max_requests_per_minute = n; } sect = Sect::None; }
                _ => { sect = Sect::None; }
            }
        }
        p
    }

    pub fn in_hard_scope(&self, url: &str) -> bool {
        if self.exclude.iter().any(|p| p.matches(url)) {
            return false;
        }
        self.hard.iter().any(|p| p.matches(url))
    }

    /// The authorization decision for one interaction.
    pub fn check(&self, url: &str, action: Action) -> Decision {
        let host = host_of(url);
        if host.is_empty() {
            return Decision::Deny("no host in target".into());
        }
        if let Some(p) = self.exclude.iter().find(|p| p.matches(url)) {
            return Decision::Deny(format!("{host} is excluded by scope rule '{}'", p.as_text()));
        }
        if self.hard.is_empty() {
            return Decision::Deny("no hard scope configured — nothing is authorized".into());
        }
        if !self.hard.iter().any(|p| p.matches(url)) {
            return Decision::Deny(format!(
                "{host} is outside the authorized scope ({})",
                self.hard.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(", ")
            ));
        }
        if action.rank() >= Action::Exploit.rank() {
            if let Some(p) = self.soft.observe_only.iter().find(|p| p.matches(url)) {
                return Decision::Deny(format!("{} is observe-only — discovery allowed, interaction is not", p.as_text()));
            }
        }
        if action == Action::Destructive && !self.soft.allow_destructive_methods {
            return Decision::Deny("destructive actions are disabled for this engagement".into());
        }
        if let Some(w) = self.rate_check() {
            return w;
        }
        Decision::Allow
    }

    /// Check an outbound HTTP request: the URL, the verb and the payload.
    pub fn check_request(&self, url: &str, method: &str, body: &str) -> Decision {
        let m = method.trim().to_uppercase();
        let action = match m.as_str() {
            "GET" | "HEAD" | "OPTIONS" => Action::Probe,
            "DELETE" | "PUT" | "PATCH" => Action::Destructive,
            _ => Action::Exploit,
        };
        if let Some(bad) = self.forbidden_in(body).or_else(|| self.forbidden_in(url)) {
            return Decision::Deny(format!("payload contains a forbidden pattern ('{bad}') — this damages the target instead of proving a bug"));
        }
        self.check(url, action)
    }

    fn forbidden_in(&self, s: &str) -> Option<String> {
        if s.is_empty() {
            return None;
        }
        let hay = s.to_lowercase();
        self.soft.forbidden_payloads.iter().find(|p| hay.contains(&p.to_lowercase())).cloned()
    }

    /// Account creation is capped rather than forbidden: a test account is
    /// often the only way to prove an access-control bug, but an agent looping
    /// on a registration form is abuse.
    pub fn check_account_creation(&self) -> Decision {
        if !self.soft.allow_account_creation {
            return Decision::Deny("account creation is disabled for this engagement".into());
        }
        let n = self.accounts.load(std::sync::atomic::Ordering::Relaxed);
        if self.soft.max_accounts > 0 && n >= self.soft.max_accounts {
            return Decision::Deny(format!("account cap reached ({} of {})", n, self.soft.max_accounts));
        }
        Decision::Allow
    }

    pub fn note_account_created(&self) {
        self.accounts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a request and report whether the rate guard is tripped.
    fn rate_check(&self) -> Option<Decision> {
        if self.soft.max_requests_per_minute == 0 {
            return None;
        }
        let now = std::time::Instant::now();
        let mut led = self.ledger.lock().ok()?;
        while led.front().map(|t| now.duration_since(*t).as_secs() >= 60).unwrap_or(false) {
            led.pop_front();
        }
        led.push_back(now);
        if led.len() as u32 > self.soft.max_requests_per_minute {
            // A warning, not a denial: the engagement should slow down, and
            // silently dropping a request would make the agent misread the
            // target as unreachable.
            return Some(Decision::Warn(format!(
                "request rate above {} per minute — throttle",
                self.soft.max_requests_per_minute
            )));
        }
        None
    }

    /// Quarantine findings proven against something outside the boundary.
    ///
    /// Returns `(kept, quarantined)`. A finding on an unauthorized host is not
    /// a finding to report — it is an incident to disclose to the operator, and
    /// shipping it in the deliverable would launder the mistake.
    pub fn audit_findings(&self, findings: Vec<crate::types::Finding>) -> (Vec<crate::types::Finding>, Vec<crate::types::Finding>) {
        let mut kept = Vec::new();
        let mut out = Vec::new();
        for f in findings {
            // A finding with no endpoint (many SAST results) has no host to
            // check; source review is bounded by the repo, not by the network.
            if f.endpoint.trim().is_empty()
                || looks_like_source_ref(&f.endpoint)
                || host_of(&f.endpoint).is_empty()
                || self.in_hard_scope(&f.endpoint)
            {
                kept.push(f);
            } else {
                out.push(f);
            }
        }
        (kept, out)
    }

    /// The scope block rendered for prompts. The rules are enforced in code;
    /// this exists so the agent does not waste a round trip discovering a
    /// boundary the guard would have refused anyway.
    pub fn prompt_block(&self) -> String {
        if self.hard.is_empty() {
            return String::new();
        }
        let mut s = String::from("AUTHORIZED SCOPE — enforced by the harness, not advisory. Requests outside it are blocked before they are sent:\n");
        s.push_str(&format!("  in scope: {}\n", self.hard.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(", ")));
        if !self.exclude.is_empty() {
            s.push_str(&format!("  excluded: {}\n", self.exclude.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(", ")));
        }
        if !self.soft.observe_only.is_empty() {
            s.push_str(&format!("  observe-only (look, never interact): {}\n", self.soft.observe_only.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(", ")));
        }
        s.push_str(&format!(
            "  guardrails: destructive methods {}, account creation {}{}, max {} req/min\n",
            if self.soft.allow_destructive_methods { "ALLOWED" } else { "BLOCKED" },
            if self.soft.allow_account_creation { "allowed" } else { "BLOCKED" },
            if self.soft.allow_account_creation && self.soft.max_accounts > 0 { format!(" (max {})", self.soft.max_accounts) } else { String::new() },
            self.soft.max_requests_per_minute
        ));
        s.push_str("  Discovering a host, link, subdomain or API does NOT authorize testing it. Report it as an observation instead.\n");
        for n in &self.soft.notes {
            s.push_str(&format!("  note: {n}\n"));
        }
        s
    }

    /// One-line summary for `/scope` and the web console.
    pub fn summary(&self) -> String {
        format!(
            "hard: {} · excluded: {} · observe-only: {} · destructive: {} · accounts: {} · {} req/min",
            if self.hard.is_empty() { "(none — nothing authorized)".into() } else { self.hard.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(",") },
            if self.exclude.is_empty() { "-".into() } else { self.exclude.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(",") },
            if self.soft.observe_only.is_empty() { "-".into() } else { self.soft.observe_only.iter().map(|p| p.as_text()).collect::<Vec<_>>().join(",") },
            if self.soft.allow_destructive_methods { "allowed" } else { "blocked" },
            if self.soft.allow_account_creation { format!("max {}", self.soft.max_accounts) } else { "blocked".into() },
            self.soft.max_requests_per_minute
        )
    }
}

/// Does this endpoint name a place in source rather than a place on the
/// network? SAST findings carry `file.ext:line`, which has no host to
/// authorize — source review is bounded by the repository, not by scope. The
/// distinction matters because `example.com:8080` also ends in `:digits`, so
/// the discriminator is a path separator or a known code extension, not the
/// colon.
pub fn looks_like_source_ref(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.contains("://") {
        return false;
    }
    if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
        return true;
    }
    const CODE_EXT: &[&str] = &[
        "rs", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "py", "java", "kt", "go", "rb", "php",
        "c", "h", "cc", "cpp", "hpp", "cs", "swift", "scala", "sql", "sh", "bash", "ps1", "tf",
        "yaml", "yml", "json", "toml", "xml", "md", "erb", "ejs", "twig", "jsp", "aspx", "cshtml",
    ];
    let Some((path, tail)) = s.rsplit_once(':') else { return false };
    if tail.is_empty() || !tail.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let ext = base.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
    path.contains('/') || path.contains('\\') || CODE_EXT.contains(&ext.as_str())
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split([',', ';', ' ', '\n', '\t'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Drop a trailing `# comment`. A scope pattern never contains `#`, and we only
/// strip when the `#` follows whitespace or opens the line.
fn strip_comment(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return line[..i].to_string();
        }
        i += 1;
    }
    line.to_string()
}

/// Strip matching surrounding quotes.
fn unquote(s: &str) -> String {
    let t = s.trim();
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// YAML-ish truthiness.
fn truthy(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "true" | "yes" | "on" | "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Finding;

    fn policy() -> ScopePolicy {
        let mut p = ScopePolicy::for_target("https://app.example.com/login");
        p.soft.max_requests_per_minute = 0; // rate guard tested separately
        p
    }

    #[test]
    fn the_default_scope_is_the_target_and_nothing_else() {
        let p = policy();
        assert_eq!(p.check("https://app.example.com/admin", Action::Exploit), Decision::Allow);
        // Discovery is not authorization: a subdomain found in recon stays out.
        match p.check("https://internal.example.com/", Action::Probe) {
            Decision::Deny(r) => assert!(r.contains("outside the authorized scope"), "{r}"),
            d => panic!("a discovered subdomain must not be authorized: {d:?}"),
        }
        assert!(!p.check("https://cdn.thirdparty.net/app.js", Action::Observe).allowed());
    }

    #[test]
    fn a_wildcard_covers_subdomains_and_the_apex() {
        let mut p = policy();
        p.allow("*.example.com");
        assert!(p.check("https://api.example.com/v1", Action::Exploit).allowed());
        assert!(p.check("https://example.com/", Action::Exploit).allowed());
        assert!(!p.check("https://example.com.evil.net/", Action::Probe).allowed(), "suffix confusion must not pass");
    }

    #[test]
    fn an_exclusion_beats_the_allowlist() {
        let mut p = policy();
        p.allow("*.example.com");
        p.deny("payments.example.com");
        match p.check("https://payments.example.com/checkout", Action::Probe) {
            Decision::Deny(r) => assert!(r.contains("excluded"), "{r}"),
            d => panic!("exclusion must win over the wildcard: {d:?}"),
        }
    }

    #[test]
    fn cidr_scope_matches_addresses_in_the_network_only() {
        let mut p = ScopePolicy::default();
        p.soft.max_requests_per_minute = 0;
        p.allow("10.0.0.0/24");
        assert!(p.check("http://10.0.0.7:8080/", Action::Exploit).allowed());
        assert!(!p.check("http://10.0.1.7/", Action::Probe).allowed());
    }

    #[test]
    fn a_url_prefix_scopes_one_path_not_its_neighbours() {
        let mut p = ScopePolicy::default();
        p.soft.max_requests_per_minute = 0;
        p.allow("https://example.com/api");
        assert!(p.check("https://example.com/api/users", Action::Exploit).allowed());
        assert!(!p.check("https://example.com/apikeys", Action::Probe).allowed(), "/api must not match /apikeys");
        assert!(!p.check("https://example.com/admin", Action::Probe).allowed());
    }

    #[test]
    fn observe_only_permits_looking_and_refuses_touching() {
        let mut p = policy();
        p.allow("*.example.com");
        p.observe_only("legacy.example.com");
        assert!(p.check("https://legacy.example.com/", Action::Observe).allowed());
        assert!(p.check("https://legacy.example.com/", Action::Probe).allowed());
        assert!(!p.check("https://legacy.example.com/", Action::Exploit).allowed());
    }

    #[test]
    fn destructive_verbs_are_off_until_the_operator_turns_them_on() {
        let mut p = policy();
        assert!(!p.check_request("https://app.example.com/orders/1", "DELETE", "").allowed());
        p.soft.allow_destructive_methods = true;
        assert!(p.check_request("https://app.example.com/orders/1", "DELETE", "").allowed());
    }

    #[test]
    fn payloads_that_destroy_data_are_refused_even_in_scope() {
        let p = policy();
        match p.check_request("https://app.example.com/search", "POST", "q=1'; DROP TABLE users--") {
            Decision::Deny(r) => assert!(r.contains("forbidden pattern"), "{r}"),
            d => panic!("a destructive payload must be refused: {d:?}"),
        }
        // The benign equivalent of the same test still goes through.
        assert!(p.check_request("https://app.example.com/search", "POST", "q=1' OR '1'='1").allowed());
    }

    #[test]
    fn account_creation_is_capped_not_unlimited() {
        let p = policy();
        for _ in 0..p.soft.max_accounts {
            assert!(p.check_account_creation().allowed());
            p.note_account_created();
        }
        match p.check_account_creation() {
            Decision::Deny(r) => assert!(r.contains("cap reached"), "{r}"),
            d => panic!("the cap must hold: {d:?}"),
        }
    }

    #[test]
    fn the_rate_guard_warns_without_blocking() {
        let mut p = policy();
        p.soft.max_requests_per_minute = 2;
        assert_eq!(p.check("https://app.example.com/a", Action::Probe), Decision::Allow);
        assert_eq!(p.check("https://app.example.com/b", Action::Probe), Decision::Allow);
        match p.check("https://app.example.com/c", Action::Probe) {
            // Still allowed — dropping it would read as "target unreachable".
            Decision::Warn(r) => assert!(r.contains("request rate")),
            d => panic!("expected a throttle warning, got {d:?}"),
        }
    }

    #[test]
    fn findings_proven_outside_the_boundary_are_quarantined() {
        let p = policy();
        let inside = Finding { endpoint: "https://app.example.com/login".into(), title: "in".into(), ..Default::default() };
        let outside = Finding { endpoint: "https://other.test/x".into(), title: "out".into(), ..Default::default() };
        let sast = Finding { endpoint: "src/auth.rs:42".into(), title: "code".into(), ..Default::default() };
        let (kept, quarantined) = p.audit_findings(vec![inside, outside, sast]);
        assert_eq!(kept.iter().map(|f| f.title.clone()).collect::<Vec<_>>(), vec!["in", "code"]);
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].title, "out");
    }

    #[test]
    fn a_source_reference_is_not_a_host() {
        assert!(looks_like_source_ref("src/auth.rs:42"));
        assert!(looks_like_source_ref("app/Main.java:100"));
        assert!(looks_like_source_ref("auth.rs:7"), "a bare file with a code extension still counts");
        assert!(looks_like_source_ref("/etc/passwd"));
        // The shape that made this necessary: a host with a port ends in
        // :digits too, and must stay a network endpoint.
        assert!(!looks_like_source_ref("example.com:8080"));
        assert!(!looks_like_source_ref("https://example.com/a.rs:42"));
        assert!(!looks_like_source_ref("10.0.0.1:22"));
    }

    #[test]
    fn an_empty_policy_authorizes_nothing() {
        let p = ScopePolicy::default();
        match p.check("https://anything.test/", Action::Observe) {
            Decision::Deny(r) => assert!(r.contains("nothing is authorized"), "{r}"),
            d => panic!("an unconfigured policy must be closed, not open: {d:?}"),
        }
    }

    #[test]
    fn from_yaml_parses_the_friendly_format_and_enforces_it() {
        let yaml = r#"
hard:
  - app.example.com
  - "*.staging.example.com"
  - https://example.com/api/v2
exclude:
  - payments.example.com
soft:
  observe_only:
    - cdn.example.com
  allow_destructive_methods: false
  max_accounts: 5
  max_requests_per_minute: 120
  forbidden_payloads:
    - "delete from"
  notes:
    - "SOW-2026-0142"
"#;
        let p = ScopePolicy::from_yaml(yaml);
        assert!(p.check_request("https://app.example.com/x", "GET", "").allowed());
        assert!(p.check_request("https://sub.staging.example.com/x", "GET", "").allowed());
        assert!(!p.check_request("https://payments.example.com/x", "GET", "").allowed());
        assert!(!p.check_request("https://evil.test/x", "GET", "").allowed());
        assert!(p.check_request("https://example.com/api/v2/users", "GET", "").allowed());
        assert!(!p.check_request("https://example.com/admin", "GET", "").allowed());
        assert!(!p.check_request("https://cdn.example.com/x", "POST", "").allowed());
        assert_eq!(p.soft.max_accounts, 5);
        assert_eq!(p.soft.max_requests_per_minute, 120);
        assert!(!p.soft.allow_destructive_methods);
        assert!(p.soft.forbidden_payloads.iter().any(|f| f == "delete from"));
        assert!(p.soft.notes.iter().any(|n| n.contains("SOW")));
    }

    #[test]
    fn from_yaml_strips_comments_and_quotes() {
        let yaml = "hard:\n  - app.example.com   # the app\n  - \"*.api.example.com\"\n";
        let p = ScopePolicy::from_yaml(yaml);
        assert!(p.check_request("https://app.example.com/x", "GET", "").allowed());
        assert!(p.check_request("https://v2.api.example.com/x", "GET", "").allowed());
    }

    #[test]
    fn an_empty_scope_yaml_authorizes_nothing() {
        let p = ScopePolicy::from_yaml("soft:\n  max_accounts: 2\n");
        assert!(p.hard.is_empty());
        assert!(!p.check_request("https://anything.test/x", "GET", "").allowed());
    }

    #[test]
    fn inline_list_form_also_parses() {
        let p = ScopePolicy::from_yaml("hard: [app.example.com, api.example.com]\n");
        assert!(p.check_request("https://api.example.com/x", "GET", "").allowed());
        assert!(p.check_request("https://app.example.com/x", "GET", "").allowed());
    }

}
