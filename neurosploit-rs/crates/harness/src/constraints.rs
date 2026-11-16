//! Operator constraints — "what may NOT be done", extracted from the task text.
//!
//! [`crate::scope`] answers *which hosts* may be touched. Operators also write
//! behavioural limits in the task description: "no port scanning", "passive
//! only", "don't brute-force", "only test api.example.com". Until now those
//! lived only in prose the model could ignore.
//!
//! This module is an extra layer **on top of** `scope.rs`, never a replacement:
//! - constraints can only *restrict*; they cannot authorize anything scope denies;
//! - each constraint is made **self-contained** (deictic phrases such as "the
//!   current target" are replaced with the concrete host) because constraints
//!   are injected into worker prompts without the original task context;
//! - only constraints the operator actually wrote are registered (no
//!   invention); when the type is unclear it defaults to `deny` (conservative);
//! - a deterministic [`ConstraintSet::check_command`] maps deny-classes to the
//!   tools that implement them, so the most common violations are blocked in
//!   code instead of depending on the model's cooperation.
//!
//! Extraction is LLM-assisted ([`extraction_prompt`] / [`parse_extraction`]) with
//! a keyword fallback ([`heuristic_extract`]) so it also works offline.

use crate::json_extract::parse_reply;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConstraintKind {
    /// A forbidden operation.
    Deny,
    /// An explicit limit on what is allowed ("passive recon only").
    Allow,
}

/// Classes of operation that map to concrete tools we can block in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenyClass {
    PortScan,
    BruteForce,
    DenialOfService,
    /// Free-form: shown to the model, not mechanically enforced.
    Other,
}

impl DenyClass {
    fn tools(self) -> &'static [&'static str] {
        match self {
            DenyClass::PortScan => &["nmap", "masscan", "naabu", "rustscan", "zmap", "unicornscan"],
            DenyClass::BruteForce => &["hydra", "medusa", "patator", "ncrack", "crowbar", "kerbrute"],
            DenyClass::DenialOfService => &["slowloris", "hping3", "goldeneye", "hulk", "siege", "ab", "wrk", "loic"],
            DenyClass::Other => &[],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub kind: ConstraintKind,
    /// Self-contained statement, concrete target written out.
    pub text: String,
    pub class: DenyClass,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintSet {
    pub items: Vec<Constraint>,
}

/// Replace deictic references with the concrete target so a constraint stays
/// meaningful when detached from the task description.
pub fn self_contain(text: &str, target: &str) -> String {
    if target.trim().is_empty() { return text.trim().to_string(); }
    let mut out = text.trim().to_string();
    for phrase in [
        "o alvo atual", "o alvo", "este alvo", "esse alvo", "o site atual", "este site", "esse site",
        "a porta atual", "o host atual", "the current target", "the target", "this target",
        "the current host", "this host", "this site", "the current site", "the current port",
    ] {
        let lower = out.to_lowercase();
        if let Some(pos) = lower.find(phrase) {
            out.replace_range(pos..pos + phrase.len(), target);
        }
    }
    out
}

impl ConstraintSet {
    pub fn new() -> Self { Self::default() }

    pub fn add(&mut self, kind: ConstraintKind, text: &str, class: DenyClass, target: &str) {
        let text = self_contain(text, target);
        if text.is_empty() || self.items.iter().any(|c| c.text == text && c.kind == kind) { return; }
        self.items.push(Constraint { kind, text, class });
    }

    pub fn is_empty(&self) -> bool { self.items.is_empty() }

    /// Block block shown to every worker. Empty string when there is nothing.
    pub fn prompt_block(&self) -> String {
        if self.items.is_empty() { return String::new(); }
        let mut s = String::from(
            "OPERATOR CONSTRAINTS (set by the operator; absolute, override any plan or hint):\n");
        for c in self.items.iter().filter(|c| c.kind == ConstraintKind::Deny) {
            s.push_str(&format!("  - DENY: {}\n", c.text));
        }
        for c in self.items.iter().filter(|c| c.kind == ConstraintKind::Allow) {
            s.push_str(&format!("  - ALLOW ONLY: {}\n", c.text));
        }
        s.push_str("If an action would violate a constraint, do not perform it; record why in your result.\n");
        s
    }

    /// Deterministic check of a shell command against mechanically enforceable
    /// deny-classes. Returns the violated constraint, if any. Token match on the
    /// command's executables (handles pipes, `sudo`, `;`, `&&`, paths).
    pub fn check_command(&self, command: &str) -> Option<&Constraint> {
        let exes = executables(command);
        self.items.iter()
            .filter(|c| c.kind == ConstraintKind::Deny)
            .find(|c| c.class.tools().iter().any(|t| exes.iter().any(|e| e == t)))
    }
}

fn executables(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in command.split(|c| c == '|' || c == ';' || c == '&' || c == '\n') {
        let mut toks = seg.split_whitespace().peekable();
        while let Some(t) = toks.peek() {
            // skip wrappers and env assignments
            if matches!(*t, "sudo" | "env" | "nohup" | "time" | "timeout" | "xargs" | "proxychains" | "proxychains4")
                || t.contains('=') || t.starts_with('-') || t.chars().all(|c| c.is_ascii_digit())
            {
                toks.next();
            } else { break; }
        }
        if let Some(t) = toks.next() {
            out.push(t.rsplit('/').next().unwrap_or(t).to_lowercase());
        }
    }
    out
}

/// Prompt for an LLM to extract constraints. Reply contract is JSON.
pub fn extraction_prompt(task: &str, target: &str) -> String {
    format!(
"Extract OPERATOR CONSTRAINTS from this pentest task. A constraint is a rule about which OPERATIONS are allowed or forbidden - not a goal, not an attack step.\n\
Rules:\n\
- Register ONLY constraints the operator wrote or emphasised. Never invent any.\n\
- Make each constraint self-contained: replace phrases like \"the current target\" with the concrete value (target: {target}).\n\
- type=deny for forbidden operations; type=allow for explicit limits (\"passive recon only\"). If unsure, use deny.\n\
- class is one of: port-scan, brute-force, denial-of-service, other.\n\
- If there are none, return {{\"constraints\":[]}}.\n\
Reply with JSON only: {{\"constraints\":[{{\"type\":\"deny\",\"class\":\"port-scan\",\"text\":\"...\"}}]}}\n\nTASK:\n{task}\n")
}

/// Parse the LLM reply into a set. Tolerant: bad entries are skipped.
pub fn parse_extraction(reply: &str, target: &str) -> ConstraintSet {
    let mut set = ConstraintSet::new();
    let Some(v) = parse_reply(reply) else { return set };
    let Some(arr) = v.get("constraints").and_then(|x| x.as_array()) else { return set };
    for item in arr {
        let text = item.get("text").and_then(|x| x.as_str()).unwrap_or("").trim();
        if text.is_empty() { continue; }
        let kind = match item.get("type").and_then(|x| x.as_str()).unwrap_or("deny") {
            "allow" => ConstraintKind::Allow,
            _ => ConstraintKind::Deny, // unknown/unclear -> conservative
        };
        let class = match item.get("class").and_then(|x| x.as_str()).unwrap_or("other") {
            "port-scan" => DenyClass::PortScan,
            "brute-force" => DenyClass::BruteForce,
            "denial-of-service" => DenyClass::DenialOfService,
            _ => DenyClass::Other,
        };
        // `class` only drives mechanical blocking for deny constraints.
        let class = if kind == ConstraintKind::Allow { DenyClass::Other } else { class };
        set.add(kind, text, class, target);
    }
    set
}

/// Keyword fallback (pt/en) used when no LLM is available. Conservative: it only
/// recognises explicit negations of well-known operation classes.
pub fn heuristic_extract(task: &str, target: &str) -> ConstraintSet {
    let t = task.to_lowercase();
    let mut set = ConstraintSet::new();
    let rules: [(&[&str], DenyClass, &str); 3] = [
        (&["não scane", "nao scane", "sem scan de porta", "não faça port scan", "nao faca port scan",
           "no port scan", "no portscan", "do not scan ports", "don't scan ports", "dont scan ports",
           "no nmap", "sem nmap"],
         DenyClass::PortScan, "Do not perform port scanning against the target"),
        (&["sem brute", "não faça brute", "nao faca brute", "proibido brute", "no brute", "no bruteforce",
           "do not brute", "don't brute", "dont brute", "no password guessing"],
         DenyClass::BruteForce, "Do not perform brute-force or password-guessing attacks"),
        (&["sem dos", "no dos", "no denial of service", "não derrube", "nao derrube", "do not stress",
           "don't stress", "no stress test", "sem teste de carga"],
         DenyClass::DenialOfService, "Do not perform denial-of-service or load/stress testing"),
    ];
    for (needles, class, text) in rules {
        if needles.iter().any(|n| t.contains(n)) {
            set.add(ConstraintKind::Deny, text, class, target);
        }
    }
    if ["somente passivo", "apenas passivo", "só passivo", "so passivo", "passive only", "passive recon only", "only passive"]
        .iter().any(|n| t.contains(n))
    {
        set.add(ConstraintKind::Allow, "Passive reconnaissance only; send no active probes or payloads",
            DenyClass::Other, target);
    }
    set
}

/// Extract with the LLM reply when available, always unioned with the keyword
/// fallback so an unhelpful model reply can never drop an obvious constraint.
pub fn extract(task: &str, target: &str, llm_reply: Option<&str>) -> ConstraintSet {
    let mut set = llm_reply.map(|r| parse_extraction(r, target)).unwrap_or_default();
    for c in heuristic_extract(task, target).items {
        if !set.items.iter().any(|x| x.kind == c.kind && x.class == c.class && c.class != DenyClass::Other) {
            set.add(c.kind, &c.text, c.class, target);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_contain_replaces_deixis() {
        assert_eq!(self_contain("Only test the current target", "api.example.com"),
                   "Only test api.example.com");
        assert_eq!(self_contain("apenas o alvo atual", "a.b.c"), "apenas a.b.c");
        assert_eq!(self_contain("no change", ""), "no change");
    }

    #[test]
    fn heuristic_finds_explicit_negations_only() {
        let s = heuristic_extract("Pentest app. Não scane portas e sem brute force.", "x.com");
        assert_eq!(s.items.len(), 2);
        assert!(heuristic_extract("full assessment of the app", "x.com").is_empty());
    }

    #[test]
    fn check_command_blocks_scanners_through_wrappers() {
        let s = heuristic_extract("no port scan", "x.com");
        assert!(s.check_command("nmap -sV x.com").is_some());
        assert!(s.check_command("sudo /usr/bin/nmap x.com").is_some());
        assert!(s.check_command("echo hi | masscan -p1-1000 1.2.3.4").is_some());
        assert!(s.check_command("curl https://x.com").is_none());
        assert!(s.check_command("echo nmap is not run").is_none(), "arguments are not executables");
    }

    #[test]
    fn parse_extraction_defaults_to_deny_and_skips_bad() {
        let reply = r#"```json
{"constraints":[{"type":"weird","class":"port-scan","text":"no scan of the target"},
{"type":"allow","text":"passive only"},{"text":""}]}```"#;
        let s = parse_extraction(reply, "x.com");
        assert_eq!(s.items.len(), 2);
        assert_eq!(s.items[0].kind, ConstraintKind::Deny);
        assert_eq!(s.items[1].kind, ConstraintKind::Allow);
        assert!(parse_extraction("no json here", "x.com").is_empty());
    }

    #[test]
    fn extract_unions_llm_with_heuristic() {
        let s = extract("no brute force please", "x.com", Some("garbage reply"));
        assert!(s.check_command("hydra -l a x.com ssh").is_some());
    }

    #[test]
    fn prompt_block_lists_deny_and_allow() {
        let mut s = ConstraintSet::new();
        s.add(ConstraintKind::Deny, "no scans", DenyClass::PortScan, "x.com");
        s.add(ConstraintKind::Allow, "passive only", DenyClass::Other, "x.com");
        let b = s.prompt_block();
        assert!(b.contains("DENY: no scans") && b.contains("ALLOW ONLY: passive only"));
        assert!(ConstraintSet::new().prompt_block().is_empty());
    }
}
