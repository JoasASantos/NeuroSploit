//! Verification / grounding engine (v3.6.3).
//!
//! Hard rule: **no claim enters the world model without a tool receipt** — raw
//! tool output, not the LLM's paraphrase. This is the empirical anti-hallucination
//! anchor that complements the POMDP belief gate:
//!
//! - **Black-box**: grounding is empirical — the finding's evidence must look
//!   like raw tool output (an HTTP response, an OOB callback, an error oracle),
//!   not prose.
//! - **White-box**: grounding is symbolic — a file:line reference into the
//!   reviewed source (reachability/taint), checked against the collected context.
//!
//! Ungrounded claims are flagged (`receipt_missing`) so the reward layer can
//! penalize them (the "claim without receipt" term).

use crate::types::Finding;

/// Verdict of grounding a single finding.
pub struct Grounded {
    pub ok: bool,
    pub kind: &'static str, // "empirical" | "symbolic" | "missing"
    pub reason: String,
}

/// Markers that suggest the evidence is a real tool receipt rather than prose.
fn looks_empirical(evidence: &str) -> bool {
    let e = evidence.to_lowercase();
    let markers = [
        "http/", "status", "200", "301", "302", "401", "403", "500",
        "set-cookie", "location:", "content-type", "<html", "<script",
        "server:", "x-", "alert(", "uid=", "root:", "sql", "error", "stack",
        "callback", "oob", "collaborator", "$ ", "# ", "curl", "nmap",
    ];
    evidence.len() >= 24 && markers.iter().filter(|m| e.contains(*m)).count() >= 2
}

/// White-box: evidence should reference a source location present in `context`.
fn looks_symbolic(f: &Finding, context: &str) -> bool {
    // endpoint like file.ext:line, and the file appears in the reviewed source.
    let loc = &f.endpoint;
    if let Some((file, _)) = loc.rsplit_once(':') {
        let base = file.rsplit('/').next().unwrap_or(file);
        if !base.is_empty() && context.contains(base) {
            return true;
        }
    }
    // or the evidence quotes code that is actually in the context
    !f.evidence.trim().is_empty()
        && f.evidence.split_whitespace().take(6).collect::<Vec<_>>().join(" ")
            .split_whitespace()
            .filter(|t| t.len() > 4 && context.contains(*t))
            .count()
            >= 2
}

/// Ground a finding. `context` is the reviewed source for white-box (empty for
/// black-box). Returns whether it has a valid receipt and of what kind.
pub fn ground(f: &Finding, context: &str, whitebox: bool) -> Grounded {
    if whitebox && !context.is_empty() {
        if looks_symbolic(f, context) {
            return Grounded { ok: true, kind: "symbolic", reason: "source location/quote matches reviewed code".into() };
        }
        return Grounded { ok: false, kind: "missing", reason: "no source reference into reviewed code".into() };
    }
    if looks_empirical(&f.evidence) {
        Grounded { ok: true, kind: "empirical", reason: "evidence resembles raw tool output".into() }
    } else {
        Grounded { ok: false, kind: "missing", reason: "evidence is paraphrase, not a tool receipt".into() }
    }
}

/// Apply the grounding gate to a finding set. Ungrounded findings are flagged
/// (receipt recorded in `votes`) and demoted to unvalidated so they never get
/// reported as confirmed. Returns (kept, demoted_count).
pub fn gate(mut findings: Vec<Finding>, context: &str, whitebox: bool) -> (Vec<Finding>, usize) {
    let mut demoted = 0;
    for f in findings.iter_mut() {
        let g = ground(f, context, whitebox);
        if !g.ok {
            f.validated = false;
            f.votes = format!("{} · receipt_missing", f.votes);
            demoted += 1;
        }
    }
    findings.retain(|f| f.validated);
    (findings, demoted)
}
