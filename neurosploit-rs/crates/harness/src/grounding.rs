//! Verification / grounding engine (v3.6.4).
//!
//! Hard rule: **no claim enters the world model without a receipt** — evidence,
//! not the LLM's bare assertion. This is the anti-hallucination anchor that
//! complements the POMDP belief gate. What counts as a receipt depends on the
//! engagement, so grounding runs in one of three modes:
//!
//! - **Empirical** (black-box / host / AI-endpoint): the finding's evidence must
//!   look like raw tool output (an HTTP response, an OOB callback, an error
//!   oracle, a shell receipt) — not prose.
//! - **Symbolic** (white-box SAST / skills audit): the receipt is a `file:line`
//!   (or `file:section`) reference into the reviewed source, or a quote of code
//!   that actually appears in it. There is NO live target to hit, so requiring an
//!   HTTP-style receipt here is wrong — a code citation IS the receipt.
//! - **Either** (grey-box): both worlds are present (source review + a running
//!   app), so a finding is grounded if it has a symbolic OR an empirical receipt.
//!
//! Ungrounded claims are flagged (`receipt_missing`) so the reward layer can
//! penalize them (the "claim without receipt" term).

use crate::types::Finding;

/// How a finding must be grounded, per engagement type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundMode {
    /// Black-box / host / AI endpoint: evidence must resemble raw tool output.
    Empirical,
    /// White-box SAST / skills audit: evidence must reference the reviewed source.
    Symbolic,
    /// Grey-box: accept either a source citation or an empirical receipt.
    Either,
}

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
/// `context` is the reviewed SOURCE (not the model transcript). When the source
/// context is unavailable, fall back to structural checks so a well-formed
/// `file:line` + code quote still grounds (a SAST finding must never be silently
/// dropped just because the caller couldn't supply the corpus).
fn looks_symbolic(f: &Finding, context: &str) -> bool {
    let loc = f.endpoint.trim();
    // A file:line / file:section reference is the canonical symbolic receipt.
    let has_file_ref = loc.rsplit_once(':')
        .map(|(file, tail)| {
            let base = file.rsplit(['/', '\\']).next().unwrap_or(file);
            // looks like a path/file (has an extension or a separator) and a
            // line/section follows — i.e. not a "host:port" style endpoint.
            !base.is_empty()
                && (base.contains('.') || file.contains('/'))
                && !tail.trim().is_empty()
        })
        .unwrap_or(false);

    if !context.is_empty() {
        // Strongest: the referenced file actually appears in the reviewed source.
        if let Some((file, _)) = loc.rsplit_once(':') {
            let base = file.rsplit(['/', '\\']).next().unwrap_or(file);
            if !base.is_empty() && context.contains(base) {
                return true;
            }
        }
        // Or the evidence quotes a distinctive code token present in the source.
        let quote_matches = f.evidence
            .split_whitespace()
            .filter(|t| t.len() > 4 && context.contains(*t))
            .count();
        if quote_matches >= 2 {
            return true;
        }
        // Source is present but neither the file nor a quote matched → still
        // accept a well-formed file:line ref with quoted evidence, since the
        // bounded corpus may simply not include the referenced file.
        return has_file_ref && f.evidence.trim().len() >= 12;
    }

    // No source corpus available: ground on a well-formed file:line reference
    // backed by non-trivial quoted evidence.
    has_file_ref && f.evidence.trim().len() >= 12
}

/// Ground a finding under `mode`. `context` is the reviewed SOURCE for symbolic/
/// either modes (empty for pure empirical). Returns whether it has a valid
/// receipt and of what kind.
pub fn ground(f: &Finding, context: &str, mode: GroundMode) -> Grounded {
    let symbolic = || looks_symbolic(f, context);
    let empirical = || looks_empirical(&f.evidence);
    match mode {
        GroundMode::Symbolic => {
            if symbolic() {
                Grounded { ok: true, kind: "symbolic", reason: "source location/quote matches reviewed code".into() }
            } else {
                Grounded { ok: false, kind: "missing", reason: "no source reference (file:line) into reviewed code".into() }
            }
        }
        GroundMode::Either => {
            if symbolic() {
                Grounded { ok: true, kind: "symbolic", reason: "source location/quote matches reviewed code".into() }
            } else if empirical() {
                Grounded { ok: true, kind: "empirical", reason: "evidence resembles raw tool output".into() }
            } else {
                Grounded { ok: false, kind: "missing", reason: "no source reference nor tool receipt".into() }
            }
        }
        GroundMode::Empirical => {
            if empirical() {
                Grounded { ok: true, kind: "empirical", reason: "evidence resembles raw tool output".into() }
            } else {
                Grounded { ok: false, kind: "missing", reason: "evidence is paraphrase, not a tool receipt".into() }
            }
        }
    }
}

/// Apply the grounding gate to a finding set under `mode`. Ungrounded findings
/// are flagged (receipt recorded in `votes`) and demoted to unvalidated so they
/// never get reported as confirmed. Returns (kept, demoted_count).
pub fn gate(mut findings: Vec<Finding>, context: &str, mode: GroundMode) -> (Vec<Finding>, usize) {
    let mut demoted = 0;
    for f in findings.iter_mut() {
        let g = ground(f, context, mode);
        if !g.ok {
            f.validated = false;
            f.votes = format!("{} · receipt_missing", f.votes);
            demoted += 1;
        }
    }
    findings.retain(|f| f.validated);
    (findings, demoted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sast_finding() -> Finding {
        // A typical SAST finding: file:line endpoint + a code quote as evidence,
        // and NO HTTP/tool-output markers (there is no live target to hit).
        Finding {
            title: "SQL injection via string-formatted query".into(),
            severity: "High".into(),
            cwe: "CWE-89".into(),
            endpoint: "src/db/users.py:42".into(),
            evidence: "query = \"SELECT * FROM users WHERE id = \" + request.args.get('id')".into(),
            validated: true,
            confidence: 0.8,
            ..Default::default()
        }
    }

    #[test]
    fn sast_finding_grounds_symbolically_against_source() {
        let src = "def get(id):\n    query = \"SELECT * FROM users WHERE id = \" + request.args.get('id')\n";
        assert!(ground(&sast_finding(), src, GroundMode::Symbolic).ok,
            "a file:line SAST finding whose code appears in the source must ground");
    }

    #[test]
    fn sast_finding_grounds_even_without_source_corpus() {
        // Regression: the whitebox gate used to run in EMPIRICAL mode (bug #33),
        // demoting every SAST finding because code quotes lack HTTP-style markers.
        // A well-formed file:line + quoted evidence must ground on its own.
        assert!(ground(&sast_finding(), "", GroundMode::Symbolic).ok,
            "SAST finding must not be demoted for lacking a tool receipt");
    }

    #[test]
    fn symbolic_rejects_bare_prose() {
        let f = Finding { endpoint: "the login flow".into(),
            evidence: "The application seems insecure.".into(), validated: true, ..Default::default() };
        assert!(!ground(&f, "", GroundMode::Symbolic).ok,
            "prose with no source reference must NOT ground symbolically");
    }

    #[test]
    fn empirical_still_requires_tool_output() {
        // Black-box unchanged: a code quote is not an empirical receipt.
        assert!(!ground(&sast_finding(), "", GroundMode::Empirical).ok);
        let http = Finding {
            endpoint: "https://t/login".into(),
            evidence: "HTTP/1.1 200 OK\nset-cookie: sid=1; \nserver: nginx\n<script>alert(1)</script>".into(),
            validated: true, ..Default::default() };
        assert!(ground(&http, "", GroundMode::Empirical).ok);
    }

    #[test]
    fn either_accepts_symbolic_or_empirical() {
        assert!(ground(&sast_finding(), "", GroundMode::Either).ok, "grey-box accepts a source citation");
    }

    #[test]
    fn gate_keeps_grounded_and_demotes_prose() {
        let good = sast_finding();
        let bad = Finding { title: "vibes".into(), endpoint: "somewhere".into(),
            evidence: "looks bad".into(), validated: true, ..Default::default() };
        let (kept, demoted) = gate(vec![good, bad], "", GroundMode::Symbolic);
        assert_eq!(kept.len(), 1);
        assert_eq!(demoted, 1);
    }
}
