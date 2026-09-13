//! Evidence & Validation Engine — deterministic, per-CWE, outside the model.
//!
//! Today a finding becomes "validated" by asking more language models: N-model
//! voting, then an adversarial refute pass. That catches sloppy reasoning, but
//! it shares the failure mode of the thing it checks — models agreeing with
//! each other is not evidence, and a confident hallucination survives a vote by
//! being confident. [`crate::grounding`] adds a receipt requirement, but it
//! matches keywords ("http/", "status", "alert(") and cannot tell a real
//! response apart from a plausible transcript of one.
//!
//! This engine asks a different question: **does the recorded evidence actually
//! demonstrate this specific weakness?** The rule is per-CWE because the answer
//! is: SQL injection is proven by a reproducible, deterministic difference
//! between a baseline and an attack response; XSS is proven by a browser
//! executing a marker the harness chose; IDOR is proven by identity B reading
//! identity A's resource *and* the response carrying A's data. None of those
//! reduce to "the evidence looks technical".
//!
//! ```text
//!   HYPOTHESIS   an agent noticed something
//!        │
//!   CANDIDATE    a reproducible interaction was built
//!        │
//!   ┌────┴──────────────────────┐
//!   │   VALIDATION ENGINE       │   deterministic, per-CWE, no LLM
//!   └────┬──────────────────────┘
//!   PASS │ UNCERTAIN │ FAIL
//!        ▼           ▼         ▼
//!   CONFIRMED   NEEDS_REVIEW  REJECTED
//! ```
//!
//! Two rules keep the engine honest:
//!
//! 1. **Absent evidence is never a pass.** A class with no validator, or a
//!    finding whose evidence was never captured, lands in `NeedsReview` — the
//!    engine says "I could not prove this", never "this is fine".
//! 2. **It can refuse, and it can confirm, but it cannot invent.** A verdict is
//!    a function of recorded artifacts. Nothing here consults a model.

use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// One recorded HTTP interaction. Deliberately small: what a validator needs is
/// what distinguishes two responses, not a full transcript.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub body: String,
    pub content_type: String,
    pub elapsed_ms: u64,
    /// Identity this exchange was performed as ("", "userA", "admin", …).
    #[serde(default)]
    pub identity: String,
}

impl Exchange {
    pub fn len(&self) -> usize {
        self.body.len()
    }
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

/// Everything the engine may reason about for one candidate finding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// The same request without the payload — what "normal" looks like.
    pub baseline: Option<Exchange>,
    /// The request carrying the payload.
    pub attack: Option<Exchange>,
    /// Independent repeats of the attack, for reproducibility.
    #[serde(default)]
    pub repeats: Vec<Exchange>,
    /// A token the harness generated, so observing it cannot be a coincidence.
    #[serde(default)]
    pub marker: String,
    /// The marker was observed where it proves the class (rendered DOM, file
    /// read-back, command output, callback).
    #[serde(default)]
    pub marker_observed: bool,
    /// A real browser executed the payload (XSS), not a string match in HTML.
    #[serde(default)]
    pub browser_executed: bool,
    /// An out-of-band callback carrying the marker was received (SSRF, blind RCE).
    #[serde(default)]
    pub callback_received: bool,
    /// Access-control pairs: the resource as its owner, and the same resource
    /// requested by a different identity.
    pub identity_a: Option<Exchange>,
    pub identity_b: Option<Exchange>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// What the engine concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "verdict", content = "reason")]
pub enum Verdict {
    /// The evidence demonstrates this class. Report it.
    Confirmed(String),
    /// Could not be proven either way — a human decides. This is the default
    /// for anything the engine does not have a rule for.
    NeedsReview(String),
    /// The evidence contradicts the claim. Drop it to informational.
    Rejected(String),
}

impl Verdict {
    pub fn status(&self) -> &'static str {
        match self {
            Verdict::Confirmed(_) => "confirmed",
            Verdict::NeedsReview(_) => "needs-review",
            Verdict::Rejected(_) => "rejected",
        }
    }
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Confirmed(r) | Verdict::NeedsReview(r) | Verdict::Rejected(r) => r,
        }
    }
}

/// Measured difference between a baseline and an attack response.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Diff {
    pub status_changed: bool,
    pub baseline_status: u16,
    pub attack_status: u16,
    /// Relative length change, 0.0..1.0+.
    pub len_ratio: f64,
    pub len_delta: i64,
    /// Milliseconds slower (negative = faster).
    pub timing_delta_ms: i64,
    /// A database/interpreter error surfaced only under attack.
    pub error_signature: Option<String>,
}

/// Error strings that indicate the payload reached an interpreter. Matched
/// against the attack response only when the baseline did NOT contain them —
/// an app that always prints SQL errors proves nothing about this payload.
const DB_ERRORS: &[&str] = &[
    "sql syntax", "mysql_fetch", "mysqli", "ora-01756", "ora-00933", "psql:", "pg_query",
    "sqlite3::", "sqlstate", "unclosed quotation mark", "quoted string not properly terminated",
    "odbc microsoft access", "microsoft ole db", "incorrect syntax near", "invalid sql statement",
    "postgresql query failed", "supplied argument is not a valid mysql",
];

pub fn diff(baseline: &Exchange, attack: &Exchange) -> Diff {
    let b_len = baseline.len() as i64;
    let a_len = attack.len() as i64;
    let len_ratio = if b_len == 0 { if a_len == 0 { 1.0 } else { f64::INFINITY } } else { a_len as f64 / b_len as f64 };
    let blow = baseline.body.to_lowercase();
    let alow = attack.body.to_lowercase();
    let error_signature = DB_ERRORS
        .iter()
        .find(|e| alow.contains(**e) && !blow.contains(**e))
        .map(|e| (*e).to_string());
    Diff {
        status_changed: baseline.status != attack.status,
        baseline_status: baseline.status,
        attack_status: attack.status,
        len_ratio,
        len_delta: a_len - b_len,
        timing_delta_ms: attack.elapsed_ms as i64 - baseline.elapsed_ms as i64,
        error_signature,
    }
}

impl Diff {
    /// Is this difference big enough to mean something? Small jitter in a
    /// dynamic page (timestamps, CSRF tokens, ads) is normal, so the threshold
    /// sits above it deliberately.
    pub fn is_significant(&self) -> bool {
        self.error_signature.is_some()
            || self.status_changed
            || self.len_ratio.is_infinite()
            || (self.len_ratio - 1.0).abs() >= 0.10
            || self.timing_delta_ms >= 4000
    }

    pub fn describe(&self) -> String {
        if let Some(e) = &self.error_signature {
            return format!("interpreter error '{e}' appeared only under the payload");
        }
        if self.status_changed {
            return format!("status {} → {}", self.baseline_status, self.attack_status);
        }
        if self.timing_delta_ms >= 4000 {
            return format!("response {}ms slower under the payload", self.timing_delta_ms);
        }
        format!("body length {:+} bytes ({:.0}% of baseline)", self.len_delta, self.len_ratio * 100.0)
    }
}

/// A canary the harness chose. Observing it in the right place cannot be a
/// coincidence, which is the difference between evidence and a string that
/// looked suspicious.
pub fn canary(prefix: &str) -> String {
    // The clock alone is not enough: two canaries minted inside the same tick
    // came out identical, and a marker that repeats proves nothing — it could
    // have come from the previous test. A process-wide counter makes
    // uniqueness independent of clock resolution, and the pid keeps two
    // concurrent runs from colliding.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Not cryptographic — it only has to be unguessable enough that the target
    // could not have produced it on its own.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ n;
    h ^= seq.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    h ^= (std::process::id() as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = h.wrapping_mul(0x1000_0000_01b3);
    h ^= h >> 29;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 32;
    format!("{prefix}{:012x}", h & 0xffff_ffff_ffff)
}

/// Did every repeat reproduce the same significant difference? One occurrence
/// of a length change on a dynamic page is noise; the same change three times
/// is behaviour.
pub fn reproducible(baseline: &Exchange, repeats: &[Exchange], min: usize) -> (bool, usize) {
    let hits = repeats.iter().filter(|r| diff(baseline, r).is_significant()).count();
    (hits >= min, hits)
}

/// A per-CWE rule. Each answers one question about recorded artifacts.
pub trait CweValidator: Send + Sync {
    fn name(&self) -> &'static str;
    /// CWE ids (bare numbers) this rule owns.
    fn cwes(&self) -> &'static [&'static str];
    /// What the class needs before it can be confirmed — shown to the operator
    /// and to the agent, so "what would prove this" is never a guess.
    fn evidence_required(&self) -> &'static [&'static str];
    fn validate(&self, f: &Finding, ev: &Evidence) -> Verdict;
}

fn cwe_num(cwe: &str) -> String {
    cwe.chars().filter(|c| c.is_ascii_digit()).collect()
}

pub struct SqliValidator;
impl CweValidator for SqliValidator {
    fn name(&self) -> &'static str {
        "sqli"
    }
    fn cwes(&self) -> &'static [&'static str] {
        &["89", "943", "564"]
    }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["baseline_request", "attack_request", "deterministic_behavior_difference", "reproducibility >= 2"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let (Some(b), Some(a)) = (&ev.baseline, &ev.attack) else {
            return Verdict::NeedsReview("no baseline/attack pair was captured — injection cannot be judged from a single response".into());
        };
        let d = diff(b, a);
        if !d.is_significant() {
            return Verdict::Rejected(format!("payload changed nothing measurable ({})", d.describe()));
        }
        // Reproducibility is the whole point: a one-off difference on a dynamic
        // page is the most common false positive in this class.
        let (ok, hits) = reproducible(b, &ev.repeats, 2);
        if !ok {
            return Verdict::NeedsReview(format!(
                "difference observed ({}) but reproduced only {hits}/{} times — not deterministic",
                d.describe(),
                ev.repeats.len()
            ));
        }
        Verdict::Confirmed(format!("{} — reproduced {hits}/{}", d.describe(), ev.repeats.len()))
    }
}

pub struct XssValidator;
impl CweValidator for XssValidator {
    fn name(&self) -> &'static str {
        "xss"
    }
    fn cwes(&self) -> &'static [&'static str] {
        &["79", "80", "83", "87"]
    }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["browser_execution", "controlled_marker", "DOM/runtime confirmation"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        if ev.marker.is_empty() {
            return Verdict::NeedsReview("no controlled marker — a payload echoed in HTML is reflection, not proof of execution".into());
        }
        if !ev.browser_executed {
            let reflected = ev
                .attack
                .as_ref()
                .map(|a| a.body.contains(&ev.marker))
                .unwrap_or(false);
            return if reflected {
                Verdict::NeedsReview("marker is reflected but no browser executed it — could be encoded, CSP-blocked, or in a non-executing context".into())
            } else {
                Verdict::Rejected("marker never reached the response".into())
            };
        }
        if !ev.marker_observed {
            return Verdict::NeedsReview("browser ran but the marker was not observed at runtime".into());
        }
        Verdict::Confirmed(format!("browser executed the payload and reported marker {}", ev.marker))
    }
}

pub struct IdorValidator;
impl CweValidator for IdorValidator {
    fn name(&self) -> &'static str {
        "idor"
    }
    fn cwes(&self) -> &'static [&'static str] {
        &["639", "862", "863", "284", "285", "566", "425"]
    }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["identity_A_resource", "identity_B_request", "successful unauthorized access", "response_semantics_match"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let (Some(a), Some(b)) = (&ev.identity_a, &ev.identity_b) else {
            return Verdict::NeedsReview("access control needs two identities — only one context was captured".into());
        };
        if a.identity == b.identity && !a.identity.is_empty() {
            return Verdict::Rejected(format!("both requests used the same identity ('{}') — nothing crossed a boundary", a.identity));
        }
        if b.status == 401 || b.status == 403 {
            return Verdict::Rejected(format!("the other identity was denied ({}) — the control works", b.status));
        }
        if b.status >= 400 {
            return Verdict::Rejected(format!("the other identity got {} — no access was obtained", b.status));
        }
        // A 200 that returns a login page or an empty shell is the classic
        // false positive: the status says yes and the body says no.
        if b.is_empty() {
            return Verdict::NeedsReview("the other identity got 200 with an empty body — no resource content to compare".into());
        }
        let overlap = semantic_overlap(&a.body, &b.body);
        if overlap < 0.6 {
            return Verdict::Rejected(format!(
                "the other identity got 200 but the body does not match the owner's resource ({:.0}% overlap) — likely a login page or generic response",
                overlap * 100.0
            ));
        }
        Verdict::Confirmed(format!(
            "identity '{}' read identity '{}'s resource: {} with {:.0}% content match",
            if b.identity.is_empty() { "B" } else { &b.identity },
            if a.identity.is_empty() { "A" } else { &a.identity },
            b.status,
            overlap * 100.0
        ))
    }
}

pub struct SsrfValidator;
impl CweValidator for SsrfValidator {
    fn name(&self) -> &'static str {
        "ssrf"
    }
    fn cwes(&self) -> &'static [&'static str] {
        &["918"]
    }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["controlled_callback OR private/canary resource retrieval"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        if ev.callback_received && !ev.marker.is_empty() {
            return Verdict::Confirmed(format!("out-of-band callback carrying marker {} was received", ev.marker));
        }
        if ev.marker_observed && !ev.marker.is_empty() {
            return Verdict::Confirmed(format!("the response returned content from the controlled internal resource ({})", ev.marker));
        }
        let timing = ev
            .baseline
            .as_ref()
            .zip(ev.attack.as_ref())
            .map(|(b, a)| diff(b, a).timing_delta_ms)
            .unwrap_or(0);
        if timing >= 4000 {
            return Verdict::NeedsReview(format!("only a timing signal ({timing}ms) — consistent with SSRF but also with a slow upstream"));
        }
        Verdict::NeedsReview("no callback and no controlled resource retrieved — SSRF cannot be proven from the response alone".into())
    }
}

pub struct LfiValidator;
impl CweValidator for LfiValidator {
    fn name(&self) -> &'static str {
        "lfi"
    }
    fn cwes(&self) -> &'static [&'static str] {
        &["22", "23", "35", "98", "73"]
    }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["controlled_file_marker OR deterministic file content"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no attack response captured".into());
        };
        if !ev.marker.is_empty() && a.body.contains(&ev.marker) {
            return Verdict::Confirmed(format!("the response returned the controlled file marker {}", ev.marker));
        }
        // Signatures of files that exist on essentially every host of that kind
        // and cannot be produced by an application by accident.
        const FILE_SIGS: &[(&str, &str)] = &[
            ("root:x:0:0", "/etc/passwd"),
            ("daemon:x:1:1", "/etc/passwd"),
            ("[boot loader]", "boot.ini"),
            ("; for 16-bit app support", "win.ini"),
            ("<?php", "PHP source disclosure"),
            ("-----BEGIN RSA PRIVATE KEY-----", "a private key"),
        ];
        if let Some((sig, what)) = FILE_SIGS.iter().find(|(s, _)| a.body.contains(*s)) {
            let baseline_had = ev.baseline.as_ref().map(|b| b.body.contains(*sig)).unwrap_or(false);
            if baseline_had {
                return Verdict::Rejected(format!("the baseline response already contained {what} — not caused by the payload"));
            }
            return Verdict::Confirmed(format!("the response disclosed {what} (signature '{sig}') only under the payload"));
        }
        Verdict::NeedsReview("no file marker and no known file signature in the response".into())
    }
}

pub struct RceValidator;
impl CweValidator for RceValidator {
    fn name(&self) -> &'static str {
        "rce"
    }
    fn cwes(&self) -> &'static [&'static str] {
        &["77", "78", "94", "95", "502", "1336", "917"]
    }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["controlled side effect", "unique nonce", "output/callback confirmation"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        if ev.marker.is_empty() {
            return Verdict::NeedsReview("command execution needs a unique nonce the target could not produce on its own".into());
        }
        let echoed = ev.attack.as_ref().map(|a| a.body.contains(&ev.marker)).unwrap_or(false);
        if echoed && ev.marker_observed {
            return Verdict::Confirmed(format!("the command's output carried the nonce {} back in the response", ev.marker));
        }
        if ev.callback_received {
            return Verdict::Confirmed(format!("the executed command called back with nonce {}", ev.marker));
        }
        if echoed {
            return Verdict::NeedsReview("the nonce appears in the response but was not confirmed as command output — it may just be reflected input".into());
        }
        Verdict::NeedsReview("no nonce in the output and no callback — execution was not demonstrated".into())
    }
}

/// Crude content-similarity: fraction of the owner's distinctive tokens that
/// also appear in the other identity's response. Enough to separate "the same
/// record" from "a login page with a 200 status", which is the distinction that
/// decides an IDOR.
fn semantic_overlap(a: &str, b: &str) -> f64 {
    let toks: Vec<&str> = a
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 4)
        .collect();
    if toks.is_empty() {
        return 0.0;
    }
    let mut distinct: Vec<&str> = toks;
    distinct.sort_unstable();
    distinct.dedup();
    let hits = distinct.iter().filter(|t| b.contains(**t)).count();
    hits as f64 / distinct.len() as f64
}

pub fn validators() -> Vec<Box<dyn CweValidator>> {
    vec![
        Box::new(SqliValidator),
        Box::new(XssValidator),
        Box::new(IdorValidator),
        Box::new(SsrfValidator),
        Box::new(LfiValidator),
        Box::new(RceValidator),
    ]
}

/// The validator that owns this finding's class, if any.
pub fn validator_for(f: &Finding) -> Option<Box<dyn CweValidator>> {
    let n = cwe_num(&f.cwe);
    if !n.is_empty() {
        if let Some(v) = validators().into_iter().find(|v| v.cwes().contains(&n.as_str())) {
            return Some(v);
        }
    }
    // Fall back to the title when the agent omitted the CWE — the class is
    // still the thing being claimed, and a missing field should not silently
    // skip validation.
    let t = f.title.to_lowercase();
    let by_title: &[(&str, fn() -> Box<dyn CweValidator>)] = &[
        ("sql injection", || Box::new(SqliValidator)),
        ("sqli", || Box::new(SqliValidator)),
        ("cross-site scripting", || Box::new(XssValidator)),
        ("xss", || Box::new(XssValidator)),
        ("idor", || Box::new(IdorValidator)),
        ("broken access control", || Box::new(IdorValidator)),
        ("bola", || Box::new(IdorValidator)),
        ("ssrf", || Box::new(SsrfValidator)),
        ("server-side request forgery", || Box::new(SsrfValidator)),
        ("path traversal", || Box::new(LfiValidator)),
        ("local file inclusion", || Box::new(LfiValidator)),
        ("remote code execution", || Box::new(RceValidator)),
        ("command injection", || Box::new(RceValidator)),
    ];
    by_title.iter().find(|(k, _)| t.contains(k)).map(|(_, mk)| mk())
}

/// The final judge: the deterministic verdict, tempered by what the rest of the
/// pipeline already established.
///
/// It can **downgrade** freely and **upgrade only within its own evidence**. A
/// class with no rule keeps whatever the vote decided but can never be silently
/// promoted to confirmed by this stage — the engine's job is to remove doubt it
/// can actually remove, not to add confidence it has not measured.
pub fn judge(f: &Finding, ev: Option<&Evidence>) -> Verdict {
    let Some(v) = validator_for(f) else {
        return Verdict::NeedsReview(format!(
            "no deterministic validator for {} — kept for human review",
            if f.cwe.is_empty() { "this class" } else { &f.cwe }
        ));
    };
    let Some(ev) = ev else {
        return Verdict::NeedsReview(format!(
            "{} requires {} — none was captured",
            v.name(),
            v.evidence_required().join(", ")
        ));
    };
    v.validate(f, ev)
}

/// How forcefully the engine's verdict is applied.
///
/// Agents have to *record* the artifacts before the engine can judge them, and
/// that contract is new. Turning enforcement on everywhere at once would mark
/// every finding from an agent that hasn't adopted it as unproven — technically
/// honest, operationally a regression. So the default is advisory: contradicted
/// findings are still rejected (that is a real measurement), but a finding the
/// votes confirmed is not demoted merely because no evidence was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Engine disabled.
    Off,
    /// Record the verdict; reject contradictions; do not demote for absent evidence.
    Advisory,
    /// The verdict is the status. Nothing is confirmed without proof.
    Enforcing,
}

impl Mode {
    /// `NEUROSPLOIT_VALIDATION=off|advisory|enforcing` (default advisory).
    pub fn from_env() -> Mode {
        match std::env::var("NEUROSPLOIT_VALIDATION").unwrap_or_default().trim().to_lowercase().as_str() {
            "off" | "0" | "false" => Mode::Off,
            "enforcing" | "enforce" | "strict" | "2" => Mode::Enforcing,
            _ => Mode::Advisory,
        }
    }
}

/// Judge a finding under `mode`, using the evidence the agent recorded on it.
pub fn apply_mode(f: &mut Finding, mode: Mode) -> Option<Verdict> {
    if mode == Mode::Off {
        return None;
    }
    let ev = f.evidence_data.clone();
    let verdict = judge(f, ev.as_ref());
    match (&verdict, mode) {
        // A contradiction is a measurement, and it counts in either mode.
        (Verdict::Rejected(_), _) => {
            apply(f, ev.as_ref());
        }
        (_, Mode::Enforcing) => {
            apply(f, ev.as_ref());
        }
        (Verdict::Confirmed(r), Mode::Advisory) => {
            f.validated = true;
            f.review_status = "confirmed".into();
            f.review_reason = format!("validated deterministically: {r}");
            f.confidence = f.confidence.max(0.9);
        }
        (Verdict::NeedsReview(r), Mode::Advisory) => {
            // Leave the vote's verdict in place; say plainly that the
            // deterministic engine could not corroborate it.
            if f.review_reason.is_empty() {
                f.review_reason = format!("not deterministically verified: {r}");
            }
        }
        (_, Mode::Off) => {}
    }
    Some(verdict)
}

/// Apply the engine to a finding, updating `review_status`/`review_reason` and
/// `validated`. Returns the verdict for logging.
pub fn apply(f: &mut Finding, ev: Option<&Evidence>) -> Verdict {
    let verdict = judge(f, ev);
    match &verdict {
        Verdict::Confirmed(r) => {
            f.validated = true;
            f.review_status = "confirmed".into();
            f.review_reason = format!("validated deterministically: {r}");
            f.confidence = f.confidence.max(0.9);
        }
        Verdict::NeedsReview(r) => {
            // Never destroy a vote-confirmed finding on missing evidence — but
            // never let it claim deterministic proof either.
            f.validated = false;
            f.review_status = "needs-review".into();
            f.review_reason = r.clone();
            f.confidence = f.confidence.min(0.7);
        }
        Verdict::Rejected(r) => {
            f.validated = false;
            f.review_status = "rejected".into();
            f.review_reason = format!("validator rejected: {r}");
            f.confidence = f.confidence.min(0.3);
        }
    }
    verdict
}

/// What the engine would need to confirm this class — rendered into exploit
/// prompts so agents collect the right artifacts *while* they have the target
/// in hand, instead of being asked for them after the run.
pub fn evidence_contract() -> String {
    let mut s = String::from(
        "EVIDENCE CONTRACT — a finding is only confirmed when the harness can verify it deterministically, without a model. Collect exactly this:\n",
    );
    for v in validators() {
        s.push_str(&format!("  {:<5} {}\n", v.name(), v.evidence_required().join(" · ")));
    }
    s.push_str("  Anything else is reported as needs-review. Record the baseline request, the attack request, and any marker the harness gave you.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(status: u16, body: &str) -> Exchange {
        Exchange { method: "GET".into(), url: "https://t.test/x".into(), status, body: body.into(), ..Default::default() }
    }
    fn f(cwe: &str, title: &str) -> Finding {
        Finding { cwe: cwe.into(), title: title.into(), confidence: 0.8, ..Default::default() }
    }

    #[test]
    fn sqli_needs_a_difference_that_repeats() {
        let base = ex(200, "welcome user");
        let attack = ex(500, "You have an error in your SQL syntax near '1''");
        // One observation, no repeats: suspicious, not proven.
        let once = Evidence { baseline: Some(base.clone()), attack: Some(attack.clone()), ..Default::default() };
        assert!(matches!(judge(&f("CWE-89", "SQLi"), Some(&once)), Verdict::NeedsReview(_)));

        let repeated = Evidence {
            baseline: Some(base),
            attack: Some(attack.clone()),
            repeats: vec![attack.clone(), attack],
            ..Default::default()
        };
        match judge(&f("CWE-89", "SQLi"), Some(&repeated)) {
            Verdict::Confirmed(r) => assert!(r.contains("sql syntax"), "{r}"),
            v => panic!("expected confirmation, got {v:?}"),
        }
    }

    #[test]
    fn sqli_is_rejected_when_the_payload_changed_nothing() {
        let same = ex(200, "welcome user");
        let ev = Evidence { baseline: Some(same.clone()), attack: Some(same), ..Default::default() };
        assert!(matches!(judge(&f("CWE-89", "SQLi"), Some(&ev)), Verdict::Rejected(_)));
    }

    #[test]
    fn an_app_that_always_prints_sql_errors_does_not_count() {
        let noisy = ex(200, "debug: sql syntax error somewhere");
        let ev = Evidence {
            baseline: Some(noisy.clone()),
            attack: Some(noisy.clone()),
            repeats: vec![noisy.clone(), noisy],
            ..Default::default()
        };
        // Identical bodies: the error is not attributable to the payload.
        assert!(matches!(judge(&f("CWE-89", "SQLi"), Some(&ev)), Verdict::Rejected(_)));
    }

    #[test]
    fn reflected_xss_without_a_browser_is_not_confirmed() {
        let marker = canary("nsxss");
        let ev = Evidence {
            marker: marker.clone(),
            attack: Some(ex(200, &format!("<div>{marker}</div>"))),
            ..Default::default()
        };
        match judge(&f("CWE-79", "Reflected XSS"), Some(&ev)) {
            Verdict::NeedsReview(r) => assert!(r.contains("no browser executed it"), "{r}"),
            v => panic!("reflection alone must not confirm XSS: {v:?}"),
        }
    }

    #[test]
    fn xss_is_confirmed_only_when_the_browser_reports_the_marker() {
        let marker = canary("nsxss");
        let ev = Evidence { marker: marker.clone(), browser_executed: true, marker_observed: true, ..Default::default() };
        assert!(matches!(judge(&f("CWE-79", "XSS"), Some(&ev)), Verdict::Confirmed(_)));
    }

    #[test]
    fn idor_rejects_a_200_that_is_really_a_login_page() {
        let owner = ex(200, "invoice 4711 total 1234.56 customer alice smith account 9981");
        let mut other = ex(200, "<html><body>please sign in to continue</body></html>");
        other.identity = "userB".into();
        let mut a = owner;
        a.identity = "userA".into();
        let ev = Evidence { identity_a: Some(a), identity_b: Some(other), ..Default::default() };
        match judge(&f("CWE-639", "IDOR"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("does not match"), "{r}"),
            v => panic!("a login page with status 200 must not pass as IDOR: {v:?}"),
        }
    }

    #[test]
    fn idor_confirms_when_the_other_identity_gets_the_owners_data() {
        let body = "invoice 4711 total 1234.56 customer alice smith account 9981";
        let mut a = ex(200, body);
        a.identity = "userA".into();
        let mut b = ex(200, body);
        b.identity = "userB".into();
        let ev = Evidence { identity_a: Some(a), identity_b: Some(b), ..Default::default() };
        assert!(matches!(judge(&f("CWE-639", "IDOR"), Some(&ev)), Verdict::Confirmed(_)));
    }

    #[test]
    fn idor_rejects_when_the_control_actually_worked() {
        let mut a = ex(200, "secret record");
        a.identity = "userA".into();
        let mut b = ex(403, "forbidden");
        b.identity = "userB".into();
        let ev = Evidence { identity_a: Some(a), identity_b: Some(b), ..Default::default() };
        match judge(&f("CWE-863", "BOLA"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("denied"), "{r}"),
            v => panic!("a 403 is the control working: {v:?}"),
        }
    }

    #[test]
    fn ssrf_needs_a_callback_or_a_retrieved_resource() {
        let ev = Evidence::default();
        assert!(matches!(judge(&f("CWE-918", "SSRF"), Some(&ev)), Verdict::NeedsReview(_)));
        let ev2 = Evidence { marker: canary("nsoob"), callback_received: true, ..Default::default() };
        assert!(matches!(judge(&f("CWE-918", "SSRF"), Some(&ev2)), Verdict::Confirmed(_)));
    }

    #[test]
    fn lfi_confirms_on_a_file_signature_the_baseline_lacked() {
        let ev = Evidence {
            baseline: Some(ex(200, "normal page")),
            attack: Some(ex(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")),
            ..Default::default()
        };
        match judge(&f("CWE-22", "Path traversal"), Some(&ev)) {
            Verdict::Confirmed(r) => assert!(r.contains("/etc/passwd"), "{r}"),
            v => panic!("expected confirmation: {v:?}"),
        }
    }

    #[test]
    fn rce_rejects_a_nonce_that_is_only_reflected_input() {
        let nonce = canary("nsrce");
        let ev = Evidence { marker: nonce.clone(), attack: Some(ex(200, &format!("you searched for {nonce}"))), ..Default::default() };
        match judge(&f("CWE-78", "Command injection"), Some(&ev)) {
            Verdict::NeedsReview(r) => assert!(r.contains("reflected input"), "{r}"),
            v => panic!("reflection is not execution: {v:?}"),
        }
    }

    #[test]
    fn a_class_without_a_validator_is_never_auto_confirmed() {
        let v = judge(&f("CWE-1004", "Cookie without HttpOnly"), None);
        assert!(matches!(v, Verdict::NeedsReview(_)), "got {v:?}");
    }

    #[test]
    fn missing_evidence_is_review_not_confirmation() {
        let v = judge(&f("CWE-89", "SQL Injection in id"), None);
        match v {
            Verdict::NeedsReview(r) => assert!(r.contains("none was captured"), "{r}"),
            v => panic!("absent evidence must never confirm: {v:?}"),
        }
    }

    #[test]
    fn the_title_routes_the_finding_when_the_cwe_is_missing() {
        let mut finding = f("", "Reflected Cross-Site Scripting in search");
        let marker = canary("nsxss");
        let ev = Evidence { marker, browser_executed: true, marker_observed: true, ..Default::default() };
        let verdict = apply(&mut finding, Some(&ev));
        assert!(matches!(verdict, Verdict::Confirmed(_)));
        assert_eq!(finding.review_status, "confirmed");
        assert!(finding.validated);
    }

    #[test]
    fn apply_downgrades_confidence_when_it_cannot_prove_the_claim() {
        let mut finding = Finding { cwe: "CWE-89".into(), title: "SQLi".into(), confidence: 0.95, validated: true, ..Default::default() };
        apply(&mut finding, None);
        assert!(!finding.validated);
        assert_eq!(finding.review_status, "needs-review");
        assert!(finding.confidence <= 0.7, "confidence must not survive unproven: {}", finding.confidence);
    }

    #[test]
    fn advisory_mode_keeps_a_voted_finding_but_says_it_is_unproven() {
        let mut finding = Finding { cwe: "CWE-89".into(), title: "SQLi".into(), confidence: 0.9, validated: true, review_status: "confirmed".into(), ..Default::default() };
        apply_mode(&mut finding, Mode::Advisory);
        assert!(finding.validated, "advisory must not demote on absent evidence");
        assert!(finding.review_reason.contains("not deterministically verified"), "{}", finding.review_reason);
    }

    #[test]
    fn enforcing_mode_demotes_the_same_finding() {
        let mut finding = Finding { cwe: "CWE-89".into(), title: "SQLi".into(), confidence: 0.9, validated: true, review_status: "confirmed".into(), ..Default::default() };
        apply_mode(&mut finding, Mode::Enforcing);
        assert!(!finding.validated);
        assert_eq!(finding.review_status, "needs-review");
    }

    #[test]
    fn a_contradiction_is_rejected_even_in_advisory_mode() {
        let same = ex(200, "welcome user");
        let mut finding = Finding {
            cwe: "CWE-89".into(),
            title: "SQLi".into(),
            confidence: 0.9,
            validated: true,
            evidence_data: Some(Evidence { baseline: Some(same.clone()), attack: Some(same), ..Default::default() }),
            ..Default::default()
        };
        apply_mode(&mut finding, Mode::Advisory);
        assert_eq!(finding.review_status, "rejected");
    }

    #[test]
    fn canaries_do_not_repeat() {
        // The regression: minting two in the same clock tick returned the same
        // token, which would let a stale marker vouch for a new finding.
        let batch: Vec<String> = (0..500).map(|_| canary("ns")).collect();
        let mut uniq = batch.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), batch.len(), "canaries must be unique even when minted back to back");
        assert!(batch[0].starts_with("ns") && batch[0].len() > 8);
    }
}
