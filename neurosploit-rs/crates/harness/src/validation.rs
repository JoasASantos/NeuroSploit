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
    /// Response headers, lowercased keys. Several classes are decided entirely
    /// by a header (`Location`, `Set-Cookie`, `Access-Control-Allow-*`), so the
    /// body alone is not enough evidence for them.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Request headers that mattered (Origin, Cookie, Authorization). Kept
    /// separate because "what we sent" and "what came back" answer different
    /// questions.
    #[serde(default)]
    pub request_headers: std::collections::BTreeMap<String, String>,
}

impl Exchange {
    pub fn len(&self) -> usize {
        self.body.len()
    }
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
    /// Case-insensitive response header lookup.
    pub fn header(&self, name: &str) -> &str {
        let n = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == n)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
    pub fn request_header(&self, name: &str) -> &str {
        let n = name.to_lowercase();
        self.request_headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == n)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
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
    // Attribution rides along with the marker: a canary that resurfaces in a
    // customer's logs, a corpus, or someone else's report should say whose
    // engine minted it without anyone having to ask. See `crate::provenance`.
    // Opt out with NEUROSPLOIT_WATERMARK=off where payload length is the
    // constraint (a reflected field with a hard character limit).
    let sigil = if watermarks_on() { crate::provenance::SIGIL } else { "" };
    format!("{sigil}{prefix}{:012x}", h & 0xffff_ffff_ffff)
}

/// Watermarking is on unless the operator turned it off.
pub fn watermarks_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NEUROSPLOIT_WATERMARK").unwrap_or_default().trim().to_lowercase() != "off")
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
        &["77", "78", "94", "95", "502", "917"]
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

pub struct OpenRedirectValidator;
impl CweValidator for OpenRedirectValidator {
    fn name(&self) -> &'static str { "redirect" }
    fn cwes(&self) -> &'static [&'static str] { &["601"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["3xx response", "Location header pointing at an attacker-controlled host"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no attack response captured".into());
        };
        let loc = a.header("location");
        if loc.is_empty() {
            // A redirect parameter that renders a link is not a redirect.
            return Verdict::Rejected("no Location header — the response does not redirect".into());
        }
        let target_host = crate::scope::host_of(&a.url);
        let dest_host = crate::scope::host_of(loc);
        if !a.is_redirect() {
            return Verdict::NeedsReview(format!("Location present but status is {} — not a redirect", a.status));
        }
        if dest_host.is_empty() || dest_host == target_host {
            return Verdict::Rejected(format!("redirect stays on {target_host} — same-origin redirects are not open redirects"));
        }
        Verdict::Confirmed(format!("{} redirect to off-site host {dest_host} (Location: {loc})", a.status))
    }
}

pub struct XxeValidator;
impl CweValidator for XxeValidator {
    fn name(&self) -> &'static str { "xxe" }
    fn cwes(&self) -> &'static [&'static str] { &["611", "776", "827"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["controlled entity retrieval (file marker or canary URL) OR out-of-band callback"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        if ev.callback_received && !ev.marker.is_empty() {
            return Verdict::Confirmed(format!("the parser fetched the external entity and called back with {}", ev.marker));
        }
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no attack response captured".into());
        };
        if !ev.marker.is_empty() && a.body.contains(&ev.marker) {
            return Verdict::Confirmed(format!("the response echoed the entity's controlled content ({})", ev.marker));
        }
        if a.body.contains("root:x:0:0") && ev.baseline.as_ref().map(|b| !b.body.contains("root:x:0:0")).unwrap_or(true) {
            return Verdict::Confirmed("the parsed document disclosed /etc/passwd through an external entity".into());
        }
        // An XML parse error proves the parser read the doctype, not that it
        // resolved anything — a very common overclaim in this class.
        let parse_error = ["entity", "doctype", "xml parsing", "saxparse"].iter().any(|k| a.body.to_lowercase().contains(k));
        if parse_error {
            return Verdict::NeedsReview("only a parser error mentioning entities — that shows the DTD was read, not that an entity resolved".into());
        }
        Verdict::NeedsReview("no entity content and no callback — XXE was not demonstrated".into())
    }
}

pub struct SstiValidator;
impl CweValidator for SstiValidator {
    fn name(&self) -> &'static str { "ssti" }
    fn cwes(&self) -> &'static [&'static str] { &["1336"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["arithmetic/expression oracle evaluated server-side", "result absent from the payload itself"]
    }
    fn validate(&self, f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no attack response captured".into());
        };
        // The oracle: the response must contain the RESULT of an expression
        // that never appears literally in what was sent. Otherwise the "proof"
        // is just the payload being echoed back.
        let sent = format!("{} {}", f.payload, a.url);
        if !ev.marker.is_empty() {
            let evaluated = a.body.contains(&ev.marker) && !sent.contains(&ev.marker);
            if evaluated {
                return Verdict::Confirmed(format!("the template engine evaluated the expression and produced {}", ev.marker));
            }
            if a.body.contains(&ev.marker) {
                return Verdict::Rejected("the marker appears in the response but was also present in the request — that is reflection, not evaluation".into());
            }
        }
        for (expr, result) in [("7*7", "49"), ("7*'7'", "7777777"), ("1337*2", "2674")] {
            if sent.contains(expr) && a.body.contains(result) && !sent.contains(result) {
                let baseline_had = ev.baseline.as_ref().map(|b| b.body.contains(result)).unwrap_or(false);
                if baseline_had {
                    return Verdict::Rejected(format!("'{result}' already appears in the baseline response — not produced by the payload"));
                }
                return Verdict::Confirmed(format!("expression '{expr}' evaluated server-side to '{result}'"));
            }
        }
        Verdict::NeedsReview("no evaluated expression observed — template injection needs an oracle whose result was never sent".into())
    }
}

pub struct CorsValidator;
impl CweValidator for CorsValidator {
    fn name(&self) -> &'static str { "cors" }
    fn cwes(&self) -> &'static [&'static str] { &["942", "346", "1385"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["request Origin", "Access-Control-Allow-Origin reflecting it", "Access-Control-Allow-Credentials: true"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no response captured".into());
        };
        let acao = a.header("access-control-allow-origin");
        let acac = a.header("access-control-allow-credentials").eq_ignore_ascii_case("true");
        let origin = a.request_header("origin");
        if acao.is_empty() {
            return Verdict::Rejected("no Access-Control-Allow-Origin in the response — CORS is not enabled here".into());
        }
        if acao == "*" {
            return if acac {
                // Browsers refuse this combination outright, so it is a
                // misconfiguration that cannot actually be exploited.
                Verdict::NeedsReview("ACAO '*' with credentials is rejected by browsers — a misconfiguration, not an exploitable one".into())
            } else {
                Verdict::Rejected("ACAO '*' without credentials exposes only data any client could already read anonymously".into())
            };
        }
        if !origin.is_empty() && acao.eq_ignore_ascii_case(origin) {
            return if acac {
                Verdict::Confirmed(format!("the app reflected attacker Origin '{origin}' into ACAO with credentials enabled — cross-origin reads of authenticated data"))
            } else {
                Verdict::NeedsReview(format!("Origin '{origin}' is reflected but credentials are not allowed — only unauthenticated data is exposed"))
            };
        }
        Verdict::Rejected(format!("ACAO is a fixed value ('{acao}'), not a reflection of the sent Origin"))
    }
}

pub struct CookieFlagsValidator;
impl CweValidator for CookieFlagsValidator {
    fn name(&self) -> &'static str { "cookie" }
    fn cwes(&self) -> &'static [&'static str] { &["614", "1004", "1275", "1018"] }
    fn evidence_required(&self) -> &'static [&'static str] { &["Set-Cookie header", "the URL's scheme"] }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = ev.attack.as_ref().or(ev.baseline.as_ref()) else {
            return Verdict::NeedsReview("no response with a Set-Cookie header captured".into());
        };
        let sc = a.header("set-cookie");
        if sc.is_empty() {
            return Verdict::Rejected("the response sets no cookie".into());
        }
        let low = sc.to_lowercase();
        let https = a.url.starts_with("https://");
        let mut missing = Vec::new();
        if !low.contains("httponly") {
            missing.push("HttpOnly");
        }
        if https && !low.contains("secure") {
            missing.push("Secure");
        }
        if !low.contains("samesite") {
            missing.push("SameSite");
        }
        if low.contains("samesite=none") && !low.contains("secure") {
            missing.push("Secure (required with SameSite=None)");
        }
        if missing.is_empty() {
            return Verdict::Rejected("the cookie carries HttpOnly, Secure and SameSite".into());
        }
        // Fully decidable from the header — no interpretation needed.
        Verdict::Confirmed(format!("Set-Cookie is missing {} ({})", missing.join(", "), short_header(sc)))
    }
}

pub struct ClickjackingValidator;
impl CweValidator for ClickjackingValidator {
    fn name(&self) -> &'static str { "framing" }
    fn cwes(&self) -> &'static [&'static str] { &["1021"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["absence of X-Frame-Options AND of CSP frame-ancestors on a state-changing page"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = ev.attack.as_ref().or(ev.baseline.as_ref()) else {
            return Verdict::NeedsReview("no response captured".into());
        };
        let xfo = a.header("x-frame-options");
        let csp = a.header("content-security-policy").to_lowercase();
        if !xfo.is_empty() {
            return Verdict::Rejected(format!("X-Frame-Options: {xfo} is present"));
        }
        if csp.contains("frame-ancestors") {
            return Verdict::Rejected("CSP frame-ancestors is set".into());
        }
        if ev.browser_executed && ev.marker_observed {
            return Verdict::Confirmed("the page rendered inside an attacker-controlled frame in a real browser".into());
        }
        Verdict::Confirmed("neither X-Frame-Options nor CSP frame-ancestors is set — the page can be framed".into())
    }
}

pub struct AuthBypassValidator;
impl CweValidator for AuthBypassValidator {
    fn name(&self) -> &'static str { "authz" }
    fn cwes(&self) -> &'static [&'static str] { &["306", "287", "288", "289", "302"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["authenticated response", "same request WITHOUT credentials", "protected content returned anyway"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let (Some(a), Some(b)) = (&ev.identity_a, &ev.identity_b) else {
            return Verdict::NeedsReview("needs the authenticated response and the unauthenticated one to compare".into());
        };
        if !b.request_header("authorization").is_empty() || !b.request_header("cookie").is_empty() {
            return Verdict::Rejected("the 'unauthenticated' request still carried credentials — nothing was bypassed".into());
        }
        if b.status == 401 || b.status == 403 {
            return Verdict::Rejected(format!("the anonymous request was denied ({}) — authentication is enforced", b.status));
        }
        if b.is_redirect() {
            let loc = b.header("location").to_lowercase();
            if loc.contains("login") || loc.contains("signin") || loc.contains("auth") {
                return Verdict::Rejected("the anonymous request was redirected to login — the control works".into());
            }
        }
        if !b.is_success() {
            return Verdict::Rejected(format!("the anonymous request got {} — no content was obtained", b.status));
        }
        let overlap = semantic_overlap(&a.body, &b.body);
        if overlap < 0.6 {
            return Verdict::Rejected(format!("anonymous got 200 but the body does not match the protected resource ({:.0}% overlap)", overlap * 100.0));
        }
        Verdict::Confirmed(format!("the protected resource was served without credentials ({:.0}% content match)", overlap * 100.0))
    }
}

pub struct JwtValidator;
impl CweValidator for JwtValidator {
    fn name(&self) -> &'static str { "jwt" }
    fn cwes(&self) -> &'static [&'static str] { &["347", "345", "290"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["a forged/modified token", "the server accepting it", "privileged content returned"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let (Some(a), Some(b)) = (&ev.identity_a, &ev.identity_b) else {
            return Verdict::NeedsReview("needs a legitimate response and one made with the forged token".into());
        };
        let forged = b.request_header("authorization");
        if forged.is_empty() {
            return Verdict::NeedsReview("the forged token was not recorded on the request".into());
        }
        if b.status == 401 || b.status == 403 {
            return Verdict::Rejected(format!("the forged token was rejected ({}) — the signature is verified", b.status));
        }
        if !b.is_success() {
            return Verdict::Rejected(format!("the forged token produced {} — no access was obtained", b.status));
        }
        let overlap = semantic_overlap(&a.body, &b.body);
        if overlap < 0.5 {
            return Verdict::Rejected(format!("200 with the forged token, but the content is not the privileged resource ({:.0}% overlap)", overlap * 100.0));
        }
        Verdict::Confirmed(format!("the server accepted a forged token and returned privileged content ({:.0}% match)", overlap * 100.0))
    }
}

pub struct RateLimitValidator;
impl CweValidator for RateLimitValidator {
    fn name(&self) -> &'static str { "ratelimit" }
    fn cwes(&self) -> &'static [&'static str] { &["307", "799", "770"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["a burst of attempts", "no 429/lockout across them", ">= 20 attempts"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        const MIN_ATTEMPTS: usize = 20;
        let n = ev.repeats.len();
        if n < MIN_ATTEMPTS {
            return Verdict::NeedsReview(format!(
                "only {n} attempt(s) recorded — absence of throttling needs at least {MIN_ATTEMPTS} to distinguish it from a limit that was never reached"
            ));
        }
        if let Some(blocked) = ev.repeats.iter().find(|r| r.status == 429 || r.status == 423) {
            return Verdict::Rejected(format!("attempt was throttled with {} — rate limiting is enforced", blocked.status));
        }
        if ev.repeats.iter().any(|r| !r.header("retry-after").is_empty()) {
            return Verdict::Rejected("the server returned Retry-After — throttling is in place".into());
        }
        Verdict::Confirmed(format!("{n} consecutive attempts, none throttled (no 429, no lockout, no Retry-After)"))
    }
}

pub struct SessionFixationValidator;
impl CweValidator for SessionFixationValidator {
    fn name(&self) -> &'static str { "session" }
    fn cwes(&self) -> &'static [&'static str] { &["384"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["session id before authentication", "session id after authentication", "they are identical"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let (Some(before), Some(after)) = (&ev.baseline, &ev.attack) else {
            return Verdict::NeedsReview("needs the pre-login and post-login responses".into());
        };
        let pre = session_id(before.header("set-cookie")).or_else(|| session_id(before.request_header("cookie")));
        let post = session_id(after.header("set-cookie")).or_else(|| session_id(after.request_header("cookie")));
        let (Some(pre), Some(post)) = (pre, post) else {
            return Verdict::NeedsReview("no session cookie was captured on one of the two responses".into());
        };
        if pre == post {
            Verdict::Confirmed(format!("the session id survived authentication unchanged ({}…)", &pre[..pre.len().min(8)]))
        } else {
            Verdict::Rejected("the session id was regenerated at login — fixation is prevented".into())
        }
    }
}

pub struct MassAssignmentValidator;
impl CweValidator for MassAssignmentValidator {
    fn name(&self) -> &'static str { "massassign" }
    fn cwes(&self) -> &'static [&'static str] { &["915", "913"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["request setting a privileged field", "read-back confirming it changed"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no attack request captured".into());
        };
        if !a.is_success() {
            return Verdict::Rejected(format!("the write was refused ({})", a.status));
        }
        // A 200 on the write proves nothing: many APIs accept and ignore extra
        // fields. Only the read-back decides it.
        let Some(verify) = &ev.identity_a else {
            return Verdict::NeedsReview("the write succeeded, but without a read-back the field may simply have been ignored".into());
        };
        if ev.marker.is_empty() {
            return Verdict::NeedsReview("needs a unique value for the privileged field so the read-back is unambiguous".into());
        }
        if verify.body.contains(&ev.marker) {
            Verdict::Confirmed(format!("the privileged field was persisted and read back ({})", ev.marker))
        } else {
            Verdict::Rejected("the read-back does not contain the injected value — the extra field was accepted and ignored".into())
        }
    }
}

pub struct CsrfValidator;
impl CweValidator for CsrfValidator {
    fn name(&self) -> &'static str { "csrf" }
    fn cwes(&self) -> &'static [&'static str] { &["352"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["state-changing request without a token / with a foreign Origin", "the change taking effect"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no cross-origin request captured".into());
        };
        if a.method.eq_ignore_ascii_case("GET") {
            return Verdict::NeedsReview("a GET is not a state change — CSRF needs the request that mutates".into());
        }
        if a.status == 403 || a.status == 419 || a.status == 401 {
            return Verdict::Rejected(format!("the request without a valid token was refused ({})", a.status));
        }
        if !a.is_success() && !a.is_redirect() {
            return Verdict::Rejected(format!("the request returned {} — no state change", a.status));
        }
        // SameSite=Lax/Strict on the session cookie stops the classic attack, so
        // a "successful" replay from a test harness would not work from a real
        // attacker page.
        let sc = a.header("set-cookie").to_lowercase();
        if sc.contains("samesite=strict") || sc.contains("samesite=lax") {
            return Verdict::NeedsReview("the session cookie is SameSite — a browser would not attach it cross-site, so this is likely not exploitable".into());
        }
        let Some(verify) = &ev.identity_a else {
            return Verdict::NeedsReview("the request succeeded, but without a read-back there is no proof the state actually changed".into());
        };
        if !ev.marker.is_empty() && verify.body.contains(&ev.marker) {
            return Verdict::Confirmed(format!("a cross-origin state change took effect and was read back ({})", ev.marker));
        }
        Verdict::NeedsReview("the read-back does not show the injected change".into())
    }
}

pub struct ExposureValidator;
impl CweValidator for ExposureValidator {
    fn name(&self) -> &'static str { "exposure" }
    fn cwes(&self) -> &'static [&'static str] { &["200", "538", "540", "548", "312", "532"] }
    fn evidence_required(&self) -> &'static [&'static str] {
        &["a 2xx response", "a recognizable secret/listing signature absent from the baseline"]
    }
    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        let Some(a) = &ev.attack else {
            return Verdict::NeedsReview("no response captured".into());
        };
        if !a.is_success() {
            return Verdict::Rejected(format!("the resource returned {} — nothing was exposed", a.status));
        }
        // A soft-404 that returns the site's normal page with status 200 is the
        // most common false positive for "exposed file".
        if let Some(b) = &ev.baseline {
            if semantic_overlap(&b.body, &a.body) > 0.9 && b.status == a.status {
                return Verdict::Rejected("the response is identical to the baseline/404 page — a soft-404, not an exposed resource".into());
            }
        }
        const SIGS: &[(&str, &str)] = &[
            ("-----BEGIN RSA PRIVATE KEY-----", "an RSA private key"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "an OpenSSH private key"),
            ("aws_secret_access_key", "AWS credentials"),
            ("AKIA", "an AWS access key id"),
            ("Index of /", "a directory listing"),
            ("<ListBucketResult", "an open object-storage bucket"),
            ("DB_PASSWORD=", "a .env file"),
            ("BEGIN CERTIFICATE", "a certificate"),
            ("[core]\nrepositoryformatversion", "a .git directory"),
        ];
        if let Some((sig, what)) = SIGS.iter().find(|(s, _)| a.body.contains(*s)) {
            let baseline_had = ev.baseline.as_ref().map(|b| b.body.contains(*sig)).unwrap_or(false);
            if baseline_had {
                return Verdict::Rejected(format!("{what} also appears in the baseline — not specific to this path"));
            }
            return Verdict::Confirmed(format!("the resource disclosed {what}"));
        }
        Verdict::NeedsReview("200 with no recognizable secret or listing signature — the impact has to be judged by a human".into())
    }
}

/// First 80 characters of a header value, for a readable verdict.
fn short_header(v: &str) -> String {
    v.chars().take(80).collect()
}

/// Extract a session identifier value from a Cookie/Set-Cookie header.
fn session_id(header: &str) -> Option<String> {
    const NAMES: &[&str] = &["sessionid", "session_id", "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid", "session", "sid"];
    for part in header.split(';') {
        let p = part.trim();
        let (k, v) = p.split_once('=')?;
        let key = k.trim().to_lowercase();
        if NAMES.iter().any(|n| key == *n) && !v.trim().is_empty() {
            return Some(v.trim().to_string());
        }
    }
    None
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
        Box::new(SstiValidator),
        Box::new(XxeValidator),
        Box::new(OpenRedirectValidator),
        Box::new(CorsValidator),
        Box::new(CookieFlagsValidator),
        Box::new(ClickjackingValidator),
        Box::new(AuthBypassValidator),
        Box::new(JwtValidator),
        Box::new(RateLimitValidator),
        Box::new(SessionFixationValidator),
        Box::new(MassAssignmentValidator),
        Box::new(CsrfValidator),
        Box::new(ExposureValidator),
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
        ("template injection", || Box::new(SstiValidator)),
        ("ssti", || Box::new(SstiValidator)),
        ("xxe", || Box::new(XxeValidator)),
        ("xml external entity", || Box::new(XxeValidator)),
        ("open redirect", || Box::new(OpenRedirectValidator)),
        ("cors", || Box::new(CorsValidator)),
        ("cookie", || Box::new(CookieFlagsValidator)),
        ("clickjacking", || Box::new(ClickjackingValidator)),
        ("authentication bypass", || Box::new(AuthBypassValidator)),
        ("missing authentication", || Box::new(AuthBypassValidator)),
        ("unauthenticated access", || Box::new(AuthBypassValidator)),
        ("jwt", || Box::new(JwtValidator)),
        ("rate limit", || Box::new(RateLimitValidator)),
        ("brute force", || Box::new(RateLimitValidator)),
        ("session fixation", || Box::new(SessionFixationValidator)),
        ("mass assignment", || Box::new(MassAssignmentValidator)),
        ("csrf", || Box::new(CsrfValidator)),
        ("cross-site request forgery", || Box::new(CsrfValidator)),
        ("directory listing", || Box::new(ExposureValidator)),
        ("information disclosure", || Box::new(ExposureValidator)),
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

    fn exh(status: u16, body: &str, headers: &[(&str, &str)]) -> Exchange {
        let mut e = ex(status, body);
        for (k, v) in headers {
            e.headers.insert((*k).to_string(), (*v).to_string());
        }
        e
    }

    #[test]
    fn open_redirect_needs_a_location_off_site() {
        let same = Evidence { attack: Some(exh(302, "", &[("Location", "/dashboard")])), ..Default::default() };
        assert!(matches!(judge(&f("CWE-601", "Open redirect"), Some(&same)), Verdict::Rejected(_)));

        let mut off = exh(302, "", &[("Location", "https://evil.test/steal")]);
        off.url = "https://t.test/go?next=https://evil.test".into();
        let ev = Evidence { attack: Some(off), ..Default::default() };
        match judge(&f("CWE-601", "Open redirect"), Some(&ev)) {
            Verdict::Confirmed(r) => assert!(r.contains("evil.test"), "{r}"),
            v => panic!("expected confirmation, got {v:?}"),
        }
    }

    #[test]
    fn a_reflected_redirect_parameter_without_a_location_is_rejected() {
        let ev = Evidence { attack: Some(ex(200, "<a href=https://evil.test>click</a>")), ..Default::default() };
        match judge(&f("CWE-601", "Open redirect"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("does not redirect"), "{r}"),
            v => panic!("a rendered link is not a redirect: {v:?}"),
        }
    }

    #[test]
    fn xxe_rejects_a_parser_error_as_proof() {
        let ev = Evidence { attack: Some(ex(500, "SAXParseException: undefined entity 'xxe'")), ..Default::default() };
        match judge(&f("CWE-611", "XXE"), Some(&ev)) {
            Verdict::NeedsReview(r) => assert!(r.contains("not that an entity resolved"), "{r}"),
            v => panic!("a parser error is not entity resolution: {v:?}"),
        }
        let ev2 = Evidence { marker: canary("nsxxe"), callback_received: true, ..Default::default() };
        assert!(matches!(judge(&f("CWE-611", "XXE"), Some(&ev2)), Verdict::Confirmed(_)));
    }

    #[test]
    fn ssti_requires_the_result_to_be_absent_from_what_was_sent() {
        let mut finding = f("CWE-1336", "SSTI");
        finding.payload = "{{7*7}}".into();
        let ev = Evidence {
            baseline: Some(ex(200, "hello")),
            attack: Some(ex(200, "hello 49")),
            ..Default::default()
        };
        match judge(&finding, Some(&ev)) {
            Verdict::Confirmed(r) => assert!(r.contains("49"), "{r}"),
            v => panic!("expected evaluation to confirm: {v:?}"),
        }

        // The trap: the payload itself already contained the "result".
        let mut echo = f("CWE-1336", "SSTI");
        echo.payload = "{{7*7}} 49".into();
        let ev2 = Evidence { attack: Some(ex(200, "you said {{7*7}} 49")), ..Default::default() };
        assert!(!matches!(judge(&echo, Some(&ev2)), Verdict::Confirmed(_)), "reflection must not confirm SSTI");
    }

    #[test]
    fn cors_confirms_only_reflection_plus_credentials() {
        let mut a = exh(200, "{}", &[("Access-Control-Allow-Origin", "https://evil.test"), ("Access-Control-Allow-Credentials", "true")]);
        a.request_headers.insert("Origin".into(), "https://evil.test".into());
        let ev = Evidence { attack: Some(a), ..Default::default() };
        assert!(matches!(judge(&f("CWE-942", "CORS misconfiguration"), Some(&ev)), Verdict::Confirmed(_)));

        // Wildcard without credentials exposes nothing an anonymous client
        // could not already read.
        let ev2 = Evidence { attack: Some(exh(200, "{}", &[("Access-Control-Allow-Origin", "*")])), ..Default::default() };
        assert!(matches!(judge(&f("CWE-942", "CORS"), Some(&ev2)), Verdict::Rejected(_)));
    }

    #[test]
    fn cookie_flags_are_decided_entirely_by_the_header() {
        let mut good = exh(200, "", &[("Set-Cookie", "sid=abc; HttpOnly; Secure; SameSite=Lax")]);
        good.url = "https://t.test/".into();
        let ev = Evidence { attack: Some(good), ..Default::default() };
        assert!(matches!(judge(&f("CWE-614", "Insecure cookie"), Some(&ev)), Verdict::Rejected(_)));

        let mut bad = exh(200, "", &[("Set-Cookie", "sid=abc; Path=/")]);
        bad.url = "https://t.test/".into();
        let ev2 = Evidence { attack: Some(bad), ..Default::default() };
        match judge(&f("CWE-1004", "Cookie without HttpOnly"), Some(&ev2)) {
            Verdict::Confirmed(r) => {
                assert!(r.contains("HttpOnly") && r.contains("Secure") && r.contains("SameSite"), "{r}");
            }
            v => panic!("a header-only class must be decidable: {v:?}"),
        }
    }

    #[test]
    fn clickjacking_is_rejected_when_either_control_is_present() {
        let ev = Evidence { attack: Some(exh(200, "", &[("X-Frame-Options", "DENY")])), ..Default::default() };
        assert!(matches!(judge(&f("CWE-1021", "Clickjacking"), Some(&ev)), Verdict::Rejected(_)));
        let ev2 = Evidence { attack: Some(exh(200, "", &[("Content-Security-Policy", "frame-ancestors 'none'")])), ..Default::default() };
        assert!(matches!(judge(&f("CWE-1021", "Clickjacking"), Some(&ev2)), Verdict::Rejected(_)));
        let ev3 = Evidence { attack: Some(ex(200, "page")), ..Default::default() };
        assert!(matches!(judge(&f("CWE-1021", "Clickjacking"), Some(&ev3)), Verdict::Confirmed(_)));
    }

    #[test]
    fn auth_bypass_rejects_a_request_that_still_carried_credentials() {
        let mut a = ex(200, "admin panel users list 4711");
        a.identity = "admin".into();
        let mut b = ex(200, "admin panel users list 4711");
        b.request_headers.insert("Cookie".into(), "sid=stolen".into());
        let ev = Evidence { identity_a: Some(a.clone()), identity_b: Some(b), ..Default::default() };
        match judge(&f("CWE-306", "Missing authentication"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("still carried credentials"), "{r}"),
            v => panic!("that is not a bypass: {v:?}"),
        }

        let anon = ex(200, "admin panel users list 4711");
        let ev2 = Evidence { identity_a: Some(a), identity_b: Some(anon), ..Default::default() };
        assert!(matches!(judge(&f("CWE-306", "Missing authentication"), Some(&ev2)), Verdict::Confirmed(_)));
    }

    #[test]
    fn auth_bypass_rejects_a_redirect_to_login() {
        let mut a = ex(200, "protected content here for real");
        a.identity = "user".into();
        let b = exh(302, "", &[("Location", "/login?next=/admin")]);
        let ev = Evidence { identity_a: Some(a), identity_b: Some(b), ..Default::default() };
        match judge(&f("CWE-306", "Missing authentication"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("login"), "{r}"),
            v => panic!("a login redirect is the control working: {v:?}"),
        }
    }

    #[test]
    fn a_forged_jwt_that_is_refused_is_not_a_finding() {
        let mut a = ex(200, "account balance 4711 owner alice");
        a.identity = "alice".into();
        let mut b = ex(401, "invalid signature");
        b.request_headers.insert("Authorization".into(), "Bearer forged.token.here".into());
        let ev = Evidence { identity_a: Some(a), identity_b: Some(b), ..Default::default() };
        match judge(&f("CWE-347", "JWT signature not verified"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("signature is verified"), "{r}"),
            v => panic!("401 means the check works: {v:?}"),
        }
    }

    #[test]
    fn missing_rate_limiting_needs_a_real_burst() {
        let few = Evidence { repeats: (0..5).map(|_| ex(200, "ok")).collect(), ..Default::default() };
        match judge(&f("CWE-307", "No rate limiting"), Some(&few)) {
            Verdict::NeedsReview(r) => assert!(r.contains("at least"), "{r}"),
            v => panic!("five attempts prove nothing: {v:?}"),
        }
        let burst = Evidence { repeats: (0..25).map(|_| ex(200, "ok")).collect(), ..Default::default() };
        assert!(matches!(judge(&f("CWE-307", "No rate limiting"), Some(&burst)), Verdict::Confirmed(_)));

        let mut throttled: Vec<Exchange> = (0..25).map(|_| ex(200, "ok")).collect();
        throttled[20] = ex(429, "slow down");
        let ev = Evidence { repeats: throttled, ..Default::default() };
        assert!(matches!(judge(&f("CWE-307", "No rate limiting"), Some(&ev)), Verdict::Rejected(_)));
    }

    #[test]
    fn session_fixation_compares_the_id_across_login() {
        let before = exh(200, "", &[("Set-Cookie", "JSESSIONID=AAAA1111; Path=/")]);
        let after_same = exh(302, "", &[("Set-Cookie", "JSESSIONID=AAAA1111; Path=/")]);
        let ev = Evidence { baseline: Some(before.clone()), attack: Some(after_same), ..Default::default() };
        assert!(matches!(judge(&f("CWE-384", "Session fixation"), Some(&ev)), Verdict::Confirmed(_)));

        let after_new = exh(302, "", &[("Set-Cookie", "JSESSIONID=BBBB2222; Path=/")]);
        let ev2 = Evidence { baseline: Some(before), attack: Some(after_new), ..Default::default() };
        assert!(matches!(judge(&f("CWE-384", "Session fixation"), Some(&ev2)), Verdict::Rejected(_)));
    }

    #[test]
    fn mass_assignment_needs_the_read_back_not_just_a_200() {
        let marker = canary("nsma");
        let ev = Evidence { marker: marker.clone(), attack: Some(ex(200, "updated")), ..Default::default() };
        match judge(&f("CWE-915", "Mass assignment"), Some(&ev)) {
            Verdict::NeedsReview(r) => assert!(r.contains("read-back"), "{r}"),
            v => panic!("APIs accept and ignore extra fields all the time: {v:?}"),
        }
        let body = format!("{{\"role\":\"{marker}\"}}");
        let ev2 = Evidence {
            marker: marker.clone(),
            attack: Some(ex(200, "updated")),
            identity_a: Some(ex(200, &body)),
            ..Default::default()
        };
        assert!(matches!(judge(&f("CWE-915", "Mass assignment"), Some(&ev2)), Verdict::Confirmed(_)));
    }

    #[test]
    fn csrf_is_not_claimed_when_the_cookie_is_samesite() {
        let mut a = exh(200, "ok", &[("Set-Cookie", "sid=x; SameSite=Lax")]);
        a.method = "POST".into();
        let ev = Evidence { attack: Some(a), ..Default::default() };
        match judge(&f("CWE-352", "CSRF"), Some(&ev)) {
            Verdict::NeedsReview(r) => assert!(r.contains("SameSite"), "{r}"),
            v => panic!("a browser would not attach that cookie cross-site: {v:?}"),
        }
    }

    #[test]
    fn csrf_rejects_a_get_and_a_refused_post() {
        let mut g = ex(200, "ok");
        g.method = "GET".into();
        assert!(matches!(judge(&f("CWE-352", "CSRF"), Some(&Evidence { attack: Some(g), ..Default::default() })), Verdict::NeedsReview(_)));
        let mut p = ex(403, "csrf token mismatch");
        p.method = "POST".into();
        assert!(matches!(judge(&f("CWE-352", "CSRF"), Some(&Evidence { attack: Some(p), ..Default::default() })), Verdict::Rejected(_)));
    }

    #[test]
    fn exposure_rejects_a_soft_404() {
        let page = "welcome to our site, nothing here, please use the navigation menu above";
        let ev = Evidence { baseline: Some(ex(200, page)), attack: Some(ex(200, page)), ..Default::default() };
        match judge(&f("CWE-548", "Directory listing exposed"), Some(&ev)) {
            Verdict::Rejected(r) => assert!(r.contains("soft-404"), "{r}"),
            v => panic!("a soft-404 is the classic false positive here: {v:?}"),
        }
    }

    #[test]
    fn exposure_confirms_a_real_secret_signature() {
        let ev = Evidence {
            baseline: Some(ex(404, "not found")),
            attack: Some(ex(200, "DB_PASSWORD=hunter2\nAPP_KEY=xyz")),
            ..Default::default()
        };
        match judge(&f("CWE-200", "Exposed .env"), Some(&ev)) {
            Verdict::Confirmed(r) => assert!(r.contains(".env"), "{r}"),
            v => panic!("expected confirmation: {v:?}"),
        }
    }

    #[test]
    fn every_validator_declares_what_it_needs() {
        for v in validators() {
            assert!(!v.cwes().is_empty(), "{} owns no CWE", v.name());
            assert!(!v.evidence_required().is_empty(), "{} states no evidence contract", v.name());
        }
    }

    #[test]
    fn no_two_validators_claim_the_same_cwe() {
        // Ambiguous ownership would make routing depend on registration order,
        // which is how a class silently gets the wrong rule.
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for v in validators() {
            for c in v.cwes() {
                if let Some((other, _)) = seen.iter().find(|(_, cwe)| cwe == c) {
                    panic!("CWE-{c} is claimed by both {} and {}", other, v.name());
                }
                seen.push((v.name(), c));
            }
        }
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
        // The sigil leads so a marker found anywhere later extracts whole.
        assert!(batch[0].starts_with(crate::provenance::SIGIL), "got {}", batch[0]);
        assert!(batch[0].contains("ns") && batch[0].len() > 8);
    }
}
