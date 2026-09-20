//! Attack graph & kill-chain mapping.
//!
//! Enriches findings with OWASP Top 10 / MITRE ATT&CK / kill-chain stage /
//! exploitability (derived from CWE + severity when the model didn't supply
//! them), then renders an attack-path graph (Mermaid) and a kill-chain table for
//! the report, plus a compact ASCII summary for the REPL.

use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// CWE → (OWASP Top 10 2021, MITRE ATT&CK technique, kill-chain stage).
fn map_cwe(cwe: &str) -> (&'static str, &'static str, &'static str) {
    let n: u32 = cwe.trim_start_matches("CWE-").parse().unwrap_or(0);
    match n {
        89 | 943 => ("A03:2021-Injection", "T1190", "initial-access"),
        77 | 78 | 94 | 95 | 917 | 1336 => ("A03:2021-Injection", "T1059", "execution"),
        79 | 80 => ("A03:2021-Injection", "T1059.007", "execution"),
        90 => ("A03:2021-Injection", "T1190", "initial-access"),
        611 | 776 => ("A05:2021-Security-Misconfiguration", "T1190", "initial-access"),
        918 => ("A10:2021-SSRF", "T1090", "lateral"),
        22 | 23 | 98 | 73 => ("A01:2021-Broken-Access-Control", "T1083", "execution"),
        639 | 862 | 863 | 284 | 285 => ("A01:2021-Broken-Access-Control", "T1078", "privesc"),
        287 | 384 | 613 | 620 => ("A07:2021-Auth-Failures", "T1078", "initial-access"),
        798 | 522 | 321 | 256 | 257 | 312 | 319 => ("A07:2021-Auth-Failures", "T1552", "credential-access"),
        502 => ("A08:2021-Software-Data-Integrity", "T1059", "execution"),
        327 | 328 | 916 | 326 | 330 => ("A02:2021-Cryptographic-Failures", "T1600", "credential-access"),
        200 | 209 | 538 | 540 | 532 => ("A05:2021-Security-Misconfiguration", "T1592", "recon"),
        // Enumeration and side channels are DISCOVERY, not initial access. The
        // fallback arm below was sending these to initial-access, which put 23
        // of 24 findings from a real engagement into one stage and flattened
        // the kill chain into a star.
        203 | 204 | 208 => ("A01:2021-Broken-Access-Control", "T1589", "discovery"),
        // Missing throttling enables credential attacks; it is not access.
        307 | 770 | 799 => ("A07:2021-Auth-Failures", "T1110", "credential-access"),
        // Password policy.
        521 | 261 | 262 | 263 => ("A07:2021-Auth-Failures", "T1110.001", "credential-access"),
        // Missing hardening headers are a configuration observation.
        693 | 1021 | 1018 => ("A05:2021-Security-Misconfiguration", "T1592", "recon"),
        // Cookie flags expose session material.
        614 | 1004 | 1275 => ("A05:2021-Security-Misconfiguration", "T1539", "credential-access"),
        // CORS reads across origins.
        942 | 346 | 1385 => ("A05:2021-Security-Misconfiguration", "T1190", "initial-access"),
        // Mass assignment writes state.
        915 | 913 => ("A08:2021-Software-Data-Integrity", "T1565", "impact"),
        // Session fixation.
        384 => ("A07:2021-Auth-Failures", "T1539", "credential-access"),
        601 => ("A01:2021-Broken-Access-Control", "T1566", "initial-access"),
        113 | 93 => ("A03:2021-Injection", "T1557", "initial-access"),
        644 => ("A03:2021-Injection", "T1557", "initial-access"),
        564 => ("A03:2021-Injection", "T1190", "execution"),
        352 => ("A01:2021-Broken-Access-Control", "T1189", "execution"),
        434 => ("A04:2021-Insecure-Design", "T1505.003", "execution"),
        1321 | 915 => ("A08:2021-Software-Data-Integrity", "T1059", "execution"),
        400 | 770 | 1333 | 799 => ("A04:2021-Insecure-Design", "T1499", "impact"),
        _ => ("A04:2021-Insecure-Design", "T1190", "initial-access"),
    }
}

fn exploitability(sev: &str, conf: f64) -> &'static str {
    match (sev, conf) {
        (_, c) if c >= 0.85 => "trivial",
        ("Critical" | "High", _) => "moderate",
        _ => "hard",
    }
}

// ---------------------------------------------------------------------------
// CVSS v3.1 base score
//
// Every finding in the last engagement shipped with an empty CVSS field: the
// schema had the column, nothing filled it, and no agent volunteered one. A
// report that grades severity as a word and leaves the industry-standard number
// blank forces the reader to re-derive it by hand, or to trust the word.
//
// So it is derived here, deterministically, from what the harness already
// knows: the weakness class (CWE) sets the impact shape, the proven
// exploitability sets attack complexity, and the auth context sets privileges
// required. The VECTOR is emitted alongside the number — a score without its
// vector cannot be checked, and an unchecked score is just a bigger adjective.
//
// This is an estimate from observed properties, not a replacement for an
// analyst's judgement on business context (which CVSS environmental metrics
// exist for). The report says so.
// ---------------------------------------------------------------------------

/// The metric choices behind one score, kept so the vector can be printed.
struct Cvss {
    av: &'static str, // attack vector
    ac: &'static str, // attack complexity
    pr: &'static str, // privileges required
    ui: &'static str, // user interaction
    s: &'static str,  // scope
    c: &'static str,  // confidentiality
    i: &'static str,  // integrity
    a: &'static str,  // availability
}

impl Cvss {
    fn vector(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.av, self.ac, self.pr, self.ui, self.s, self.c, self.i, self.a
        )
    }

    /// The v3.1 base equation, verbatim from the specification.
    fn score(&self) -> f64 {
        let w = |v: &str, table: &[(&str, f64)]| table.iter().find(|(k, _)| *k == v).map(|(_, n)| *n).unwrap_or(0.0);
        let av = w(self.av, &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2)]);
        let ac = w(self.ac, &[("L", 0.77), ("H", 0.44)]);
        let ui = w(self.ui, &[("N", 0.85), ("R", 0.62)]);
        let scope_changed = self.s == "C";
        // Privileges-required weights differ when scope changes — the one place
        // the equation is not a simple lookup.
        let pr = match (self.pr, scope_changed) {
            ("N", _) => 0.85,
            ("L", false) => 0.62,
            ("L", true) => 0.68,
            ("H", false) => 0.27,
            ("H", true) => 0.5,
            _ => 0.85,
        };
        let cia = |v: &str| w(v, &[("H", 0.56), ("L", 0.22), ("N", 0.0)]);
        let iss = 1.0 - (1.0 - cia(self.c)) * (1.0 - cia(self.i)) * (1.0 - cia(self.a));
        let impact = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
        } else {
            6.42 * iss
        };
        if impact <= 0.0 {
            return 0.0;
        }
        let exploitability = 8.22 * av * ac * pr * ui;
        let base = if scope_changed {
            (1.08 * (impact + exploitability)).min(10.0)
        } else {
            (impact + exploitability).min(10.0)
        };
        // CVSS rounds UP to one decimal, which is not the same as rounding.
        (base * 10.0).ceil() / 10.0
    }
}

// ---------------------------------------------------------------------------
// Demonstrated-impact ladder
//
// "SQLi = Critical" is the shortcut this replaces. The same weakness is a very
// different finding depending on how far it was actually taken:
//
//   reached the interpreter        →  the mechanic is proven, impact is not
//   read data                      →  confidentiality impact is real
//   read SENSITIVE data            →  and it is high
//   wrote / changed state          →  integrity impact is real
//   executed code                  →  the system is compromised
//   reached a second system        →  scope changes
//
// So the CVSS metrics come from the rung the evidence reached, not from the
// class name. A SQL injection where nothing was extracted does not score like
// one that dumped a customer table, and the report can defend the difference
// because the rung is derived from recorded observations.
// ---------------------------------------------------------------------------

/// How far the evidence actually took the weakness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rung {
    /// The target behaved differently, and that is all that was shown.
    Reached,
    /// Data came back.
    ReadData,
    /// The data that came back is sensitive (credentials, personal data, keys).
    ReadSensitive,
    /// State changed, and the change was read back.
    Wrote,
    /// Code ran, with output or a callback to prove it.
    Executed,
    /// A second system was reached from the first.
    CrossedSystem,
}

impl Rung {
    pub fn as_str(self) -> &'static str {
        match self {
            Rung::Reached => "reached the vulnerable component",
            Rung::ReadData => "read data",
            Rung::ReadSensitive => "read sensitive data",
            Rung::Wrote => "changed state (verified by read-back)",
            Rung::Executed => "executed code",
            Rung::CrossedSystem => "reached a second system",
        }
    }
}

/// Signatures of data worth grading as sensitive. Matching one is what
/// separates "the query returned rows" from "the query returned credentials".
const SENSITIVE: &[&str] = &[
    "password", "passwd", "senha", "hash", "bcrypt", "$2y$", "$2a$", "ssn", "cpf", "credit card",
    "card_number", "cvv", "api_key", "apikey", "secret", "private key", "begin rsa", "authorization:",
    "bearer ", "session", "token", "email", "phone", "birth",
];

/// Read the rung off the recorded evidence.
///
/// Only observations count. A finding that says "could lead to RCE" without an
/// observation of code running stays where its evidence put it — which is the
/// entire point of grading this way.
/// The kind of data a finding demonstrably exposed, read from any slot the
/// agent used (structured evidence body, or the prose evidence/impact). This is
/// the "data type" axis: a credential or key dump is a confidentiality breach
/// regardless of whether the receipt landed in the structured slot, and it must
/// not be recalibrated away just because `evidence_data` was left null.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass { None, Data, Sensitive }

const CREDENTIALS: &[&str] = &[
    "password", "passwd", "senha", "bcrypt", "$2y$", "$2a$", "api_key", "apikey",
    "api key", "secret", "private key", "begin rsa", "bearer ", "authorization:",
    "aws_secret", "aws_access_key", "credit card", "card_number",
    "cvv", "ssn", "cpf",
];

pub fn data_class(f: &Finding) -> DataClass {
    let mut hay = format!("{} {} {}", f.evidence, f.impact, f.payload).to_lowercase();
    if let Some(e) = f.evidence_data.as_ref() {
        for ex in [e.attack.as_ref(), e.baseline.as_ref(), e.identity_a.as_ref(), e.identity_b.as_ref()].into_iter().flatten() {
            hay.push(' ');
            hay.push_str(&ex.body.to_lowercase());
        }
    }
    if CREDENTIALS.iter().any(|s| hay.contains(s)) {
        return DataClass::Sensitive;
    }
    // A record dump without a credential signature is still data read.
    if SENSITIVE.iter().any(|s| hay.contains(s)) {
        return DataClass::Data;
    }
    DataClass::None
}

pub fn demonstrated_rung(f: &Finding) -> Rung {
    let ev = f.evidence_data.as_ref();
    let text = format!("{} {}", f.evidence, f.impact).to_lowercase();

    // Executed: a nonce echoed from command output, or an out-of-band callback.
    if let Some(e) = ev {
        if e.callback_received && !e.marker.is_empty() {
            return if e.marker_observed { Rung::CrossedSystem } else { Rung::Executed };
        }
        if e.marker_observed && !e.marker.is_empty() {
            let echoed = e.attack.as_ref().map(|a| a.body.contains(&e.marker)).unwrap_or(false);
            if echoed && e.browser_executed {
                return Rung::Executed;
            }
        }
        // Wrote: a read-back that now contains what was injected.
        if let (Some(verify), false) = (e.identity_a.as_ref(), e.marker.is_empty()) {
            if verify.body.contains(&e.marker) {
                return Rung::Wrote;
            }
        }
        // Read: a body came back that the baseline did not have.
        if let (Some(b), Some(a)) = (&e.baseline, &e.attack) {
            if a.status < 400 && a.len() > b.len() + 64 {
                let body = a.body.to_lowercase();
                if SENSITIVE.iter().any(|s| body.contains(s) && !b.body.to_lowercase().contains(s)) {
                    return Rung::ReadSensitive;
                }
                return Rung::ReadData;
            }
        }
    }

    // Falling back to the prose is weaker and deliberately conservative: only
    // unambiguous past-tense observations count, never "could" or "may".
    if text.contains("command output") || text.contains("id=") && text.contains("uid=") {
        return Rung::Executed;
    }
    if SENSITIVE.iter().any(|s| text.contains(s)) && (text.contains("returned") || text.contains("disclosed") || text.contains("dumped")) {
        return Rung::ReadSensitive;
    }
    Rung::Reached
}

/// Temporal metrics, from what the engagement knows about itself.
///
/// `E` (exploit code maturity) is High when a runnable PoC exists — the harness
/// wrote one. `RC` (report confidence) follows the validation verdict rather
/// than an opinion: Confirmed only when something deterministic confirmed it.
fn temporal(f: &Finding) -> (&'static str, &'static str) {
    let e = if !f.repro_steps.is_empty() || f.evidence_data.is_some() { "F" } else { "P" };
    let rc = match f.review_status.as_str() {
        "confirmed" => "C",
        "needs-review" => "R",
        _ => "U",
    };
    (e, rc)
}

/// Derive a CVSS v3.1 base score + vector for a finding.
/// Evidence-graded CVSS via the FIRST-verbatim calculator in `crate::cvss`.
///
/// The class proposes the vector's shape (which of C/I/A it *can* affect, the
/// scope, the exploitability axes); the demonstrated rung decides which impact
/// metrics actually have a receipt. `crate::cvss::grade` then keeps two scores:
/// the demonstrated one (what the evidence proved, the reported number) and the
/// potential one (what the class could reach). This is what wires the real
/// CVSS 3.1 equation — the older `cvss_for` is kept only as a fallback for a
/// finding with no structured evidence to grade.
pub fn cvss_graded(f: &Finding) -> Option<crate::cvss::Graded> {
    use crate::cvss::{Ac, Av, Imp, Pr, Scope, Ui, Vector};
    let n: u32 = f.cwe.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0);
    if n == 0 {
        return None;
    }
    let imp = |s: &str| match s { "H" => Imp::High, "L" => Imp::Low, _ => Imp::None };
    // Class → the impact shape it CAN have (the potential ceiling) + scope.
    let (c, i, a, scope) = match n {
        77 | 78 | 94 | 95 | 502 | 917 | 1336 => ("H", "H", "H", Scope::Changed),
        89 | 943 | 564 => ("H", "H", "L", Scope::Unchanged),
        22 | 23 | 35 | 98 | 73 => ("H", "N", "N", Scope::Unchanged),
        918 => ("H", "L", "N", Scope::Changed),
        639 | 862 | 863 | 284 | 285 | 306 | 566 | 425 => ("H", "H", "N", Scope::Unchanged),
        287 | 288 | 289 | 290 | 347 | 345 | 384 => ("H", "H", "N", Scope::Unchanged),
        79 | 80 | 83 | 87 => ("L", "L", "N", Scope::Changed),
        352 => ("N", "H", "N", Scope::Unchanged),
        611 | 776 | 827 => ("H", "N", "L", Scope::Changed),
        319 | 522 | 798 | 312 | 256 | 257 | 321 => ("H", "N", "N", Scope::Unchanged),
        200 | 209 | 538 | 540 | 548 | 532 | 530 => ("L", "N", "N", Scope::Unchanged),
        307 | 799 | 770 | 400 => ("N", "N", "L", Scope::Unchanged),
        601 => ("L", "L", "N", Scope::Changed),
        1021 => ("N", "L", "N", Scope::Unchanged),
        113 | 93 | 644 => ("L", "L", "N", Scope::Unchanged),
        525 | 524 => ("L", "N", "N", Scope::Unchanged),
        _ => ("L", "N", "N", Scope::Unchanged),
    };
    let authenticated = f.auth_context.eq_ignore_ascii_case("authenticated") || !f.account.is_empty();
    let proposed = Vector {
        // Web engagement defaults; the class overrides where it matters.
        av: Av::Network,
        ac: match n { 362 | 208 | 385 => Ac::High, _ => Ac::Low }, // race/timing = high AC
        pr: if authenticated { Pr::Low } else { Pr::None },
        ui: match n { 79 | 80 | 83 | 87 | 352 | 601 | 1021 => Ui::Required, _ => Ui::None },
        scope,
        c: imp(c),
        i: imp(i),
        a: imp(a),
    };
    // The demonstrated rung decides which impact metrics carry a receipt.
    let rung = demonstrated_rung(f);
    // Data type is a first-class impact receipt: a demonstrated credential/PII
    // exposure grants the confidentiality metric even if the rung slot was
    // empty (e.g. the agent recorded the dump in prose, not evidence_data).
    let dc = data_class(f);
    let has_c = matches!(rung, Rung::ReadData | Rung::ReadSensitive | Rung::Wrote | Rung::Executed | Rung::CrossedSystem)
        || dc != DataClass::None;
    let has_i = matches!(rung, Rung::Wrote | Rung::Executed | Rung::CrossedSystem);
    let has_a = matches!(rung, Rung::Executed | Rung::CrossedSystem);
    Some(crate::cvss::grade(proposed, move |m| match m {
        "C" => has_c,
        "I" => has_i,
        "A" => has_a,
        _ => true,
    }))
}

pub fn cvss_for(f: &Finding) -> (f64, String) {
    let n: u32 = f.cwe.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0);
    let authenticated = f.auth_context.eq_ignore_ascii_case("authenticated") || !f.account.is_empty();

    // The class sets the CEILING; the evidence sets the score. A SQL injection
    // that reached the interpreter and extracted nothing does not deserve the
    // number a dumped customer table earns, and grading by class name is how
    // both end up "Critical".
    let rung = demonstrated_rung(f);

    // Impact shape by weakness class. Anything unmapped stays conservative:
    // guessing high impact from an unknown class is how scores get inflated.
    let (c, i, a, scope) = match n {
        // Injection / execution: full compromise of the interpreter's context.
        77 | 78 | 94 | 95 | 502 | 917 | 1336 => ("H", "H", "H", "C"),
        // SQL injection: reads and writes the datastore.
        89 | 943 | 564 => ("H", "H", "L", "U"),
        // Path traversal / file read.
        22 | 23 | 35 | 98 | 73 => ("H", "N", "N", "U"),
        // SSRF: reaches other systems.
        918 => ("H", "L", "N", "C"),
        // Access control / IDOR / auth bypass: another user's data.
        639 | 862 | 863 | 284 | 285 | 306 | 566 | 425 => ("H", "H", "N", "U"),
        // Broken authentication / token verification.
        287 | 288 | 289 | 290 | 347 | 345 | 384 => ("H", "H", "N", "U"),
        // XSS: runs in the victim's session, in the browser's scope.
        79 | 80 | 83 | 87 => ("L", "L", "N", "C"),
        // XXE.
        611 | 776 | 827 => ("H", "N", "L", "C"),
        // Credential exposure / cleartext transmission.
        319 | 522 | 798 | 312 | 256 | 257 | 321 => ("H", "N", "N", "U"),
        // Secrets / sensitive data disclosure.
        200 | 209 | 538 | 540 | 548 | 532 => ("L", "N", "N", "U"),
        // Enumeration / observable discrepancy: identities, not content.
        204 | 203 | 208 => ("L", "N", "N", "U"),
        // Missing rate limiting: an enabler, and a resource cost.
        307 | 799 | 770 | 400 => ("L", "N", "L", "U"),
        // CSRF: acts as the victim.
        352 => ("N", "H", "N", "U"),
        // Open redirect: phishing leverage, no direct data loss.
        601 => ("N", "L", "N", "C"),
        // Cookie flags / missing hardening: exposure only under another
        // condition (an attacker already on the network, a second bug).
        614 | 1004 | 1275 | 693 | 1021 | 1018 => ("L", "N", "N", "U"),
        // CORS with credentials.
        942 | 346 | 1385 => ("H", "L", "N", "C"),
        // Mass assignment.
        915 | 913 => ("L", "H", "N", "U"),
        _ => ("L", "N", "N", "U"),
    };

    // Lower the class ceiling to the rung the evidence actually reached.
    let (c, i, a, scope) = clamp_to_rung(c, i, a, scope, rung);

    let m = Cvss {
        av: "N", // everything the harness tests black-box is network-reachable
        // "How hard was it?" is not a guess here — the harness recorded whether
        // the exploit was trivial or took work.
        ac: if f.exploitability.eq_ignore_ascii_case("hard") { "H" } else { "L" },
        pr: if authenticated { "L" } else { "N" },
        // CSRF and XSS need a victim to act; nothing else here does.
        ui: if matches!(n, 352 | 79 | 80 | 83 | 87 | 601) { "R" } else { "N" },
        s: scope,
        c,
        i,
        a,
    };
    let base = m.score();
    // Temporal metrics only ever lower the score, and they encode facts the
    // engagement owns: whether a runnable proof exists, and how confident the
    // validation was.
    let (e, rc) = temporal(f);
    let score = (base * temporal_factor(e, rc) * 10.0).ceil() / 10.0;
    (score, format!("{}/E:{e}/RL:X/RC:{rc}", m.vector()))
}

/// The v3.1 temporal multiplier. RL is left undefined (`X`) because the harness
/// has no view of the vendor's remediation state.
fn temporal_factor(e: &str, rc: &str) -> f64 {
    let ev = match e { "X" => 1.0, "H" => 1.0, "F" => 0.97, "P" => 0.94, _ => 0.91 };
    let rcv = match rc { "C" => 1.0, "R" => 0.96, "U" => 0.92, _ => 1.0 };
    ev * rcv
}

/// Clamp a class's impact shape to what was actually demonstrated.
fn clamp_to_rung(
    c: &'static str,
    i: &'static str,
    a: &'static str,
    scope: &'static str,
    rung: Rung,
) -> (&'static str, &'static str, &'static str, &'static str) {
    match rung {
        // Nothing was extracted, written or run: the engagement showed only
        // that the component is reachable and behaves differently. Leaving the
        // class's availability impact in place here put "reached" ABOVE "read
        // data" — the ladder inverted at its first rung.
        Rung::Reached => (min_impact(c, "L"), "N", "N", "U"),
        // Data came back, but nothing in it was shown to be sensitive. This can
        // legitimately tie with Reached: a verbose error IS data read.
        Rung::ReadData => (min_impact(c, "L"), "N", "N", "U"),
        Rung::ReadSensitive => (c, "N", "N", scope),
        Rung::Wrote => (min_impact(c, "L"), i, "N", scope),
        Rung::Executed => (c, i, a, scope),
        // A second system was reached — this is the one rung that RAISES scope,
        // and only because crossing it was observed.
        Rung::CrossedSystem => (c, i, a, "C"),
    }
}

/// The lower of two impact levels.
fn min_impact(a: &'static str, b: &'static str) -> &'static str {
    let rank = |v: &str| match v { "H" => 2, "L" => 1, _ => 0 };
    if rank(a) <= rank(b) { a } else { b }
}

/// Fill in any empty mapping fields on each finding (does not overwrite model-set values).
/// Back-fill a minimal structured `evidence_data` from a finding's prose when
/// the agent left it null but clearly recorded a proof in text. It does NOT
/// invent evidence: it copies what the finding already states (the endpoint as
/// the attack URL, the evidence text as the response body) into the structured
/// slot the deterministic grader and TypeSafe read, so a proof written as
/// narrative is no longer treated as "no receipt". A credential/PII dump that
/// lived only in prose then keeps its severity.
pub fn backfill_evidence(f: &mut Finding) {
    if f.evidence_data.is_some() {
        return;
    }
    // Only salvage when there is a substantive textual proof to carry over.
    let body = if !f.evidence.trim().is_empty() { f.evidence.clone() } else { return };
    if body.len() < 12 {
        return;
    }
    let url = f.endpoint.split_whitespace().last().unwrap_or(&f.endpoint).to_string();
    let ex = crate::validation::Exchange {
        method: f.endpoint.split_whitespace().next().filter(|m| m.chars().all(|c| c.is_ascii_uppercase())).unwrap_or("GET").to_string(),
        url,
        status: 200,
        body,
        content_type: String::new(),
        ..Default::default()
    };
    f.evidence_data = Some(crate::validation::Evidence { attack: Some(ex), ..Default::default() });
}

pub fn enrich(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        // Salvage a structured receipt from prose BEFORE grading, so a proof the
        // agent wrote as narrative is graded, not discarded.
        backfill_evidence(f);
        let (owasp, mitre, stage) = map_cwe(&f.cwe);
        if f.owasp.is_empty() { f.owasp = owasp.into(); }
        if f.mitre.is_empty() { f.mitre = mitre.into(); }
        if f.stage.is_empty() { f.stage = stage.into(); }
        if f.exploitability.is_empty() { f.exploitability = exploitability(&f.severity, f.confidence).into(); }
        if f.business_impact.is_empty() { f.business_impact = f.impact.clone(); }
        // A severity word without the industry-standard number makes the reader
        // re-derive it by hand or take it on faith.
        if f.cvss.is_empty() {
            // Evidence-graded first (FIRST-verbatim, demonstrated vs potential);
            // fall back to the class ladder only when there is no evidence to grade.
            match cvss_graded(f) {
                Some(g) if g.demonstrated_score > 0.0 => {
                    f.cvss = format!("{:.1} ({})", g.demonstrated_score, g.demonstrated.vector_string());
                    // Record the potential ceiling in the impact text when it is
                    // meaningfully higher, so the reader sees both numbers.
                    if g.potential_score - g.demonstrated_score > 0.5 && !f.impact.contains("potential CVSS") {
                        f.impact = format!("{} (potential CVSS {:.1} if fully exploited)", f.impact, g.potential_score).trim().to_string();
                    }
                }
                _ => {
                    let (score, vector) = cvss_for(f);
                    if score > 0.0 { f.cvss = format!("{score:.1} ({vector})"); }
                }
            }
        }
    }
}

/// Recompute the kill-chain stage from the CWE, overwriting what is there.
///
/// `enrich` only fills empty fields, which is right during a run — an agent's
/// own judgement should survive. On a REBUILD it is wrong: a finished run's
/// stages were written by an older mapping, and the whole point of rebuilding
/// is to apply the current one. A real engagement had 23 of 24 findings sitting
/// in `initial-access` because the old fallback put them there, and no rebuild
/// could fix it.
pub fn remap_stages(findings: &mut [Finding]) -> usize {
    let mut changed = 0;
    for f in findings.iter_mut() {
        if f.cwe.is_empty() {
            continue;
        }
        let (owasp, mitre, stage) = map_cwe(&f.cwe);
        if f.stage != stage {
            f.stage = stage.into();
            changed += 1;
        }
        // OWASP and MITRE travel with the stage; leaving them stale would make
        // the report internally inconsistent.
        f.owasp = owasp.into();
        f.mitre = mitre.into();
    }
    changed
}

const STAGE_ORDER: &[&str] = &[
    "recon", "initial-access", "execution", "credential-access", "privesc", "lateral", "exfil", "impact",
];

fn stage_rank(s: &str) -> usize {
    STAGE_ORDER.iter().position(|x| *x == s).unwrap_or(STAGE_ORDER.len())
}

/// Mermaid flowchart of the attack path: findings grouped by kill-chain stage,
/// with explicit chains_from edges plus implicit stage→stage progression.
pub fn mermaid(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut out = String::from("flowchart LR\n");
    // stage subgraphs
    let mut by_stage: std::collections::BTreeMap<usize, Vec<&Finding>> = Default::default();
    for f in findings {
        by_stage.entry(stage_rank(&f.stage)).or_default().push(f);
    }
    let node_id = |f: &Finding| -> String {
        format!("n{}", sanitize_id(&f.id))
    };
    for (rank, group) in &by_stage {
        let stage = STAGE_ORDER.get(*rank).copied().unwrap_or("other");
        out.push_str(&format!("  subgraph S{rank}[\"{}\"]\n", stage));
        for f in group {
            out.push_str(&format!("    {}[\"{}<br/>{} · {}\"]\n",
                node_id(f), esc(&f.title), esc(&f.severity), esc(&f.owasp)));
        }
        out.push_str("  end\n");
    }
    // explicit chain edges
    let ids: std::collections::HashMap<&str, &Finding> = findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let mut had_edge = false;
    for f in findings {
        for src in &f.chains_from {
            if let Some(sf) = ids.get(src.as_str()) {
                out.push_str(&format!("  {} --> {}\n", node_id(sf), node_id(f)));
                had_edge = true;
            }
        }
    }
    // implicit progression between consecutive populated stages if no explicit edges
    if !had_edge && by_stage.len() > 1 {
        let ranks: Vec<usize> = by_stage.keys().copied().collect();
        for w in ranks.windows(2) {
            if let (Some(a), Some(b)) = (by_stage[&w[0]].first(), by_stage[&w[1]].first()) {
                out.push_str(&format!("  {} -.-> {}\n", node_id(a), node_id(b)));
            }
        }
    }
    out
}

/// Compact ASCII kill-chain for the REPL: one line per stage with its findings.
pub fn ascii_killchain(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "  (no findings to map)".into();
    }
    let mut by_stage: std::collections::BTreeMap<usize, Vec<&Finding>> = Default::default();
    for f in findings {
        by_stage.entry(stage_rank(&f.stage)).or_default().push(f);
    }
    let mut out = String::new();
    for (rank, group) in &by_stage {
        let stage = STAGE_ORDER.get(*rank).copied().unwrap_or("other");
        out.push_str(&format!("  ▸ {:<16} ", stage));
        let items: Vec<String> = group.iter()
            .map(|f| format!("[{}] {} ({})", f.severity, f.title, f.mitre))
            .collect();
        out.push_str(&items.join("\n                     "));
        out.push('\n');
    }
    out
}

fn sanitize_id(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).take(24).collect()
}
fn esc(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ").chars().take(60).collect()
}

#[cfg(test)]
mod cvss_tests {
    use super::*;

    fn f(cwe: &str, exploitability: &str, auth: &str) -> Finding {
        Finding { cwe: cwe.into(), exploitability: exploitability.into(), auth_context: auth.into(), ..Default::default() }
    }

    /// Known-good anchors from the CVSS v3.1 specification's own arithmetic.
    #[test]
    fn the_base_equation_matches_the_specification() {
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (the classic unauthenticated RCE)
        let m = Cvss { av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "H", a: "H" };
        assert!((m.score() - 9.8).abs() < 0.05, "got {}", m.score());
        // Scope change pushes the same impact to 10.0
        let m = Cvss { av: "N", ac: "L", pr: "N", ui: "N", s: "C", c: "H", i: "H", a: "H" };
        assert!((m.score() - 10.0).abs() < 0.05, "got {}", m.score());
        // Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
        let m = Cvss { av: "N", ac: "L", pr: "N", ui: "R", s: "C", c: "L", i: "L", a: "N" };
        assert!((m.score() - 6.1).abs() < 0.05, "got {}", m.score());
        // No impact at all must score zero, not a floor.
        let m = Cvss { av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "N", i: "N", a: "N" };
        assert_eq!(m.score(), 0.0);
    }

    #[test]
    fn the_vector_is_emitted_so_the_score_can_be_checked() {
        let (_, vector) = cvss_for(&f("CWE-89", "trivial", ""));
        assert!(vector.starts_with("CVSS:3.1/AV:N/AC:L/PR:N"), "{vector}");
        assert!(vector.contains("/E:") && vector.contains("/RC:"), "temporal metrics travel with it: {vector}");
    }

    /// The behaviour the demonstrated-impact ladder exists to produce: a class
    /// name does not set the score. An SQLi with no extraction is not the same
    /// finding as one that returned credentials, and the report has to be able
    /// to defend the difference.
    #[test]
    fn a_class_name_alone_does_not_earn_a_critical() {
        use crate::validation::{Evidence, Exchange};
        let bare = cvss_for(&f("CWE-89", "trivial", "")).0;
        assert!(bare < 7.0, "nothing was demonstrated, so nothing justifies a high score: {bare}");

        let proven = Finding {
            cwe: "CWE-89".into(),
            exploitability: "trivial".into(),
            evidence_data: Some(Evidence {
                baseline: Some(Exchange { status: 200, body: "welcome".into(), ..Default::default() }),
                attack: Some(Exchange {
                    status: 200,
                    body: format!("welcome alice@example.com bcrypt $2y$10$abcdef{}", "x".repeat(90)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let demonstrated = cvss_for(&proven).0;
        assert!(demonstrated > bare, "extraction must score above a bare reachability claim ({demonstrated} vs {bare})");
        // The temporal metrics pull the base down: no runnable PoC was recorded
        // (E:P) and nothing validated it (RC:U), which is the honest reading of
        // a finding nobody has reproduced yet.
        assert!(demonstrated >= 6.5, "a proven sensitive-data read is serious: {demonstrated}");
    }

    #[test]
    fn proven_difficulty_and_required_privileges_move_the_score() {
        let easy = cvss_for(&f("CWE-639", "trivial", "")).0;
        let hard = cvss_for(&f("CWE-639", "hard", "")).0;
        let authed = cvss_for(&f("CWE-639", "trivial", "authenticated")).0;
        assert!(hard < easy, "a hard exploit must not score like a trivial one ({hard} vs {easy})");
        assert!(authed < easy, "needing an account must lower the score ({authed} vs {easy})");
    }

    #[test]
    fn hardening_gaps_do_not_score_like_demonstrated_compromises() {
        use crate::validation::{Evidence, Exchange};
        let cookie = cvss_for(&f("CWE-614", "trivial", "")).0;
        let headers = cvss_for(&f("CWE-693", "trivial", "")).0;
        assert!(cookie < 6.0 && headers < 6.0, "cookie {cookie}, headers {headers}");

        // Command execution scores like one only when execution was observed.
        let marker = crate::validation::canary("nsrce");
        let proven_rce = Finding {
            cwe: "CWE-78".into(),
            exploitability: "trivial".into(),
            evidence_data: Some(Evidence {
                marker: marker.clone(),
                marker_observed: true,
                browser_executed: true,
                attack: Some(Exchange { status: 200, body: format!("uid=0(root) {marker}"), ..Default::default() }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let rce = cvss_for(&proven_rce).0;
        assert!(rce >= 9.0, "demonstrated command execution is critical: {rce}");
        assert!(rce > cookie + 3.0, "and far above a hardening gap");
    }

    #[test]
    fn an_unknown_weakness_stays_conservative() {
        let (score, _) = cvss_for(&f("CWE-99999", "trivial", ""));
        assert!(score < 6.0, "guessing high impact from an unknown class inflates reports: {score}");
    }

    #[test]
    fn enrich_fills_the_field_and_leaves_an_agent_supplied_score_alone() {
        let mut v = vec![
            Finding { cwe: "CWE-307".into(), severity: "Medium".into(), ..Default::default() },
            Finding { cwe: "CWE-89".into(), cvss: "7.0 (analyst override)".into(), ..Default::default() },
        ];
        enrich(&mut v);
        assert!(v[0].cvss.starts_with(|c: char| c.is_ascii_digit()), "got {:?}", v[0].cvss);
        assert!(v[0].cvss.contains("CVSS:3.1/"), "the vector must travel with the score");
        assert_eq!(v[1].cvss, "7.0 (analyst override)", "a supplied score is not overwritten");
    }
}

#[cfg(test)]
mod ladder_tests {
    use super::*;
    use crate::validation::{Evidence, Exchange};

    fn sqli(evidence_data: Option<Evidence>) -> Finding {
        Finding { cwe: "CWE-89".into(), exploitability: "trivial".into(), evidence_data, ..Default::default() }
    }
    fn ex(status: u16, body: &str) -> Exchange {
        Exchange { method: "GET".into(), url: "https://t/x".into(), status, body: body.into(), ..Default::default() }
    }

    /// The point of the whole ladder: one weakness, three engagements, three
    /// defensible numbers.
    #[test]
    fn the_same_sqli_scores_by_how_far_it_was_taken() {
        let reached = sqli(Some(Evidence {
            baseline: Some(ex(200, "welcome")),
            attack: Some(ex(500, "You have an error in your SQL syntax")),
            ..Default::default()
        }));
        let read = sqli(Some(Evidence {
            baseline: Some(ex(200, "welcome")),
            attack: Some(ex(200, &format!("welcome{}", "row,".repeat(60)))),
            ..Default::default()
        }));
        let sensitive = sqli(Some(Evidence {
            baseline: Some(ex(200, "welcome")),
            attack: Some(ex(200, &format!("welcome alice@example.com bcrypt $2y$10$abcdefghijklmnop{}", "x".repeat(80)))),
            ..Default::default()
        }));

        assert_eq!(demonstrated_rung(&reached), Rung::Reached);
        assert_eq!(demonstrated_rung(&read), Rung::ReadData);
        assert_eq!(demonstrated_rung(&sensitive), Rung::ReadSensitive);

        let (s_reached, _) = cvss_for(&reached);
        let (s_read, _) = cvss_for(&read);
        let (s_sensitive, _) = cvss_for(&sensitive);
        assert!(s_reached <= s_read, "reached {s_reached} must not outscore read {s_read}");
        assert!(s_read < s_sensitive, "read {s_read} must score below sensitive read {s_sensitive}");
    }

    #[test]
    fn a_prose_claim_of_rce_does_not_climb_the_ladder() {
        let mut f = sqli(None);
        f.impact = "This could lead to remote code execution and full server compromise".into();
        assert_eq!(demonstrated_rung(&f), Rung::Reached, "'could lead to' is not an observation");
    }

    #[test]
    fn a_verified_write_is_graded_above_a_read() {
        let marker = crate::validation::canary("nsw");
        let wrote = Finding {
            cwe: "CWE-915".into(),
            evidence_data: Some(Evidence {
                marker: marker.clone(),
                attack: Some(ex(200, "updated")),
                identity_a: Some(ex(200, &format!("{{\"role\":\"{marker}\"}}"))),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(demonstrated_rung(&wrote), Rung::Wrote);
    }

    #[test]
    fn an_out_of_band_callback_is_the_top_rung() {
        let f = Finding {
            cwe: "CWE-918".into(),
            evidence_data: Some(Evidence {
                marker: crate::validation::canary("nsoob"),
                callback_received: true,
                marker_observed: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(demonstrated_rung(&f), Rung::CrossedSystem);
        let (score, vector) = cvss_for(&f);
        assert!(vector.contains("/S:C"), "reaching a second system changes scope: {vector}");
        assert!(score > 8.0, "{score}");
    }

    #[test]
    fn the_vector_carries_the_temporal_metrics() {
        let mut f = sqli(None);
        f.review_status = "needs-review".into();
        let (_, vector) = cvss_for(&f);
        assert!(vector.contains("/E:"), "{vector}");
        assert!(vector.contains("/RC:R"), "needs-review must show as Reasonable, not Confirmed: {vector}");

        f.review_status = "confirmed".into();
        f.repro_steps = vec!["curl ...".into()];
        let (score_confirmed, v2) = cvss_for(&f);
        assert!(v2.contains("/RC:C") && v2.contains("/E:F"), "{v2}");
        let (score_review, _) = cvss_for(&Finding { review_status: "needs-review".into(), ..f.clone() });
        assert!(score_review <= score_confirmed, "an unconfirmed finding must not outscore a confirmed one");
    }

    #[test]
    fn temporal_metrics_only_ever_lower_the_score() {
        for e in ["H", "F", "P", "U"] {
            for rc in ["C", "R", "U"] {
                assert!(temporal_factor(e, rc) <= 1.0, "{e}/{rc}");
            }
        }
        assert_eq!(temporal_factor("H", "C"), 1.0);
    }


    #[test]
    fn graded_cvss_wires_the_first_calculator_and_splits_demonstrated_from_potential() {
        let reached = sqli(Some(Evidence { attack: Some(ex(200, "ok")), ..Default::default() }));
        let g = cvss_graded(&reached).expect("graded");
        assert!(g.demonstrated_score <= g.potential_score);

        let proven = sqli(Some(Evidence { attack: Some(ex(200, "password=hunter2 bearer eyJ...")), ..Default::default() }));
        let g2 = cvss_graded(&proven).expect("graded");
        assert!(g2.demonstrated_score >= g.demonstrated_score, "reading data cannot lower the score");
        assert!(g2.demonstrated.vector_string().contains("CVSS:3.1/"));
    }
    #[test]
    fn data_class_reads_credentials_from_prose_and_backfills() {
        // The exact benchmark case: a BOLA whose proof (admin password dump) is
        // in prose, evidence_data null. data_class must see the credential, and
        // backfill must give the grader a structured receipt.
        let mut f = Finding {
            cwe: "CWE-639".into(),
            title: "BOLA on /api/v2/users/:id".into(),
            endpoint: "GET https://t.test/api/v2/users/1".into(),
            evidence: "GET /api/v2/users/1 with a customer token returned admin record incl. password=SuperSecret and apiKey=nk_live_x".into(),
            ..Default::default()
        };
        assert_eq!(data_class(&f), DataClass::Sensitive, "a credential dump is sensitive data");
        assert!(f.evidence_data.is_none());
        backfill_evidence(&mut f);
        assert!(f.evidence_data.is_some(), "prose proof is salvaged into the structured slot");
        // Now the graded CVSS keeps a confidentiality receipt (data type), not 0.
        let g = cvss_graded(&f).expect("graded");
        assert!(g.demonstrated_score > 0.0, "a demonstrated credential exposure is not zero");
    }

    #[test]
    fn backfill_does_not_invent_evidence_when_there_is_none() {
        let mut f = Finding { cwe: "CWE-79".into(), endpoint: "https://t.test/x".into(), evidence: "".into(), ..Default::default() };
        backfill_evidence(&mut f);
        assert!(f.evidence_data.is_none(), "no prose proof, nothing to salvage");
    }

}
