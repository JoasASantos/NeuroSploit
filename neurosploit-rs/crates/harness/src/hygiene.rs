//! Report-hygiene & exploitation-depth pass (v3.5.2).
//!
//! Encodes the post-engagement discipline learned from reviewing real
//! AI-pentest output, applied deterministically after validation:
//!  1. **Calibrate severity to PROVEN impact** — an unproven High/Critical
//!     (hedged language, no payload, thin evidence) is capped to Medium and
//!     re-titled "(potential)". No inflated severities.
//!  2. **Exposed → exploited** — flag info-disclosure / exposed-service /
//!     leaked-credential findings on a host that has no actual exploit, so the
//!     operator knows to *use* what was exposed (or down-rate it to a lead).
//!  3. **Consolidate hygiene** — when the same hygiene class (missing headers,
//!     clickjacking, cookie flags, TLS, info-disclosure…) repeats across many
//!     assets, advise merging into ONE finding with an affected-asset table,
//!     instead of inflating the count one-per-host.
//!
//! All functions are pure/deterministic; only `calibrate` mutates findings
//! (severity/title/confidence). The rest return advisory strings streamed to
//! the operator and recorded with the run.
use crate::types::Finding;

fn host_of(endpoint: &str) -> String {
    let s = endpoint.trim();
    let s = s.split("://").last().unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    s.split('?').next().unwrap_or(s).to_lowercase()
}

fn sev_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        x if x.starts_with("crit") => 4,
        x if x.starts_with("high") => 3,
        x if x.starts_with("med") => 2,
        x if x.starts_with("low") => 1,
        _ => 0,
    }
}

fn short(s: &str) -> String {
    s.chars().take(64).collect()
}

/// Hedging words that signal an impact was described but not demonstrated
/// (English + Portuguese, since engagements are bilingual).
const WEASEL: &[&str] = &[
    "could ", "may ", "might ", "potential", "possible", "possibly", "teóric", "theoret",
    "poderia", "possív", "potencial", "if the ", "caso o", "caso a", "would allow", "permitiria",
];

/// A finding that *exposes* something (recon/disclosure) rather than being an
/// exploit with demonstrated impact.
fn is_exposure(f: &Finding) -> bool {
    let cwe = f.cwe.to_lowercase();
    let t = f.title.to_lowercase();
    ["200", "527", "538", "942", "497", "209", "548", "16"].iter().any(|c| cwe.contains(c))
        || [
            "disclosure", "exposed", "exposi", "exposure", "catalog", "catálogo", "cors",
            "banner", "version", "versão", "header", "cabeçalho", ".git", "enumerat",
            "fingerprint", "wsdl", "swagger", "missing security", "outdated", "eol",
        ]
        .iter()
        .any(|k| t.contains(k))
}

/// Reads as unproven: hedged or thin evidence AND no concrete payload.
fn looks_unproven(f: &Finding) -> bool {
    let blob = format!("{} {} {}", f.title, f.impact, f.evidence).to_lowercase();
    let hedged = WEASEL.iter().any(|w| blob.contains(w));
    let weak_ev = f.evidence.trim().chars().count() < 40;
    let no_payload = f.payload.trim().is_empty();
    (hedged || weak_ev) && no_payload
}

/// Normalized hygiene class, for consolidation advice.
fn class_of(f: &Finding) -> &'static str {
    let t = f.title.to_lowercase();
    if t.contains("header") || t.contains("cabeçalho") { "missing-security-headers" }
    else if t.contains("clickjack") || t.contains("frame") { "clickjacking" }
    else if t.contains("hsts") || t.contains("strict-transport") { "missing-hsts" }
    else if t.contains("cookie") { "cookie-flags" }
    else if t.contains("tls") || t.contains("ssl") { "weak-tls" }
    else if t.contains("cors") { "cors-misconfig" }
    else if t.contains("version") || t.contains("versão") || t.contains("banner") || t.contains("eol") || t.contains("outdated") { "version-disclosure" }
    else { "information-disclosure" }
}

/// Cap inflated, unproven High/Critical findings to Medium. Returns advisories.
pub fn calibrate(findings: &mut [Finding]) -> Vec<String> {
    let mut notes = Vec::new();
    for f in findings.iter_mut() {
        if sev_rank(&f.severity) >= 3 && looks_unproven(f) {
            let old = f.severity.clone();
            f.severity = "Medium".into();
            f.confidence = f.confidence.min(0.5);
            let low = f.title.to_lowercase();
            if !low.contains("potential") && !low.contains("potencial") {
                f.title = format!("{} (potential — impact not demonstrated)", f.title);
            }
            notes.push(format!(
                "severity calibrated: \"{}\" {old} → Medium (impact not demonstrated)",
                short(&f.title)
            ));
        }
    }
    notes
}

/// "Exposed → exploited": exposures on a host with no real exploit get flagged.
pub fn depth_audit(findings: &[Finding]) -> Vec<String> {
    let exploited: std::collections::HashSet<String> = findings
        .iter()
        .filter(|f| !is_exposure(f) && sev_rank(&f.severity) >= 2)
        .map(|f| host_of(&f.endpoint))
        .collect();
    let mut notes = Vec::new();
    for f in findings.iter().filter(|f| is_exposure(f)) {
        if !exploited.contains(&host_of(&f.endpoint)) {
            notes.push(format!(
                "depth gap: \"{}\" exposed but not exploited — USE it (call the endpoint / decode the artifact / log in / hit the dev host) to prove impact, or down-rate to a lead",
                short(&f.title)
            ));
        }
    }
    notes.truncate(8);
    notes
}

/// Advise consolidating hygiene classes that repeat across multiple assets.
pub fn hygiene_summary(findings: &[Finding]) -> Vec<String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut groups: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for f in findings.iter().filter(|f| is_exposure(f)) {
        groups.entry(class_of(f)).or_default().insert(host_of(&f.endpoint));
    }
    let mut notes = Vec::new();
    for (class, hosts) in groups {
        if hosts.len() > 1 {
            notes.push(format!(
                "hygiene: '{class}' affects {} assets — consolidate into ONE finding with an affected-asset table (don't inflate the count one-per-host)",
                hosts.len()
            ));
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn f(title: &str, sev: &str, cwe: &str, ep: &str, ev: &str, payload: &str) -> Finding {
        let mut x = Finding::default();
        x.title = title.into(); x.severity = sev.into(); x.cwe = cwe.into();
        x.endpoint = ep.into(); x.evidence = ev.into(); x.payload = payload.into();
        x
    }

    #[test]
    fn unproven_high_is_capped() {
        let mut v = vec![f("Flooding DoS", "High", "CWE-770", "https://a/x", "could overload", "")];
        let notes = calibrate(&mut v);
        assert_eq!(v[0].severity, "Medium");
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn proven_high_is_kept() {
        let mut v = vec![f("SQLi", "High", "CWE-89", "https://a/x",
            "id=1' UNION SELECT version()-- returned 8.0.32 in the response body, proving injection", "1' OR '1'='1")];
        calibrate(&mut v);
        assert_eq!(v[0].severity, "High");
    }

    #[test]
    fn exposure_without_exploit_flagged() {
        let v = vec![f("Information Disclosure - .git exposed", "Low", "CWE-527", "https://a/.git", "leaked", "")];
        assert_eq!(depth_audit(&v).len(), 1);
    }

    #[test]
    fn exposure_with_exploit_on_same_host_not_flagged() {
        let v = vec![
            f("Information Disclosure - banner", "Low", "CWE-200", "https://a/x", "Server: IIS", ""),
            f("SQL Injection", "High", "CWE-89", "https://a/login", "dumped users", "1'--"),
        ];
        assert!(depth_audit(&v).is_empty());
    }
}
