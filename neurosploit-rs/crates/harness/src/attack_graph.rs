//! Attack graph & kill-chain mapping.
//!
//! Enriches findings with OWASP Top 10 / MITRE ATT&CK / kill-chain stage /
//! exploitability (derived from CWE + severity when the model didn't supply
//! them), then renders an attack-path graph (Mermaid) and a kill-chain table for
//! the report, plus a compact ASCII summary for the REPL.

use crate::types::Finding;

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
        601 => ("A01:2021-Broken-Access-Control", "T1566", "initial-access"),
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

/// Derive a CVSS v3.1 base score + vector for a finding.
pub fn cvss_for(f: &Finding) -> (f64, String) {
    let n: u32 = f.cwe.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0);
    let authenticated = f.auth_context.eq_ignore_ascii_case("authenticated") || !f.account.is_empty();

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
    (m.score(), m.vector())
}

/// Fill in any empty mapping fields on each finding (does not overwrite model-set values).
pub fn enrich(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let (owasp, mitre, stage) = map_cwe(&f.cwe);
        if f.owasp.is_empty() { f.owasp = owasp.into(); }
        if f.mitre.is_empty() { f.mitre = mitre.into(); }
        if f.stage.is_empty() { f.stage = stage.into(); }
        if f.exploitability.is_empty() { f.exploitability = exploitability(&f.severity, f.confidence).into(); }
        if f.business_impact.is_empty() { f.business_impact = f.impact.clone(); }
        // A severity word without the industry-standard number makes the reader
        // re-derive it by hand or take it on faith.
        if f.cvss.is_empty() {
            let (score, vector) = cvss_for(f);
            if score > 0.0 { f.cvss = format!("{score:.1} ({vector})"); }
        }
    }
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
        let (score, vector) = cvss_for(&f("CWE-89", "trivial", ""));
        assert!(score >= 9.0, "unauthenticated trivial SQLi should be critical: {score}");
        assert!(vector.starts_with("CVSS:3.1/AV:N/AC:L/PR:N"), "{vector}");
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
    fn hardening_gaps_do_not_score_like_compromises() {
        let cookie = cvss_for(&f("CWE-614", "trivial", "")).0;
        let headers = cvss_for(&f("CWE-693", "trivial", "")).0;
        let rce = cvss_for(&f("CWE-78", "trivial", "")).0;
        assert!(cookie < 6.0 && headers < 6.0, "cookie {cookie}, headers {headers}");
        assert!(rce > 9.0, "command injection {rce}");
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
