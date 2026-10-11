//! Report deliverables that answer more than "it happened".
//!
//! The request/response-plus-narrative block answers one question. These
//! artifacts answer the ones a recipient actually asks, all derived from the
//! evidence the engine already recorded on each finding (`evidence_data`):
//!
//! - **Is it real?** `differential-proof.md` — the negative control next to the
//!   attack, the computed difference, and the distribution over repeats.
//! - **Can I trust the record?** `evidence-custody.{md,json}` — every artifact
//!   classed as OBSERVED (from the wire, hashed), DERIVED (computed by the
//!   deterministic engine) or INFERRED (model narrative), with a hash chain.
//! - **Is it still open / did my fix work?** `tests/` — each finding as an
//!   executable regression test (pytest asserting the *secure* behaviour, so it
//!   fails while vulnerable and passes once fixed) plus a nuclei template, and a
//!   `Makefile` with `make verify-<id>`.
//! - **Would we see it?** `detection/` — Sigma, ModSecurity and SIEM queries
//!   for each exploit, to replay the attack and check the defensive stack.
//! - **Who needs what?** `persona-{dev,appsec,executive}.md`.
//!
//! Everything here is additive and best-effort: it is written next to the
//! existing reports and a failure never affects them. Request credentials are
//! never written out — tests read them from environment variables.

use crate::types::Finding;
use crate::validation::{diff, Evidence, Exchange, Expect};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::Path;

/// Write every deliverable under `<dir>/deliverables/`.
pub fn write_all(target: &str, findings: &[Finding], dir: &Path) -> std::io::Result<()> {
    let out = dir.join("deliverables");
    std::fs::create_dir_all(out.join("tests"))?;
    std::fs::create_dir_all(out.join("nuclei"))?;
    std::fs::create_dir_all(out.join("detection"))?;

    let live: Vec<&Finding> = findings.iter().filter(|f| f.review_status != "rejected").collect();

    std::fs::write(out.join("differential-proof.md"), differential_markdown(target, &live))?;
    let (custody_md, custody_json) = custody(target, &live);
    std::fs::write(out.join("evidence-custody.md"), custody_md)?;
    std::fs::write(out.join("evidence-custody.json"), custody_json)?;

    let mut make = String::from(
        "# NeuroSploit — exploit-as-test.\n# Each test asserts the SECURE behaviour: it FAILS while the finding is open\n# and PASSES once it is fixed. Credentials come from the environment:\n#   NS_TARGET (default below), NS_HDR_AUTHORIZATION, NS_HDR_COOKIE, NS_HDR_X_API_KEY\n",
    );
    let _ = writeln!(make, "NS_TARGET ?= {}\nexport NS_TARGET\n", target.trim_end_matches('/'));
    let mut targets = Vec::new();
    let mut untestable: Vec<String> = Vec::new();
    for f in &live {
        let Some(t) = TestCase::from_finding(f) else {
            if f.evidence_data.is_some() {
                untestable.push(format!("{} — {}", slug(f), short(&f.title, 90)));
            }
            continue;
        };
        let s = slug(f);
        std::fs::write(out.join("tests").join(format!("test_{s}.py")), t.pytest(f))?;
        std::fs::write(out.join("nuclei").join(format!("{s}.yaml")), t.nuclei(f))?;
        let _ = writeln!(make, "verify-{s}:\n\tpython3 -m pytest -q tests/test_{s}.py\n");
        let _ = writeln!(make, "nuclei-{s}:\n\tnuclei -silent -t nuclei/{s}.yaml -u $(NS_TARGET)\n");
        targets.push(format!("verify-{s}"));
    }
    if !untestable.is_empty() {
        let _ = writeln!(make, "# Not auto-testable (no harness marker, no negative control with a different\n# status, no identity swap) — reproduce these from report.md:");
        for u in &untestable {
            let _ = writeln!(make, "#   {}", u.replace('\n', " "));
        }
        make.push('\n');
    }
    let _ = writeln!(make, "verify-all: {}\n", targets.join(" "));
    let _ = writeln!(make, ".PHONY: verify-all {}", targets.join(" "));
    std::fs::write(out.join("Makefile"), make)?;

    let (sigma_files, modsec, siem) = detection(&live);
    for (name, body) in sigma_files {
        std::fs::write(out.join("detection").join(name), body)?;
    }
    std::fs::write(out.join("detection").join("modsecurity.conf"), modsec)?;
    std::fs::write(out.join("detection").join("siem-queries.md"), siem)?;

    std::fs::write(out.join("persona-dev.md"), persona_dev(target, &live))?;
    std::fs::write(out.join("persona-appsec.md"), persona_appsec(target, &live))?;
    std::fs::write(out.join("persona-executive.md"), persona_executive(target, findings))?;
    std::fs::write(out.join("README.md"), index(target, &live))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// shared helpers

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// A filesystem/Makefile-safe identifier for a finding.
pub fn slug(f: &Finding) -> String {
    let base = if f.id.is_empty() { format!("{}-{}", f.title, f.endpoint) } else { f.id.clone() };
    let mut s: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        format!("f-{}", &sha256_hex(f.title.as_bytes())[..10])
    } else if s.len() > 48 {
        format!("{}-{}", &s[..40], &sha256_hex(base.as_bytes())[..6])
    } else {
        s
    }
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Header names whose values are credentials — never written to disk.
fn is_secret_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "x-api-key" | "x-auth-token" | "proxy-authorization" | "x-csrf-token"
    )
}

fn env_name(header: &str) -> String {
    format!(
        "NS_HDR_{}",
        header.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect::<String>()
    )
}

/// Split an absolute URL into (path+query) relative to its origin.
fn path_of(url: &str) -> String {
    if let Some(i) = url.find("://") {
        let rest = &url[i + 3..];
        return match rest.find('/') {
            Some(j) => rest[j..].to_string(),
            None => "/".to_string(),
        };
    }
    if url.starts_with('/') { url.to_string() } else { format!("/{url}") }
}

fn is_rejected(f: &Finding) -> bool {
    f.review_status == "rejected"
}

fn verdict_label(f: &Finding) -> &str {
    if f.review_status.is_empty() {
        if f.validated { "confirmed" } else { "unvalidated" }
    } else {
        &f.review_status
    }
}

// ---------------------------------------------------------------------------
// #2 Differential proof

fn exchange_row(label: &str, x: &Exchange) -> String {
    format!(
        "| {} | `{} {}` | {} | {} | {} B | {} ms | `{}` |",
        label,
        md_cell(&x.method),
        md_cell(&short(&path_of(&x.url), 70)),
        if x.identity.is_empty() { "—".into() } else { md_cell(&x.identity) },
        x.status,
        x.body.len(),
        x.elapsed_ms,
        &sha256_hex(x.body.as_bytes())[..12]
    )
}

const ROW_HEAD: &str = "| role | request | identity | status | size | time | body sha256 |\n|---|---|---|---|---|---|---|";

fn stats(xs: &[u64]) -> Option<(u64, u64, u64, f64, f64)> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_unstable();
    let n = v.len() as f64;
    let mean = v.iter().sum::<u64>() as f64 / n;
    let var = v.iter().map(|x| (*x as f64 - mean).powi(2)).sum::<f64>() / n;
    Some((v[0], v[v.len() / 2], v[v.len() - 1], mean, var.sqrt()))
}

/// The differential section for one finding (also used by the AppSec persona).
pub fn differential_for(f: &Finding) -> String {
    let mut s = String::new();
    let Some(ev) = f.evidence_data.as_ref() else {
        s.push_str("_No structured evidence was captured for this finding, so it cannot be shown against a negative control. Treat it as unproven until re-tested._\n");
        return s;
    };
    let mut rows: Vec<String> = Vec::new();
    if let Some(b) = &ev.baseline {
        rows.push(exchange_row("control (no payload)", b));
    }
    if let Some(a) = &ev.attack {
        rows.push(exchange_row("**attack**", a));
    }
    if let Some(a) = &ev.identity_a {
        rows.push(exchange_row("owner (identity A)", a));
    }
    if let Some(b) = &ev.identity_b {
        rows.push(exchange_row("**other identity (B)**", b));
    }
    if let Some(o) = &ev.oracle {
        rows.push(exchange_row("privileged control (non-existent id)", &o.privileged));
        rows.push(exchange_row("**should-be-denied (non-existent id)**", &o.denied));
    }
    for p in &ev.matrix {
        let label = match p.expect {
            Expect::Allow => format!("matrix: {} (expected allow)", p.identity),
            Expect::Deny => format!("**matrix: {} (expected deny)**", p.identity),
        };
        rows.push(exchange_row(&label, &p.exchange));
    }
    if rows.is_empty() {
        s.push_str("_Evidence was recorded but contains no request pair — no differential can be shown._\n");
    } else {
        let _ = writeln!(s, "{ROW_HEAD}");
        for r in rows {
            let _ = writeln!(s, "{r}");
        }
        s.push('\n');
    }
    if let (Some(b), Some(a)) = (&ev.baseline, &ev.attack) {
        let d = diff(b, a);
        let _ = writeln!(
            s,
            "**Computed difference (control → attack):** {} — {}.\n",
            d.describe(),
            if d.is_significant() { "significant" } else { "NOT significant" }
        );
    }
    if !ev.repeats.is_empty() {
        let mut statuses: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
        for r in &ev.repeats {
            *statuses.entry(r.status).or_default() += 1;
        }
        let dist: Vec<String> = statuses.iter().map(|(k, v)| format!("{k}×{v}")).collect();
        let _ = writeln!(s, "**Reproducibility:** {} independent repeat(s); status distribution {}.", ev.repeats.len(), dist.join(", "));
        let times: Vec<u64> = ev.repeats.iter().map(|r| r.elapsed_ms).collect();
        if let Some((min, med, max, mean, sd)) = stats(&times) {
            let _ = writeln!(s, "**Timing over repeats:** min {min} ms · median {med} ms · max {max} ms · mean {mean:.0} ms · σ {sd:.0} ms.");
            if let Some(b) = &ev.baseline {
                let _ = writeln!(
                    s,
                    "Control took {} ms; the attack's slowest-to-fastest band sits {} the control.",
                    b.elapsed_ms,
                    if min > b.elapsed_ms + (2.0 * sd) as u64 { "entirely above" } else { "overlapping" }
                );
            }
        }
        s.push('\n');
    }
    let mut proofs = Vec::new();
    if ev.callback_received {
        proofs.push(format!("out-of-band callback carrying marker `{}` was received", ev.marker));
    }
    if ev.browser_executed {
        proofs.push(format!("a real browser executed the payload (marker `{}`)", ev.marker));
    }
    if ev.marker_observed && !ev.callback_received && !ev.browser_executed {
        proofs.push(format!("harness-chosen marker `{}` was observed where it proves the class", ev.marker));
    }
    if !proofs.is_empty() {
        let _ = writeln!(s, "**Independent proof:** {}.\n", proofs.join("; "));
    }
    s
}

fn differential_markdown(target: &str, findings: &[&Finding]) -> String {
    let mut s = format!(
        "# Differential proof — {target}\n\nEach finding is shown against its negative control: the same request without the payload (or as the identity that should be refused), next to the attack. A finding whose attack is indistinguishable from its control is not a finding.\n\n"
    );
    for f in findings {
        let _ = writeln!(s, "## {} — {}\n", md_cell(&f.title), f.severity);
        let _ = writeln!(s, "Verdict: **{}** {}\n", verdict_label(f), if f.review_reason.is_empty() { String::new() } else { format!("— {}", f.review_reason) });
        s.push_str(&differential_for(f));
        s.push('\n');
    }
    s
}

// ---------------------------------------------------------------------------
// #3 Observed vs derived vs inferred, with a chain of custody

fn custody(target: &str, findings: &[&Finding]) -> (String, String) {
    let generated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut head = sha256_hex(format!("neurosploit-custody|{target}").as_bytes());
    let genesis = head.clone();
    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut md = format!(
        "# Evidence & chain of custody — {target}\n\nEvery statement in the report belongs to one of three classes:\n\n- **OBSERVED** — bytes captured from the wire. Each is hashed (SHA-256 of the response body) and chained.\n- **DERIVED** — computed by the deterministic validation engine from observed bytes (verdict, CVSS). Re-running the engine on the same bytes yields the same result.\n- **INFERRED** — written by a language model (titles, narrative, impact). A hypothesis, never evidence.\n\nChain: `link = sha256(previous_link || artifact_hash)`, starting from `sha256(\"neurosploit-custody|<target>\")`. Altering, removing or reordering any observed artifact changes every later link.\n\nGenesis: `{genesis}` · generated (unix): {generated}\n\n"
    );
    for f in findings {
        let _ = writeln!(md, "## {}\n", md_cell(&f.title));
        let mut observed: Vec<(String, &Exchange)> = Vec::new();
        if let Some(ev) = f.evidence_data.as_ref() {
            collect_exchanges(ev, &mut observed);
        }
        let _ = writeln!(md, "### OBSERVED (wire)\n");
        if observed.is_empty() {
            let _ = writeln!(md, "_Nothing captured from the wire for this finding._\n");
        } else {
            let _ = writeln!(md, "| role | request | status | body sha256 | link |\n|---|---|---|---|---|");
            for (role, x) in &observed {
                let body_hash = sha256_hex(x.body.as_bytes());
                let record = format!("{}|{}|{}|{}|{}|{}", f.id, role, x.method, x.url, x.status, body_hash);
                let artifact = sha256_hex(record.as_bytes());
                head = sha256_hex(format!("{head}{artifact}").as_bytes());
                let _ = writeln!(
                    md,
                    "| {} | `{} {}` | {} | `{}` | `{}` |",
                    md_cell(role),
                    md_cell(&x.method),
                    md_cell(&short(&path_of(&x.url), 60)),
                    x.status,
                    &body_hash[..16],
                    &head[..16]
                );
                entries.push(serde_json::json!({
                    "finding_id": f.id, "class": "observed", "role": role,
                    "method": x.method, "url": x.url, "status": x.status,
                    "identity": x.identity, "body_sha256": body_hash,
                    "artifact_sha256": artifact, "link": head,
                }));
            }
            md.push('\n');
        }
        let _ = writeln!(md, "### DERIVED (deterministic engine)\n");
        let _ = writeln!(md, "- verdict: **{}**{}", verdict_label(f), if f.review_reason.is_empty() { String::new() } else { format!(" — {}", f.review_reason) });
        if !f.cvss.is_empty() {
            let _ = writeln!(md, "- CVSS: `{}`", f.cvss);
        }
        md.push('\n');
        let _ = writeln!(md, "### INFERRED (model narrative — hypothesis)\n");
        // The narrative is referenced, not copied: model prose can quote what
        // the target returned (tokens, passwords, personal data), and a custody
        // record needs to pin the text, not repeat it. The full text is in
        // report.md; the hash proves which text this was.
        let _ = writeln!(md, "- title: {}", md_cell(&short(&f.title, 160)));
        for (k, v) in [("impact", &f.impact), ("business impact", &f.business_impact), ("agent narrative", &f.evidence)] {
            if !v.trim().is_empty() {
                let _ = writeln!(md, "- {k}: {} chars · sha256 `{}` (text in report.md)", v.chars().count(), &sha256_hex(v.as_bytes())[..16]);
            }
        }
        md.push('\n');
    }
    let _ = writeln!(md, "---\n**Chain head:** `{head}` over {} observed artifact(s).", entries.len());
    let json = serde_json::json!({
        "target": target, "generated_unix": generated, "genesis": genesis,
        "head": head, "algorithm": "link = sha256(prev_link || sha256(finding|role|method|url|status|body_sha256))",
        "artifacts": entries,
    });
    (md, serde_json::to_string_pretty(&json).unwrap_or_default())
}

fn collect_exchanges<'a>(ev: &'a Evidence, out: &mut Vec<(String, &'a Exchange)>) {
    if let Some(x) = &ev.baseline {
        out.push(("control".into(), x));
    }
    if let Some(x) = &ev.attack {
        out.push(("attack".into(), x));
    }
    for (i, x) in ev.repeats.iter().enumerate() {
        out.push((format!("repeat {}", i + 1), x));
    }
    if let Some(x) = &ev.identity_a {
        out.push(("identity A".into(), x));
    }
    if let Some(x) = &ev.identity_b {
        out.push(("identity B".into(), x));
    }
    if let Some(o) = &ev.oracle {
        out.push(("oracle privileged".into(), &o.privileged));
        out.push(("oracle denied".into(), &o.denied));
    }
    for p in &ev.matrix {
        out.push((format!("matrix {}", p.identity), &p.exchange));
    }
}

// ---------------------------------------------------------------------------
// #1 Exploit-as-test

/// What a regression test needs: the vulnerable request and how to recognise
/// that it still works.
struct TestCase {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    secret_headers: Vec<String>,
    body: String,
    vuln_status: u16,
    control_status: Option<u16>,
    signature: Option<String>,
}

impl TestCase {
    fn from_finding(f: &Finding) -> Option<TestCase> {
        let ev = f.evidence_data.as_ref()?;
        // The exchange that demonstrates the flaw, and its negative control.
        let (attack, control): (&Exchange, Option<&Exchange>) = if let Some(a) = &ev.attack {
            (a, ev.baseline.as_ref())
        } else if let Some(b) = &ev.identity_b {
            (b, None)
        } else if let Some(o) = &ev.oracle {
            (&o.denied, None)
        } else {
            let p = ev.matrix.iter().find(|p| p.expect == Expect::Deny && p.exchange.is_success())?;
            (&p.exchange, None)
        };
        if attack.url.is_empty() {
            return None;
        }
        let mut headers = Vec::new();
        let mut secret_headers = Vec::new();
        for (k, v) in &attack.request_headers {
            if is_secret_header(k) {
                secret_headers.push(k.clone());
            } else if !matches!(k.to_ascii_lowercase().as_str(), "host" | "content-length") {
                headers.push((k.clone(), v.clone()));
            }
        }
        // Only honest oracles. A word guessed from one response body is not one:
        // the body may be the agent's prose, and the word may be leaked data.
        //  - the harness marker (a nonce it chose) still in the response;
        //  - a recorded negative control that answered with a different status;
        //  - an identity swap (BOLA/BFLA/oracle/matrix), fixed by a refusal.
        let marker = (!ev.marker.is_empty() && attack.body.contains(&ev.marker)).then(|| ev.marker.clone());
        let status_oracle = control.map(|c| c.status != attack.status && attack.status != 0).unwrap_or(false);
        let identity_swap = ev.attack.is_none() && attack.is_success();
        if marker.is_none() && !status_oracle && !identity_swap {
            return None;
        }
        let signature = marker;
        Some(TestCase {
            method: if attack.method.is_empty() { "GET".into() } else { attack.method.to_uppercase() },
            path: path_of(&attack.url),
            headers,
            secret_headers,
            body: if attack.method.eq_ignore_ascii_case("GET") { String::new() } else { f.payload.clone() },
            vuln_status: attack.status,
            control_status: control.map(|c| c.status),
            signature,
        })
    }

    fn pytest(&self, f: &Finding) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "\"\"\"Regression test for: {}", f.title.replace("\"\"\"", "'''"));
        let _ = writeln!(s, "\nCWE: {} · severity: {} · verdict: {}", f.cwe, f.severity, verdict_label(f));
        let _ = writeln!(s, "\nAsserts the SECURE behaviour: FAILS while the finding is open, PASSES once fixed.");
        let _ = writeln!(s, "Generated by NeuroSploit from recorded evidence; credentials come from the environment.\n\"\"\"");
        s.push_str("import os\n\nimport requests\n\n");
        let _ = writeln!(s, "TARGET = os.environ.get(\"NS_TARGET\", \"\").rstrip(\"/\")");
        let _ = writeln!(s, "METHOD = {}", py_str(&self.method));
        let _ = writeln!(s, "PATH = {}", py_str(&self.path));
        let _ = writeln!(s, "BODY = {}", py_str(&self.body));
        let _ = writeln!(s, "VULN_STATUS = {}", self.vuln_status);
        let _ = writeln!(s, "SIGNATURE = {}", self.signature.as_deref().map(py_str).unwrap_or_else(|| "None".into()));
        s.push_str("\n\ndef _headers():\n    h = {\n");
        for (k, v) in &self.headers {
            let _ = writeln!(s, "        {}: {},", py_str(k), py_str(v));
        }
        s.push_str("    }\n");
        for k in &self.secret_headers {
            let _ = writeln!(s, "    if os.environ.get({e}):\n        h[{k}] = os.environ[{e}]", e = py_str(&env_name(k)), k = py_str(k));
        }
        s.push_str("    return h\n\n\n");
        if !self.secret_headers.is_empty() {
            let envs: Vec<String> = self.secret_headers.iter().map(|k| py_str(&env_name(k))).collect();
            let _ = writeln!(s, "REQUIRED_ENV = [{}]\n", envs.join(", "));
            s.push_str("import pytest  # noqa: E402\n\n\n@pytest.fixture(autouse=True)\ndef _need_credentials():\n    missing = [e for e in REQUIRED_ENV if not os.environ.get(e)]\n    if missing:\n        pytest.skip(\"set \" + \", \".join(missing) + \" — without the identity the request would be refused for the wrong reason and the test would pass falsely\")\n\n\n");
        }
        s.push_str("def _send():\n    assert TARGET, \"set NS_TARGET\"\n    return requests.request(METHOD, TARGET + PATH, headers=_headers(), data=BODY or None, timeout=30, verify=False, allow_redirects=False)\n\n\n");
        s.push_str("def test_finding_is_fixed():\n    r = _send()\n    still_vulnerable = r.status_code == VULN_STATUS and (SIGNATURE is None or SIGNATURE in r.text)\n");
        let _ = writeln!(
            s,
            "    assert not still_vulnerable, (\n        f\"still vulnerable: {{METHOD}} {{PATH}} returned {{r.status_code}}\"\n        + (f\" containing {{SIGNATURE!r}}\" if SIGNATURE else \"\")\n    )"
        );
        if let Some(c) = self.control_status {
            let _ = writeln!(
                s,
                "\n\n# Negative control recorded at test time: the same request without the payload\n# returned HTTP {c}. A fix should make the attack behave like the control."
            );
        }
        s
    }

    fn nuclei(&self, f: &Finding) -> String {
        let sev = match f.severity.to_lowercase().as_str() {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "info",
        };
        let mut s = String::new();
        let _ = writeln!(s, "id: neurosploit-{}", slug(f));
        let _ = writeln!(s, "info:\n  name: {}\n  author: neurosploit\n  severity: {sev}", yq(&f.title));
        let _ = writeln!(s, "  description: {}", yq(&short(&f.impact, 300)));
        let cwe: String = f.cwe.chars().filter(|c| c.is_ascii_digit()).collect();
        if !cwe.is_empty() {
            let _ = writeln!(s, "  classification:\n    cwe-id: CWE-{cwe}");
        }
        let _ = writeln!(s, "  tags: neurosploit,regression\n\nhttp:\n  - method: {}\n    path:\n      - \"{{{{BaseURL}}}}{}\"", self.method, self.path.replace('"', "%22"));
        if !self.headers.is_empty() || !self.secret_headers.is_empty() {
            s.push_str("    headers:\n");
            for (k, v) in &self.headers {
                let _ = writeln!(s, "      {}: {}", k, yq(v));
            }
            for k in &self.secret_headers {
                // nuclei: pass with  -var auth_<name>=...  (never stored here)
                let var = format!("auth_{}", k.to_ascii_lowercase().replace('-', "_"));
                let _ = writeln!(s, "      {k}: \"{{{{{var}}}}}\"");
            }
        }
        if !self.body.is_empty() {
            let _ = writeln!(s, "    body: {}", yq(&self.body));
        }
        s.push_str("    matchers-condition: and\n    matchers:\n");
        let _ = writeln!(s, "      - type: status\n        status:\n          - {}", self.vuln_status);
        if let Some(sig) = &self.signature {
            let _ = writeln!(s, "      - type: word\n        part: body\n        words:\n          - {}", yq(sig));
        }
        s
    }
}


fn py_str(s: &str) -> String {
    format!("{:?}", s) // Rust debug quoting is a valid Python string literal for ASCII/escapes
}

/// Single-quoted YAML scalar.
fn yq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''").replace('\n', " "))
}

// ---------------------------------------------------------------------------
// #7 Detection content

#[derive(Clone, Copy, PartialEq)]
enum Class {
    Sqli,
    Xss,
    Traversal,
    Ssrf,
    Rce,
    Authz,
    Other,
}

fn classify(f: &Finding) -> Class {
    let n: String = f.cwe.chars().take_while(|c| *c != ';' && *c != ',').filter(|c| c.is_ascii_digit()).collect();
    // The CWE decides when there is one; the title (which can mention the
    // finding a chain started from — "SQLi-leaked password") only when not.
    let t = if n.is_empty() { f.title.to_lowercase() } else { String::new() };
    let is = |c: &[&str]| c.contains(&n.as_str());
    if is(&["89", "943", "564"]) || t.contains("sql") {
        Class::Sqli
    } else if is(&["79", "80", "83", "87"]) || t.contains("xss") || t.contains("cross-site scripting") {
        Class::Xss
    } else if is(&["22", "23", "35", "98", "73"]) || t.contains("traversal") || t.contains("file inclusion") {
        Class::Traversal
    } else if is(&["918"]) || t.contains("ssrf") {
        Class::Ssrf
    } else if is(&["77", "78", "94", "95", "502", "917", "1336"]) || t.contains("command") || t.contains("rce") || t.contains("code execution") {
        Class::Rce
    } else if is(&["639", "862", "863", "285", "284", "566", "425", "306"]) || t.contains("authoriz") || t.contains("idor") || t.contains("bola") || t.contains("access control") {
        Class::Authz
    } else {
        Class::Other
    }
}

fn class_keywords(c: Class) -> &'static [&'static str] {
    match c {
        Class::Sqli => &["' or ", "union select", "sleep(", "pg_sleep", "waitfor delay", "benchmark(", "information_schema", "--"],
        Class::Xss => &["<script", "onerror=", "onload=", "javascript:", "<svg", "alert("],
        Class::Traversal => &["../", "..%2f", "%2e%2e", "/etc/passwd", "win.ini"],
        Class::Ssrf => &["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "file://", "gopher://"],
        Class::Rce => &[";id", "|id", "$(", "`", "/bin/sh", "whoami", "copy from program"],
        Class::Authz | Class::Other => &[],
    }
}

/// The concrete indicator from this finding's own request (payload or query).
fn concrete_indicator(f: &Finding) -> Option<String> {
    let p = f.payload.trim();
    // A payload that names a credential field carries a credential.
    let low = p.to_lowercase();
    if ["password", "passwd", "pwd=", "pass=", "token", "secret", "api_key", "apikey", "authorization", "cookie", "session"]
        .iter()
        .any(|k| low.contains(k))
    {
        return None;
    }
    if !p.is_empty() && p.len() <= 200 {
        return Some(p.to_string());
    }
    let url = f.evidence_data.as_ref().and_then(|e| e.attack.as_ref()).map(|a| a.url.clone()).unwrap_or_default();
    url.split_once('?').map(|(_, q)| short(q, 200))
}

fn detection(findings: &[&Finding]) -> (Vec<(String, String)>, String, String) {
    let mut sigmas = Vec::new();
    let mut modsec = String::from(
        "# NeuroSploit — ModSecurity rules derived from confirmed exploits.\n# Review before enabling; start in DetectionOnly (SecRuleEngine DetectionOnly).\n\n",
    );
    let mut siem = String::from(
        "# SIEM queries derived from the exploits\n\nReplay each exploit (`make verify-<id>` in `../`) and confirm the matching query returns the request. An exploit your monitoring did not surface is a detection gap and a finding in its own right.\n\n",
    );
    for (i, f) in findings.iter().enumerate() {
        let c = classify(f);
        let s = slug(f);
        let path = path_of(&f.endpoint);
        let stem = path.split('?').next().unwrap_or("/").to_string();
        let mut kws: Vec<String> = class_keywords(c).iter().map(|k| k.to_string()).collect();
        // The finding's own payload is a useful indicator only when it is attack
        // syntax. For credential reuse, auth bypass or access control it is
        // often the credential itself — which must never land in a WAF rule or
        // a SIEM query shared with the SOC.
        if matches!(c, Class::Sqli | Class::Xss | Class::Traversal | Class::Ssrf | Class::Rce) {
            if let Some(ind) = concrete_indicator(f) {
                kws.insert(0, ind);
            }
        }
        let rule_id = 9_400_000 + (i as u32);
        let cwe: String = f.cwe.chars().filter(|c| c.is_ascii_digit()).collect();

        // Sigma
        let mut sg = String::new();
        let _ = writeln!(sg, "title: {}", yq(&format!("NeuroSploit — {}", f.title)));
        let _ = writeln!(sg, "id: {}", uuid_like(&s));
        let _ = writeln!(sg, "status: experimental\ndescription: {}", yq(&format!("Detects the request pattern NeuroSploit used to exploit: {}", short(&f.title, 200))));
        let _ = writeln!(sg, "author: NeuroSploit\nlogsource:\n  category: webserver\ndetection:");
        if c == Class::Authz || kws.is_empty() {
            let _ = writeln!(sg, "  selection:\n    cs-uri-stem|contains: {}\n    sc-status: 200", yq(&stem));
            let _ = writeln!(sg, "  condition: selection\n# Authorization flaws are behavioural: alert when this endpoint returns 200 to a\n# principal outside its allowed roles — needs identity-aware correlation (see SIEM query).");
        } else {
            let _ = writeln!(sg, "  selection_path:\n    cs-uri-stem|contains: {}", yq(&stem));
            let _ = writeln!(sg, "  selection_payload:\n    cs-uri-query|contains:");
            for k in &kws {
                let _ = writeln!(sg, "      - {}", yq(k));
            }
            let _ = writeln!(sg, "  condition: selection_path and selection_payload");
        }
        let _ = writeln!(sg, "level: {}", match f.severity.to_lowercase().as_str() { "critical" => "critical", "high" => "high", "medium" => "medium", _ => "low" });
        if !cwe.is_empty() {
            let _ = writeln!(sg, "tags:\n  - cwe.{cwe}");
        }
        sigmas.push((format!("{s}.sigma.yml"), sg));

        // ModSecurity
        let _ = writeln!(modsec, "# {} ({})", f.title.replace('\n', " "), f.endpoint);
        if c == Class::Authz || kws.is_empty() {
            let _ = writeln!(modsec, "# Authorization flaw — fix in the application; a WAF cannot tell roles apart.\n");
        } else {
            let alt: Vec<String> = kws.iter().map(|k| regex_escape(k)).collect();
            let _ = writeln!(
                modsec,
                "SecRule REQUEST_FILENAME \"@beginsWith {}\" \"id:{rule_id},phase:2,deny,status:403,log,msg:'NeuroSploit: {}',tag:'CWE-{}',chain\"\n    SecRule ARGS|REQUEST_BODY \"@rx (?i)(?:{})\" \"t:urlDecodeUni\"\n",
                stem.replace('"', ""),
                f.title.replace('\'', "").replace('"', "").replace('\n', " "),
                if cwe.is_empty() { "0".into() } else { cwe.clone() },
                alt.join("|")
            );
        }

        // SIEM
        let _ = writeln!(siem, "## {}\n", md_cell(&f.title));
        let terms: Vec<String> = kws.iter().take(6).map(|k| format!("\"{}\"", k.replace('"', "\\\""))).collect();
        if c == Class::Authz || terms.is_empty() {
            let _ = writeln!(siem, "Splunk:\n```\nindex=web uri_path=\"*{}*\" status=200 | stats count values(user) by src_ip, user, uri_path\n```", stem);
            let _ = writeln!(siem, "Elastic (KQL):\n```\nurl.path : *{}* and http.response.status_code : 200\n```\nCorrelate `user` against the roles allowed on this route; any other principal is the exploit.\n", stem);
        } else {
            let _ = writeln!(siem, "Splunk:\n```\nindex=web uri_path=\"*{}*\" ({})\n```", stem, terms.join(" OR "));
            let _ = writeln!(siem, "Elastic (KQL):\n```\nurl.path : *{}* and url.query : ({})\n```\n", stem, terms.join(" or "));
        }
    }
    (sigmas, modsec, siem)
}

fn regex_escape(s: &str) -> String {
    let mut o = String::new();
    for ch in s.chars() {
        if "\\.^$|?*+()[]{}/\"'".contains(ch) {
            o.push('\\');
        }
        o.push(ch);
    }
    o
}

/// Deterministic UUID-shaped id (Sigma rules want a stable `id`).
fn uuid_like(seed: &str) -> String {
    let h = sha256_hex(seed.as_bytes());
    format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

// ---------------------------------------------------------------------------
// #9 Personas

fn sev_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn sorted<'a>(findings: &[&'a Finding]) -> Vec<&'a Finding> {
    let mut v = findings.to_vec();
    v.sort_by_key(|f| sev_rank(&f.severity));
    v
}

fn persona_dev(target: &str, findings: &[&Finding]) -> String {
    let mut s = format!("# For developers — {target}\n\nOne ticket per finding: where it is, how to reproduce it, the test that proves it, and the fix.\n\n");
    for f in sorted(findings) {
        let sl = slug(f);
        let _ = writeln!(s, "## [{}] {}\n", f.severity, md_cell(&f.title));
        let loc = crate::report::location_line(f);
        if !loc.is_empty() {
            let _ = writeln!(s, "**Where:** {loc}\n");
        }
        if !f.cwe.is_empty() {
            let _ = writeln!(s, "**Class:** {}\n", f.cwe);
        }
        if TestCase::from_finding(f).is_some() {
            let _ = writeln!(s, "**Prove it / verify your fix:** `make -C deliverables verify-{sl}` — fails while vulnerable, passes when fixed. Add `deliverables/tests/test_{sl}.py` to CI as a regression test.\n");
        } else {
            let _ = writeln!(s, "**Prove it:** no structured evidence was recorded; reproduce with the steps in `report.md`.\n");
        }
        if !f.remediation.trim().is_empty() {
            let _ = writeln!(s, "**Fix:** {}\n", f.remediation.trim());
        }
    }
    s
}

fn persona_appsec(target: &str, findings: &[&Finding]) -> String {
    let mut s = format!(
        "# For AppSec — {target}\n\nVerdicts are computed by the deterministic engine; each finding carries its differential proof. Chains are in the attack graph (`graph.json` / web console).\n\n| severity | finding | CWE | CVSS | verdict |\n|---|---|---|---|---|\n"
    );
    for f in sorted(findings) {
        let _ = writeln!(s, "| {} | {} | {} | `{}` | {} |", f.severity, md_cell(&short(&f.title, 80)), md_cell(&f.cwe), md_cell(&f.cvss), verdict_label(f));
    }
    s.push('\n');
    for f in sorted(findings) {
        let _ = writeln!(s, "## {}\n", md_cell(&f.title));
        if !f.chains_from.is_empty() {
            let _ = writeln!(s, "Chained from: {}\n", f.chains_from.join(" → "));
        }
        s.push_str(&differential_for(f));
        s.push('\n');
    }
    s
}

/// What a finding does to the business, from what the evidence shows — never a
/// quote of the model's prose, which can carry the very data it exposed.
fn impact_phrase(f: &Finding) -> String {
    use crate::attack_graph::{data_class, demonstrated_rung, DataClass, Rung};
    use crate::chain::Capability as C;
    let mut parts: Vec<&str> = Vec::new();
    match data_class(f) {
        DataClass::Sensitive => parts.push("exposes sensitive data (credentials, keys or personal data)"),
        DataClass::Data => parts.push("exposes data that should not be reachable"),
        DataClass::None => {}
    }
    for c in crate::chain::provides(f) {
        let p = match c {
            C::CodeExecution => "lets an attacker run code on the system",
            C::PrivilegedContext => "lets an attacker act with someone else's privileges",
            C::InternalNetwork => "reaches systems behind the application",
            C::SessionMaterial | C::WeakCredentials => "yields usable credentials or sessions",
            C::DataAccess if parts.is_empty() => "gives read access to data",
            _ => continue,
        };
        if !parts.contains(&p) {
            parts.push(p);
        }
    }
    let proven = match demonstrated_rung(f) {
        Rung::Executed | Rung::CrossedSystem => "demonstrated",
        Rung::ReadSensitive | Rung::Wrote | Rung::ReadData => "demonstrated with a data read",
        Rung::Reached => "reached, impact not yet demonstrated",
    };
    if parts.is_empty() {
        format!("weakness confirmed ({proven})")
    } else {
        format!("{} ({proven})", parts.join("; "))
    }
}

fn persona_executive(target: &str, all: &[Finding]) -> String {
    let live: Vec<&Finding> = all.iter().filter(|f| !is_rejected(f)).collect();
    let confirmed = live.iter().filter(|f| verdict_label(f) == "confirmed").count();
    let review = live.len() - confirmed;
    let rejected = all.len() - live.len();
    let count = |sev: &str| live.iter().filter(|f| f.severity.eq_ignore_ascii_case(sev)).count();
    let mut s = format!("# Executive summary — {target}\n\n");
    let _ = writeln!(
        s,
        "The assessment reported **{}** issue(s): {} critical, {} high, {} medium, {} low. **{confirmed}** are confirmed by reproducible evidence; {review} need human review. {rejected} candidate(s) were discarded by the validation engine because the evidence did not hold up.\n",
        live.len(), count("critical"), count("high"), count("medium"), count("low")
    );
    let top: Vec<&Finding> = sorted(&live).into_iter().filter(|f| sev_rank(&f.severity) <= 1).take(5).collect();
    if !top.is_empty() {
        s.push_str("## What matters most\n\n");
        for f in top {
            let _ = writeln!(s, "- **{}** — {}", md_cell(&short(&f.title, 90)), impact_phrase(f));
        }
        s.push('\n');
    }
    let personal = live.iter().any(|f| {
        let t = format!("{} {} {}", f.title, f.impact, f.business_impact).to_lowercase();
        ["cpf", "e-mail", "email", "pii", "personal", "pessoa", "dados pessoais", "address", "endereço", "birth", "nascimento"].iter().any(|k| t.contains(k))
    });
    if personal {
        s.push_str("## Regulatory exposure\n\nAt least one finding touches personal data. Depending on jurisdiction this can engage data-protection law (e.g. GDPR Art. 32 security of processing and Art. 33/34 breach notification; equivalents such as LGPD, CCPA/CPRA, PIPEDA). Run with `--compliance gdpr` for a control-level mapping.\n\n");
    }
    s.push_str("_Severity reflects demonstrated impact, not vulnerability class. Absence of a finding is not evidence of security — only that this engagement did not find the specific issue._\n");
    s
}

fn index(target: &str, findings: &[&Finding]) -> String {
    let n_tests = findings.iter().filter(|f| TestCase::from_finding(f).is_some()).count();
    let n_untestable = findings.iter().filter(|f| f.evidence_data.is_some() && TestCase::from_finding(f).is_none()).count();
    format!(
        "# Deliverables — {target}\n\n\
| file | question it answers |\n|---|---|\n\
| `differential-proof.md` | Is it real? Attack vs negative control, computed diff, repeat distribution |\n\
| `evidence-custody.md` / `.json` | Can I trust the record? Observed vs derived vs inferred, hash-chained |\n\
| `tests/`, `nuclei/`, `Makefile` | Is it still open? Did my fix work? ({n_tests} executable regression test(s)) |\n\
| `detection/` | Would we see it? Sigma, ModSecurity, Splunk/Elastic |\n\
| `persona-dev.md` · `persona-appsec.md` · `persona-executive.md` | Same evidence, three audiences |\n\n\
Run all regression tests: `NS_TARGET=<url> NS_HDR_AUTHORIZATION='Bearer …' make -C deliverables verify-all`.\n\n\
{n_untestable} finding(s) have no honest automatic oracle (no harness marker, no negative control with a different status, no identity swap) and are listed in the Makefile; reproduce them from report.md.\n"
    )
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(method: &str, url: &str, status: u16, body: &str) -> Exchange {
        Exchange { method: method.into(), url: url.into(), status, body: body.into(), elapsed_ms: 100, ..Default::default() }
    }

    fn sqli_finding() -> Finding {
        let mut attack = ex("GET", "https://t.test/search?q=1'+OR+1=1--", 200, "<tr>ns-mark-123 admin</tr>");
        attack.request_headers.insert("Authorization".into(), "Bearer SUPERSECRETTOKEN".into());
        attack.request_headers.insert("Accept".into(), "text/html".into());
        let baseline = ex("GET", "https://t.test/search?q=1", 200, "<tr>no results</tr>");
        Finding {
            id: "VULN-123".into(),
            title: "SQL Injection in search".into(),
            severity: "High".into(),
            cwe: "CWE-89".into(),
            endpoint: "https://t.test/search".into(),
            payload: "1' OR 1=1--".into(),
            impact: "Dumps every row".into(),
            remediation: "Use parameterised queries".into(),
            review_status: "confirmed".into(),
            validated: true,
            evidence_data: Some(Evidence {
                baseline: Some(baseline),
                attack: Some(attack.clone()),
                repeats: vec![attack.clone(), attack],
                marker: "ns-mark-123".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ns_deliv_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn writes_every_artifact() {
        let d = tmp("all");
        write_all("https://t.test", &[sqli_finding()], &d).unwrap();
        let o = d.join("deliverables");
        for f in ["differential-proof.md", "evidence-custody.md", "evidence-custody.json", "Makefile", "README.md",
                  "tests/test_vuln-123.py", "nuclei/vuln-123.yaml", "detection/vuln-123.sigma.yml",
                  "detection/modsecurity.conf", "detection/siem-queries.md",
                  "persona-dev.md", "persona-appsec.md", "persona-executive.md"] {
            assert!(o.join(f).exists(), "missing {f}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn credentials_are_never_written() {
        let d = tmp("secret");
        write_all("https://t.test", &[sqli_finding()], &d).unwrap();
        for e in walk(&d) {
            let body = std::fs::read_to_string(&e).unwrap_or_default();
            assert!(!body.contains("SUPERSECRETTOKEN"), "token leaked into {}", e.display());
        }
        let test = std::fs::read_to_string(d.join("deliverables/tests/test_vuln-123.py")).unwrap();
        assert!(test.contains("NS_HDR_AUTHORIZATION"), "auth should come from env");
        let _ = std::fs::remove_dir_all(&d);
    }

    fn walk(d: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { out.extend(walk(&p)); } else { out.push(p); }
            }
        }
        out
    }

    #[test]
    fn pytest_asserts_secure_behaviour_on_the_harness_marker() {
        let f = sqli_finding();
        let t = TestCase::from_finding(&f).unwrap();
        let py = t.pytest(&f);
        assert!(py.contains("assert not still_vulnerable"));
        assert!(py.contains("VULN_STATUS = 200"));
        assert_eq!(t.signature.as_deref(), Some("ns-mark-123"), "only the harness marker is a signature");
        assert!(py.contains("REQUIRED_ENV") && py.contains("pytest.skip"), "missing credentials must skip, not pass");
    }

    #[test]
    fn no_honest_oracle_means_no_test() {
        // Attack and control answer the same status, no marker: any word picked
        // from the body would be a guess (and maybe leaked data) — no test.
        let mut f = sqli_finding();
        let ev = f.evidence_data.as_mut().unwrap();
        ev.marker.clear();
        assert!(TestCase::from_finding(&f).is_none());
        // A control with a different status is an honest oracle.
        let mut g = sqli_finding();
        let ev = g.evidence_data.as_mut().unwrap();
        ev.marker.clear();
        ev.baseline.as_mut().unwrap().status = 401;
        let t = TestCase::from_finding(&g).expect("status oracle");
        assert!(t.signature.is_none());
    }

    #[test]
    fn credentials_never_reach_detection_or_executive_summary() {
        let mut f = sqli_finding();
        f.title = "Credential reuse via SQLi-leaked admin password logs into /admin".into();
        f.cwe = "CWE-522".into();
        f.payload = "username=admin&password=Hunter2Secret".into();
        f.business_impact = "Attacker logs in as admin with Hunter2Secret".into();
        f.severity = "Critical".into();
        let (sig, modsec, siem) = detection(&[&f]);
        for (_, body) in &sig {
            assert!(!body.contains("Hunter2Secret"));
        }
        assert!(!modsec.contains("Hunter2Secret") && !siem.contains("Hunter2Secret"));
        assert!(!persona_executive("https://t.test", &[f]).contains("Hunter2Secret"));
    }

    #[test]
    fn custody_hashes_narrative_instead_of_copying_it() {
        let mut f = sqli_finding();
        f.evidence = "dumped users: admin / Hunter2Secret".into();
        let (md, _) = custody("https://t.test", &[&f]);
        assert!(!md.contains("Hunter2Secret"));
        assert!(md.contains("agent narrative:") && md.contains("sha256"));
    }

    #[test]
    fn differential_shows_control_and_attack() {
        let md = differential_for(&sqli_finding());
        assert!(md.contains("control (no payload)"));
        assert!(md.contains("**attack**"));
        assert!(md.contains("Reproducibility"));
    }

    #[test]
    fn custody_chain_changes_when_evidence_changes() {
        let f1 = sqli_finding();
        let mut f2 = sqli_finding();
        f2.evidence_data.as_mut().unwrap().attack.as_mut().unwrap().body.push('x');
        let (_, j1) = custody("https://t.test", &[&f1]);
        let (_, j2) = custody("https://t.test", &[&f2]);
        let h1: serde_json::Value = serde_json::from_str(&j1).unwrap();
        let h2: serde_json::Value = serde_json::from_str(&j2).unwrap();
        assert_ne!(h1["head"], h2["head"], "tampering must change the chain head");
        assert_eq!(h1["genesis"], h2["genesis"]);
    }

    #[test]
    fn finding_without_evidence_is_flagged_not_faked() {
        let f = Finding { title: "Narrative only".into(), severity: "Low".into(), ..Default::default() };
        assert!(TestCase::from_finding(&f).is_none(), "no evidence → no test is invented");
        assert!(differential_for(&f).contains("cannot be shown against a negative control"));
    }

    #[test]
    fn sigma_and_modsec_for_injection() {
        let (sig, modsec, siem) = detection(&[&sqli_finding()]);
        assert_eq!(sig.len(), 1);
        assert!(sig[0].1.contains("cs-uri-query|contains"));
        assert!(modsec.contains("SecRule REQUEST_FILENAME"));
        assert!(siem.contains("Splunk"));
    }

    #[test]
    fn rejected_findings_are_left_out() {
        let mut f = sqli_finding();
        f.review_status = "rejected".into();
        let d = tmp("rej");
        write_all("https://t.test", &[f], &d).unwrap();
        assert!(!d.join("deliverables/tests/test_vuln-123.py").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
