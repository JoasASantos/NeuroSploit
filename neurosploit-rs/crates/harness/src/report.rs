use crate::types::Finding;
use std::path::{Path, PathBuf};

/// Engagement metadata for the report: names the ASSET (product + stack), not just
/// the URL. Read from `meta.json` written by the pipeline after the probe.
#[derive(Default, Clone, serde::Deserialize)]
pub struct EngagementMeta {
    #[serde(default)] pub target: String,
    #[serde(default)] pub asset: String,
    #[serde(default)] pub title: String,
    #[serde(default)] pub tech: Vec<String>,
    #[serde(default)] pub server: String,
    #[serde(default)] pub status: u16,
}

/// Read `<dir>/meta.json` if present (best-effort).
pub fn read_meta(dir: &Path) -> EngagementMeta {
    std::fs::read_to_string(dir.join("meta.json")).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}


/// The blank, structured Typst template (rendering logic). Data (`meta`,
/// `findings`) is prepended by `typst_report` to make a self-contained file.
const TYPST_TEMPLATE: &str = include_str!("../../../templates/report.typ");

fn sev_rank(s: &str) -> u8 {
    match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

fn sev_color(s: &str) -> &'static str {
    match s {
        "Critical" => "#c0392b",
        "High" => "#e67e22",
        "Medium" => "#f1c40f",
        "Low" => "#3498db",
        _ => "#7f8c8d",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Render an HTML report for the validated findings.
pub fn html(target: &str, findings: &[Finding], meta: &EngagementMeta) -> String {
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| sev_rank(&f.severity));

    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for f in &sorted {
        *counts.entry(f.severity.as_str()).or_default() += 1;
    }
    let chips: String = if counts.is_empty() {
        "<span class=chip style=background:#27ae60>No validated findings</span>".into()
    } else {
        counts
            .iter()
            .map(|(s, n)| format!("<span class=chip style=background:{}>{}: {}</span>", sev_color(s), s, n))
            .collect()
    };

    let rows: String = sorted
        .iter()
        .enumerate()
        .map(|(i, f)| {
            format!(
                "<section class=finding><h3><span class=sev style=background:{}>{}</span> {}. {}{review}</h3>\
                 <div class=m>{} · {} · CVSS {} · votes {} · conf {:.2}</div>\
                 <div class=m>Endpoint: {}</div>{authline}{reviewnote}\
                 <h4>Payload</h4><pre>{}</pre><h4>Evidence</h4><pre>{}</pre>{shots}\
                 <h4>Impact</h4><p>{}</p><h4>Remediation</h4><p>{}</p></section>",
                sev_color(&f.severity), esc(&f.severity), i + 1, esc(&f.title),
                esc(&f.agent), esc(&f.cwe), esc(&f.cvss), esc(&f.votes), f.confidence,
                esc(&f.endpoint), esc(&f.payload), esc(&f.evidence), esc(&f.impact), esc(&f.remediation),
                shots = if f.screenshots.is_empty() { String::new() } else {
                    let imgs: String = f.screenshots.iter()
                        .map(|p| format!("<figure class=shot><img src=\"{}\" alt=\"proof for {}\"><figcaption>{}</figcaption></figure>",
                            esc(p), esc(&f.title), esc(p))).collect();
                    format!("<h4>Proof screenshots</h4><div class=shots>{imgs}</div>")
                },
                review = if needs_review(f) { " <span class=sev style=background:#8e44ad>NEEDS REVIEW</span>" } else { "" },
                reviewnote = if needs_review(f) && !f.review_reason.is_empty() {
                    format!("<div class=m style=color:#8e44ad>⚠ Needs human review — {}</div>", esc(&f.review_reason))
                } else { String::new() },
                authline = {
                    // Show the auth context and which test account proved this finding.
                    if f.auth_context.is_empty() && f.account.is_empty() { String::new() }
                    else {
                        let ac = if f.auth_context.is_empty() { String::new() } else { format!("Auth: <b>{}</b>", esc(&f.auth_context)) };
                        let acct = if f.account.is_empty() { String::new() } else { format!("{}Account: {}", if ac.is_empty() { "" } else { " · " }, esc(&f.account)) };
                        format!("<div class=m>{ac}{acct}</div>")
                    }
                },
            )
        })
        .collect();
    let body = if rows.is_empty() {
        "<p><em>No validated findings were produced for this engagement.</em></p>".to_string()
    } else {
        rows
    };

    // Attack graph (Mermaid) + kill-chain table.
    let graph = crate::attack_graph::mermaid(&sorted);
    let graph_block = if graph.is_empty() {
        String::new()
    } else {
        let rows: String = sorted.iter().map(|f| format!(
            "<tr><td>{}</td><td><span class=sev style=background:{}>{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&f.stage), sev_color(&f.severity), esc(&f.severity), esc(&f.title),
            esc(&f.owasp), esc(&f.mitre), esc(&f.exploitability))).collect();
        format!(
            "<h2>Attack Path &amp; Kill Chain</h2>\
             <div class=mermaid>{graph}</div>\
             <table class=kc><tr><th>Stage</th><th>Sev</th><th>Finding</th><th>OWASP</th><th>MITRE</th><th>Exploitability</th></tr>{rows}</table>\
             <script type=module>import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';mermaid.initialize({{startOnLoad:true,theme:'dark'}});</script>"
        )
    };
    format!(
        "<!DOCTYPE html><html><head><meta charset=utf-8><title>NeuroSploit Report — {t}</title><style>\
         table.kc{{border-collapse:collapse;width:100%;margin:14px 0;font-size:13px}}table.kc th,table.kc td{{border:1px solid #e3e3e3;padding:6px 9px;text-align:left}}\
         .mermaid{{background:#0f1117;border-radius:10px;padding:16px;margin:14px 0;overflow:auto}}\
         body{{font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:860px;margin:40px auto;padding:0 24px}}\
         h1{{margin:0}}.meta{{color:#666;margin:4px 0 18px}}.chip{{color:#fff;border-radius:999px;padding:4px 12px;margin-right:8px;font-size:13px;font-weight:600}}\
         .finding{{border:1px solid #e3e3e3;border-radius:12px;padding:16px 20px;margin:16px 0}}.finding h3{{margin:0 0 8px;font-size:16px}}\
         .sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}}.m{{color:#666;font-size:12px}}\
         pre{{background:#0f1117;color:#dfe6f3;padding:11px;border-radius:8px;overflow:auto;font-size:12.5px}}\
         h4{{margin:12px 0 3px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:#8b5cf6}}\
         .shots{{display:flex;flex-wrap:wrap;gap:12px;margin:6px 0}}\
         .shot{{margin:0;max-width:100%}}.shot img{{max-width:100%;border:1px solid #e3e3e3;border-radius:8px;display:block}}\
         .shot figcaption{{color:#888;font-size:11px;margin-top:3px;font-family:ui-monospace,Menlo,monospace}}\
         .b{{color:#8b5cf6;font-weight:800}}</style></head><body>\
         <h1><span class=b>NeuroSploit</span> Penetration Test Report</h1>\
         <div class=meta>Asset: <b>{asset}</b> · Target: <b>{t}</b>{techline} · v3.6.5 · multi-model validated</div>\
         <div>{chips}</div>{graph_block}<h2>Findings ({n})</h2>{body}\
         <p class=meta>Authorized testing only. Confirmed findings passed multi-model voting, receipt grounding and adversarial refute; \"needs-review\" are flagged for a human.<br>NeuroSploit v3.6.5 · by <b>Joas A Santos</b> &amp; <b>Red Team Leaders</b></p></body></html>",
        t = esc(target), chips = chips, n = sorted.len(), body = body, graph_block = graph_block,
        asset = esc(if meta.asset.is_empty() { "unidentified web asset" } else { &meta.asset }),
        techline = if meta.tech.is_empty() { String::new() } else { format!(" · {}", esc(&meta.tech.join(", "))) },
    )
}

// ===== Typst report =====

/// Is the `typst` binary available on PATH?
fn typst_available() -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("typst").is_file()))
        .unwrap_or(false)
}

fn sorted_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut v = findings.to_vec();
    v.sort_by_key(|f| sev_rank(&f.severity));
    v
}

/// Escape a string for embedding inside a Typst `"..."` literal (single line).
fn tq(s: &str) -> String {
    let cleaned: String = s.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], " ");
    format!("\"{}\"", cleaned)
}

/// Generate a self-contained `report.typ` (data + bundled template) in `dir`
/// and compile it to `report.pdf` via the `typst` binary. Falls back to leaving
/// the `.typ` when `typst` is unavailable.
pub fn typst_report(target: &str, findings: &[Finding], dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let run_id = dir.file_name().and_then(|s| s.to_str()).unwrap_or("run").to_string();
    let meta = read_meta(dir);

    // Prose blocks + account list rendered in Rust, passed as strings to Typst.
    let sorted = sorted_findings(findings);
    let confirmed: Vec<&Finding> = sorted.iter().filter(|f| !needs_review(f)).collect();
    let review: Vec<&Finding> = sorted.iter().filter(|f| needs_review(f)).collect();
    let asset = if meta.asset.is_empty() { "unidentified web asset".to_string() } else { meta.asset.clone() };
    let accounts = findings.iter().find(|f| f.id == "test-accounts").map(|f| f.evidence.clone()).unwrap_or_default();

    let mut data = String::new();
    data.push_str(&format!(
        "#let meta = (target: {}, asset: {}, tech: {}, server: {}, run_id: {}, generated: {}, model: {}, exec: {}, conclusion: {}, accounts: {})\n",
        tq(target), tq(&asset), tq(&meta.tech.join(", ")), tq(&meta.server),
        tq(&run_id), tq("July 2026"), tq("multi-model"),
        tq(&strip_md(&exec_summary(target, &meta, &confirmed, &review))),
        tq(&strip_md(&conclusion(target, &meta, &confirmed, &review))),
        tq(&strip_md(&accounts)),
    ));
    data.push_str("#let findings = (\n");
    for f in &sorted {
        let owasp = if f.owasp.is_empty() { f.cwe.clone() } else { f.owasp.clone() };
        let status = if needs_review(f) { "needs-review" } else { "confirmed" };
        let shots = format!("({})",
            f.screenshots.iter().map(|p| format!("{},", tq(p))).collect::<String>());
        data.push_str(&format!(
            "  (severity: {}, title: {}, agent: {}, cwe: {}, owasp: {}, cvss: {}, endpoint: {}, payload: {}, evidence: {}, impact: {}, remediation: {}, votes: {}, confidence: {}, status: {}, auth: {}, screenshots: {}),\n",
            tq(&f.severity), tq(&f.title), tq(&f.agent), tq(&f.cwe), tq(&owasp), tq(&f.cvss),
            tq(&f.endpoint), tq(&f.payload), tq(&f.evidence), tq(&f.impact),
            tq(&f.remediation), tq(&f.votes), f.confidence, tq(status),
            tq(if f.auth_context.is_empty() { "-" } else { &f.auth_context }),
            shots,
        ));
    }
    data.push_str(")\n\n");

    let typ_path = dir.join("report.typ");
    std::fs::write(&typ_path, format!("{data}{TYPST_TEMPLATE}"))?;

    if typst_available() {
        let pdf_path = dir.join("report.pdf");
        match std::process::Command::new("typst")
            .arg("compile").arg(&typ_path).arg(&pdf_path).output()
        {
            Ok(o) if o.status.success() && pdf_path.exists() => return Ok(pdf_path),
            Ok(o) => eprintln!("typst compile failed: {}",
                String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("").trim()),
            Err(e) => eprintln!("typst not runnable: {e}"),
        }
    }
    Ok(typ_path)
}

/// True if a finding is flagged for human review (kept, not deleted).
fn needs_review(f: &Finding) -> bool { f.review_status == "needs-review" }

/// Strip Markdown emphasis/backticks so prose renders cleanly inside Typst.
fn strip_md(s: &str) -> String {
    s.replace("**", "").replace('`', "").replace('*', "")
}

/// Written prose executive summary: names the asset, the counts, and the top risks.
fn exec_summary(target: &str, meta: &EngagementMeta, confirmed: &[&Finding], review: &[&Finding]) -> String {
    let asset = if meta.asset.is_empty() { format!("the web asset at `{target}`") }
        else { format!("**{}** (`{target}`)", meta.asset) };
    let stack = if meta.tech.is_empty() { String::new() }
        else { format!(" The asset fingerprints as {}.", meta.tech.join(", ")) };
    if confirmed.is_empty() && review.is_empty() {
        return format!("This authorized engagement assessed {asset}.{stack} No findings were \
            produced: candidate issues were either unproven or rejected by multi-model adversarial \
            validation. The asset presented no confirmed weaknesses within the tested scope.\n\n");
    }
    let by_sev = |list: &[&Finding], s: &str| list.iter().filter(|f| f.severity == s).count();
    let crit = by_sev(confirmed, "Critical");
    let high = by_sev(confirmed, "High");
    let med = by_sev(confirmed, "Medium");
    let low = by_sev(confirmed, "Low");
    let mut risk = Vec::new();
    if crit > 0 { risk.push(format!("{crit} critical")); }
    if high > 0 { risk.push(format!("{high} high")); }
    if med > 0 { risk.push(format!("{med} medium")); }
    if low > 0 { risk.push(format!("{low} low")); }
    let riskline = if risk.is_empty() { "no severity-rated confirmed".into() } else { risk.join(", ") };
    let top: Vec<String> = confirmed.iter().take(3).map(|f| format!("*{}*", f.title)).collect();
    let topline = if top.is_empty() { String::new() } else { format!(" The most significant confirmed issues are {}.", top.join(", ")) };
    let reviewline = if review.is_empty() { String::new() }
        else { format!(" A further **{}** finding(s) are flagged **needs-review** — kept for a human analyst to adjudicate rather than discarded.", review.len()) };
    format!("This authorized penetration test assessed {asset}.{stack} The engagement confirmed \
        **{} finding(s)** ({riskline}) via multi-model voting, tool-receipt grounding and an adversarial \
        refute pass.{topline}{reviewline} Details, evidence and remediation follow.\n\n", confirmed.len())
}

/// Render a Markdown report: asset identification, executive summary, a
/// vulnerability table, created test accounts (from the vault), detailed
/// confirmed findings, a separate needs-review section, and a written conclusion.
pub fn markdown(target: &str, findings: &[Finding], meta: &EngagementMeta) -> String {
    let sorted = sorted_findings(findings);
    let confirmed: Vec<&Finding> = sorted.iter().filter(|f| !needs_review(f)).collect();
    let review: Vec<&Finding> = sorted.iter().filter(|f| needs_review(f)).collect();

    let fmt = |f: &Finding, i: usize| -> String {
        let mut s = format!("### {}. [{}] {}\n\n", i + 1, f.severity, f.title);
        let mut m = vec![format!("**Agent:** {}", f.agent)];
        if !f.cwe.is_empty() { m.push(format!("**CWE:** {}", f.cwe)); }
        if !f.owasp.is_empty() { m.push(format!("**OWASP:** {}", f.owasp)); }
        if !f.cvss.is_empty() { m.push(format!("**CVSS:** {}", f.cvss)); }
        if !f.votes.is_empty() { m.push(format!("**Votes:** {}", f.votes)); }
        m.push(format!("**Confidence:** {:.2}", f.confidence));
        if !f.auth_context.is_empty() { m.push(format!("**Auth:** {}", f.auth_context)); }
        if !f.account.is_empty() { m.push(format!("**Account:** {}", f.account)); }
        s.push_str(&m.join(" · "));
        s.push_str("\n\n");
        if needs_review(f) && !f.review_reason.is_empty() {
            s.push_str(&format!("> ⚠️ **Needs human review** — {}\n\n", f.review_reason));
        }
        if !f.endpoint.is_empty() { s.push_str(&format!("**Endpoint:** `{}`\n\n", f.endpoint)); }
        if !f.payload.is_empty() { s.push_str(&format!("**Payload**\n```\n{}\n```\n\n", f.payload)); }
        if !f.evidence.is_empty() { s.push_str(&format!("**Evidence**\n```\n{}\n```\n\n", f.evidence)); }
        if !f.screenshots.is_empty() {
            s.push_str("**Proof screenshots**\n\n");
            for p in &f.screenshots { s.push_str(&format!("![{}]({})\n\n", f.title.replace(']', ")"), p)); }
        }
        if !f.impact.is_empty() { s.push_str(&format!("**Impact:** {}\n\n", f.impact)); }
        if !f.remediation.is_empty() { s.push_str(&format!("**Remediation:** {}\n\n", f.remediation)); }
        s.push_str("---\n\n");
        s
    };

    let mut out = String::new();
    out.push_str("# NeuroSploit Penetration Test Report\n\n");
    out.push_str("_by Joas A Santos & Red Team Leaders · NeuroSploit v3.6.5 · confidential_\n\n");

    // --- Asset under test ---
    out.push_str("## Asset under test\n\n");
    out.push_str(&format!("- **Asset:** {}\n", if meta.asset.is_empty() { "unidentified web asset".into() } else { meta.asset.clone() }));
    out.push_str(&format!("- **URL / target:** `{target}`\n"));
    if !meta.title.is_empty() { out.push_str(&format!("- **Page title:** {}\n", meta.title)); }
    if !meta.tech.is_empty() { out.push_str(&format!("- **Technology:** {}\n", meta.tech.join(", "))); }
    if !meta.server.is_empty() { out.push_str(&format!("- **Server:** {}\n", meta.server)); }
    out.push_str("\n");

    // --- Executive summary ---
    out.push_str("## Executive summary\n\n");
    out.push_str(&exec_summary(target, meta, &confirmed, &review));

    // --- Vulnerability table ---
    out.push_str("## Vulnerability summary\n\n");
    if confirmed.is_empty() && review.is_empty() {
        out.push_str("_No findings._\n\n");
    } else {
        out.push_str("| # | Vulnerability | Severity | CWE / OWASP | Status | Auth |\n");
        out.push_str("|---|---------------|----------|-------------|--------|------|\n");
        for (i, f) in sorted.iter().enumerate() {
            let owc = if !f.owasp.is_empty() { f.owasp.clone() } else { f.cwe.clone() };
            let status = if needs_review(f) { "needs-review" } else { "confirmed" };
            let auth = if f.auth_context.is_empty() { "-" } else { f.auth_context.as_str() };
            out.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n",
                i + 1, f.title.replace('|', "\\|"), f.severity, owc.replace('|', "\\|"), status, auth));
        }
        out.push_str("\n");
    }

    // --- Test accounts created (from the vault cleanup finding) ---
    if let Some(acc) = findings.iter().find(|f| f.id == "test-accounts") {
        out.push_str("## Test accounts created (delete after)\n\n");
        out.push_str("These accounts were created to reach the authenticated surface. Credentials are in the run vault (`.neurosploit/vault/<run-id>.json`); delete them once testing is complete.\n\n");
        out.push_str(&format!("{}\n\n", acc.evidence));
    }

    // --- Detailed confirmed findings ---
    out.push_str(&format!("## Confirmed findings ({})\n\n", confirmed.len()));
    if confirmed.is_empty() { out.push_str("_None confirmed._\n\n"); }
    else { for (i, f) in confirmed.iter().enumerate() { out.push_str(&fmt(f, i)); } }

    // --- Needs-review ---
    if !review.is_empty() {
        out.push_str(&format!("## Needs human review ({}) — signalled, not deleted\n\n", review.len()));
        out.push_str("The harness kept these uncertain findings for a human to adjudicate instead of discarding them.\n\n");
        for (i, f) in review.iter().enumerate() { out.push_str(&fmt(f, i)); }
    }

    // --- Conclusion ---
    out.push_str("## Conclusion\n\n");
    out.push_str(&conclusion(target, meta, &confirmed, &review));
    out
}

/// Written conclusion paragraph.
fn conclusion(target: &str, meta: &EngagementMeta, confirmed: &[&Finding], review: &[&Finding]) -> String {
    let asset = if meta.asset.is_empty() { format!("the asset at `{target}`") } else { format!("**{}**", meta.asset) };
    let has_high = confirmed.iter().any(|f| f.severity == "Critical" || f.severity == "High");
    let mut s = String::new();
    if confirmed.is_empty() && review.is_empty() {
        s.push_str(&format!("Within the tested scope, {asset} did not yield confirmed vulnerabilities. \
            This is not proof of absence — re-test after changes and widen scope (authenticated flows, \
            business logic, and any endpoints not reachable during this run).\n"));
    } else {
        s.push_str(&format!("The assessment of {asset} confirmed {} finding(s)", confirmed.len()));
        if has_high { s.push_str(" including high-impact issues that warrant prompt remediation"); }
        s.push_str(". Prioritise fixes by severity, then re-test to verify closure.");
        if !review.is_empty() {
            s.push_str(&format!(" {} additional finding(s) are flagged for human review — a security \
                analyst should adjudicate these before they are accepted or dismissed.", review.len()));
        }
        s.push_str(" Remediation guidance accompanies each finding above.\n");
    }
    s
}

/// Structured JSON report: run metadata + findings split into confirmed and
/// needs-review buckets (plus the flat list). Machine-consumable.
pub fn json_report(target: &str, findings: &[Finding], run_id: &str, meta: &EngagementMeta) -> String {
    let confirmed: Vec<&Finding> = findings.iter().filter(|f| !needs_review(f)).collect();
    let review: Vec<&Finding> = findings.iter().filter(|f| needs_review(f)).collect();
    let v = serde_json::json!({
        "tool": "NeuroSploit",
        "version": "3.6.5",
        "target": target,
        "run_id": run_id,
        "asset": {
            "name": if meta.asset.is_empty() { "unidentified web asset" } else { &meta.asset },
            "title": meta.title,
            "tech": meta.tech,
            "server": meta.server,
        },
        "summary": {
            "confirmed": confirmed.len(),
            "needs_review": review.len(),
            "total": findings.len(),
        },
        "confirmed": confirmed,
        "needs_review": review,
        "findings": findings,
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

/// Write the full report bundle: Markdown, JSON, HTML, and the Typst/PDF.
/// Returns the primary artifact path (PDF if typst present, else the .typ).
pub fn write_all(target: &str, findings: &[Finding], dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let run_id = dir.file_name().and_then(|s| s.to_str()).unwrap_or("run").to_string();
    let meta = read_meta(dir);
    std::fs::write(dir.join("report.md"), markdown(target, findings, &meta))?;
    std::fs::write(dir.join("report.json"), json_report(target, findings, &run_id, &meta))?;
    std::fs::write(dir.join("report.html"), html(target, findings, &meta))?;
    typst_report(target, findings, dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Finding;

    #[test]
    fn markdown_separates_confirmed_and_needs_review() {
        let confirmed = Finding { title: "SQLi login bypass".into(), severity: "High".into(),
            endpoint: "/rest/user/login".into(), evidence: "HTTP/1.1 200".into(),
            review_status: "confirmed".into(), validated: true, confidence: 0.9, ..Default::default() };
        let review = Finding { title: "Maybe SSRF".into(), severity: "Medium".into(),
            review_status: "needs-review".into(), review_reason: "below vote quorum (1/3)".into(),
            confidence: 0.33, ..Default::default() };
        let meta = EngagementMeta { asset: "OWASP Juice Shop".into(), ..Default::default() };
        let md = markdown("http://t", &[confirmed, review.clone()], &meta);
        assert!(md.contains("## Confirmed findings (1)"));
        assert!(md.contains("## Needs human review (1)"));
        assert!(md.contains("Needs human review") && md.contains("below vote quorum"));
        assert!(md.contains("OWASP Juice Shop")); // asset named, not just URL

        let js = json_report("http://t", &[review], "run1", &meta);
        let v: serde_json::Value = serde_json::from_str(&js).unwrap();
        assert_eq!(v["summary"]["needs_review"], 1);
        assert_eq!(v["summary"]["confirmed"], 0);
    }
}
