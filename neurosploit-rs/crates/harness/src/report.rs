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

/// Render an HTML report for the validated findings — same design language as
/// the Typst PDF template (`templates/report.typ`): violet brand accent,
/// severity-colored left-border finding cards, a 5-box executive-summary
/// grid, and a vulnerability summary table. No attack-path/kill-chain
/// section — that lives in the interactive web console's live graph instead.
pub fn html(target: &str, findings: &[Finding], meta: &EngagementMeta) -> String {
    html_with_pocs(target, findings, meta, &[])
}

/// As [`html`], but told which scripts exist in the run's `pocs/` directory so
/// each finding can link the ones it cites.
pub fn html_with_pocs(target: &str, findings: &[Finding], meta: &EngagementMeta, available_pocs: &[String]) -> String {
    let available_pocs = available_pocs.to_vec();
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| sev_rank(&f.severity));

    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for f in &sorted {
        if !needs_review(f) { *counts.entry(f.severity.as_str()).or_default() += 1; }
    }
    // Executive-summary grid: always all 5 severities, zero-count included —
    // matches the Typst template's #grid(columns: 5, ...) exactly.
    let summary_grid: String = ["Critical", "High", "Medium", "Low", "Info"]
        .iter()
        .map(|s| format!(
            "<div class=sumbox style=border-color:{}><div class=sumn style=color:{}>{}</div><div class=suml>{}</div></div>",
            sev_color(s), sev_color(s), counts.get(*s).copied().unwrap_or(0), s.to_uppercase()
        ))
        .collect();

    // Vulnerability summary table — numbered, title, severity badge, status, OWASP.
    let vuln_summary: String = if sorted.is_empty() {
        String::new()
    } else {
        let rows: String = sorted.iter().enumerate().map(|(i, f)| format!(
            "<tr><td>{}</td><td>{}</td><td><span class=sev style=background:{}>{}</span></td>\
             <td>{}</td><td>{}</td></tr>",
            i + 1, esc(&f.title), sev_color(&f.severity), esc(&f.severity),
            if needs_review(f) { "<span style=color:#8e44ad>needs-review</span>".to_string() } else { "<span style=color:#27ae60>confirmed</span>".to_string() },
            esc(&f.owasp),
        )).collect();
        format!(
            "<h2>Vulnerability Summary</h2>\
             <table class=kc><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Status</th><th>OWASP / CWE</th></tr>{rows}</table>"
        )
    };

    let rows: String = sorted
        .iter()
        .enumerate()
        .map(|(i, f)| {
            format!(
                "<section class=finding style=border-left-color:{sevc}>\
                 <h3><span class=sev style=background:{sevc}>{sev}</span> {i}. {title}{review}</h3>\
                 <table class=fieldgrid>\
                   <tr><td class=fk>Criticality</td><td>{sev}</td><td class=fk>Status</td><td>{status}</td></tr>\
                   <tr><td class=fk>OWASP / CWE</td><td>{owaspcwe}</td><td class=fk>Confidence</td><td>{confline}</td></tr>\
                   <tr><td class=fk>Location</td><td colspan=3>{endpoint}</td></tr>\
                   <tr><td class=fk>Agent</td><td>{agent}</td>{authcell}</tr>\
                 </table>\
                 {reviewnote}\
                 <h4>Where the problem is</h4><p class=where>{where_}</p>\
                 <h4>What it means</h4><p>{impact}</p>\
                 <h4>How to fix it</h4><p>{remediation}</p>\
                 <h4>Proof of concept — step by step</h4>{steps}\
                 {payloadblock}\
                 <h4>Technical evidence</h4><pre>{evidence}</pre>{shots}\
                 {scripts}</section>",
                sevc = sev_color(&f.severity), sev = esc(&f.severity), i = i + 1, title = esc(&f.title),
                agent = esc(&f.agent),
                owaspcwe = [esc(&f.owasp), esc(&f.cwe)].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · "),
                confline = if f.votes.is_empty() { format!("conf {:.2}", f.confidence) } else { format!("{} · conf {:.2}", esc(&f.votes), f.confidence) },
                endpoint = esc(&f.endpoint),
                where_ = esc(&location_line(f)),
                steps = {
                    // Numbered, pasteable commands. A reader who cannot
                    // reproduce a finding has to take it on faith, and a report
                    // that must be believed is worth less than one that can be
                    // checked.
                    let items: String = repro_steps(f).iter()
                        .map(|st| format!("<li><pre class=step>{}</pre></li>", esc(st)))
                        .collect();
                    format!("<ol class=steps>{items}</ol>")
                },
                payloadblock = if f.payload.trim().is_empty() { String::new() } else {
                    format!("<h4>Payload</h4><pre class=payload>{}</pre>", esc(f.payload.trim()))
                },
                scripts = {
                    let names = poc_scripts(f, &available_pocs);
                    if names.is_empty() { String::new() } else {
                        let items: String = names.iter()
                            .map(|n| format!("<li><a href=\"pocs/{n}\"><code>pocs/{n}</code></a></li>", n = esc(n)))
                            .collect();
                        format!("<h4>Runnable script (extra)</h4><p class=hint>The steps above are the proof; this script automates them.</p><ul class=pocs>{items}</ul>")
                    }
                },
                evidence = esc(&technical_evidence(f)),
                impact = esc(&f.impact), remediation = esc(&f.remediation),
                status = if needs_review(f) { "<span style=color:#8e44ad>needs-review</span>" } else { "<span style=color:#27ae60>confirmed</span>" },
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
                authcell = {
                    if f.auth_context.is_empty() && f.account.is_empty() { "<td class=fk></td><td></td>".to_string() }
                    else {
                        let ac = if f.auth_context.is_empty() { "—".to_string() } else { esc(&f.auth_context) };
                        let acct = if f.account.is_empty() { String::new() } else { format!(" · {}", esc(&f.account)) };
                        format!("<td class=fk>Auth context</td><td>{ac}{acct}</td>")
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

    format!(
        "<!DOCTYPE html><html><head><meta charset=utf-8><title>NeuroSploit Report — {t}</title><style>\
         :root{{--violet:#7c5cff}}\
         body{{font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:860px;margin:40px auto;padding:0 24px}}\
         h1{{margin:0;font-size:26px}}h2{{font-size:15px;margin:22px 0 8px}}\
         .b{{color:var(--violet);font-weight:800}}.sub{{color:#888;font-size:13px;margin:2px 0 16px}}\
         table.assettbl{{border-collapse:collapse;width:100%;margin:0 0 16px;font-size:12.5px}}\
         table.assettbl td{{border:0.5pt solid #ddd;padding:6px 9px}}table.assettbl td:first-child{{color:#888;width:160px}}\
         .summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:10px 0 6px}}\
         .sumbox{{border:1px solid #ddd;border-radius:6px;padding:10px 6px;text-align:center}}\
         .sumn{{font-size:20px;font-weight:800}}.suml{{font-size:9px;letter-spacing:.4px;color:#888;margin-top:2px}}\
         table.kc{{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:12.5px}}\
         table.kc th,table.kc td{{border:0.5pt solid #ddd;padding:6px 9px;text-align:left}}\
         table.kc th{{color:#555;font-size:11px;text-transform:uppercase;letter-spacing:.3px}}\
         .finding{{border:0.5pt solid #ddd;border-left:3pt solid #999;border-radius:6px;padding:14px 18px;margin:14px 0}}\
         .finding h3{{margin:0 0 8px;font-size:15px}}\
         table.fieldgrid{{border-collapse:collapse;width:100%;font-size:11.5px;margin-bottom:6px}}\
         table.fieldgrid td{{padding:3px 6px}}.fk{{color:#888;white-space:nowrap;width:1%}}\
         .sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}}.m{{color:#666;font-size:12px}}\
         pre{{background:#0f1117;color:#dfe6f3;padding:11px;border-radius:8px;overflow:auto;font-size:12.5px;white-space:pre-wrap}}\
         h4{{margin:12px 0 3px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--violet)}}\
         .shots{{display:flex;flex-wrap:wrap;gap:12px;margin:6px 0}}\
         .shot{{margin:0;max-width:100%}}.shot img{{max-width:100%;border:0.5pt solid #ddd;border-radius:8px;display:block}}\
         .shot figcaption{{color:#888;font-size:11px;margin-top:3px;font-family:ui-monospace,Menlo,monospace}}\
         .footer{{color:#888;font-size:11px;margin-top:24px;border-top:0.5pt solid #ddd;padding-top:10px}}\
         </style></head><body>\
         <h1><span class=b>Neuro</span>Sploit</h1><div class=sub>Penetration Test Report</div>\
         <table class=assettbl>\
           <tr><td>Asset</td><td><b>{asset}</b></td></tr>\
           <tr><td>URL / target</td><td>{t}</td></tr>\
           {techrow}{serverrow}\
         </table>\
         <h2>Executive Summary</h2><div class=summary-grid>{summary_grid}</div>\
         {vuln_summary}\
         <h2>Findings ({n})</h2>{body}\
         <p class=footer>Authorized testing only. Confirmed findings passed multi-model voting, receipt grounding and adversarial refute; \"needs-review\" are flagged for a human.<br>NeuroSploit v4.0.0 · by <b>Joas A Santos</b> &amp; <b>Red Team Leaders</b></p></body></html>",
        t = esc(target), n = sorted.len(), body = body, summary_grid = summary_grid, vuln_summary = vuln_summary,
        asset = esc(if meta.asset.is_empty() { "unidentified web asset" } else { &meta.asset }),
        techrow = if meta.tech.is_empty() { String::new() } else { format!("<tr><td>Technology</td><td>{}</td></tr>", esc(&meta.tech.join(", "))) },
        serverrow = if meta.server.is_empty() { String::new() } else { format!("<tr><td>Server</td><td>{}</td></tr>", esc(&meta.server)) },
    )
}

// ===== Typst report =====

// ---------------------------------------------------------------------------
// Proof of concept & technical evidence
//
// A finding is only useful if the reader can (a) find the problem, (b) see why
// it matters, (c) fix it, and (d) reproduce it without trusting us. The report
// used to print a payload blob and an evidence blob, which serves (d) badly and
// the rest not at all: "payload: ' OR 1=1--" tells a developer nothing about
// WHERE to look, and a PoC script attached as a file is a black box unless you
// run it.
//
// So the PoC is rendered as steps a person can paste, with the script offered
// as an extra artifact rather than as the proof itself.
// ---------------------------------------------------------------------------

/// Where the problem is, in one line, as precisely as the finding allows.
pub fn location_line(f: &Finding) -> String {
    match (f.location.trim(), f.endpoint.trim()) {
        ("", "") => "(location not recorded)".into(),
        ("", ep) => ep.to_string(),
        (loc, "") => loc.to_string(),
        (loc, ep) if loc.contains(ep) => loc.to_string(),
        (loc, ep) => format!("{ep} — {loc}"),
    }
}

/// A curl command that reproduces the request, built from the structured
/// evidence when the agent recorded it and from the endpoint/payload otherwise.
pub fn curl_command(f: &Finding) -> String {
    if let Some(ev) = &f.evidence_data {
        if let Some(a) = &ev.attack {
            let mut cmd = String::from("curl -i -s");
            let method = a.method.to_uppercase();
            if !method.is_empty() && method != "GET" {
                cmd.push_str(&format!(" -X {method}"));
            }
            for (k, v) in &a.request_headers {
                // Never print a real credential into a document that gets
                // shared; the reader substitutes their own.
                let val = if is_secret_header(k) { "<redacted — use your own>" } else { v.as_str() };
                cmd.push_str(&format!(" \\\n  -H '{k}: {val}'"));
            }
            if !f.payload.trim().is_empty() && method != "GET" {
                cmd.push_str(&format!(" \\\n  --data-raw '{}'", f.payload.replace('\'', "'\\''")));
            }
            cmd.push_str(&format!(" \\\n  '{}'", a.url));
            return cmd;
        }
    }
    if f.endpoint.trim().is_empty() {
        return String::new();
    }
    format!("curl -i -s '{}'", f.endpoint.trim())
}

fn is_secret_header(k: &str) -> bool {
    let k = k.to_lowercase();
    k == "authorization" || k == "cookie" || k == "x-api-key" || k.contains("token") || k.contains("secret")
}

/// Ordered reproduction steps. Uses what the agent recorded; falls back to a
/// minimal derived sequence so every finding carries something runnable.
pub fn repro_steps(f: &Finding) -> Vec<String> {
    if !f.repro_steps.is_empty() {
        return f.repro_steps.clone();
    }
    let mut steps = Vec::new();
    let curl = curl_command(f);
    if let Some(ev) = &f.evidence_data {
        if let Some(b) = &ev.baseline {
            steps.push(format!("Baseline — request the same resource without the payload:\ncurl -i -s '{}'", b.url));
        }
        if ev.identity_a.is_some() && ev.identity_b.is_some() {
            let a = ev.identity_a.as_ref().unwrap();
            let b = ev.identity_b.as_ref().unwrap();
            steps.push(format!("As {}: curl -i -s '{}'", if a.identity.is_empty() { "the owner" } else { &a.identity }, a.url));
            steps.push(format!("As {}: request the SAME resource:\ncurl -i -s '{}'", if b.identity.is_empty() { "the other identity" } else { &b.identity }, b.url));
            steps.push("Compare the two bodies — the second returning the first's data is the finding.".into());
            return steps;
        }
    }
    if !curl.is_empty() {
        steps.push(format!("Send the request carrying the payload:\n{curl}"));
    }
    if !f.payload.trim().is_empty() {
        steps.push(format!("Payload used:\n{}", f.payload.trim()));
    }
    if steps.is_empty() {
        steps.push("No reproduction steps were recorded for this finding.".into());
    }
    steps
}

/// The detailed technical evidence: the measured difference between baseline
/// and attack, then the raw exchanges. This is what turns "it returned a 500"
/// into something a reviewer can check.
pub fn technical_evidence(f: &Finding) -> String {
    let mut out = String::new();
    if let Some(ev) = &f.evidence_data {
        if let (Some(b), Some(a)) = (&ev.baseline, &ev.attack) {
            let d = crate::validation::diff(b, a);
            out.push_str(&format!(
                "MEASURED DIFFERENCE\n  baseline : {} {} · {} bytes · {} ms\n  attack   : {} {} · {} bytes · {} ms\n  delta    : {}\n",
                b.status, b.url, b.len(), b.elapsed_ms,
                a.status, a.url, a.len(), a.elapsed_ms,
                d.describe()
            ));
            if !ev.repeats.is_empty() {
                let (ok, hits) = crate::validation::reproducible(b, &ev.repeats, 2);
                out.push_str(&format!(
                    "  repeats  : {hits}/{} reproduced the same difference{}\n",
                    ev.repeats.len(),
                    if ok { "" } else { " — NOT deterministic" }
                ));
            }
            out.push('\n');
        }
        if !ev.marker.is_empty() {
            out.push_str(&format!(
                "CONTROLLED MARKER\n  {} — observed: {}{}{}\n\n",
                ev.marker,
                if ev.marker_observed { "yes" } else { "no" },
                if ev.browser_executed { " · executed in a real browser" } else { "" },
                if ev.callback_received { " · out-of-band callback received" } else { "" },
            ));
        }
        for (label, x) in [("BASELINE", &ev.baseline), ("ATTACK", &ev.attack), ("AS OWNER", &ev.identity_a), ("AS OTHER IDENTITY", &ev.identity_b)] {
            if let Some(x) = x {
                out.push_str(&render_exchange(label, x));
            }
        }
    }
    if !f.evidence.trim().is_empty() {
        out.push_str("AGENT-RECORDED EVIDENCE\n");
        out.push_str(f.evidence.trim());
        out.push('\n');
    }
    out.trim_end().to_string()
}

fn render_exchange(label: &str, x: &crate::validation::Exchange) -> String {
    let mut s = format!("{label}\n  {} {} → {}\n", if x.method.is_empty() { "GET" } else { &x.method }, x.url, x.status);
    if !x.identity.is_empty() {
        s.push_str(&format!("  identity: {}\n", x.identity));
    }
    for k in ["location", "set-cookie", "content-type", "access-control-allow-origin", "access-control-allow-credentials", "x-frame-options", "content-security-policy", "retry-after"] {
        let v = x.header(k);
        if !v.is_empty() {
            s.push_str(&format!("  {k}: {}\n", clip(v, 200)));
        }
    }
    if !x.body.trim().is_empty() {
        s.push_str(&format!("  body ({} bytes, excerpt):\n{}\n", x.len(), indent(&clip(x.body.trim(), 1200), "    ")));
    }
    s.push('\n');
    s
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let cut: String = s.chars().take(n).collect();
    format!("{cut}…")
}

fn indent(s: &str, pad: &str) -> String {
    s.lines().map(|l| format!("{pad}{l}")).collect::<Vec<_>>().join("\n")
}

/// PoC scripts this finding cites, or that the run wrote. The script is an
/// extra artifact — the steps above are the proof.
pub fn poc_scripts(f: &Finding, available: &[String]) -> Vec<String> {
    let cited = format!("{} {} {}", f.evidence, f.payload, f.repro_steps.join(" "));
    let matches: Vec<String> = available.iter().filter(|p| cited.contains(p.as_str())).cloned().collect();
    matches
}

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
            "  (severity: {}, title: {}, agent: {}, cwe: {}, owasp: {}, cvss: {}, endpoint: {}, payload: {}, evidence: {}, impact: {}, remediation: {}, votes: {}, confidence: {}, status: {}, auth: {}, screenshots: {}, location: {}, steps: {}),\n",
            tq(&f.severity), tq(&f.title), tq(&f.agent), tq(&f.cwe), tq(&owasp), tq(&f.cvss),
            tq(&f.endpoint), tq(&f.payload), tq(&technical_evidence(f)), tq(&f.impact),
            tq(&f.remediation), tq(&f.votes), f.confidence, tq(status),
            tq(if f.auth_context.is_empty() { "-" } else { &f.auth_context }),
            shots,
            tq(&location_line(f)),
            // The PDF gets the same pasteable steps as the HTML — a printed
            // report that cannot be reproduced is the one people argue with.
            tq(&repro_steps(f).iter().enumerate().map(|(i, st)| format!("{}. {}", i + 1, st)).collect::<Vec<_>>().join("\n\n")),
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
    s.replace("**", "").replace(['`', '*'], "")
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
        // Order follows how a reader works through a finding: where it is, what
        // it means, how to fix it, then how to see it for themselves.
        s.push_str(&format!("**Where the problem is:** {}\n\n", location_line(f)));
        if !f.impact.is_empty() { s.push_str(&format!("**What it means:** {}\n\n", f.impact)); }
        if !f.remediation.is_empty() { s.push_str(&format!("**How to fix it:** {}\n\n", f.remediation)); }
        let steps = repro_steps(f);
        if !steps.is_empty() {
            s.push_str("**Proof of concept — step by step**\n\n");
            for (n, st) in steps.iter().enumerate() {
                s.push_str(&format!("{}. ```\n{}\n```\n", n + 1, st));
            }
            s.push('\n');
        }
        if !f.payload.trim().is_empty() { s.push_str(&format!("**Payload**\n```\n{}\n```\n\n", f.payload.trim())); }
        let tech = technical_evidence(f);
        if !tech.is_empty() { s.push_str(&format!("**Technical evidence**\n```\n{}\n```\n\n", tech)); }
        if !f.screenshots.is_empty() {
            s.push_str("**Proof screenshots**\n\n");
            for p in &f.screenshots { s.push_str(&format!("![{}]({})\n\n", f.title.replace(']', ")"), p)); }
        }
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
    out.push('\n');

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
        out.push('\n');
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
/// A "## Reproduction — PoC scripts" section listing the runnable proof-of-concept
/// scripts agents wrote to `<run>/pocs/`. Each is a self-contained artifact the
/// operator can re-run to replicate a finding, so the report ships with a live
/// reproduction kit — not just prose. Empty string when no PoCs were produced.
pub fn pocs_section(dir: &Path) -> String {
    let pocs = dir.join("pocs");
    let mut entries: Vec<(String, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&pocs) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() { continue; }
            let name = match p.file_name().and_then(|s| s.to_str()) { Some(n) => n.to_string(), None => continue };
            // First non-empty comment line doubles as a one-line description.
            let desc = std::fs::read_to_string(&p).ok()
                .and_then(|t| t.lines()
                    .map(|l| l.trim())
                    .find(|l| l.starts_with('#') || l.starts_with("//") || l.starts_with("/*"))
                    .map(|l| l.trim_start_matches(['#', '/', '*', ' ']).trim().to_string()))
                .unwrap_or_default();
            entries.push((name, desc));
        }
    }
    if entries.is_empty() { return String::new(); }
    entries.sort();
    let mut s = String::from("## Reproduction — PoC scripts\n\n");
    s.push_str("Runnable proofs written to `pocs/` during the engagement. Re-run any of \
        them to replicate the corresponding finding.\n\n");
    for (name, desc) in entries {
        if desc.is_empty() {
            s.push_str(&format!("- `pocs/{name}`\n"));
        } else {
            s.push_str(&format!("- `pocs/{name}` — {desc}\n"));
        }
    }
    s.push('\n');
    s
}

pub fn write_all(target: &str, findings: &[Finding], dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let run_id = dir.file_name().and_then(|s| s.to_str()).unwrap_or("run").to_string();
    let meta = read_meta(dir);
    let mut md = markdown(target, findings, &meta);
    md.push_str(&pocs_section(dir));
    std::fs::write(dir.join("report.md"), md)?;
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
