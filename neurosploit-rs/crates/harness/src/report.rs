use crate::types::Finding;
use std::path::{Path, PathBuf};

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
pub fn html(target: &str, findings: &[Finding]) -> String {
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
                "<section class=finding><h3><span class=sev style=background:{}>{}</span> {}. {}</h3>\
                 <div class=m>{} · {} · CVSS {} · votes {} · conf {:.2}</div>\
                 <div class=m>Endpoint: {}</div>\
                 <h4>Payload</h4><pre>{}</pre><h4>Evidence</h4><pre>{}</pre>\
                 <h4>Impact</h4><p>{}</p><h4>Remediation</h4><p>{}</p></section>",
                sev_color(&f.severity), esc(&f.severity), i + 1, esc(&f.title),
                esc(&f.agent), esc(&f.cwe), esc(&f.cvss), esc(&f.votes), f.confidence,
                esc(&f.endpoint), esc(&f.payload), esc(&f.evidence), esc(&f.impact), esc(&f.remediation),
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
         .b{{color:#8b5cf6;font-weight:800}}</style></head><body>\
         <h1><span class=b>NeuroSploit</span> Penetration Test Report</h1>\
         <div class=meta>Target: <b>{t}</b> · v3.5.1 Rust harness · multi-model validated</div>\
         <div>{chips}</div>{graph_block}<h2>Findings ({n})</h2>{body}\
         <p class=meta>Authorized testing only. Findings confirmed by multi-model adversarial voting.<br>NeuroSploit v3.5.1 · by <b>Joas A Santos</b> &amp; <b>Red Team Leaders</b></p></body></html>",
        t = esc(target), chips = chips, n = sorted.len(), body = body, graph_block = graph_block,
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

    let mut data = String::new();
    data.push_str(&format!(
        "#let meta = (target: {}, run_id: {}, generated: {}, model: {})\n",
        tq(target), tq(&run_id), tq("NeuroSploit v3.5.1"), tq("multi-model")
    ));
    data.push_str("#let findings = (\n");
    for f in sorted_findings(findings) {
        let owasp = if f.owasp.is_empty() { f.cwe.clone() } else { f.owasp.clone() };
        data.push_str(&format!(
            "  (severity: {}, title: {}, agent: {}, cwe: {}, owasp: {}, cvss: {}, endpoint: {}, payload: {}, evidence: {}, impact: {}, remediation: {}, votes: {}, confidence: {}),\n",
            tq(&f.severity), tq(&f.title), tq(&f.agent), tq(&f.cwe), tq(&owasp), tq(&f.cvss),
            tq(&f.endpoint), tq(&f.payload), tq(&f.evidence), tq(&f.impact),
            tq(&f.remediation), tq(&f.votes), f.confidence,
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
