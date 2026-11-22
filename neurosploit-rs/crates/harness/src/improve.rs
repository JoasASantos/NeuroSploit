//! Self-improvement pass — turn a run's friction into a reviewable issue.
//!
//! A pentest harness fails in ways the final report never shows: an agent ran
//! out of output budget mid-JSON, a tool was missing from the sandbox, recon
//! saw a surface the planner never dispatched, a target answered something no
//! validator understood. Those are the signals that make the *next* run better,
//! and they are exactly the ones nobody has time to read.
//!
//! This module collects those signals from a finished run and hands them to a
//! (deliberately cheap) model with one job: write an issue — problem, evidence,
//! proposed fix, and an example patch — for a human to accept or reject. It
//! never edits code and never opens a PR on its own; `--create` is required to
//! post, so the default is a local Markdown artifact.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signal {
    /// `status` · `error` · `trace` · `coverage` · `tool` · `parse`.
    pub kind: String,
    pub detail: String,
}

const SIGNAL_NEEDLES: &[(&str, &str)] = &[
    ("error", "error"),
    ("failed", "failure"),
    ("not found", "missing component"),
    ("unsupported", "unsupported"),
    ("truncated", "truncated output"),
    ("parse", "parse issue"),
    ("timeout", "timeout"),
    ("denied", "policy denial"),
    ("no findings", "empty result"),
];

/// Collect the run's friction points. Read-only and best-effort.
pub fn collect(dir: &Path) -> Vec<Signal> {
    let mut out = Vec::new();

    if let Ok(text) = std::fs::read_to_string(dir.join("status.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("unknown");
            let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
            out.push(Signal { kind: "status".into(), detail: format!("state={state} target={target}") });
            if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
                out.push(Signal { kind: "error".into(), detail: err.to_string() });
            }
        }
    }

    let findings = std::fs::read_to_string(dir.join("findings.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    out.push(Signal { kind: "coverage".into(), detail: format!("{findings} confirmed finding(s)") });

    if let Ok(text) = std::fs::read_to_string(dir.join("audit.jsonl")) {
        let denied = text.lines().filter(|l| l.contains("\"policy_decision\":\"deny") || l.contains("deny:")).count();
        if denied > 0 {
            out.push(Signal { kind: "policy".into(), detail: format!("{denied} denied action(s) in the audit trail") });
        }
        let failed = text.lines().filter(|l| l.contains("failed") || l.contains("\"result\":\"error")).count();
        if failed > 0 {
            out.push(Signal { kind: "error".into(), detail: format!("{failed} failed action(s) in the audit trail") });
        }
    }

    let traces = dir.join("traces");
    if let Ok(rd) = std::fs::read_dir(&traces) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
            let low = text.to_lowercase();
            for (needle, label) in SIGNAL_NEEDLES {
                if low.contains(needle) {
                    if let Some(line) = text.lines().find(|l| l.to_lowercase().contains(needle)) {
                        out.push(Signal {
                            kind: "trace".into(),
                            detail: format!("{name}: {label} — {}", crate::limits::clip(line.trim(), 240)),
                        });
                    }
                }
            }
        }
    }

    // Cap: the issue needs representative evidence, not a dump.
    out.truncate(40);
    out
}

pub fn prompt(dir: &Path, signals: &[Signal]) -> String {
    let mut s = String::new();
    s.push_str(&format!("Run directory: {}\n\n", dir.display()));
    s.push_str("Observed friction (machine-collected, may be noisy):\n");
    for sig in signals {
        s.push_str(&format!("- [{}] {}\n", sig.kind, sig.detail));
    }
    s
}

pub const SYSTEM: &str = "You are a senior engineer reviewing a penetration-testing harness's own run. \
From the friction signals, write ONE GitHub issue that would make the next run materially better. \
Be concrete and grounded ONLY in the signals provided — do not invent facts. \
Output Markdown with exactly these sections:\n\
# <short imperative title>\n\
## Problem\n## Evidence\n## Root cause (hypothesis)\n## Proposed fix\n## Example patch (or config change)\n## Acceptance criteria\n\
Keep it under 700 words. The patch may be a diff or a complete small file; it is a proposal, not a PR.";

/// Persist the issue next to the run and in the global improvements folder.
pub fn save(dir: &Path, run_id: &str, markdown: &str) -> Result<std::path::PathBuf> {
    let local = dir.join("improvement-issue.md");
    std::fs::write(&local, markdown)?;
    let global = Path::new(".neurosploit").join("improvements");
    if std::fs::create_dir_all(&global).is_ok() {
        let _ = std::fs::write(global.join(format!("{run_id}.md")), markdown);
    }
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_status_and_findings() {
        let dir = std::env::temp_dir().join(format!("ns-improve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("status.json"), r#"{"state":"complete","target":"https://x"}"#).unwrap();
        std::fs::write(dir.join("findings.json"), "[]").unwrap();
        let sig = collect(&dir);
        assert!(sig.iter().any(|s| s.kind == "status"));
        assert!(sig.iter().any(|s| s.detail.contains("0 confirmed")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prompt_lists_signals() {
        let p = prompt(Path::new("/tmp/x"), &[Signal { kind: "error".into(), detail: "boom".into() }]);
        assert!(p.contains("boom"));
    }
}
