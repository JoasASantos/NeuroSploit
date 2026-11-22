//! Optional OpenSearch log shipping — one index per engagement/project.
//!
//! Runs already leave a rich trail on disk (`audit.jsonl`, `traces/*.md`,
//! `findings.json`, `status.json`, `usage.json`, toolbox logs). That trail is
//! excellent forensics and terrible operations: it lives in a directory per
//! run, so answering "show me every error this customer's targets produced
//! this week" means walking a filesystem and parsing five formats.
//!
//! This module is the bridge. [`collect_run`] turns a finished run into a flat
//! list of structured [`LogEvent`]s; [`ship`] bulk-indexes them into
//! OpenSearch. Index names are derived from the engagement project, so every
//! customer/domain gets its own `ns-<project>` index and the usual OpenSearch
//! tooling (Kibana-style queries, per-project retention) works without a
//! custom backend.
//!
//! Three rules keep this safe to enable:
//!
//! - It is **opt-in and best-effort**. With `OPENSEARCH_URL` unset every
//!   function is a no-op, and a failed shipment never fails the run.
//! - It **never invents** what it indexes: every event is either a parsed line
//!   from an existing artifact or counts/status read from one.
//! - It **does not redact on the way in**. The vault already owns secrets;
//!   the log store is an operator control plane, and a redacted log cannot
//!   reproduce a bug. Access to the index is the control, not mangling the
//!   evidence.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Connection + naming settings, resolved from the environment.
#[derive(Clone, Debug)]
pub struct Config {
    /// Base URL, e.g. `http://127.0.0.1:9200`.
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Engagement project/company/domain label — the index discriminator.
    pub project: String,
    /// Index template. `{project}` and `{date}` are substituted.
    pub index: String,
    /// Verify TLS certificates (disable only for a self-signed local install).
    pub verify_tls: bool,
}

impl Config {
    /// Resolve from the environment, or `None` when shipping is not configured.
    ///
    /// `OPENSEARCH_URL` is the switch. `project` (when given) wins over
    /// `NS_LOG_PROJECT`; the fallback label is `default`.
    pub fn from_env(project: Option<&str>) -> Option<Self> {
        let url = env_nonempty("OPENSEARCH_URL")?;
        let project = project
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| env_nonempty("NS_LOG_PROJECT"))
            .unwrap_or_else(|| "default".to_string());
        let index = env_nonempty("OPENSEARCH_INDEX").unwrap_or_else(|| "ns-{project}".to_string());
        let verify_tls = env_nonempty("OPENSEARCH_VERIFY_TLS")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(true);
        Some(Self {
            url: url.trim_end_matches('/').to_string(),
            username: env_nonempty("OPENSEARCH_USERNAME"),
            password: env_nonempty("OPENSEARCH_PASSWORD"),
            project,
            index,
            verify_tls,
        })
    }

    /// Concrete index name for a date (`YYYY.MM.DD`), lowercased and sanitized
    /// to OpenSearch's index rules (no uppercase, no `\/*?"<>| ,#:`, not
    /// starting with `_`, `-`, `+`).
    pub fn index_for(&self, date: &str) -> String {
        let rendered = self
            .index
            .replace("{project}", &self.project)
            .replace("{date}", date);
        sanitize_index(&rendered)
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Force a string into a legal OpenSearch index name.
pub fn sanitize_index(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+') {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches(|c| c == '_' || c == '-' || c == '+').to_string();
    let mut out = if out.is_empty() { "ns-default".to_string() } else { out };
    if out.len() > 200 {
        out.truncate(200);
    }
    out
}

/// One indexable log record. The field set is deliberately flat and stable so
/// dashboards and saved searches can be shared between evidence classes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LogEvent {
    /// RFC3339 UTC.
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    /// Engagement project / customer / domain.
    pub project: String,
    /// Artifact class: run · audit · trace · finding · error · usage · status · poc.
    pub kind: String,
    /// info · low · medium · high · critical · error.
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Human-readable one-liner.
    pub message: String,
    /// The unmodified source record (or the artifact text), for reproduction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl LogEvent {
    pub fn new(project: &str, kind: &str, level: &str, message: impl Into<String>) -> Self {
        Self {
            timestamp: now_rfc3339(),
            project: project.to_string(),
            kind: kind.to_string(),
            level: level.to_string(),
            run_id: None,
            agent: None,
            target: None,
            message: message.into(),
            data: None,
        }
    }
}

/// Turn a finished (or in-progress) run directory into flat events.
///
/// Missing artifacts are skipped — a run that died during recon is exactly the
/// kind of run whose partial logs matter — so this never errors on a sparse
/// directory.
pub fn collect_run(dir: &Path, project: &str) -> Vec<LogEvent> {
    let run_id = dir.file_name().and_then(|s| s.to_str()).map(|s| s.to_string());
    let mut events: Vec<LogEvent> = Vec::new();
    let mut push = |mut e: LogEvent| {
        e.run_id = run_id.clone();
        events.push(e);
    };

    if let Some(meta) = read_json(&dir.join("status.json")) {
        let state = meta.get("state").and_then(|v| v.as_str()).unwrap_or("unknown");
        let mut e = LogEvent::new(project, "status", "info", format!("run status: {state}"));
        e.target = meta.get("target").and_then(|v| v.as_str()).map(String::from);
        e.data = Some(meta);
        push(e);
    }

    if let Some(arr) = read_json(&dir.join("findings.json")).and_then(|v| v.as_array().cloned()) {
        for f in arr {
            let severity = f.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
            let title = f.get("title").and_then(|v| v.as_str()).unwrap_or("finding");
            let target = f.get("endpoint").and_then(|v| v.as_str()).map(String::from);
            let mut e = LogEvent::new(project, "finding", severity, title.to_string());
            e.target = target;
            e.data = Some(f);
            push(e);
        }
    }

    for line in read_lines(&dir.join("audit.jsonl")) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let decision = v.get("policy_decision").and_then(|x| x.as_str()).unwrap_or("");
        let level = if decision.starts_with("deny") { "error" } else { "info" };
        let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("action");
        let result = v.get("result").and_then(|x| x.as_str()).unwrap_or("");
        let mut e = LogEvent::new(project, "audit", level, format!("{action}: {result}"));
        e.agent = v.get("agent").and_then(|x| x.as_str()).map(String::from);
        e.target = v.get("target").and_then(|x| x.as_str()).map(String::from);
        e.timestamp = v
            .get("timestamp")
            .and_then(|x| x.as_str())
            .map(String::from)
            .unwrap_or_else(now_rfc3339);
        e.data = Some(v);
        push(e);
    }

    for (name, text) in read_dir_text(&dir.join("traces")) {
        let mut e = LogEvent::new(
            project,
            "trace",
            "info",
            format!("{name}: {} bytes of agent transcript", text.len()),
        );
        e.agent = Some(name.clone());
        e.data = Some(serde_json::json!({ "agent": name, "text": text }));
        push(e);
    }

    if let Some(v) = read_json(&dir.join("usage.json")) {
        let mut e = LogEvent::new(project, "usage", "info", "token/cost usage");
        e.data = Some(v);
        push(e);
    }

    if let Some(v) = read_json(&dir.join("errors.json")) {
        let mut e = LogEvent::new(project, "error", "error", "error report");
        e.data = Some(v);
        push(e);
    }
    for line in read_lines(&dir.join("errors.jsonl")) {
        let mut e = LogEvent::new(project, "error", "error", "logged error");
        e.data = serde_json::from_str(&line).ok().or_else(|| Some(serde_json::json!({ "text": line })));
        push(e);
    }
    for (name, text) in read_dir_text(&dir.join("pocs")) {
        if !text.is_empty() {
            let mut e = LogEvent::new(project, "poc", "info", format!("poc artifact: {name}"));
            e.data = Some(serde_json::json!({ "name": name, "text": text }));
            push(e);
        }
    }
    events
}

fn read_lines(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    text.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect()
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn read_dir_text(dir: &Path) -> Vec<(String, String)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<(String, String)> = rd
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let text = std::fs::read_to_string(e.path()).ok()?;
            Some((name, text))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Bulk-index events. Returns how many documents the cluster accepted.
///
/// A shipment is chunked at 500 documents. HTTP/transport failures surface as
/// an error for the caller to warn about; individual item failures are counted
/// from the bulk response and reported in the returned [`PushReport`].
pub async fn ship(cfg: &Config, events: &[LogEvent]) -> anyhow::Result<PushReport> {
    if events.is_empty() {
        return Ok(PushReport::default());
    }
    let mut client = reqwest::Client::builder().user_agent("neurosploit-logship/4.4");
    if !cfg.verify_tls {
        client = client.danger_accept_invalid_certs(true);
    }
    let client = client.build()?;
    let index = cfg.index_for(&today());

    let mut report = PushReport { attempted: events.len(), ..Default::default() };
    for chunk in events.chunks(500) {
        let mut body = String::new();
        for e in chunk {
            let meta = serde_json::json!({ "index": { "_index": index } });
            body.push_str(&serde_json::to_string(&meta)?);
            body.push('\n');
            body.push_str(&serde_json::to_string(e)?);
            body.push('\n');
        }
        let mut req = client
            .post(format!("{}/_bulk", cfg.url))
            .header("Content-Type", "application/x-ndjson")
            .body(body);
        if let Some(user) = &cfg.username {
            req = req.basic_auth(user, Some(cfg.password.clone().unwrap_or_default()));
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("OpenSearch _bulk returned {status}: {}", truncate(&text, 400));
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if v.get("errors").and_then(|x| x.as_bool()) == Some(true) {
                if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
                    for item in items {
                        let idx = item.get("index").unwrap_or(item);
                        if idx.get("error").is_some() {
                            report.failed += 1;
                        } else {
                            report.indexed += 1;
                        }
                    }
                }
            } else {
                report.indexed += chunk.len();
            }
        } else {
            report.indexed += chunk.len();
        }
    }
    Ok(report)
}

/// Summarize a shipment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PushReport {
    pub attempted: usize,
    pub indexed: usize,
    pub failed: usize,
}

/// `GET /` — proves the URL, credentials and reachability before a run.
pub async fn ping(cfg: &Config) -> anyhow::Result<String> {
    let mut client = reqwest::Client::builder().user_agent("neurosploit-logship/4.4");
    if !cfg.verify_tls {
        client = client.danger_accept_invalid_certs(true);
    }
    let client = client.build()?;
    let mut req = client.get(format!("{}/", cfg.url));
    if let Some(user) = &cfg.username {
        req = req.basic_auth(user, Some(cfg.password.clone().unwrap_or_default()));
    }
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("OpenSearch returned {status}: {}", truncate(&text, 400));
    }
    Ok(text)
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `YYYY.MM.DD` in UTC.
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}.{m:02}.{d:02}")
}

/// RFC3339 UTC timestamp for now.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_from_unix(secs)
}

fn rfc3339_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

/// Howard Hinnant's days→civil conversion (proleptic Gregorian, UTC).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}

/// Convenience: collect and ship one run directory.
pub async fn push_run(cfg: &Config, dir: &Path) -> anyhow::Result<(PushReport, usize)> {
    let events = collect_run(dir, &cfg.project);
    let n = events.len();
    let report = ship(cfg, &events).await?;
    Ok((report, n))
}

/// Locate a run directory from a run id (`ns-…`) or a path, against `root`.
pub fn resolve_run(root: &Path, run: &str) -> Option<PathBuf> {
    let p = PathBuf::from(run);
    if p.is_dir() {
        return Some(p);
    }
    let candidate = root.join(run);
    candidate.is_dir().then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_is_lowercase_and_legal() {
        assert_eq!(sanitize_index("NS-Acme/Prod 01"), "ns-acme-prod-01");
        assert_eq!(sanitize_index("__x__"), "x");
        assert_eq!(sanitize_index(""), "ns-default");
    }

    #[test]
    fn template_substitution() {
        let cfg = Config {
            url: "http://localhost:9200".into(),
            username: None,
            password: None,
            project: "Aureon".into(),
            index: "ns-{project}-{date}".into(),
            verify_tls: true,
        };
        assert_eq!(cfg.index_for("2026.11.22"), "ns-aureon-2026.11.22");
    }

    #[test]
    fn date_conversion() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_700_000_000), "2023-11-14T22:13:20Z");
    }

}

/// Structured log entry for per-agent real-time logging.
/// Complements the post-run [`LogEvent`] with live entries emitted during execution.
#[derive(Debug, Serialize, Deserialize)]
pub struct StructuredLog {
    pub ts: u64,
    pub level: String,
    pub agent: String,
    pub phase: String,
    pub message: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl StructuredLog {
    pub fn info(agent: &str, phase: &str, msg: &str, target: &str) -> Self {
        Self {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: "info".into(),
            agent: agent.to_string(),
            phase: phase.to_string(),
            message: msg.to_string(),
            target: target.to_string(),
            finding_id: None,
            error: None,
        }
    }

    pub fn warn(agent: &str, phase: &str, msg: &str, target: &str) -> Self {
        Self {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: "warn".into(),
            agent: agent.to_string(),
            phase: phase.to_string(),
            message: msg.to_string(),
            target: target.to_string(),
            finding_id: None,
            error: None,
        }
    }

    pub fn error(agent: &str, phase: &str, msg: &str, err: &str, target: &str) -> Self {
        Self {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: "error".into(),
            agent: agent.to_string(),
            phase: phase.to_string(),
            message: msg.to_string(),
            target: target.to_string(),
            finding_id: None,
            error: Some(err.to_string()),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests_structured {
    use super::*;

    #[test]
    fn structured_log_serializes() {
        let log = StructuredLog::info("sqli", "exploit", "testing param id", "http://t");
        let json = log.to_json();
        assert!(json.contains("\"agent\":\"sqli\""));
        assert!(json.contains("\"level\":\"info\""));
        assert!(!json.contains("finding_id"));
    }

    #[test]
    fn collect_reads_audit_and_traces() {
        let dir = std::env::temp_dir().join(format!("ns-logship-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("traces")).unwrap();
        std::fs::write(
            dir.join("audit.jsonl"),
            "{\"timestamp\":\"2026-01-01T00:00:00Z\",\"agent\":\"sqli\",\"action\":\"GET /a\",\"target\":\"http://t\",\"policy_decision\":\"allow\",\"result\":\"200\"}\n",
        )
        .unwrap();
        std::fs::write(dir.join("traces").join("sqli.md"), "GET /a -> 200").unwrap();
        std::fs::write(dir.join("findings.json"), "[{\"title\":\"XSS\",\"severity\":\"high\",\"endpoint\":\"http://t/x\"}]").unwrap();
        let events = collect_run(&dir, "acme");
        assert!(events.iter().any(|e| e.kind == "audit" && e.agent.as_deref() == Some("sqli")));
        assert!(events.iter().any(|e| e.kind == "trace" && e.agent.as_deref() == Some("sqli.md")));
        assert!(events.iter().any(|e| e.kind == "finding" && e.level == "high"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
