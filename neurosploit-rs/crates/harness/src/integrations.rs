//! External integrations (v3.5.3): GitHub / GitLab (private repos, PR/MR code
//! review, commit watching) and Jira (open one vulnerability card per finding).
//!
//! Config persists to `<project>/.neurosploit/integrations.json`. **Secrets are
//! never stored** — only the *name* of the env var holding each token is saved;
//! the value is read from the environment at use time.
use crate::types::Finding;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
pub struct GithubCfg {
    pub enabled: bool,
    pub token_env: String, // e.g. GITHUB_TOKEN (a PAT with `repo` scope for private repos)
    pub api: String,       // https://api.github.com (or GHE base)
}
impl Default for GithubCfg {
    fn default() -> Self { Self { enabled: false, token_env: "GITHUB_TOKEN".into(), api: "https://api.github.com".into() } }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GitlabCfg {
    pub enabled: bool,
    pub token_env: String, // GITLAB_TOKEN
    pub base: String,      // https://gitlab.com (or self-hosted)
}
impl Default for GitlabCfg {
    fn default() -> Self { Self { enabled: false, token_env: "GITLAB_TOKEN".into(), base: "https://gitlab.com".into() } }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct JiraCfg {
    pub enabled: bool,
    pub base_url: String,  // https://your-org.atlassian.net
    pub email_env: String, // JIRA_EMAIL
    pub token_env: String, // JIRA_API_TOKEN
    pub project_key: String,
    pub issue_type: String, // Bug / Vulnerability / Task
}
impl Default for JiraCfg {
    fn default() -> Self {
        Self { enabled: false, base_url: String::new(), email_env: "JIRA_EMAIL".into(),
               token_env: "JIRA_API_TOKEN".into(), project_key: String::new(), issue_type: "Bug".into() }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Integrations {
    pub github: GithubCfg,
    pub gitlab: GitlabCfg,
    pub jira: JiraCfg,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Severity as a numeric rank (Critical=4 … Info=0) for gate comparisons.
pub fn severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0,
    }
}

/// The single worst confirmed severity across findings (skips needs-review), as
/// a rank. 0 when nothing confirmed.
pub fn worst_confirmed_rank(findings: &[Finding]) -> u8 {
    findings.iter()
        .filter(|f| f.review_status != "needs-review")
        .map(|f| severity_rank(&f.severity))
        .max().unwrap_or(0)
}

/// Does any CONFIRMED finding meet/exceed `threshold` (a severity word)? This is
/// the CI gate: true → the PR should be blocked. An unknown threshold disables
/// the gate (returns false).
pub fn gate_trips(findings: &[Finding], threshold: &str) -> bool {
    let t = severity_rank(threshold);
    if t == 0 && !matches!(threshold.trim().to_ascii_lowercase().as_str(), "low" | "info") {
        return false; // unknown threshold word → no gate
    }
    worst_confirmed_rank(findings) >= t
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default()
}

impl Integrations {
    pub fn path(dir: &Path) -> std::path::PathBuf { dir.join("integrations.json") }

    pub fn load(dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).ok();
        std::fs::write(Self::path(dir), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn github_token(&self) -> Option<String> { env(&self.github.token_env) }
    pub fn gitlab_token(&self) -> Option<String> { env(&self.gitlab.token_env) }

    /// Inject a token into an https git URL so private repos can be cloned.
    /// No-op if the matching integration is off, the token env is unset, or the
    /// URL doesn't match the configured host.
    pub fn authed_clone_url(&self, url: &str) -> String {
        if self.github.enabled {
            if let Some(rest) = url.strip_prefix("https://github.com/") {
                if let Some(tok) = self.github_token() {
                    return format!("https://x-access-token:{tok}@github.com/{rest}");
                }
            }
        }
        if self.gitlab.enabled {
            let host = self.gitlab.base.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/');
            let prefix = format!("https://{host}/");
            if let Some(rest) = url.strip_prefix(&prefix) {
                if let Some(tok) = self.gitlab_token() {
                    return format!("https://oauth2:{tok}@{host}/{rest}");
                }
            }
        }
        url.to_string()
    }

    /// Post a comment on a GitHub PR/issue (`repo` = `owner/name`).
    pub async fn github_comment(&self, repo: &str, number: u64, body: &str) -> Result<()> {
        let tok = self.github_token().ok_or_else(|| anyhow!("{} not set", self.github.token_env))?;
        let url = format!("{}/repos/{}/issues/{}/comments", self.github.api.trim_end_matches('/'), repo, number);
        let resp = client().post(&url)
            .header("User-Agent", "NeuroSploit")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(tok)
            .json(&serde_json::json!({ "body": body }))
            .send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("github comment failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    /// Set a GitHub commit status (Checks-style) so branch protection can BLOCK a
    /// merge on a failing state. `state` ∈ success|failure|error|pending. `context`
    /// names the check (e.g. "neurosploit/security"). Requires a token with
    /// `repo:status` (or `statuses:write` on fine-grained PATs).
    pub async fn github_set_status(&self, repo: &str, sha: &str, state: &str,
                                   context: &str, description: &str, target_url: Option<&str>) -> Result<()> {
        let tok = self.github_token().ok_or_else(|| anyhow!("{} not set", self.github.token_env))?;
        let url = format!("{}/repos/{}/statuses/{}", self.github.api.trim_end_matches('/'), repo, sha);
        // GitHub caps status description at 140 chars.
        let desc: String = description.chars().take(140).collect();
        let mut body = serde_json::json!({ "state": state, "context": context, "description": desc });
        if let Some(u) = target_url { body["target_url"] = serde_json::json!(u); }
        let resp = client().post(&url)
            .header("User-Agent", "NeuroSploit")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(tok)
            .json(&body)
            .send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("github status failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    /// Submit a PR review. `event` ∈ APPROVE | REQUEST_CHANGES | COMMENT. Used to
    /// REQUEST_CHANGES when critical/high findings land — combined with a "require
    /// review" branch rule, this blocks the merge until a human overrides.
    pub async fn github_pr_review(&self, repo: &str, number: u64, event: &str, body: &str) -> Result<()> {
        let tok = self.github_token().ok_or_else(|| anyhow!("{} not set", self.github.token_env))?;
        let url = format!("{}/repos/{}/pulls/{}/reviews", self.github.api.trim_end_matches('/'), repo, number);
        let resp = client().post(&url)
            .header("User-Agent", "NeuroSploit")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(tok)
            .json(&serde_json::json!({ "event": event, "body": body }))
            .send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("github review failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    /// Head commit SHA of a PR (needed to attach a commit status to the PR tip).
    pub async fn github_pr_head_sha(&self, repo: &str, number: u64) -> Result<String> {
        let url = format!("{}/repos/{}/pulls/{}", self.github.api.trim_end_matches('/'), repo, number);
        let mut req = client().get(&url)
            .header("User-Agent", "NeuroSploit")
            .header("Accept", "application/vnd.github+json");
        if let Some(t) = self.github_token() { req = req.bearer_auth(t); }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("github PR API {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        let v: serde_json::Value = resp.json().await?;
        v["head"]["sha"].as_str().map(|s| s.to_string()).ok_or_else(|| anyhow!("no head.sha in response"))
    }

    /// Latest commit SHA of a branch via the GitHub API (for `watch`).
    pub async fn github_latest_sha(&self, repo: &str, branch: &str) -> Result<String> {
        let url = format!("{}/repos/{}/commits/{}", self.github.api.trim_end_matches('/'), repo, branch);
        let mut req = client().get(&url)
            .header("User-Agent", "NeuroSploit")
            .header("Accept", "application/vnd.github+json");
        if let Some(t) = self.github_token() { req = req.bearer_auth(t); }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("github commits API {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        let v: serde_json::Value = resp.json().await?;
        v["sha"].as_str().map(|s| s.to_string()).ok_or_else(|| anyhow!("no sha in response"))
    }

    /// Create one Jira issue. Returns the issue key (e.g. SEC-123).
    pub async fn jira_card(&self, summary: &str, description: &str) -> Result<String> {
        let email = env(&self.jira.email_env).ok_or_else(|| anyhow!("{} not set", self.jira.email_env))?;
        let token = env(&self.jira.token_env).ok_or_else(|| anyhow!("{} not set", self.jira.token_env))?;
        if self.jira.base_url.is_empty() || self.jira.project_key.is_empty() {
            return Err(anyhow!("jira base_url/project_key not configured (run /integrations setup jira)"));
        }
        let url = format!("{}/rest/api/2/issue", self.jira.base_url.trim_end_matches('/'));
        let payload = serde_json::json!({
            "fields": {
                "project": { "key": self.jira.project_key },
                "summary": summary,
                "description": description,
                "issuetype": { "name": self.jira.issue_type },
            }
        });
        let resp = client().post(&url)
            .basic_auth(email, Some(token))
            .header("Accept", "application/json")
            .json(&payload)
            .send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("jira create failed: {} {}", status, text));
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        Ok(v["key"].as_str().unwrap_or("?").to_string())
    }

    /// Open one Jira card per finding. Returns (created keys, errors).
    pub async fn jira_cards_for(&self, target: &str, findings: &[Finding]) -> (Vec<String>, Vec<String>) {
        let (mut keys, mut errs) = (Vec::new(), Vec::new());
        for f in findings {
            let summary = format!("[{}] {} — {}", f.severity, f.title, target);
            let description = format!(
                "*Target:* {target}\n*Severity:* {} | *CVSS:* {} | *CWE:* {}\n*Location:* {}\n\n*Impact:*\n{}\n\n*PoC / payload:*\n{{code}}{}{{code}}\n\n*Evidence:*\n{{code}}{}{{code}}\n\n*Remediation:*\n{}\n\n_Filed automatically by NeuroSploit._",
                f.severity, f.cvss, f.cwe, f.endpoint, f.impact, f.payload, f.evidence, f.remediation
            );
            match self.jira_card(&summary, &description).await {
                Ok(k) => keys.push(k),
                Err(e) => errs.push(format!("{}: {e}", f.title)),
            }
        }
        (keys, errs)
    }

    /// Human-readable status (for `/integrations` and the CLI).
    pub fn status_lines(&self) -> Vec<String> {
        let badge = |on: bool, tok: bool| if !on { "off".to_string() }
            else if tok { "on  ✓ token".to_string() } else { "on  ⚠ token env not set".to_string() };
        vec![
            format!("github : {:<18} (clone private repos · PR review · watch)  env={}", badge(self.github.enabled, self.github_token().is_some()), self.github.token_env),
            format!("gitlab : {:<18} (clone private repos · MR review)          env={}", badge(self.gitlab.enabled, self.gitlab_token().is_some()), self.gitlab.token_env),
            format!("jira   : {:<18} (open a card per finding)  project={} base={}",
                badge(self.jira.enabled, env(&self.jira.token_env).is_some()),
                if self.jira.project_key.is_empty() { "-" } else { &self.jira.project_key },
                if self.jira.base_url.is_empty() { "-" } else { &self.jira.base_url }),
        ]
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::types::Finding;

    fn f(sev: &str, status: &str) -> Finding {
        Finding { severity: sev.into(), review_status: status.into(), ..Default::default() }
    }

    #[test]
    fn gate_blocks_on_threshold_and_above() {
        let fs = vec![f("High", "confirmed"), f("Low", "confirmed")];
        assert!(gate_trips(&fs, "high"));
        assert!(gate_trips(&fs, "medium"));
        assert!(!gate_trips(&fs, "critical"));
    }

    #[test]
    fn gate_ignores_needs_review() {
        let fs = vec![f("Critical", "needs-review")];
        assert!(!gate_trips(&fs, "critical"));
        assert_eq!(worst_confirmed_rank(&fs), 0);
    }

    #[test]
    fn unknown_threshold_disables_gate() {
        let fs = vec![f("Critical", "confirmed")];
        assert!(!gate_trips(&fs, "banana"));
    }
}
