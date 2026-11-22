//! Engagement inputs — turn the artifacts an operator already has into targets.
//!
//! A real engagement starts with a pile of files: an IP list from the client, a
//! Swagger/OpenAPI document, an `.ovpn` profile, the Rules of Engagement, a
//! screenshot of the topology. Retyping those into flags is where scope
//! mistakes happen. [`Brief`] reads them once and produces:
//!
//! - the **targets** (base URLs and hosts) to seed recon with,
//! - a **scope YAML** the harness can enforce directly (`--scope-file`),
//! - the **transport** implied by an `.ovpn`,
//! - **exclusions and notes** from the RoE,
//! - a metadata record for a topology image (kept, not interpreted).
//!
//! It is a parser, not a scanner: nothing here sends traffic. Everything it
//! emits is reviewable text, so the operator can correct a bad assumption
//! before the first request.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Brief {
    /// Hosts/CIDRs from the IP list.
    pub ips: Vec<String>,
    /// Base URLs from the API document.
    pub base_urls: Vec<String>,
    /// Endpoint paths from the API document.
    pub endpoints: Vec<String>,
    /// `openvpn:<path>` when a profile was supplied.
    pub transport: Option<String>,
    /// Hard exclusions found in the RoE.
    pub out_of_scope: Vec<String>,
    /// Free-text RoE notes, bounded.
    pub notes: Vec<String>,
    /// Path to the topology image, recorded for the report.
    pub topology: Option<String>,
    pub roe: Option<String>,
}

impl Brief {
    pub fn targets(&self) -> Vec<String> {
        let mut v: Vec<String> = self.base_urls.clone();
        for ip in &self.ips {
            if !v.iter().any(|x| x == ip) {
                v.push(ip.clone());
            }
        }
        v
    }

    /// A scope YAML the harness enforces, including the API hosts and the
    /// exclusions, with the RoE notes carried as (non-enforced) context.
    pub fn scope_yaml(&self) -> String {
        let mut s = String::from("hard:\n");
        for t in self.targets() {
            let host = if t.contains("://") {
                crate::scope::host_of(&t)
            } else if t
                .split_once('/')
                .map(|(_, bits)| !bits.is_empty() && bits.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false)
            {
                // A CIDR must keep its prefix length; splitting on '/' would
                // quietly widen 10.0.1.0/24 to a single host.
                t.clone()
            } else {
                t.split('/').next().unwrap_or(&t).to_string()
            };
            if !host.is_empty() {
                s.push_str(&format!("  - {host}\n"));
            }
        }
        if !self.out_of_scope.is_empty() {
            s.push_str("exclude:\n");
            for x in &self.out_of_scope {
                s.push_str(&format!("  - {x}\n"));
            }
        }
        s.push_str("soft:\n");
        s.push_str("  notes:\n");
        for n in self.notes.iter().take(20) {
            s.push_str(&format!("    - {}\n", n.replace('\n', " ")));
        }
        s
    }

    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "targets: {} · endpoints: {} · exclusions: {} · transport: {}\n",
            self.targets().len(),
            self.endpoints.len(),
            self.out_of_scope.len(),
            self.transport.as_deref().unwrap_or("direct")
        ));
        if let Some(t) = &self.topology {
            s.push_str(&format!("topology: {t}\n"));
        }
        for n in &self.notes {
            s.push_str(&format!("note: {n}\n"));
        }
        s
    }
}

pub fn from_files(
    ips: Option<&Path>,
    swagger: Option<&Path>,
    ovpn: Option<&Path>,
    roe: Option<&Path>,
    topology: Option<&Path>,
) -> Result<Brief> {
    let mut b = Brief::default();
    if let Some(p) = ips {
        for line in std::fs::read_to_string(p)?.lines() {
            let t = line.split('#').next().unwrap_or("").trim();
            if !t.is_empty() && !b.ips.iter().any(|x| x == t) {
                b.ips.push(t.to_string());
            }
        }
    }
    if let Some(p) = swagger {
        absorb_api(&mut b, &std::fs::read_to_string(p)?);
    }
    if let Some(p) = ovpn {
        b.transport = Some(format!("openvpn:{}", p.display()));
    }
    if let Some(p) = roe {
        b.roe = Some(p.display().to_string());
        let text = std::fs::read_to_string(p).unwrap_or_default();
        for line in text.lines() {
            let t = line.trim();
            let lower = t.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("out-of-scope:").or_else(|| lower.strip_prefix("exclude:")) {
                let _ = rest;
                let val = t.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
                if !val.is_empty() {
                    b.out_of_scope.push(val.to_string());
                }
            } else if t.starts_with("- ") && (lower.contains("out of scope") || lower.contains("fora de escopo")) {
                b.out_of_scope.push(t.trim_start_matches("- ").to_string());
            } else if !t.is_empty() && b.notes.len() < 40 {
                b.notes.push(crate::limits::clip(t, 240));
            }
        }
        b.notes.truncate(40);
    }
    if let Some(p) = topology {
        if p.is_file() {
            b.topology = Some(p.display().to_string());
        } else {
            anyhow::bail!("topology file not found: {}", p.display());
        }
    }
    Ok(b)
}

/// Extract base URL(s) and paths from an OpenAPI/Swagger document. JSON is
/// parsed properly; YAML is read line-wise (servers/url and path keys), which
/// covers the shapes teams actually hand over.
fn absorb_api(b: &mut Brief, text: &str) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(servers) = v.get("servers").and_then(|x| x.as_array()) {
            for s in servers {
                if let Some(u) = s.get("url").and_then(|x| x.as_str()) {
                    push(&mut b.base_urls, u);
                }
            }
        }
        let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("");
        let base = v.get("basePath").and_then(|x| x.as_str()).unwrap_or("");
        if !host.is_empty() {
            let scheme = v.get("schemes").and_then(|x| x.as_array()).and_then(|a| a.first()).and_then(|x| x.as_str()).unwrap_or("https");
            push(&mut b.base_urls, &format!("{scheme}://{host}{base}"));
        }
        if let Some(paths) = v.get("paths").and_then(|x| x.as_object()) {
            for k in paths.keys() {
                push(&mut b.endpoints, k);
            }
        }
        return;
    }
    // YAML fallback.
    let mut in_servers = false;
    let mut in_paths = false;
    for raw in text.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let t = raw.trim();
        if t.starts_with("servers:") { in_servers = true; in_paths = false; continue; }
        if t.starts_with("paths:") { in_paths = true; in_servers = false; continue; }
        if indent == 0 && !t.is_empty() && !t.starts_with('-') { in_servers = false; in_paths = false; }
        if in_servers {
            if let Some(u) = t.strip_prefix("- url:").or_else(|| t.strip_prefix("url:")) {
                push(&mut b.base_urls, u.trim().trim_matches(['"', '\'']));
            }
        }
        if in_paths && indent == 2 && t.starts_with('/') {
            let key = t.trim_end_matches(':').trim();
            push(&mut b.endpoints, key);
        }
    }
}

fn push(v: &mut Vec<String>, s: &str) {
    let s = s.trim();
    if !s.is_empty() && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// Write the brief and the derived scope file, returning both paths.
pub fn write(b: &Brief, out_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(out_dir)?;
    let brief = out_dir.join("brief.json");
    std::fs::write(&brief, serde_json::to_string_pretty(b)?)?;
    let scope = out_dir.join("scope.yaml");
    std::fs::write(&scope, b.scope_yaml())?;
    Ok((brief, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_openapi() {
        let mut b = Brief::default();
        absorb_api(&mut b, r#"{"servers":[{"url":"https://api.example.com/v2"}],"paths":{"/users":{},"/login":{}}}"#);
        assert_eq!(b.base_urls, vec!["https://api.example.com/v2"]);
        let mut eps = b.endpoints.clone(); eps.sort();
        assert_eq!(eps, vec!["/login", "/users"]);
    }

    #[test]
    fn parses_yaml_openapi() {
        let mut b = Brief::default();
        absorb_api(&mut b, "servers:\n  - url: https://y.example.com\npaths:\n  /a:\n  /b:\n");
        assert!(b.base_urls.contains(&"https://y.example.com".to_string()));
        assert!(b.endpoints.contains(&"/a".to_string()));
        assert!(b.endpoints.contains(&"/b".to_string()));
    }

    #[test]
    fn scope_includes_hosts_and_exclusions() {
        let b = Brief {
            ips: vec!["10.0.0.4".into()],
            base_urls: vec!["https://app.example.com/api".into()],
            out_of_scope: vec!["payments.example.com".into()],
            notes: vec!["test window 02:00".into()],
            ..Default::default()
        };
        let y = b.scope_yaml();
        assert!(y.contains("10.0.0.4"));
        assert!(y.contains("app.example.com"));
        assert!(y.contains("payments.example.com"));
        assert!(y.contains("test window"));
    }
}
