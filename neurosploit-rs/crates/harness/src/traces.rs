//! Shared agent traces — what one agent observed, available to the next.
//!
//! Agents run one specialty each, in parallel, and until now each saw only its
//! own transcript. The valuable observations of a run — an error that names the
//! database, a hidden parameter, a version banner, an endpoint only reachable
//! after login — often show up in one agent's process without ever becoming a
//! finding, and the next agent re-derives them (or never does).
//!
//! Every agent's transcript is written to `<run>/traces/<agent>.md` as soon as it
//! finishes. From those files the harness extracts a *structured* digest —
//! endpoint paths, parameter names, error signatures, product versions, block
//! signals — and every later prompt carries it, together with the directory to
//! `grep` for the full context. The digest never copies raw lines (which may
//! hold credentials or personal data) and is fenced as untrusted data, because
//! a trace is mostly target output and the target may be trying to steer the
//! model.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// `<workdir>/traces`, created on demand.
pub fn dir(workdir: Option<&str>) -> Option<PathBuf> {
    let d = Path::new(workdir?).join("traces");
    std::fs::create_dir_all(&d).ok()?;
    Some(std::fs::canonicalize(&d).unwrap_or(d))
}

fn file_name(agent: &str) -> String {
    let s: String = agent.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    format!("{}.md", if s.is_empty() { "agent".into() } else { s })
}

/// Record one agent's transcript (overwrites: the latest pass is the trace).
pub fn record(workdir: Option<&str>, agent: &str, text: &str) {
    if text.trim().is_empty() {
        return;
    }
    if let Some(d) = dir(workdir) {
        let _ = std::fs::write(d.join(file_name(agent)), text);
    }
}

/// Record every agent of a phase.
pub fn record_all<F>(workdir: Option<&str>, raw: &[(String, String, F)]) {
    for (agent, text, _) in raw {
        record(workdir, agent, text);
    }
}

const ERROR_SIGNATURES: &[(&str, &str)] = &[
    ("sql syntax", "SQL syntax error"),
    ("sqlstate", "SQLSTATE error"),
    ("ora-0", "Oracle error"),
    ("pg_query", "PostgreSQL error"),
    ("psql:", "PostgreSQL error"),
    ("mysql_fetch", "MySQL error"),
    ("unclosed quotation", "MSSQL error"),
    ("sqlite3::", "SQLite error"),
    ("traceback (most recent call last)", "Python traceback"),
    ("java.lang.", "Java exception"),
    ("nullreferenceexception", ".NET exception"),
    ("system.web.", "ASP.NET error"),
    ("fatal error:", "PHP fatal error"),
    ("undefined index", "PHP notice"),
    ("stack trace", "stack trace"),
    ("template syntax error", "template engine error"),
    ("xml parsing error", "XML parser error"),
];

const BLOCK_SIGNALS: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("mod_security", "ModSecurity"),
    ("modsecurity", "ModSecurity"),
    ("request rejected", "WAF rejection"),
    ("access denied", "access denied"),
    ("too many requests", "rate limiting"),
    ("captcha", "CAPTCHA"),
];

const PRODUCTS: &[&str] = &[
    "nginx", "apache", "iis", "php", "tomcat", "jetty", "express", "django", "flask", "rails", "laravel", "spring",
    "wordpress", "drupal", "joomla", "postgresql", "mysql", "mariadb", "mongodb", "redis", "elasticsearch", "openssl",
    "node", "jquery", "angular", "react", "vue", "grafana", "jenkins", "gitlab", "openfire", "solr", "kibana", "keycloak",
];

/// Extract structured observations from all traces, excluding one agent's own.
pub fn digest(workdir: Option<&str>, exclude: Option<&str>) -> String {
    let Some(d) = workdir.map(|w| Path::new(w).join("traces")) else { return String::new() };
    let Ok(rd) = std::fs::read_dir(&d) else { return String::new() };
    let skip = exclude.map(file_name);
    let mut endpoints: BTreeSet<String> = BTreeSet::new();
    let mut params: BTreeSet<String> = BTreeSet::new();
    let mut errors: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut blocks: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut versions: BTreeSet<String> = BTreeSet::new();
    let path_re = regex::Regex::new(r#"(?:\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+|https?://[A-Za-z0-9.\-:]+)(/[A-Za-z0-9_\-./{}%:@]*)"#).expect("path regex");
    let param_re = regex::Regex::new(r"[?&]([A-Za-z_][A-Za-z0-9_\-\[\]]{0,40})=").expect("param regex");
    let ver_re = regex::Regex::new(r"(?i)\b([a-z][a-z0-9.\-]{1,20})[/ ]v?(\d+\.\d+(?:\.\d+)?)\b").expect("version regex");
    let mut sources = 0usize;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if Some(&name) == skip.as_ref() || !name.ends_with(".md") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        sources += 1;
        let agent = name.trim_end_matches(".md").to_string();
        for c in path_re.captures_iter(&text) {
            let p = c[1].split(['?', '#']).next().unwrap_or("").trim_end_matches(['.', ',', ':', ')']);
            if p.len() > 1 && p.len() <= 120 {
                endpoints.insert(crate::authz_matrix::template(p));
            }
        }
        for c in param_re.captures_iter(&text) {
            params.insert(c[1].to_string());
        }
        let low = text.to_lowercase();
        for (needle, label) in ERROR_SIGNATURES {
            if low.contains(needle) {
                errors.entry(label).or_default().insert(agent.clone());
            }
        }
        for (needle, label) in BLOCK_SIGNALS {
            if low.contains(needle) {
                blocks.entry(label).or_default().insert(agent.clone());
            }
        }
        for c in ver_re.captures_iter(&text) {
            let product = c[1].to_lowercase();
            if PRODUCTS.contains(&product.as_str()) {
                versions.insert(format!("{product} {}", &c[2]));
            }
        }
    }
    if sources == 0 {
        return String::new();
    }
    let take = |set: &BTreeSet<String>, n: usize| set.iter().take(n).cloned().collect::<Vec<_>>().join(", ");
    let mut body = String::new();
    if !endpoints.is_empty() {
        body.push_str(&format!("- endpoints seen ({}): {}\n", endpoints.len(), take(&endpoints, 40)));
    }
    if !params.is_empty() {
        body.push_str(&format!("- parameters seen ({}): {}\n", params.len(), take(&params, 40)));
    }
    for (label, agents) in &errors {
        body.push_str(&format!("- error signature: {label} (in {})\n", take(agents, 6)));
    }
    for (label, agents) in &blocks {
        body.push_str(&format!("- block signal: {label} (in {})\n", take(agents, 6)));
    }
    if !versions.is_empty() {
        body.push_str(&format!("- versions seen: {}\n", take(&versions, 20)));
    }
    if body.is_empty() {
        return String::new();
    }
    crate::taint::fence(&body, &format!("observations extracted from {sources} other agent trace(s)"))
}

/// The block every prompt carries: where the traces are, and the digest.
pub fn prompt_block(workdir: Option<&str>, exclude: Option<&str>) -> String {
    let Some(d) = dir(workdir) else { return String::new() };
    let digest = digest(workdir, exclude);
    let mut s = format!(
        "SHARED TRACES: other agents' full transcripts are in {} (one file per agent). Before re-deriving something — an error, a parameter, a version, an authenticated route — `grep -ril '<keyword>' {}` and build on what another agent already saw; cite the file you used.\n",
        d.display(),
        d.display()
    );
    if !digest.is_empty() {
        s.push_str(&digest);
        s.push('\n');
    }
    s.push('\n');
    s
}

// ── Cross-worker trace search ──
// Artex-inspired: workers query other workers' raw traces for observations
// that never became formal facts. The digest is a summary; this is grep on
// steroids — structured, ranked, and privacy-aware.

/// A single search hit from another worker's trace.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceHit {
    pub agent: String,
    pub line_number: usize,
    pub context: String,
    pub relevance: f64,
}

/// Query result from cross-worker trace search.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TraceSearchResult {
    pub hits: Vec<TraceHit>,
    pub agents_searched: usize,
    pub total_matches: usize,
}

/// Search all agent traces for specific patterns. Returns ranked hits with
/// surrounding context. Unlike `digest()`, this searches raw lines — so the
/// caller (the planner or an agent prompt) gets the exact observation another
/// worker made, not a derived summary.
///
/// `queries` — keywords, regexes, or phrases to find.
/// `exclude` — skip this agent's own trace.
/// `max_hits` — cap to avoid prompt bloat.
pub fn search(
    workdir: Option<&str>,
    queries: &[&str],
    exclude: Option<&str>,
    max_hits: usize,
) -> TraceSearchResult {
    let Some(d) = workdir.map(|w| Path::new(w).join("traces")) else {
        return TraceSearchResult::default();
    };
    let Ok(rd) = std::fs::read_dir(&d) else {
        return TraceSearchResult::default();
    };
    let skip = exclude.map(file_name);
    let mut result = TraceSearchResult::default();

    let query_lower: Vec<String> = queries.iter().map(|q| q.to_lowercase()).collect();

    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if Some(&name) == skip.as_ref() || !name.ends_with(".md") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
        let agent = name.trim_end_matches(".md").to_string();
        result.agents_searched += 1;

        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();
            let mut match_count = 0usize;
            for q in &query_lower {
                if line_lower.contains(q.as_str()) {
                    match_count += 1;
                }
            }
            if match_count == 0 { continue; }

            result.total_matches += 1;
            if result.hits.len() >= max_hits { continue; }

            // Gather context: 1 line before, the match, 1 line after.
            let start = i.saturating_sub(1);
            let end = (i + 2).min(lines.len());
            let context: String = lines[start..end].join("\n");

            // Relevance: fraction of query terms matched, boosted by position.
            let relevance = match_count as f64 / queries.len().max(1) as f64;

            result.hits.push(TraceHit {
                agent: agent.clone(),
                line_number: i + 1,
                context: sanitize_context(&context),
                relevance,
            });
        }
    }

    // Sort by relevance descending
    result.hits.sort_by(|a, b| b.relevance.partial_cmp(&a.relevance).unwrap_or(std::cmp::Ordering::Equal));
    result.hits.truncate(max_hits);
    result
}

/// Targeted search: find which agent observed a specific endpoint, parameter,
/// error, or technology. Returns the raw observation lines with agent attribution.
pub fn who_observed(workdir: Option<&str>, pattern: &str) -> Vec<(String, String)> {
    let result = search(workdir, &[pattern], None, 20);
    result.hits.into_iter()
        .map(|h| (h.agent, h.context))
        .collect()
}

/// Generate a prompt block for cross-worker trace search results.
pub fn search_prompt_block(results: &TraceSearchResult, query_desc: &str) -> String {
    if results.hits.is_empty() { return String::new(); }

    let mut s = format!("CROSS-WORKER TRACE SEARCH for '{query_desc}' ({} hits across {} agents):\n",
        results.total_matches, results.agents_searched);
    for hit in results.hits.iter().take(15) {
        s.push_str(&format!("  [{}:L{}] (rel={:.0}%) {}\n",
            hit.agent, hit.line_number, hit.relevance * 100.0,
            hit.context.lines().next().unwrap_or("")));
    }
    s
}

/// Strip potential secrets from context lines while keeping the observation.
fn sanitize_context(context: &str) -> String {
    let secret_re = regex::Regex::new(
        r"(?i)(password|secret|token|api[_-]?key|authorization|bearer)\s*[=:]\s*\S+"
    ).expect("secret regex");
    secret_re.replace_all(context, "$1=<REDACTED>").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("ns_traces_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.display().to_string()
    }

    #[test]
    fn digest_extracts_structure_not_raw_lines() {
        let w = tmp("digest");
        record(Some(&w), "sqli_error", "GET /api/orders/12?id=1&sort=asc\nYou have an error in your SQL syntax near\nServer: nginx/1.18.0\npassword=Hunter2Secret");
        record(Some(&w), "xss_reflected", "POST https://t.test/search?q=x\nblocked by Cloudflare");
        let d = digest(Some(&w), None);
        assert!(d.contains("/api/orders/{id}"), "{d}");
        assert!(d.contains("sort"), "{d}");
        assert!(d.contains("SQL syntax error"), "{d}");
        assert!(d.contains("nginx 1.18"), "{d}");
        assert!(d.contains("Cloudflare"), "{d}");
        assert!(!d.contains("Hunter2Secret"), "raw lines (and secrets) must not be copied");
        assert!(d.contains("UNTRUSTED"), "digest must be fenced as data");
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn own_trace_is_excluded() {
        let w = tmp("excl");
        record(Some(&w), "agent_a", "GET /only-a");
        assert!(digest(Some(&w), Some("agent_a")).is_empty());
        assert!(digest(Some(&w), None).contains("/only-a"));
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn prompt_block_points_to_the_directory() {
        let w = tmp("block");
        let b = prompt_block(Some(&w), None);
        assert!(b.contains("traces"));
        assert!(b.contains("grep -ril"));
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn cross_worker_search_finds_observations() {
        let w = tmp("xsearch");
        record(Some(&w), "agent_a", "Found hidden endpoint /api/admin/debug\nServer returned 500 with stack trace");
        record(Some(&w), "agent_b", "Parameter 'callback' reflects input unfiltered\nTested XSS on /search");
        let result = search(Some(&w), &["endpoint", "admin"], None, 10);
        assert!(result.agents_searched >= 1);
        assert!(!result.hits.is_empty());
        assert!(result.hits[0].agent == "agent_a");
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn cross_worker_search_excludes_self() {
        let w = tmp("xsearch_excl");
        record(Some(&w), "my_agent", "Found something interesting about /api/secret");
        let result = search(Some(&w), &["secret"], Some("my_agent"), 10);
        assert!(result.hits.is_empty());
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn cross_worker_search_redacts_secrets() {
        let w = tmp("xsearch_redact");
        record(Some(&w), "recon", "Authorization: Bearer sk-12345abc\nFound /api/users");
        let result = search(Some(&w), &["/api/users"], None, 10);
        assert!(!result.hits.is_empty());
        assert!(result.hits[0].context.contains("REDACTED"));
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn who_observed_returns_agent_attribution() {
        let w = tmp("who_obs");
        record(Some(&w), "sqli_agent", "Detected SQL error on /login endpoint");
        record(Some(&w), "xss_agent", "No reflection found");
        let obs = who_observed(Some(&w), "SQL error");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].0, "sqli_agent");
        let _ = std::fs::remove_dir_all(&w);
    }
}
