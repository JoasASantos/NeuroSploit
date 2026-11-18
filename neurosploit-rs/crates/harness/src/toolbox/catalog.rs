//! The curated toolbox catalog.
//!
//! The catalog is data (`tools/toolbox.json`) embedded at compile time so a
//! distributed binary always carries it, while operators can extend it without
//! touching Rust. Every entry is a *capability descriptor*, not an installed
//! tool: the runner detects, optionally provisions, and executes it under the
//! engagement's scope/constraints.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const CATALOG_JSON: &str = include_str!("../../../../tools/toolbox.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub id: String,
    pub name: String,
    pub binary: String,
    pub category: String,
    pub description: String,
    /// Template command. `{target}`, `{host}` and `{url}` are substituted.
    pub usage: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Actively probes the target (scanners/fuzzers/brute force).
    #[serde(default)]
    pub intrusive: bool,
    /// Needs root/CAP_NET_RAW (SYN scans, sniffers, ARP, ...).
    #[serde(default)]
    pub requires_root: bool,
    /// Installer → package. Supported: apt, pipx, go, cargo, npm, gem, docker.
    #[serde(default)]
    pub install: BTreeMap<String, String>,
    /// Optional MCP server hint (name in the MCP catalog).
    #[serde(default)]
    pub mcp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCatalog {
    pub version: u32,
    pub updated: String,
    pub tools: Vec<ToolSpec>,
}

static CATALOG: OnceLock<ToolCatalog> = OnceLock::new();

pub fn catalog() -> &'static ToolCatalog {
    CATALOG.get_or_init(|| {
        serde_json::from_str(CATALOG_JSON).unwrap_or_else(|e| {
            eprintln!("[toolbox] invalid embedded toolbox.json: {e}");
            ToolCatalog { version: 1, updated: String::new(), tools: Vec::new() }
        })
    })
}

pub fn all() -> &'static [ToolSpec] {
    &catalog().tools
}

pub fn find(id: &str) -> Option<&'static ToolSpec> {
    let needle = id.trim().to_ascii_lowercase();
    all().iter().find(|t| {
        t.id.eq_ignore_ascii_case(&needle)
            || t.binary.eq_ignore_ascii_case(&needle)
            || t.name.eq_ignore_ascii_case(&needle)
    })
}

pub fn search(query: &str) -> Vec<&'static ToolSpec> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return all().iter().collect();
    }
    all()
        .iter()
        .filter(|t| {
            t.id.to_ascii_lowercase().contains(&q)
                || t.name.to_ascii_lowercase().contains(&q)
                || t.binary.to_ascii_lowercase().contains(&q)
                || t.category.to_ascii_lowercase().contains(&q)
                || t.description.to_ascii_lowercase().contains(&q)
                || t.tags.iter().any(|x| x.to_ascii_lowercase().contains(&q))
        })
        .collect()
}

pub fn categories() -> Vec<(String, usize)> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for t in all() {
        *out.entry(t.category.clone()).or_insert(0) += 1;
    }
    out.into_iter().collect()
}

/// Recommended tool IDs for an engagement mode. Missing tools are fine — the
/// caller runs what is available (and optionally provisions).
pub fn mode_plan(mode: &str) -> Vec<&'static str> {
    match mode.to_ascii_lowercase().as_str() {
        "run" | "web" | "greybox" | "whitebox" => vec![
            "httpx", "whatweb", "wafw00f", "katana", "gau", "ffuf", "feroxbuster",
            "nuclei", "nikto", "sqlmap", "dalfox", "jwt_tool", "arjun", "trufflehog",
        ],
        "host" | "infra" => vec![
            "rustscan", "nmap", "naabu", "httpx", "enum4linux_ng", "netexec",
            "smbmap", "ldapsearch", "searchsploit", "responder",
        ],
        "internal" | "ad" => vec![
            "netexec", "enum4linux_ng", "bloodhound_python", "kerbrute", "certipy",
            "impacket_getuserspns", "impacket_getnpusers", "impacket_secretsdump",
            "ldapdomaindump", "smbclient", "rpcclient", "mitm6", "responder",
        ],
        "cloud" => vec![
            "trivy", "prowler", "scoutsuite", "checkov", "kube_bench", "kube_hunter",
            "cloud_enum", "s3scanner", "cloudsplaining",
        ],
        "container" => vec!["trivy", "grype", "syft", "dockle", "hadolint", "crane", "skopeo"],
        "mobile" => vec!["apktool", "jadx", "apkleaks", "frida", "objection", "mobsf"],
        "binary" => vec![
            "ghidra_headless", "radare2", "rizin", "binwalk", "checksec", "gdb",
            "objdump", "strings", "one_gadget", "ropper",
        ],
        "aitest" | "ai" => vec!["garak", "promptfoo", "pyrit", "llm_guard", "giskard"],
        _ => vec!["httpx", "nmap", "nuclei", "ffuf", "trufflehog"],
    }
}

/// Compact, context-budget-friendly catalogue for prompt injection. The model
/// sees IDs, categories and one-line descriptions; it calls `tools info` or the
/// MCP `tool_info` for full usage.
pub fn prompt_summary(max_per_category: usize, max_chars: usize) -> String {
    let mut out = String::new();
    for (cat, _) in categories() {
        let mut n = 0;
        out.push_str(&format!("[{cat}] "));
        for t in all().iter().filter(|t| t.category == cat) {
            if n >= max_per_category { break; }
            let item = format!("{} ({})", t.id, short(&t.description, 72));
            if out.len() + item.len() + 2 > max_chars { break; }
            out.push_str(&item);
            out.push_str("; ");
            n += 1;
        }
        out.push('\n');
        if out.len() > max_chars { break; }
    }
    out
}

fn short(s: &str, n: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= n { flat } else { flat.chars().take(n.saturating_sub(1)).collect::<String>() + "…" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_large_and_unique() {
        let tools = all();
        assert!(tools.len() >= 200, "expected 200+ tools, got {}", tools.len());
        let mut ids = std::collections::HashSet::new();
        for t in tools {
            assert!(ids.insert(t.id.clone()), "duplicate tool id: {}", t.id);
            assert!(!t.binary.trim().is_empty(), "{} has no binary", t.id);
            assert!(!t.category.trim().is_empty(), "{} has no category", t.id);
            assert!(!t.usage.trim().is_empty(), "{} has no usage", t.id);
        }
        assert!(find("nmap").is_some());
        assert!(find("rustscan").is_some());
        assert!(find("netexec").is_some());
        assert!(find("trivy").is_some());
        assert!(find("apktool").is_some());
    }

    #[test]
    fn search_and_plans_work() {
        assert!(search("port-scan").iter().any(|t| t.id == "nmap"));
        assert!(search("kerberos").iter().any(|t| t.id == "kerbrute"));
        assert!(mode_plan("ad").contains(&"netexec"));
        assert!(mode_plan("web").contains(&"nuclei"));
        assert!(!prompt_summary(3, 4000).is_empty());
    }
}
