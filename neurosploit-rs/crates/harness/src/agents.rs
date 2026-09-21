use regex::Regex;
use serde::Serialize;
use std::path::Path;
use walkdir::WalkDir;

/// One markdown specialist/meta agent.
#[derive(Clone, Debug, Serialize)]
pub struct Agent {
    pub name: String,
    pub title: String,
    pub cwe: String,
    pub kind: String, // "vuln" | "meta"
    #[serde(skip)]
    pub system: String,
    #[serde(skip)]
    pub user: String,
}

/// The loaded `agents_md/` library.
#[derive(Default)]
pub struct Library {
    pub vulns: Vec<Agent>,
    pub meta: Vec<Agent>,
    pub recon: Vec<Agent>,
    pub code: Vec<Agent>,
    pub infra: Vec<Agent>,
    pub chains: Vec<Agent>,
    /// AI/LLM/agent/MCP/skills security agents (OWASP LLM Top 10, MCP risks…).
    pub ai: Vec<Agent>,
    pub mobile: Vec<Agent>,
}

impl Library {
    pub fn total(&self) -> usize {
        self.vulns.len() + self.meta.len() + self.recon.len() + self.code.len()
            + self.infra.len() + self.chains.len() + self.ai.len() + self.mobile.len()
    }
}

/// Load `<base>/agents_md/{vulns,meta,recon,code,infra,chains,ai}/*.md`.
pub fn load(base: &Path) -> Library {
    let root = base.join("agents_md");
    Library {
        vulns: load_dir(&root.join("vulns"), "vuln"),
        meta: load_dir(&root.join("meta"), "meta"),
        recon: load_dir(&root.join("recon"), "recon"),
        code: load_dir(&root.join("code"), "code"),
        infra: load_dir(&root.join("infra"), "infra"),
        chains: load_dir(&root.join("chains"), "chain"),
        ai: load_dir(&root.join("ai"), "ai"),
        mobile: load_dir(&root.join("mobile"), "mobile"),
    }
}

fn load_dir(dir: &Path, kind: &str) -> Vec<Agent> {
    let title_re = Regex::new(r"(?m)^#\s+(.+?)\s*$").unwrap();
    let cwe_re = Regex::new(r"CWE-\d+").unwrap();
    let user_re = Regex::new(r"(?s)##\s*User Prompt\s*\n(.*?)(?:\n##\s|\z)").unwrap();
    let sys_re = Regex::new(r"(?s)##\s*System Prompt\s*\n(.*?)(?:\n##\s|\z)").unwrap();
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    for entry in WalkDir::new(dir).max_depth(1).into_iter().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
        let title = title_re
            .captures(&text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| name.clone());
        let cwe = cwe_re.find(&text).map(|m| m.as_str().to_string()).unwrap_or_default();
        let user = user_re
            .captures(&text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let system = sys_re
            .captures(&text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        out.push(Agent { name, title, cwe, kind: kind.to_string(), system, user });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}
