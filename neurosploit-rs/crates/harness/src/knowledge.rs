use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use walkdir::WalkDir;

/// A single knowledge entry parsed from an agent markdown file.
#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeEntry {
    pub name: String,
    pub title: String,
    /// Category derived from the parent directory: "vuln", "recon", "mobile", etc.
    pub category: String,
    pub cwes: Vec<String>,
    /// The user prompt section — methodology steps and techniques.
    pub methodology: String,
    /// The system prompt section — role context.
    pub role_context: String,
    /// Keywords extracted from title + methodology for matching.
    pub keywords: Vec<String>,
}

/// Searchable knowledge base built from all agent markdown files.
#[derive(Debug, Clone, Default)]
pub struct KnowledgeBase {
    pub entries: Vec<KnowledgeEntry>,
}

/// Load all agent markdowns under `<base>/agents_md/` as knowledge entries.
pub fn load(base: &Path) -> KnowledgeBase {
    let root = base.join("agents_md");
    let mut entries = Vec::new();

    let title_re = Regex::new(r"(?m)^#\s+(.+?)\s*$").unwrap();
    let cwe_re = Regex::new(r"CWE-\d+").unwrap();
    let user_re = Regex::new(r"(?s)##\s*User Prompt\s*\n(.*?)(?:\n##\s|\z)").unwrap();
    let sys_re = Regex::new(r"(?s)##\s*System Prompt\s*\n(.*?)(?:\n##\s|\z)").unwrap();

    if !root.is_dir() {
        return KnowledgeBase { entries };
    }

    for entry in WalkDir::new(&root).into_iter().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }

        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        // Derive category from the immediate parent directory name.
        let category = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| match s {
                "vulns" => "vuln",
                "chains" => "chain",
                _ => s,
            })
            .unwrap_or("unknown")
            .to_string();

        let title = title_re
            .captures(&text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| name.clone());

        let cwes: Vec<String> = cwe_re
            .find_iter(&text)
            .map(|m| m.as_str().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let methodology = user_re
            .captures(&text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();

        let role_context = sys_re
            .captures(&text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();

        let keywords = extract_keywords(&format!("{} {}", title, methodology));

        entries.push(KnowledgeEntry {
            name,
            title,
            category,
            cwes,
            methodology,
            role_context,
            keywords,
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    KnowledgeBase { entries }
}

impl KnowledgeBase {
    /// Find entries relevant to a task description. Scores by keyword overlap
    /// and CWE match bonus.
    pub fn query(&self, task: &str, limit: usize) -> Vec<&KnowledgeEntry> {
        let task_tokens: HashSet<String> = extract_keywords(task).into_iter().collect();
        if task_tokens.is_empty() {
            return Vec::new();
        }

        // Extract any CWE references from the task.
        let cwe_re = Regex::new(r"CWE-\d+").unwrap();
        let task_cwes: HashSet<String> = cwe_re
            .find_iter(task)
            .map(|m| m.as_str().to_string())
            .collect();

        let mut scored: Vec<(usize, &KnowledgeEntry)> = self
            .entries
            .iter()
            .map(|e| {
                let keyword_hits = e
                    .keywords
                    .iter()
                    .filter(|kw| task_tokens.contains(kw.as_str()))
                    .count();
                let cwe_bonus = if !task_cwes.is_empty() {
                    e.cwes
                        .iter()
                        .filter(|c| task_cwes.contains(c.as_str()))
                        .count()
                        * 3
                } else {
                    0
                };
                (keyword_hits + cwe_bonus, e)
            })
            .filter(|(score, _)| *score > 0)
            .collect();

        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored.into_iter().take(limit).map(|(_, e)| e).collect()
    }

    /// Get methodology text for the top matching entries, formatted for
    /// injection into an agent prompt.
    ///
    /// Returns an empty string when nothing matches.
    pub fn methodology_for(&self, task: &str, max_entries: usize, max_chars: usize) -> String {
        let results = self.query(task, max_entries);
        if results.is_empty() {
            return String::new();
        }

        let mut out = String::from(
            "KNOWLEDGE BASE (reference methodology \u{2014} adapt to your task, do not follow blindly):\n",
        );
        let mut budget = max_chars.saturating_sub(out.len());

        for entry in results {
            let cwe_label = if entry.cwes.is_empty() {
                String::new()
            } else {
                format!(" ({})", entry.cwes.join(", "))
            };
            let header = format!("--- {}{} ---\n", entry.title, cwe_label);
            if header.len() >= budget {
                break;
            }
            out.push_str(&header);
            budget = budget.saturating_sub(header.len());

            let body = if entry.methodology.len() > budget {
                format!("{}...\n", &entry.methodology[..budget.saturating_sub(4)])
            } else {
                format!("{}\n", entry.methodology)
            };
            out.push_str(&body);
            budget = budget.saturating_sub(body.len());
            if budget == 0 {
                break;
            }
        }

        out
    }

    /// Find entries by CWE number (e.g. `"CWE-89"`).
    pub fn by_cwe(&self, cwe: &str) -> Vec<&KnowledgeEntry> {
        self.entries
            .iter()
            .filter(|e| e.cwes.iter().any(|c| c == cwe))
            .collect()
    }

    /// Find entries by category (e.g. `"vuln"`, `"mobile"`).
    pub fn by_category(&self, cat: &str) -> Vec<&KnowledgeEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == cat)
            .collect()
    }

    /// Total entries loaded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries are loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Extract deduplicated, lowercased keywords from text, filtering out stop
/// words and very short tokens.
fn extract_keywords(text: &str) -> Vec<String> {
    let stop: HashSet<&str> = [
        "the", "and", "for", "with", "that", "this", "from", "are", "was", "you", "your", "can",
        "will", "not", "but", "has", "have", "had", "all", "any", "its", "into", "also", "use",
        "using", "each", "when", "then", "than", "been", "does", "how", "may", "should", "would",
        "could", "where", "which", "what", "who", "these", "those", "them", "they", "their",
        "other", "about", "more", "some", "such",
    ]
    .iter()
    .copied()
    .collect();

    text.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .map(|w| w.to_lowercase())
        .filter(|w| w.len() >= 3 && !stop.contains(w.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_kb() -> KnowledgeBase {
        KnowledgeBase {
            entries: vec![
                KnowledgeEntry {
                    name: "sqli".into(),
                    title: "SQL Injection".into(),
                    category: "vuln".into(),
                    cwes: vec!["CWE-89".into()],
                    methodology: "Test parameters with single quotes and UNION SELECT...".into(),
                    role_context: "SQL injection specialist".into(),
                    keywords: extract_keywords("SQL Injection test parameters UNION SELECT"),
                },
                KnowledgeEntry {
                    name: "xss".into(),
                    title: "Cross-Site Scripting".into(),
                    category: "vuln".into(),
                    cwes: vec!["CWE-79".into()],
                    methodology: "Inject script tags into input fields and URL parameters..."
                        .into(),
                    role_context: "XSS specialist".into(),
                    keywords: extract_keywords(
                        "Cross-Site Scripting inject script tags input fields",
                    ),
                },
                KnowledgeEntry {
                    name: "apk_static".into(),
                    title: "APK Static Analysis".into(),
                    category: "mobile".into(),
                    cwes: vec!["CWE-919".into()],
                    methodology: "Decompile APK with jadx, search for hardcoded secrets...".into(),
                    role_context: "Mobile reverse engineering specialist".into(),
                    keywords: extract_keywords(
                        "APK Static Analysis decompile jadx hardcoded secrets",
                    ),
                },
            ],
        }
    }

    #[test]
    fn query_finds_relevant_entries() {
        let kb = sample_kb();
        let r = kb.query("test SQL injection on login form", 2);
        assert!(!r.is_empty());
        assert_eq!(r[0].name, "sqli");
    }

    #[test]
    fn methodology_for_formats_context_block() {
        let kb = sample_kb();
        let m = kb.methodology_for("test SQL injection", 1, 5000);
        assert!(m.contains("KNOWLEDGE BASE"));
        assert!(m.contains("SQL Injection"));
        assert!(m.contains("CWE-89"));
    }

    #[test]
    fn by_cwe_finds_entries() {
        let kb = sample_kb();
        assert_eq!(kb.by_cwe("CWE-79").len(), 1);
        assert_eq!(kb.by_cwe("CWE-79")[0].name, "xss");
    }

    #[test]
    fn keywords_extraction_filters_stopwords() {
        let kw = extract_keywords("the quick SQL injection for the web application");
        assert!(kw.contains(&"sql".to_string()));
        assert!(kw.contains(&"injection".to_string()));
        assert!(!kw.contains(&"the".to_string()));
        assert!(!kw.contains(&"for".to_string()));
    }

    #[test]
    fn by_category_filters() {
        let kb = sample_kb();
        let mobile = kb.by_category("mobile");
        assert_eq!(mobile.len(), 1);
        assert_eq!(mobile[0].name, "apk_static");
    }

    #[test]
    fn empty_query_returns_nothing() {
        let kb = sample_kb();
        let r = kb.query("", 5);
        assert!(r.is_empty());
    }

    #[test]
    fn cwe_query_boosts_score() {
        let kb = sample_kb();
        // Query mentions CWE-79 so XSS should rank first even with SQL terms.
        let r = kb.query("CWE-79 test injection", 3);
        assert!(!r.is_empty());
        assert_eq!(r[0].name, "xss");
    }

    #[test]
    fn methodology_for_empty_on_no_match() {
        let kb = sample_kb();
        let m = kb.methodology_for("zzz_nonexistent_term_zzz", 5, 5000);
        assert!(m.is_empty());
    }
}
