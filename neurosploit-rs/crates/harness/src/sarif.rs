//! SARIF 2.1.0 export for a finished run.
//!
//! SARIF (Static Analysis Results Interchange Format) is the format GitHub code
//! scanning, Azure DevOps, and most CI dashboards ingest. Emitting it next to
//! `report.md` lets a NeuroSploit run drop straight into a pipeline: upload
//! `report.sarif` and every finding shows up as an annotated alert, coloured by
//! severity, linked to its CWE, on the exact endpoint it was proven against.
//!
//! This is a pure projection of the findings already on disk — no model calls,
//! no fabrication. It is emitted by [`crate::report::write_all`] and rebuilt by
//! [`crate::report::rebuild`], and can be regenerated on demand from the CLI.
//!
//! We follow the parts of the spec CI actually consumes:
//!   - one `run` with a `tool.driver` carrying a de-duplicated `rules` array,
//!   - `security-severity` (0.0..10.0) on each rule, which GitHub uses to bucket
//!     the alert into critical/high/medium/low,
//!   - one `result` per finding with `ruleId`, `level`, a message, and a
//!     physical location pointing at the endpoint.

use crate::types::Finding;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// SARIF result level. GitHub renders error/warning/note distinctly.
fn level_for(severity: &str) -> &'static str {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none",
    }
}

/// Numeric CVSS base score parsed from the leading float of the `cvss` field
/// (e.g. "9.8 (AV:N/AC:L/...)" -> 9.8). Falls back to a severity-band midpoint
/// so GitHub still buckets the alert when no vector was graded.
fn security_severity(f: &Finding) -> String {
    let parsed = f
        .cvss
        .trim()
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|t| !t.is_empty())
        .and_then(|t| t.parse::<f64>().ok())
        .filter(|v| (0.0..=10.0).contains(v));
    let score = parsed.unwrap_or_else(|| match f.severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 9.5,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 2.5,
        _ => 0.0,
    });
    format!("{score:.1}")
}

/// A stable rule id for a finding: prefer the CWE, else the agent class.
fn rule_id(f: &Finding) -> String {
    let cwe = f.cwe.trim();
    if cwe.is_empty() {
        let agent = f.agent.trim();
        if agent.is_empty() { "NEUROSPLOIT.finding".to_string() } else { format!("NEUROSPLOIT.{agent}") }
    } else if cwe.to_ascii_uppercase().starts_with("CWE-") {
        cwe.to_ascii_uppercase()
    } else {
        format!("CWE-{cwe}")
    }
}

/// Help URI for a CWE-style rule id (deep link to the MITRE entry).
fn help_uri(rule_id: &str) -> Option<String> {
    let num: String = rule_id.chars().filter(|c| c.is_ascii_digit()).collect();
    if rule_id.starts_with("CWE-") && !num.is_empty() {
        Some(format!("https://cwe.mitre.org/data/definitions/{num}.html"))
    } else {
        None
    }
}

/// Build the full SARIF 2.1.0 document for a run's findings.
pub fn to_sarif(target: &str, findings: &[Finding]) -> Value {
    // De-duplicate rules by id; the first finding of each class defines the rule.
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    for f in findings {
        let id = rule_id(f);
        rules.entry(id.clone()).or_insert_with(|| {
            let mut rule = json!({
                "id": id,
                "name": if f.cwe.trim().is_empty() { f.agent.clone() } else { f.cwe.clone() },
                "shortDescription": { "text": rule_short_desc(f) },
                "defaultConfiguration": { "level": level_for(&f.severity) },
                "properties": {
                    "security-severity": security_severity(f),
                    "tags": rule_tags(f),
                }
            });
            if let Some(uri) = help_uri(&id) {
                rule["helpUri"] = json!(uri);
            }
            rule
        });
    }

    let results: Vec<Value> = findings.iter().map(|f| result_for(f)).collect();

    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "NeuroSploit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/CyberSecurityUP/neurosploit-rs",
                    "rules": rules.into_values().collect::<Vec<_>>(),
                }
            },
            "properties": { "target": target },
            "results": results,
        }]
    })
}

fn rule_short_desc(f: &Finding) -> String {
    if !f.cwe.trim().is_empty() {
        f.title.clone()
    } else {
        format!("{} finding", f.agent)
    }
}

/// Rule tags CI can facet on: OWASP + MITRE when known, plus "security".
fn rule_tags(f: &Finding) -> Vec<String> {
    let mut tags = vec!["security".to_string()];
    if !f.owasp.trim().is_empty() { tags.push(f.owasp.clone()); }
    if !f.mitre.trim().is_empty() { tags.push(f.mitre.clone()); }
    tags
}

fn result_for(f: &Finding) -> Value {
    // The endpoint is the closest thing to a physical location for a web
    // finding; `location` (param/field/step) refines the message.
    let uri = if f.endpoint.trim().is_empty() { "target".to_string() } else { f.endpoint.clone() };
    let mut text = f.title.clone();
    if !f.location.trim().is_empty() {
        text.push_str(&format!(" — {}", f.location));
    }
    if !f.impact.trim().is_empty() {
        text.push_str(&format!("\nImpact: {}", f.impact));
    }

    let mut props = json!({
        "confidence": f.confidence,
        "validated": f.validated,
        "severity": f.severity,
    });
    if !f.cvss.trim().is_empty() { props["cvss"] = json!(f.cvss); }
    if !f.owasp.trim().is_empty() { props["owasp"] = json!(f.owasp); }
    if !f.mitre.trim().is_empty() { props["mitre"] = json!(f.mitre); }
    if !f.review_status.trim().is_empty() { props["reviewStatus"] = json!(f.review_status); }

    json!({
        "ruleId": rule_id(f),
        "level": level_for(&f.severity),
        "message": { "text": text },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri }
            }
        }],
        "partialFingerprints": { "neurosploitFindingId": f.id },
        "properties": props,
    })
}

/// Serialize the SARIF document to pretty JSON.
pub fn to_string(target: &str, findings: &[Finding]) -> String {
    serde_json::to_string_pretty(&to_sarif(target, findings)).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: &str, cwe: &str, cvss: &str) -> Finding {
        Finding {
            id: "f1".into(),
            agent: "web".into(),
            title: "SQL injection".into(),
            severity: sev.into(),
            cwe: cwe.into(),
            cvss: cvss.into(),
            endpoint: "https://app.example.com/api/login".into(),
            ..Default::default()
        }
    }

    #[test]
    fn levels_map_from_severity() {
        assert_eq!(level_for("Critical"), "error");
        assert_eq!(level_for("high"), "error");
        assert_eq!(level_for("Medium"), "warning");
        assert_eq!(level_for("Low"), "note");
        assert_eq!(level_for("Info"), "none");
    }

    #[test]
    fn cvss_score_parsed_from_vector_string() {
        let f = finding("Critical", "CWE-89", "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)");
        assert_eq!(security_severity(&f), "9.8");
    }

    #[test]
    fn cvss_falls_back_to_severity_band() {
        let f = finding("High", "CWE-89", "");
        assert_eq!(security_severity(&f), "7.5");
    }

    #[test]
    fn rule_id_prefers_cwe() {
        assert_eq!(rule_id(&finding("High", "CWE-89", "")), "CWE-89");
        assert_eq!(rule_id(&finding("High", "89", "")), "CWE-89");
        assert_eq!(rule_id(&finding("High", "", "")), "NEUROSPLOIT.web");
    }

    #[test]
    fn help_uri_deep_links_cwe() {
        assert_eq!(help_uri("CWE-89").as_deref(), Some("https://cwe.mitre.org/data/definitions/89.html"));
        assert_eq!(help_uri("NEUROSPLOIT.web"), None);
    }

    #[test]
    fn document_is_wellformed_and_dedupes_rules() {
        let fs = vec![
            finding("Critical", "CWE-89", "9.8"),
            finding("High", "CWE-89", "8.1"),
            finding("Medium", "CWE-79", "6.1"),
        ];
        let doc = to_sarif("https://app.example.com", &fs);
        assert_eq!(doc["version"], "2.1.0");
        let rules = doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "two distinct CWEs -> two rules");
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["ruleId"], "CWE-89");
        assert_eq!(results[0]["level"], "error");
    }
}
