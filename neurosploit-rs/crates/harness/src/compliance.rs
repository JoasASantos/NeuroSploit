//! Compliance framing — mapping findings to the controls a client is audited on.
//!
//! A client who has to answer to PCI-DSS, HIPAA or SOC 2 does not read a
//! pentest report as a list of CWEs. They read it as "which of my controls does
//! this put at risk, and what do I tell the assessor". So this module takes the
//! findings the engagement already proved and re-frames them against the
//! control catalogue of each framework: a reflected-XSS finding is *also* a gap
//! against PCI-DSS 6.2.4 and SOC 2 CC7.1, and saying so is most of the work of
//! turning a technical report into one a compliance team can act on.
//!
//! ## The honesty line, drawn hard
//!
//! A scanner cannot declare compliance. Compliance is an auditor's conclusion
//! over an entire environment — policies, evidence, scope, compensating
//! controls — almost none of which a pentest sees. What a finding *can* do is
//! **indicate a gap** against a specific control: evidence the assessor will
//! want to look at. So every output here is phrased as "this finding bears on
//! control X", never "you are non-compliant with X". A tool that prints a green
//! "PCI COMPLIANT" badge off a scan is lying, and the client's QSA knows it.
//!
//! Absence of findings is treated the same way: it is *not* evidence of
//! compliance, only absence of the specific gaps this engagement tested for —
//! and the summary says so rather than leaving a reader to assume the opposite.

use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// A compliance framework we can map findings onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framework {
    /// PCI-DSS v4.0 — payment card data.
    PciDss,
    /// HIPAA Security Rule (45 CFR §164.3xx) — protected health information.
    Hipaa,
    /// SOC 2 — Trust Services Criteria (security, availability, confidentiality).
    Soc2,
}

impl Framework {
    pub fn as_str(self) -> &'static str {
        match self {
            Framework::PciDss => "pci-dss",
            Framework::Hipaa => "hipaa",
            Framework::Soc2 => "soc2",
        }
    }
    pub fn title(self) -> &'static str {
        match self {
            Framework::PciDss => "PCI-DSS v4.0",
            Framework::Hipaa => "HIPAA Security Rule",
            Framework::Soc2 => "SOC 2 (Trust Services Criteria)",
        }
    }
    pub fn parse(s: &str) -> Option<Framework> {
        Some(match s.trim().to_lowercase().replace([' ', '_'], "-").as_str() {
            "pci" | "pci-dss" | "pcidss" => Framework::PciDss,
            "hipaa" => Framework::Hipaa,
            "soc2" | "soc-2" | "soc" => Framework::Soc2,
            _ => return None,
        })
    }
    pub fn all() -> [Framework; 3] {
        [Framework::PciDss, Framework::Hipaa, Framework::Soc2]
    }
}

/// One control a finding bears on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    /// The control's own identifier in the framework ("6.2.4", "CC6.7",
    /// "§164.312(e)(1)").
    pub id: String,
    /// What the control requires, in a sentence.
    pub requirement: String,
}

impl Control {
    fn new(id: &str, requirement: &str) -> Control {
        Control { id: id.into(), requirement: requirement.into() }
    }
}

/// The controls a class of weakness bears on, per framework.
///
/// Keyed on the security *category* a CWE belongs to, not on the raw CWE
/// number, because the mapping is the same for a whole family: every injection
/// class points at the same secure-coding controls. [`categorize`] does the
/// CWE→category step so this table stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    Injection,
    BrokenAccessControl,
    BrokenAuth,
    CryptoTransport,
    SensitiveDataExposure,
    SecurityMisconfig,
    Ssrf,
    VulnerableComponent,
    InsufficientLogging,
    Csrf,
    Other,
}

/// Place a finding in a control-relevant category.
fn categorize(f: &Finding) -> Category {
    let n = f.cwe.chars().filter(|c| c.is_ascii_digit()).collect::<String>();
    let t = format!("{} {}", f.title, f.cwe).to_lowercase();
    let is = |cwe: &[&str]| cwe.contains(&n.as_str());
    if is(&["89", "79", "78", "77", "94", "917", "611", "1336", "943", "564", "113", "90"]) || t.contains("injection") || t.contains("xss") {
        Category::Injection
    } else if is(&["639", "863", "862", "285", "22", "23", "918"]) && !t.contains("ssrf") || t.contains("idor") || t.contains("access control") || t.contains("bola") || t.contains("path traversal") {
        Category::BrokenAccessControl
    } else if is(&["287", "306", "307", "384", "620", "521", "347", "1004"]) || t.contains("auth") || t.contains("jwt") || t.contains("session") || t.contains("rate limit") || t.contains("brute") {
        Category::BrokenAuth
    } else if is(&["319", "311", "326", "327", "523"]) || t.contains("cleartext") || t.contains("tls") || t.contains("hsts") || t.contains("weak cipher") {
        Category::CryptoTransport
    } else if is(&["200", "209", "532", "538", "540", "312", "530", "525", "524"]) || t.contains("disclosure") || t.contains("exposed") || t.contains("leak") {
        Category::SensitiveDataExposure
    } else if is(&["16", "1021", "614", "942", "650", "548", "1230", "693", "644"]) || t.contains("misconfig") || t.contains("cors") || t.contains("clickjack") || t.contains("header") || t.contains("directory listing") {
        Category::SecurityMisconfig
    } else if is(&["918"]) || t.contains("ssrf") || t.contains("server-side request") {
        Category::Ssrf
    } else if is(&["1035", "1104", "937"]) || t.contains("outdated") || t.contains("vulnerable component") || t.contains("known cve") {
        Category::VulnerableComponent
    } else if is(&["778", "223"]) || t.contains("logging") || t.contains("audit trail") {
        Category::InsufficientLogging
    } else if is(&["352"]) || t.contains("csrf") || t.contains("cross-site request") {
        Category::Csrf
    } else {
        Category::Other
    }
}

fn controls_for(cat: Category, fw: Framework) -> Vec<Control> {
    use Category::*;
    use Framework::*;
    match (fw, cat) {
        // ---- PCI-DSS v4.0 ------------------------------------------------
        (PciDss, Injection) => vec![
            Control::new("6.2.4", "Software engineering techniques prevent or mitigate common software attacks (injection included) in bespoke and custom software"),
            Control::new("6.3.1", "Security vulnerabilities are identified and managed"),
        ],
        (PciDss, BrokenAccessControl) => vec![
            Control::new("7.2.1", "An access control model restricts access based on need-to-know and least privilege"),
            Control::new("6.2.4", "Custom software resists attacks on access-control logic"),
        ],
        (PciDss, BrokenAuth) => vec![
            Control::new("8.3.1", "Strong authentication for users and administrators is enforced"),
            Control::new("8.3.6", "Passwords/passphrases meet minimum strength and lockout requirements"),
        ],
        (PciDss, CryptoTransport) => vec![
            Control::new("4.2.1", "Strong cryptography protects PAN during transmission over open, public networks"),
        ],
        (PciDss, SensitiveDataExposure) => vec![
            Control::new("3.5.1", "PAN is rendered unreadable wherever stored"),
            Control::new("6.2.4", "Custom software does not leak sensitive data through errors or debug output"),
        ],
        (PciDss, SecurityMisconfig) => vec![
            Control::new("2.2.1", "System components are configured securely and hardened"),
            Control::new("6.4.1", "Public-facing web applications are protected against attacks"),
        ],
        (PciDss, Ssrf) => vec![Control::new("1.3.1", "Inbound/outbound traffic to the CDE is restricted to what is necessary"), Control::new("6.2.4", "Custom software mitigates SSRF")],
        (PciDss, VulnerableComponent) => vec![Control::new("6.3.3", "Security patches are installed within a defined window"), Control::new("11.3.1", "Internal vulnerability scans are performed and findings resolved")],
        (PciDss, InsufficientLogging) => vec![Control::new("10.2.1", "Audit logs capture all access to system components and cardholder data")],
        (PciDss, Csrf) => vec![Control::new("6.2.4", "Custom software mitigates cross-site request forgery")],
        (PciDss, Other) => vec![Control::new("6.3.1", "Security vulnerabilities are identified, risk-ranked and managed")],

        // ---- HIPAA Security Rule ----------------------------------------
        (Hipaa, Injection) => vec![Control::new("§164.312(c)(1)", "Integrity — protect ePHI from improper alteration or destruction"), Control::new("§164.308(a)(1)(ii)(A)", "Risk analysis identifies vulnerabilities to ePHI")],
        (Hipaa, BrokenAccessControl) => vec![Control::new("§164.312(a)(1)", "Access control — allow access to ePHI only to authorized persons"), Control::new("§164.308(a)(4)", "Information access management")],
        (Hipaa, BrokenAuth) => vec![Control::new("§164.312(d)", "Person or entity authentication verifies identity before ePHI access"), Control::new("§164.308(a)(5)(ii)(D)", "Password management")],
        (Hipaa, CryptoTransport) => vec![Control::new("§164.312(e)(1)", "Transmission security guards against unauthorized access to ePHI in transit"), Control::new("§164.312(e)(2)(ii)", "Encryption of ePHI in transit")],
        (Hipaa, SensitiveDataExposure) => vec![Control::new("§164.312(a)(2)(iv)", "Encryption and decryption of ePHI at rest"), Control::new("§164.502(b)", "Minimum necessary — limit ePHI disclosure")],
        (Hipaa, SecurityMisconfig) => vec![Control::new("§164.308(a)(1)(ii)(B)", "Risk management — implement measures to reduce risks and vulnerabilities")],
        (Hipaa, Ssrf) => vec![Control::new("§164.312(a)(1)", "Access control over internal systems reachable from the application")],
        (Hipaa, VulnerableComponent) => vec![Control::new("§164.308(a)(1)(ii)(B)", "Risk management includes remediating known vulnerabilities")],
        (Hipaa, InsufficientLogging) => vec![Control::new("§164.312(b)", "Audit controls record and examine activity in systems with ePHI")],
        (Hipaa, Csrf) => vec![Control::new("§164.312(a)(1)", "Access control — prevent actions performed without authorization")],
        (Hipaa, Other) => vec![Control::new("§164.308(a)(1)(ii)(A)", "Risk analysis of vulnerabilities to ePHI")],

        // ---- SOC 2 (Trust Services Criteria) ----------------------------
        (Soc2, Injection) => vec![Control::new("CC7.1", "Detect and remediate vulnerabilities in the system"), Control::new("CC8.1", "Change management prevents introduction of insecure code")],
        (Soc2, BrokenAccessControl) => vec![Control::new("CC6.1", "Logical access controls restrict access to authorized users"), Control::new("CC6.3", "Access is granted based on least privilege")],
        (Soc2, BrokenAuth) => vec![Control::new("CC6.1", "Identification and authentication of users before access")],
        (Soc2, CryptoTransport) => vec![Control::new("CC6.7", "Data in transit is protected with encryption")],
        (Soc2, SensitiveDataExposure) => vec![Control::new("C1.1", "Confidential information is protected from unauthorized disclosure"), Control::new("CC6.7", "Protection of information during transmission and disposal")],
        (Soc2, SecurityMisconfig) => vec![Control::new("CC6.6", "Boundary protection and secure configuration of the system")],
        (Soc2, Ssrf) => vec![Control::new("CC6.6", "Boundary protection restricts unauthorized internal connections")],
        (Soc2, VulnerableComponent) => vec![Control::new("CC7.1", "Vulnerabilities in components are identified and remediated")],
        (Soc2, InsufficientLogging) => vec![Control::new("CC7.2", "Security events are monitored and logged for analysis")],
        (Soc2, Csrf) => vec![Control::new("CC6.1", "Actions are performed only by authenticated, authorized users")],
        (Soc2, Other) => vec![Control::new("CC7.1", "Vulnerabilities are identified, evaluated and remediated")],
    }
}

/// A finding, mapped to the controls it bears on in one framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedFinding {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub controls: Vec<Control>,
}

/// The compliance view of an engagement, for one framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub framework_title: String,
    pub mapped: Vec<MappedFinding>,
    /// Controls with at least one finding against them, most-cited first.
    pub controls_with_gaps: Vec<ControlGap>,
    pub tested_finding_count: usize,
}

/// A control and the findings that bear on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGap {
    pub control: Control,
    pub finding_ids: Vec<String>,
    /// Highest severity among the findings that hit this control.
    pub max_severity: String,
}

fn sev_rank(s: &str) -> u8 {
    match s.trim().to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

/// Build the compliance view for one framework.
///
/// Only findings that survived validation are mapped — an unconfirmed finding
/// is not a control gap, it is a lead, and putting leads in front of an auditor
/// as gaps is how a report loses the room.
pub fn map_findings(findings: &[Finding], fw: Framework, confirmed_only: bool) -> ComplianceReport {
    use std::collections::BTreeMap;
    let mut mapped = Vec::new();
    let mut gaps: BTreeMap<String, ControlGap> = BTreeMap::new();

    for f in findings {
        if confirmed_only && !f.validated {
            continue;
        }
        let cat = categorize(f);
        let controls = controls_for(cat, fw);
        for c in &controls {
            let entry = gaps.entry(c.id.clone()).or_insert_with(|| ControlGap {
                control: c.clone(),
                finding_ids: Vec::new(),
                max_severity: "info".into(),
            });
            entry.finding_ids.push(f.id.clone());
            if sev_rank(&f.severity) > sev_rank(&entry.max_severity) {
                entry.max_severity = f.severity.clone();
            }
        }
        mapped.push(MappedFinding {
            finding_id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity.clone(),
            controls,
        });
    }

    let mut controls_with_gaps: Vec<ControlGap> = gaps.into_values().collect();
    controls_with_gaps.sort_by(|a, b| {
        sev_rank(&b.max_severity)
            .cmp(&sev_rank(&a.max_severity))
            .then(b.finding_ids.len().cmp(&a.finding_ids.len()))
            .then(a.control.id.cmp(&b.control.id))
    });

    ComplianceReport {
        framework: fw.as_str().into(),
        framework_title: fw.title().into(),
        tested_finding_count: mapped.len(),
        mapped,
        controls_with_gaps,
    }
}

impl ComplianceReport {
    /// The disclaimer that keeps the framing honest. Rendered at the top of the
    /// compliance section, non-negotiably.
    pub fn disclaimer(&self) -> String {
        format!(
            "This mapping shows where the findings in this engagement bear on {} controls. It is an input to a \
             compliance assessment, NOT a compliance determination: only a qualified assessor, over the full \
             environment, can conclude compliance. Absence of a finding against a control is not evidence that the \
             control is met — only that this engagement did not test for a gap there.",
            self.framework_title
        )
    }

    /// A compact Markdown section for the report.
    pub fn to_markdown(&self) -> String {
        let mut s = format!("## Compliance mapping — {}\n\n> {}\n\n", self.framework_title, self.disclaimer());
        if self.controls_with_gaps.is_empty() {
            s.push_str("No confirmed finding in this engagement mapped to a control in this framework.\n");
            return s;
        }
        s.push_str(&format!("{} confirmed finding(s) bear on {} control(s):\n\n", self.tested_finding_count, self.controls_with_gaps.len()));
        s.push_str("| Control | Requirement | Severity | Findings |\n|---|---|---|---|\n");
        for g in &self.controls_with_gaps {
            s.push_str(&format!(
                "| **{}** | {} | {} | {} |\n",
                g.control.id,
                g.control.requirement,
                g.max_severity,
                g.finding_ids.len()
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, cwe: &str, title: &str, sev: &str, validated: bool) -> Finding {
        Finding { id: id.into(), cwe: cwe.into(), title: title.into(), severity: sev.into(), validated, ..Default::default() }
    }

    #[test]
    fn an_injection_finding_maps_to_secure_coding_across_frameworks() {
        let sqli = f("f1", "CWE-89", "SQL injection", "high", true);
        let pci = map_findings(&[sqli.clone()], Framework::PciDss, true);
        assert!(pci.controls_with_gaps.iter().any(|g| g.control.id == "6.2.4"));

        let soc = map_findings(&[sqli.clone()], Framework::Soc2, true);
        assert!(soc.controls_with_gaps.iter().any(|g| g.control.id == "CC7.1"));

        let hipaa = map_findings(&[sqli], Framework::Hipaa, true);
        assert!(hipaa.controls_with_gaps.iter().any(|g| g.control.id.contains("164.312(c)")));
    }

    #[test]
    fn cleartext_maps_to_transmission_security() {
        let ct = f("f2", "CWE-319", "Cleartext transmission", "medium", true);
        let hipaa = map_findings(&[ct.clone()], Framework::Hipaa, true);
        assert!(hipaa.controls_with_gaps.iter().any(|g| g.control.id.contains("164.312(e)")));
        let pci = map_findings(&[ct], Framework::PciDss, true);
        assert!(pci.controls_with_gaps.iter().any(|g| g.control.id == "4.2.1"));
    }

    #[test]
    fn unconfirmed_findings_are_not_control_gaps() {
        let lead = f("f3", "CWE-89", "possible SQLi", "high", false);
        let pci = map_findings(&[lead], Framework::PciDss, true);
        assert!(pci.controls_with_gaps.is_empty(), "a lead is not a gap an auditor should see");
    }

    #[test]
    fn control_gaps_are_ordered_by_severity() {
        let findings = vec![
            f("low", "CWE-1021", "clickjacking", "low", true),
            f("crit", "CWE-89", "SQLi", "critical", true),
        ];
        let pci = map_findings(&findings, Framework::PciDss, true);
        assert_eq!(sev_rank(&pci.controls_with_gaps[0].max_severity), 5, "the critical control gap leads");
    }

    #[test]
    fn the_disclaimer_refuses_to_claim_compliance() {
        let r = map_findings(&[f("f", "CWE-79", "XSS", "high", true)], Framework::PciDss, true);
        let d = r.disclaimer();
        assert!(d.contains("NOT a compliance determination"));
        assert!(d.contains("Absence of a finding"), "silence must not read as compliance");
    }

    #[test]
    fn markdown_renders_a_table_with_the_disclaimer_on_top() {
        let r = map_findings(&[f("f", "CWE-306", "missing auth", "high", true)], Framework::Soc2, true);
        let md = r.to_markdown();
        assert!(md.starts_with("## Compliance mapping"));
        assert!(md.contains("NOT a compliance determination"));
        assert!(md.contains("| Control |"));
    }

    #[test]
    fn framework_parsing_accepts_the_common_spellings() {
        assert_eq!(Framework::parse("pci"), Some(Framework::PciDss));
        assert_eq!(Framework::parse("PCI-DSS"), Some(Framework::PciDss));
        assert_eq!(Framework::parse("soc 2"), Some(Framework::Soc2));
        assert_eq!(Framework::parse("HIPAA"), Some(Framework::Hipaa));
        assert_eq!(Framework::parse("nist"), None);
    }
}
