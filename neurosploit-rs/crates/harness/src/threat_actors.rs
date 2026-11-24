//! Threat actor similarity — mapping the techniques a run observed to the
//! public TTP profiles of known intrusion sets.
//!
//! A client who reads "T1190, T1059, T1078" in a report has to do the next
//! step by hand: "who operates like this, and what do they do *next*?" This
//! module does that step. It takes the MITRE ATT&CK technique ids already
//! stamped on each finding (by `attack_graph::enrich` or the agent) and
//! overlaps them against a small, curated, offline catalogue of well-known
//! groups — the same kind of TTP→group mapping Microsoft, Google GTIG and the
//! FBI publish in their threat reports.
//!
//! ## The honesty line, drawn hard
//!
//! Technique overlap is **not attribution**. T1190 (exploit a public-facing
//! application) is used by essentially every intrusion set on earth; a web
//! pentest's technique profile will overlap with dozens of groups and proves
//! nothing about who attacked anyone. What the overlap *is* useful for:
//!
//! - prioritising detection engineering against the TTPs a matching group is
//!   known to chain *after* the ones this engagement proved possible;
//! - giving the report reader a pointer to public reporting about actors who
//!   favour the same weaknesses.
//!
//! Every output therefore says "similarity", never "attribution", and the
//! section carries that caveat in words, not just in a footnote.

use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// A curated, public-profile intrusion set. `techniques` are base ATT&CK ids
/// ("T1190"); sub-techniques observed on findings are collapsed to their base
/// before matching, so "T1003.001" matches an actor listed with "T1003".
struct ActorProfile {
    name: &'static str,
    aliases: &'static [&'static str],
    /// One-line public characterisation (motivation/nexus).
    profile: &'static str,
    techniques: &'static [&'static str],
}

/// The catalogue. Technique lists are the *core* of each group's public
/// MITRE ATT&CK profile, not an exhaustive dump — a small accurate set ranks
/// better than a large noisy one.
const ACTORS: &[ActorProfile] = &[
    ActorProfile {
        name: "APT29",
        aliases: &["Cozy Bear", "Midnight Blizzard", "NOBELIUM"],
        profile: "State-nexus espionage; cloud identity and valid-account abuse.",
        techniques: &["T1190", "T1078", "T1566", "T1059", "T1003", "T1027", "T1021", "T1041", "T1071", "T1552", "T1105"],
    },
    ActorProfile {
        name: "APT28",
        aliases: &["Fancy Bear", "Forest Blizzard"],
        profile: "State-nexus espionage; credential harvesting and edge-device exploitation.",
        techniques: &["T1566", "T1190", "T1078", "T1110", "T1059", "T1003", "T1021", "T1041", "T1560", "T1027"],
    },
    ActorProfile {
        name: "Lazarus Group",
        aliases: &["Diamond Sleet", "Labyrinth Chollima"],
        profile: "State-nexus financial theft and espionage; supply-chain and destructive follow-on.",
        techniques: &["T1190", "T1566", "T1059", "T1055", "T1003", "T1027", "T1041", "T1105", "T1486", "T1565", "T1195"],
    },
    ActorProfile {
        name: "APT41",
        aliases: &["Brass Typhoon", "Double Dragon", "Winnti"],
        profile: "State-nexus espionage plus financially motivated side operations; web shells on edge apps.",
        techniques: &["T1190", "T1505", "T1059", "T1003", "T1021", "T1046", "T1078", "T1105", "T1195", "T1552"],
    },
    ActorProfile {
        name: "Volt Typhoon",
        aliases: &["BRONZE SILHOUETTE", "Vanguard Panda"],
        profile: "State-nexus pre-positioning on critical infrastructure; living-off-the-land.",
        techniques: &["T1190", "T1078", "T1003", "T1059", "T1021", "T1046", "T1036", "T1027"],
    },
    ActorProfile {
        name: "Scattered Spider",
        aliases: &["UNC3944", "Octo Tempest"],
        profile: "Financially motivated; social engineering, MFA fatigue, cloud and SaaS identity abuse.",
        techniques: &["T1078", "T1656", "T1621", "T1566", "T1110", "T1557", "T1552", "T1528", "T1486", "T1021"],
    },
    ActorProfile {
        name: "FIN7",
        aliases: &["Carbon Spider", "Sangria Tempest"],
        profile: "Financially motivated; carding and ransomware adjacency, heavy phishing initial access.",
        techniques: &["T1566", "T1059", "T1055", "T1003", "T1021", "T1486", "T1078", "T1027", "T1105"],
    },
    ActorProfile {
        name: "TA505",
        aliases: &["Graceful Spider", "Hive0065"],
        profile: "Financially motivated; mass-malspam and managed-cl0p-ransomware precursor access.",
        techniques: &["T1566", "T1190", "T1059", "T1486", "T1490", "T1048", "T1105", "T1078"],
    },
    ActorProfile {
        name: "Wizard Spider",
        aliases: &["Conti", "TrickBot", "DEV-0193"],
        profile: "Financially motivated ransomware; domain-wide encryption after quiet lateral spread.",
        techniques: &["T1486", "T1566", "T1059", "T1003", "T1021", "T1078", "T1490", "T1489", "T1105"],
    },
    ActorProfile {
        name: "Cl0p",
        aliases: &["FIN11 adjacency", "Lace Tempest"],
        profile: "Financially motivated extortion; mass exploitation of file-transfer and edge appliances.",
        techniques: &["T1190", "T1059", "T1486", "T1490", "T1048", "T1105", "T1078"],
    },
    ActorProfile {
        name: "Kimsuky",
        aliases: &["Emerald Sleet", "Velvet Chollima"],
        profile: "State-nexus espionage; credential phishing and browser/session theft.",
        techniques: &["T1566", "T1059", "T1552", "T1560", "T1071", "T1078", "T1539"],
    },
    ActorProfile {
        name: "OilRig",
        aliases: &["APT34", "Hazel Sandstorm"],
        profile: "State-nexus espionage against government and energy; web shells and DNS tunnelling.",
        techniques: &["T1566", "T1190", "T1505", "T1059", "T1078", "T1552", "T1027", "T1071"],
    },
    // Documented by Microsoft / Google GTIG / CrowdStrike in 2026 reporting on
    // agentic-framework-driven intrusions (ARTEX). Included because a modern
    // engagement increasingly *looks* like these clusters: machine-tempo,
    // identity-first, cloud-heavy.
    ActorProfile {
        name: "Storm-0940 / UNC7228",
        aliases: &["per Microsoft", "UNC7228 per GTIG"],
        profile: "Suspected state-nexus espionage; OAuth app consent abuse and cloud permission mapping at machine tempo.",
        techniques: &["T1078", "T1195", "T1199", "T1098", "T1528", "T1555", "T1087", "T1580", "T1595", "T1110", "T1552", "T1606"],
    },
    ActorProfile {
        name: "VAPOR PANDA",
        aliases: &["per CrowdStrike"],
        profile: "Suspected state-nexus espionage; web-shell drops, Kerberoasting and DCSync after rapid web-app compromise.",
        techniques: &["T1595", "T1190", "T1505", "T1003", "T1558", "T1110", "T1046", "T1071", "T1059", "T1552", "T1105"],
    },
];

/// One group's overlap with what the run observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorMatch {
    pub name: String,
    pub aliases: Vec<String>,
    pub profile: String,
    /// Technique ids present in BOTH the run and the group's public profile.
    pub matched_techniques: Vec<String>,
    /// matched / size of the group's catalogue entry.
    pub coverage: f64,
    /// Sørensen–Dice against the run's whole technique set — keeps a group
    /// that matches 2 of 2 ahead of one that matches 2 of 12.
    pub score: f64,
}

/// Collapse a technique id to its base: "T1059.007" -> "T1059".
fn base(id: &str) -> &str {
    id.split('.').next().unwrap_or(id).trim()
}

/// The deduplicated set of base technique ids a run's findings carry.
fn run_techniques(findings: &[Finding]) -> Vec<String> {
    let mut set: Vec<String> = Vec::new();
    for f in findings {
        let b = base(&f.mitre);
        if b.starts_with('T') && b.len() >= 5 && !set.iter().any(|t| t == b) {
            set.push(b.to_string());
        }
    }
    set
}

/// Rank the catalogue against the run's observed techniques.
///
/// A single shared technique is noise — everything shares T1190 with
/// everything else — so a match needs at least two overlapping techniques to
/// be reported at all.
pub fn match_actors(findings: &[Finding]) -> Vec<ActorMatch> {
    let run = run_techniques(findings);
    if run.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<ActorMatch> = ACTORS
        .iter()
        .filter_map(|a| {
            let matched: Vec<String> = a
                .techniques
                .iter()
                .filter(|t| run.iter().any(|r| r == *t))
                .map(|t| t.to_string())
                .collect();
            if matched.len() < 2 {
                return None;
            }
            let coverage = matched.len() as f64 / a.techniques.len() as f64;
            let score = 2.0 * matched.len() as f64 / (a.techniques.len() + run.len()) as f64;
            Some(ActorMatch {
                name: a.name.into(),
                aliases: a.aliases.iter().map(|s| s.to_string()).collect(),
                profile: a.profile.into(),
                matched_techniques: matched,
                coverage,
                score,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.matched_techniques
            .len()
            .cmp(&a.matched_techniques.len())
            .then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
    });
    out.truncate(5);
    out
}

/// The report section. Empty string when there is nothing defensible to say —
/// no section at all is better than a section that reads as attribution on
/// the strength of one shared technique.
pub fn markdown(findings: &[Finding]) -> String {
    let matches = match_actors(findings);
    if matches.is_empty() {
        return String::new();
    }
    let mut s = String::from("## Threat actor similarity (TTP overlap)\n\n");
    s.push_str("The techniques proven in this engagement overlap with the public TTP profiles of the \
        intrusion sets below. **This is similarity, not attribution** — the techniques listed are in \
        broad use, and overlap says nothing about who would attack this asset. It is useful as a \
        prioritisation aid: the matching groups are documented to chain further techniques on top of \
        the ones proven here, which is where detection and hardening effort should go next.\n\n");
    s.push_str("| Group | Also known as | Profile | Shared techniques | Coverage |\n");
    s.push_str("|-------|---------------|---------|-------------------|----------|\n");
    for m in &matches {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {:.0}% |\n",
            m.name.replace('|', "\\|"),
            m.aliases.join(", ").replace('|', "\\|"),
            m.profile.replace('|', "\\|"),
            m.matched_techniques.join(", "),
            m.coverage * 100.0
        ));
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(mitre: &str) -> Finding {
        Finding { mitre: mitre.into(), ..Default::default() }
    }

    #[test]
    fn no_techniques_no_section() {
        let fs = vec![Finding::default()];
        assert!(match_actors(&fs).is_empty());
        assert!(markdown(&fs).is_empty());
    }

    #[test]
    fn one_shared_technique_is_noise_and_reports_nothing() {
        // T1190 alone matches nearly every group; it must not produce a section.
        let fs = vec![finding("T1190")];
        assert!(match_actors(&fs).is_empty(), "a single overlap must stay silent");
    }

    #[test]
    fn sub_techniques_collapse_to_their_base() {
        let fs = vec![finding("T1003.001"), finding("T1059.007"), finding("T1190")];
        let m = match_actors(&fs);
        assert!(!m.is_empty());
        let apt41 = m.iter().find(|x| x.name == "APT41").expect("APT41 uses all three base ids");
        assert!(apt41.matched_techniques.contains(&"T1003".to_string()));
    }

    #[test]
    fn an_identity_first_profile_surfaces_the_identity_first_groups() {
        let fs = vec![
            finding("T1078"), finding("T1098"), finding("T1528"), finding("T1555"),
            finding("T1580"), finding("T1110"),
        ];
        let m = match_actors(&fs);
        assert_eq!(m.first().map(|x| x.name.as_str()), Some("Storm-0940 / UNC7228"),
            "the densest overlap should rank first: {m:?}");
    }

    #[test]
    fn the_section_says_similarity_not_attribution() {
        let fs = vec![finding("T1190"), finding("T1505"), finding("T1059"), finding("T1078")];
        let md = markdown(&fs);
        assert!(md.contains("similarity, not attribution"), "{md}");
        assert!(md.contains("| Group |"));
    }

    #[test]
    fn ranking_prefers_more_matched_then_better_score() {
        let fs = vec![finding("T1486"), finding("T1490"), finding("T1048"), finding("T1105"), finding("T1190"), finding("T1059")];
        let m = match_actors(&fs);
        for w in m.windows(2) {
            assert!(w[0].matched_techniques.len() >= w[1].matched_techniques.len());
        }
        assert!(m.len() <= 5);
    }
}
