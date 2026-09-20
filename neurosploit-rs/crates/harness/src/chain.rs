//! Attack paths, derived per vulnerability.
//!
//! The Arena engagement produced 24 findings, a graph with 83 edges — and
//! exactly **one** chain edge, inferred. Two defects caused that, and both are
//! about a step nobody was doing rather than a model reasoning badly:
//!
//! 1. `chains_from` came back empty on every finding. Agents work one
//!    vulnerability at a time and have no view of what the other twelve agents
//!    found, so asking each of them to link its result to findings it never saw
//!    is asking for something it cannot know.
//! 2. The CWE→stage mapping sent 23 of 24 findings to `initial-access` through
//!    its fallback arm. With one populated stage there is no progression to
//!    draw, so the kill-chain view collapsed into a star.
//!
//! So chaining happens **here**, after every agent has reported, where the
//! whole finding set is visible at once. The rules are about *enablement*: what
//! one weakness gives an attacker that another one needs. Account enumeration
//! yields a list of valid identities; absent rate limiting turns that list into
//! guessing attempts; a permissive password policy makes the guessing land.
//! None of those three is severe alone, and the sequence is how accounts get
//! taken over.
//!
//! Every derived edge says it was derived, carries the reason, and never
//! outranks an edge an agent asserted from evidence.

use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// What a weakness *gives* an attacker, or *needs* from one. Chaining is the
/// join between the two: a producer of `ValidIdentities` feeds a consumer of
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Knowledge of which accounts/objects exist.
    ValidIdentities,
    /// Unlimited attempts against a control.
    UnlimitedAttempts,
    /// Guessable or reusable credentials.
    WeakCredentials,
    /// A session or token belonging to someone.
    SessionMaterial,
    /// Internal detail: versions, paths, stack traces, config.
    InternalKnowledge,
    /// Code or queries running on the target.
    CodeExecution,
    /// Reach into systems behind the target.
    InternalNetwork,
    /// Read of data the attacker should not have.
    DataAccess,
    /// Acting as another identity.
    PrivilegedContext,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ValidIdentities => "valid identities",
            Capability::UnlimitedAttempts => "unlimited attempts",
            Capability::WeakCredentials => "weak credentials",
            Capability::SessionMaterial => "session material",
            Capability::InternalKnowledge => "internal knowledge",
            Capability::CodeExecution => "code execution",
            Capability::InternalNetwork => "internal network reach",
            Capability::DataAccess => "data access",
            Capability::PrivilegedContext => "privileged context",
        }
    }
}

fn cwe_num(cwe: &str) -> u32 {
    cwe.chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// What this weakness hands an attacker.
pub fn provides(f: &Finding) -> Vec<Capability> {
    let t = format!("{} {}", f.title, f.evidence).to_lowercase();
    match cwe_num(&f.cwe) {
        // Enumeration / observable discrepancy / timing.
        200 | 203 | 204 | 208 => {
            if t.contains("account") || t.contains("user") || t.contains("email") || t.contains("enumerat") {
                vec![Capability::ValidIdentities, Capability::InternalKnowledge]
            } else {
                vec![Capability::InternalKnowledge]
            }
        }
        209 | 532 | 538 | 540 | 548 | 693 | 1021 => vec![Capability::InternalKnowledge],
        // CRLF / response splitting / host-header: header control feeds cache
        // poisoning and redirect abuse downstream.
        113 | 93 | 644 => vec![Capability::InternalKnowledge, Capability::SessionMaterial],
        // Missing throttling turns any guess into an unlimited one.
        307 | 770 | 799 | 400 => vec![Capability::UnlimitedAttempts],
        // Password policy.
        521 | 261 | 262 | 263 => vec![Capability::WeakCredentials],
        // Credential exposure and transport.
        319 | 522 | 798 | 312 | 256 | 257 | 321 | 614 | 1004 | 1275 | 384 => {
            vec![Capability::SessionMaterial, Capability::WeakCredentials]
        }
        // Injection / execution.
        77 | 78 | 94 | 95 | 502 | 917 | 1336 => vec![Capability::CodeExecution, Capability::DataAccess],
        89 | 943 | 564 => vec![Capability::DataAccess, Capability::WeakCredentials],
        // File read.
        22 | 23 | 35 | 98 | 73 => vec![Capability::DataAccess, Capability::InternalKnowledge],
        // SSRF reaches behind the edge.
        918 | 611 | 776 => vec![Capability::InternalNetwork],
        // Access control and auth bypass hand over someone else's context.
        639 | 862 | 863 | 284 | 285 | 306 | 287 | 288 | 347 | 345 | 566 | 425 => {
            vec![Capability::PrivilegedContext, Capability::DataAccess]
        }
        // XSS runs in a victim's session.
        79 | 80 | 83 | 87 => vec![Capability::SessionMaterial],
        _ => vec![],
    }
}

/// What an attacker must already have for this weakness to be worth much.
pub fn requires(f: &Finding) -> Vec<Capability> {
    match cwe_num(&f.cwe) {
        // Guessing needs someone to guess against.
        307 | 770 | 799 => vec![Capability::ValidIdentities],
        // A weak password matters once you can try it, repeatedly.
        521 | 261 | 262 | 263 => vec![Capability::ValidIdentities, Capability::UnlimitedAttempts],
        // Taking over an account needs credentials or a session.
        287 | 288 | 384 | 640 => vec![Capability::WeakCredentials],
        // Reading another user's object needs to know it exists.
        639 | 566 | 425 => vec![Capability::ValidIdentities],
        // Stealing a session needs somewhere to steal it from.
        614 | 1004 | 1275 => vec![Capability::SessionMaterial],
        // Escalation needs a foothold.
        269 | 250 | 668 => vec![Capability::PrivilegedContext],
        // Second-order SQLi: the stored payload only fires on the (often
        // privileged) trigger page, so it needs that context to be reached.
        564 => vec![Capability::PrivilegedContext],
        _ => vec![],
    }
}

/// One derived link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub from: usize,
    pub to: usize,
    /// The capability that makes the link real.
    pub via: Capability,
    pub reason: String,
    /// Derived rather than asserted by an agent.
    pub inferred: bool,
}

/// Derive enablement links across a finding set.
///
/// Only same-host links are drawn: two weaknesses on unrelated assets do not
/// chain just because their classes fit, and a graph that claims they do is
/// worse than one with no edges.
pub fn derive_links(findings: &[Finding]) -> Vec<Link> {
    let mut links = Vec::new();
    for (i, producer) in findings.iter().enumerate() {
        let gives = provides(producer);
        if gives.is_empty() {
            continue;
        }
        for (j, consumer) in findings.iter().enumerate() {
            if i == j {
                continue;
            }
            if host_of(&producer.endpoint) != host_of(&consumer.endpoint) {
                continue;
            }
            // A weakness does not enable itself. CWE-614 both yields session
            // material and needs it, so on a real run its duplicates chained to
            // each other in a circle — an "attack path" from a cookie flag to
            // the same cookie flag.
            if cwe_num(&producer.cwe) == cwe_num(&consumer.cwe) {
                continue;
            }
            if !producer.id.is_empty() && producer.id == consumer.id {
                continue;
            }
            for need in requires(consumer) {
                if gives.contains(&need) {
                    links.push(Link {
                        from: i,
                        to: j,
                        via: need,
                        reason: format!(
                            "{} yields {}, which {} needs to be worth exploiting",
                            short(&producer.title),
                            need.as_str(),
                            short(&consumer.title)
                        ),
                        inferred: true,
                    });
                }
            }
        }
    }
    links
}

/// One finding's own attack path: what leads to it, and what it leads to.
///
/// This is the per-vulnerability view — a reader looking at "weak password
/// policy" wants to know it only matters because enumeration produced a list
/// and nothing throttles the guessing, not to hunt for that in a global graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AttackPath {
    /// Findings that must come first, nearest cause last.
    pub preceded_by: Vec<PathStep>,
    /// What this one opens up.
    pub enables: Vec<PathStep>,
    /// The narrative, ready to print.
    pub narrative: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathStep {
    pub finding_id: String,
    pub title: String,
    pub via: Capability,
    pub severity: String,
}

/// Build the path around one finding.
pub fn path_for(index: usize, findings: &[Finding], links: &[Link]) -> AttackPath {
    let step = |k: usize, via: Capability| PathStep {
        finding_id: findings[k].id.clone(),
        title: findings[k].title.clone(),
        via,
        severity: findings[k].severity.clone(),
    };
    let preceded_by: Vec<PathStep> = links.iter().filter(|l| l.to == index).map(|l| step(l.from, l.via)).collect();
    let enables: Vec<PathStep> = links.iter().filter(|l| l.from == index).map(|l| step(l.to, l.via)).collect();

    let me = &findings[index];
    let mut narrative = String::new();
    if preceded_by.is_empty() && enables.is_empty() {
        narrative = format!("{} stands alone in this engagement — nothing else found feeds it, and it feeds nothing else.", short(&me.title));
    } else {
        if !preceded_by.is_empty() {
            narrative.push_str(&format!(
                "Reaching this needs {}: {}. ",
                preceded_by.iter().map(|s| s.via.as_str()).collect::<Vec<_>>().join(" and "),
                preceded_by.iter().map(|s| short(&s.title)).collect::<Vec<_>>().join("; ")
            ));
        }
        if !enables.is_empty() {
            narrative.push_str(&format!(
                "It then supplies {} to {}.",
                enables.iter().map(|s| s.via.as_str()).collect::<Vec<_>>().join(" and "),
                enables.iter().map(|s| short(&s.title)).collect::<Vec<_>>().join("; ")
            ));
        }
    }
    AttackPath { preceded_by, enables, narrative }
}

/// Fill in `chains_from` where agents left it empty.
///
/// An agent sees one vulnerability and cannot link to findings it never saw, so
/// asking it to was always going to return nothing. Derived links are written
/// only into findings that have none — an asserted chain is evidence and is
/// never overwritten by a rule.
pub fn apply_links(findings: &mut [Finding]) -> usize {
    let links = derive_links(findings);
    // Ids are collected first: `chains_from` holds ids, and writing into one
    // finding while reading another's id needs the reads done up front.
    let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
    let mut written = 0usize;
    for (i, f) in findings.iter_mut().enumerate() {
        if !f.chains_from.is_empty() {
            continue;
        }
        let sources: Vec<String> = links
            .iter()
            .filter(|l| l.to == i)
            .map(|l| l.from)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|k| ids.get(k).cloned().filter(|s| !s.is_empty()))
            .collect();
        if !sources.is_empty() {
            f.chains_from = sources;
            written += 1;
        }
    }
    written
}

/// Drop chain links that violate the invariants, wherever they came from.
///
/// `apply_links` only fills an empty `chains_from`, which is right — an
/// asserted chain is evidence. But a link written by an EARLIER version of
/// these rules is not evidence, and on a rebuild it would survive forever: a
/// real report kept "cookie flag ← the same cookie flag" through two rebuilds
/// because nothing was allowed to touch it. A repair pass removes links that
/// cannot be true regardless of who wrote them: a finding citing itself, a
/// weakness citing its own class, and an id that names nothing.
pub fn repair(findings: &mut [Finding]) -> usize {
    let by_id: std::collections::HashMap<String, (String, String)> = findings
        .iter()
        .filter(|f| !f.id.is_empty())
        .map(|f| (f.id.clone(), (f.cwe.clone(), f.endpoint.clone())))
        .collect();
    let mut removed = 0usize;
    for f in findings.iter_mut() {
        let before = f.chains_from.len();
        let me_cwe = cwe_num(&f.cwe);
        let me_id = f.id.clone();
        let me_host = host_of(&f.endpoint);
        f.chains_from.retain(|src| {
            if *src == me_id {
                return false;
            }
            match by_id.get(src) {
                // An id nobody answers to is a dangling reference, not a chain.
                None => false,
                Some((cwe, endpoint)) => cwe_num(cwe) != me_cwe && host_of(endpoint) == me_host,
            }
        });
        f.chains_from.sort();
        f.chains_from.dedup();
        removed += before - f.chains_from.len();
    }
    removed
}

fn host_of(endpoint: &str) -> String {
    crate::scope::host_of(endpoint)
}

fn short(s: &str) -> String {
    let t: String = s.chars().take(64).collect();
    if s.chars().count() > 64 { format!("{t}…") } else { t }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, cwe: &str, title: &str, sev: &str) -> Finding {
        Finding {
            id: id.into(),
            cwe: cwe.into(),
            title: title.into(),
            severity: sev.into(),
            endpoint: "https://arenahockeypara.com.br/Account/Login".into(),
            ..Default::default()
        }
    }

    /// The Arena chain, which the engagement found as three unrelated Mediums.
    fn arena() -> Vec<Finding> {
        vec![
            f("enum", "CWE-204", "Account enumeration via verbose /Account/Register response", "Medium"),
            f("rate", "CWE-307", "No rate limiting or account lockout on /Account/Login", "Medium"),
            f("pw", "CWE-521", "Weak password policy — breached passwords accepted", "Medium"),
        ]
    }

    #[test]
    fn enumeration_feeds_brute_force_which_feeds_weak_passwords() {
        let links = derive_links(&arena());
        let via = |from: usize, to: usize| links.iter().find(|l| l.from == from && l.to == to).map(|l| l.via);
        assert_eq!(via(0, 1), Some(Capability::ValidIdentities), "enumeration gives the list brute force needs");
        assert_eq!(via(0, 2), Some(Capability::ValidIdentities));
        assert_eq!(via(1, 2), Some(Capability::UnlimitedAttempts), "no throttling is what makes a weak password land");
    }

    #[test]
    fn a_per_vulnerability_path_reads_as_a_sentence() {
        let fs = arena();
        let links = derive_links(&fs);
        let p = path_for(2, &fs, &links); // the weak password policy
        assert_eq!(p.preceded_by.len(), 2, "{:?}", p);
        assert!(p.enables.is_empty());
        assert!(p.narrative.contains("valid identities"));
        assert!(p.narrative.contains("unlimited attempts"));
    }

    #[test]
    fn a_finding_that_chains_with_nothing_says_so() {
        let fs = vec![f("hsts", "CWE-319", "Missing HSTS", "Low")];
        let links = derive_links(&fs);
        let p = path_for(0, &fs, &links);
        assert!(p.narrative.contains("stands alone"), "{}", p.narrative);
    }

    #[test]
    fn chains_from_is_filled_only_where_the_agent_left_it_empty() {
        let mut fs = arena();
        fs[1].chains_from = vec!["asserted-by-an-agent".into()];
        let written = apply_links(&mut fs);
        assert_eq!(written, 1, "only the finding with no asserted chain is written");
        assert_eq!(fs[1].chains_from, vec!["asserted-by-an-agent"], "an asserted chain is evidence and is never overwritten");
        assert_eq!(fs[2].chains_from, vec!["enum", "rate"]);
        assert!(fs[0].chains_from.is_empty(), "the first step has nothing before it");
    }

    #[test]
    fn weaknesses_on_different_hosts_do_not_chain() {
        let mut fs = arena();
        fs[1].endpoint = "https://other.example.org/login".into();
        let links = derive_links(&fs);
        assert!(
            !links.iter().any(|l| (l.from == 1 || l.to == 1)),
            "classes fitting is not a reason to chain across unrelated assets"
        );
    }

    #[test]
    fn a_cookie_without_secure_chains_from_whatever_produced_the_session() {
        let fs = vec![
            f("xss", "CWE-79", "Reflected XSS in search", "Medium"),
            f("cookie", "CWE-614", "Session cookie without Secure", "Low"),
        ];
        let links = derive_links(&fs);
        assert_eq!(links.iter().find(|l| l.from == 0 && l.to == 1).map(|l| l.via), Some(Capability::SessionMaterial));
    }

    /// CWE-614 yields session material and also needs it. On a real run its
    /// duplicates chained to each other, producing an "attack path" from a
    /// cookie flag to the same cookie flag.
    #[test]
    fn a_weakness_class_never_chains_to_itself() {
        let fs = vec![
            f("c1", "CWE-614", "Antiforgery cookie without Secure", "Low"),
            f("c2", "CWE-614 (Sensitive Cookie…)", "Antiforgery cookie set without Secure over HTTPS", "Low"),
        ];
        assert!(derive_links(&fs).is_empty(), "one cookie flag does not enable another");
    }

    #[test]
    fn repair_removes_links_that_cannot_be_true() {
        let mut fs = arena();
        fs[0].id = "enum".into();
        // Everything a stale rule could have written.
        fs[1].chains_from = vec!["rate".into(), "enum".into(), "ghost-id".into(), "enum".into()];
        fs[2].chains_from = vec!["pw".into()];
        let removed = repair(&mut fs);
        assert_eq!(fs[1].chains_from, vec!["enum"], "self-reference, dangling id and duplicate all go");
        assert!(fs[2].chains_from.is_empty(), "a finding citing itself keeps nothing");
        assert_eq!(removed, 4);
    }

    #[test]
    fn repair_drops_a_link_to_the_same_weakness_class() {
        let mut fs = vec![
            f("c1", "CWE-614", "Cookie without Secure", "Low"),
            f("c2", "CWE-614", "Cookie without Secure over HTTPS", "Low"),
        ];
        fs[1].chains_from = vec!["c1".into()];
        assert_eq!(repair(&mut fs), 1);
        assert!(fs[1].chains_from.is_empty());
    }

    #[test]
    fn repair_keeps_a_legitimate_link() {
        let mut fs = arena();
        fs[1].chains_from = vec!["enum".into()];
        assert_eq!(repair(&mut fs), 0);
        assert_eq!(fs[1].chains_from, vec!["enum"]);
    }

    #[test]
    fn a_weakness_with_nothing_to_give_produces_no_links() {
        let fs = vec![f("x", "CWE-99999", "Something unmapped", "Info"), f("rate", "CWE-307", "No rate limiting", "Medium")];
        assert!(derive_links(&fs).is_empty(), "an unmapped class must not invent enablement");
    }
}
