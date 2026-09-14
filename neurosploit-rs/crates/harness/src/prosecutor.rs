//! The Evidence Prosecutor — a second judge that only asks what was observed.
//!
//! The existing voters answer "is this finding real?", which invites them to
//! judge the whole narrative at once. That is how a proven missing control got
//! deleted for having an overstated headline: one lever, one verdict, and the
//! observation went out with the story.
//!
//! This judge has a narrower brief, and four questions in a fixed order:
//!
//! 1. What exactly did we observe?
//! 2. Which sentence in the finding goes beyond that?
//! 3. What would have to be observed for the claimed impact to become factual?
//! 4. **Can the finding survive if the impact sentence is removed?**
//!
//! The fourth is the one that decides retain-versus-reject, and it is why this
//! judge cannot delete anything. It returns a *minimal claim* — the largest
//! statement the ledger supports — and [`crate::claims`] rebuilds the finding
//! from it. A prosecutor that could also pass sentence would just be the old
//! voter with a better prompt.

use crate::claims::{ClaimSet, EvidenceLedger};
use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// System prompt. Deliberately forbids a verdict: this judge reports what the
/// evidence supports and never whether to keep the finding.
pub const PROSECUTOR_SYS: &str = "You are an evidence prosecutor reviewing a security finding. You do NOT decide whether to keep or drop it — you decide what the recorded evidence actually supports.\n\
Answer four questions, in order:\n\
1. What exactly was OBSERVED? Quote only what appears in the evidence ledger.\n\
2. Which sentences in the finding go BEYOND what was observed? List them verbatim.\n\
3. What would have to be observed for the claimed impact to become factual? Be concrete (a confirmed account, a delivered email, returned data, command output).\n\
4. If every unsupported sentence were removed, would a security-relevant statement remain? If yes, write that statement as `minimal_claim` — the largest claim the evidence fully supports.\n\
Rules: a claim with no supporting evidence id is unsupported no matter how plausible. Absence of a control (no 429, no HSTS, no lockout) IS security-relevant on its own. Do not soften or restate the observation — quote it.\n\
Reply with ONLY this JSON:\n\
{\"observed\":[\"...\"],\"overreaching\":[\"...\"],\"missing_observations\":[\"...\"],\"survives_without_impact\":true|false,\"minimal_claim\":\"...\"}";

/// What the prosecutor found. No verdict field — by design.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProsecutorVerdict {
    /// Quoted observations, from the ledger.
    #[serde(default)]
    pub observed: Vec<String>,
    /// Sentences in the finding that go past the evidence.
    #[serde(default)]
    pub overreaching: Vec<String>,
    /// What would have to be seen for the claimed impact to be a fact.
    #[serde(default)]
    pub missing_observations: Vec<String>,
    /// Does anything security-relevant remain once the overreach is removed?
    #[serde(default)]
    pub survives_without_impact: bool,
    /// The largest fully supported statement.
    #[serde(default)]
    pub minimal_claim: String,
}

impl ProsecutorVerdict {
    /// Did the finding claim more than it showed?
    pub fn overreached(&self) -> bool {
        !self.overreaching.is_empty()
    }

    /// Is this verdict internally consistent?
    ///
    /// A model that says "nothing survives" while handing back a minimal claim
    /// has contradicted itself, and the safe reading is the one that keeps the
    /// observation: the claim is the concrete artifact, the boolean is an
    /// opinion about it.
    pub fn coherent(&self) -> bool {
        !(self.survives_without_impact && self.minimal_claim.trim().is_empty())
    }

    /// The statement the report should make, given everything above.
    pub fn effective_claim(&self, fallback: &str) -> String {
        if !self.minimal_claim.trim().is_empty() {
            self.minimal_claim.trim().to_string()
        } else {
            fallback.to_string()
        }
    }
}

/// Parse the prosecutor's reply, tolerating the fences and preamble models add.
pub fn parse_verdict(text: &str) -> Option<ProsecutorVerdict> {
    let mut candidates: Vec<&str> = Vec::new();
    // A fenced block is the machine-readable answer when there is one.
    let mut rest = text;
    let mut blocks: Vec<&str> = Vec::new();
    while let Some(open) = rest.find("```") {
        let after = &rest[open + 3..];
        let Some(close) = after.find("```") else { break };
        let inner = after[..close].trim_start_matches("json").trim();
        blocks.push(inner);
        rest = &after[close + 3..];
    }
    candidates.extend(blocks.into_iter().rev());
    if let (Some(a), Some(b)) = (text.find('{'), text.rfind('}')) {
        if b > a {
            candidates.push(&text[a..=b]);
        }
    }
    candidates.into_iter().find_map(|c| serde_json::from_str::<ProsecutorVerdict>(c).ok())
}

/// Fold the prosecutor's reading into the finding's claim set.
///
/// It can only ever *narrow*: the impact claim is demoted to potential and the
/// mechanic is replaced by the minimal supported statement. Nothing here can
/// raise a severity, add an impact, or remove a finding — the prosecutor's job
/// is to shrink a claim to its evidence, and a judge able to do more than that
/// would be able to do the damage it was built to prevent.
pub fn apply(set: &mut ClaimSet, v: &ProsecutorVerdict) -> bool {
    if !v.overreached() {
        return false;
    }
    if !v.minimal_claim.trim().is_empty() {
        set.mechanic.claim = v.minimal_claim.trim().to_string();
    }
    if !set.impact.claim.trim().is_empty() {
        // What was asserted as impact becomes potential impact, with the
        // conditions that would make it factual stated alongside it.
        let mut potential = set.impact.claim.trim().to_string();
        if !v.missing_observations.is_empty() {
            potential.push_str(&format!(" (requires: {})", v.missing_observations.join("; ")));
        }
        if set.potential_impact.trim().is_empty() {
            set.potential_impact = potential;
        }
        set.impact.claim = String::new();
        set.impact.evidence.clear();
        set.impact.status = Some(crate::claims::ClaimStatus::Unproven);
    }
    true
}

/// The case file handed to the prosecutor: the finding's own words next to the
/// ledger, so the comparison is possible at all.
pub fn case_file(f: &Finding, set: &ClaimSet) -> String {
    let ledger = if set.ledger.items.is_empty() {
        "(no evidence ledger was recorded)".to_string()
    } else {
        set.ledger
            .items
            .iter()
            .map(|e| format!("{}: {} [{}]", e.id, e.observed, e.source))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "FINDING\ntitle: {}\nseverity: {}\nmechanic claim: {}\nimpact claim: {}\nimpact prose: {}\n\nEVIDENCE LEDGER\n{}\n",
        f.title,
        f.severity,
        set.mechanic.claim,
        set.impact.claim,
        f.impact.chars().take(1200).collect::<String>(),
        ledger
    )
}

/// A ledger built from whatever a finding already carries, for findings that
/// arrived before the claim contract existed. Weaker than an agent-built one —
/// it can only quote what was written — but it lets the prosecutor work on the
/// back catalogue instead of silently skipping it.
pub fn ledger_from_finding(f: &Finding) -> EvidenceLedger {
    let mut l = EvidenceLedger::default();
    if let Some(ev) = &f.evidence_data {
        if let Some(b) = &ev.baseline {
            l.add(&format!("baseline {} {} → {} ({} bytes)", b.method, b.url, b.status, b.len()), "replay");
        }
        if let Some(a) = &ev.attack {
            l.add(&format!("attack {} {} → {} ({} bytes)", a.method, a.url, a.status, a.len()), "replay");
        }
        for (i, r) in ev.repeats.iter().enumerate() {
            l.add(&format!("repeat #{} → {}", i + 1, r.status), "replay");
        }
        if ev.browser_executed {
            l.add("a real browser executed the payload and reported the marker", "browser");
        }
        if ev.callback_received {
            l.add("an out-of-band callback carrying the marker was received", "oob");
        }
    }
    for line in f.evidence.lines().filter(|l| !l.trim().is_empty()).take(20) {
        l.add(line.trim(), "agent");
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{Claim, ClaimStatus};

    fn verdict_json() -> &'static str {
        r#"Here is my analysis.

```json
{"observed":["25 POSTs returned HTTP 302","no Retry-After header"],
 "overreaching":["Reset email flooding against a victim's mailbox"],
 "missing_observations":["a confirmed account","mail delivery observed"],
 "survives_without_impact":true,
 "minimal_claim":"The password-reset endpoint accepts repeated requests with no observable HTTP throttling"}
```"#
    }

    #[test]
    fn the_verdict_is_parsed_out_of_narration_and_fences() {
        let v = parse_verdict(verdict_json()).expect("must parse");
        assert!(v.overreached());
        assert!(v.survives_without_impact);
        assert_eq!(v.observed.len(), 2);
        assert!(v.minimal_claim.contains("no observable HTTP throttling"));
    }

    #[test]
    fn applying_it_narrows_the_claim_and_never_adds_one() {
        let mut set = ClaimSet {
            mechanic: Claim { claim: "Reset email flooding".into(), status: Some(ClaimStatus::Proven), evidence: vec!["E01".into()] },
            impact: Claim { claim: "Victim receives 25 reset emails".into(), status: Some(ClaimStatus::Proven), evidence: vec![] },
            ..Default::default()
        };
        let v = parse_verdict(verdict_json()).unwrap();
        assert!(apply(&mut set, &v));

        assert!(set.mechanic.claim.contains("throttling"), "the mechanic becomes the supported statement");
        assert!(set.impact.claim.is_empty(), "the unsupported impact is removed as a claim");
        assert!(set.potential_impact.contains("Victim receives 25 reset emails"), "and survives as potential");
        assert!(set.potential_impact.contains("confirmed account"), "with what would make it factual");
        assert_eq!(set.impact.status, Some(ClaimStatus::Unproven));
    }

    #[test]
    fn a_finding_that_did_not_overreach_is_left_alone() {
        let mut set = ClaimSet {
            mechanic: Claim { claim: "userB read userA's invoice".into(), status: Some(ClaimStatus::Proven), evidence: vec!["E01".into()] },
            impact: Claim { claim: "cross-tenant data access".into(), status: Some(ClaimStatus::Proven), evidence: vec!["E01".into()] },
            ..Default::default()
        };
        let before = set.clone();
        let v = ProsecutorVerdict { survives_without_impact: true, minimal_claim: "something else".into(), ..Default::default() };
        assert!(!apply(&mut set, &v), "no overreach, nothing to narrow");
        assert_eq!(set, before);
    }

    #[test]
    fn a_self_contradicting_verdict_is_detected() {
        let bad = ProsecutorVerdict { survives_without_impact: true, minimal_claim: "  ".into(), ..Default::default() };
        assert!(!bad.coherent(), "claiming survival while producing no claim is a contradiction");
        let ok = ProsecutorVerdict { survives_without_impact: false, minimal_claim: String::new(), ..Default::default() };
        assert!(ok.coherent());
    }

    #[test]
    fn the_prosecutor_is_not_given_a_verdict_field_to_fill() {
        // The prompt must never invite a keep/drop decision — that is the lever
        // that deleted a proven finding in the first place.
        let p = PROSECUTOR_SYS.to_lowercase();
        assert!(p.contains("you do not decide whether to keep or drop"));
        assert!(!p.contains("\"verdict\""));
        assert!(!p.contains("reject"));
    }

    #[test]
    fn a_case_file_puts_the_claim_next_to_the_ledger() {
        let f = Finding { title: "Flooding".into(), severity: "High".into(), impact: "Attackers flood mailboxes.".into(), ..Default::default() };
        let mut ledger = EvidenceLedger::default();
        ledger.add("POST #1 -> 302", "http");
        let set = ClaimSet { ledger, ..Default::default() };
        let cf = case_file(&f, &set);
        assert!(cf.contains("FINDING") && cf.contains("EVIDENCE LEDGER"));
        assert!(cf.contains("E01: POST #1 -> 302 [http]"));
    }

    #[test]
    fn an_old_finding_still_gets_a_ledger_to_be_judged_against() {
        let f = Finding {
            evidence: "Baseline: 200, 19539 bytes\nBurst of 25 POSTs: all 200, no 429".into(),
            ..Default::default()
        };
        let l = ledger_from_finding(&f);
        assert_eq!(l.items.len(), 2);
        assert_eq!(l.items[0].source, "agent");
        assert!(l.get("E02").is_some());
    }

    #[test]
    fn structured_evidence_produces_a_richer_ledger_than_prose() {
        use crate::validation::{Evidence, Exchange};
        let f = Finding {
            evidence_data: Some(Evidence {
                baseline: Some(Exchange { method: "GET".into(), url: "https://t/x".into(), status: 200, body: "a".into(), ..Default::default() }),
                attack: Some(Exchange { method: "GET".into(), url: "https://t/x?p=1".into(), status: 500, body: "err".into(), ..Default::default() }),
                repeats: vec![Exchange { status: 500, ..Default::default() }],
                browser_executed: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let l = ledger_from_finding(&f);
        let sources: Vec<&str> = l.items.iter().map(|i| i.source.as_str()).collect();
        assert!(sources.contains(&"replay") && sources.contains(&"browser"));
        assert!(l.items.iter().any(|i| i.observed.contains("baseline")));
    }
}
