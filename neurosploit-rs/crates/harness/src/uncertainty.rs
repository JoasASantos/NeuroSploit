//! The uncertainty engine — deciding whether to judge or to go look again.
//!
//! Everything upstream produces a verdict and stops. When the evidence is thin
//! the answer is `needs-review`, which hands a human the same thin evidence and
//! asks them to do the collecting. That is the wrong party: the harness still
//! has the target, the session and the tooling; the reviewer has a paragraph.
//!
//! So before the deterministic validators run, each candidate is scored for how
//! *undecided* it is, and a finding whose uncertainty is high and whose missing
//! evidence is **obtainable** gets one more collection round instead of a
//! verdict.
//!
//! ```text
//!                    VOTES
//!                      │
//!              UNCERTAINTY ENGINE
//!                 ╱          ╲
//!        low uncertainty   high uncertainty
//!              │                  │
//!           validate      gather more evidence ──┐
//!                                   ▲            │
//!                                   └────────────┘
//!                                   (bounded retries)
//! ```
//!
//! Two rules keep the loop from becoming a treadmill:
//!
//! - **Only obtainable gaps trigger a round.** "No confirmed account exists"
//!   is not something another request fixes; "no baseline was captured" is.
//!   Asking again for what the engagement cannot reach burns budget and changes
//!   nothing.
//! - **Attempts are bounded and recorded.** After the cap the finding is judged
//!   on what exists, with the gap named in its review reason — an honest
//!   `needs-review` that says exactly what was missing beats a silent one.

use crate::types::Finding;
use crate::validation::{Evidence, Verdict};
use serde::{Deserialize, Serialize};

/// What is missing, and whether the harness can still get it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "gap", content = "detail")]
pub enum Gap {
    /// No unmodified comparison was recorded.
    Baseline,
    /// The difference was seen once; the class needs it to reproduce.
    Reproduction(usize),
    /// A class decided by execution has no browser observation.
    BrowserRun,
    /// An access-control claim has only one identity.
    SecondIdentity,
    /// A blind class has no out-of-band channel.
    OutOfBandChannel,
    /// The harness cannot reach what the claim needs (no confirmed account, no
    /// authenticated session). Recorded, never retried.
    Unreachable(String),
}

impl Gap {
    /// Can another collection round close this?
    ///
    /// The distinction is the whole point: a missing baseline is one request
    /// away, a confirmed account behind an email gate is not, and retrying the
    /// second forever is how a budget disappears.
    pub fn obtainable(&self) -> bool {
        !matches!(self, Gap::Unreachable(_))
    }
    pub fn describe(&self) -> String {
        match self {
            Gap::Baseline => "no baseline was captured, so no difference can be attributed to the payload".into(),
            Gap::Reproduction(n) => format!("the difference was observed {n} time(s); this class needs it to reproduce"),
            Gap::BrowserRun => "the class is decided by execution and no browser has run the payload".into(),
            Gap::SecondIdentity => "an access-control claim needs the same resource requested as another identity".into(),
            Gap::OutOfBandChannel => "a blind class needs a channel the harness controls to observe the callback".into(),
            Gap::Unreachable(w) => format!("out of reach for this assessment: {w}"),
        }
    }
}

/// How undecided a candidate is, and why.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Assessment {
    /// 0.0 = decided, 1.0 = nothing to go on.
    pub uncertainty: f64,
    pub gaps: Vec<Gap>,
}

impl Assessment {
    /// Gaps another round could actually close.
    pub fn actionable(&self) -> Vec<&Gap> {
        self.gaps.iter().filter(|g| g.obtainable()).collect()
    }
    /// Should the harness collect again rather than judge now?
    pub fn wants_more_evidence(&self, threshold: f64) -> bool {
        self.uncertainty >= threshold && !self.actionable().is_empty()
    }
}

/// Score a candidate's uncertainty from what its class needs versus what it has.
///
/// This is deliberately mechanical. The question "how sure are we?" answered by
/// a model is another opinion; answered by counting missing artifacts it is a
/// measurement.
pub fn assess(f: &Finding) -> Assessment {
    let Some(v) = crate::validation::validator_for(f) else {
        // No deterministic rule owns this class, so more evidence would not
        // change the outcome — the engine has nothing to apply to it.
        return Assessment {
            uncertainty: 0.5,
            gaps: vec![Gap::Unreachable(format!("no deterministic validator owns {}", if f.cwe.is_empty() { "this class" } else { &f.cwe }))],
        };
    };
    let name = v.name();
    let ev = f.evidence_data.clone().unwrap_or_default();
    let mut gaps: Vec<Gap> = Vec::new();

    let needs_diff = matches!(name, "sqli" | "ssti" | "lfi" | "exposure" | "session");
    if needs_diff && ev.baseline.is_none() {
        gaps.push(Gap::Baseline);
    }
    if name == "sqli" && ev.repeats.len() < 2 {
        gaps.push(Gap::Reproduction(ev.repeats.len()));
    }
    if name == "xss" && !ev.browser_executed {
        gaps.push(Gap::BrowserRun);
    }
    if matches!(name, "idor" | "authz" | "jwt") && (ev.identity_a.is_none() || ev.identity_b.is_none()) {
        gaps.push(Gap::SecondIdentity);
    }
    if matches!(name, "ssrf" | "xxe") && !ev.callback_received && !ev.marker_observed {
        gaps.push(Gap::OutOfBandChannel);
    }
    if name == "ratelimit" && ev.repeats.len() < 20 {
        gaps.push(Gap::Reproduction(ev.repeats.len()));
    }

    // A verdict already reached lowers uncertainty regardless of what is
    // missing: the engine is not undecided about a finding it rejected.
    let decided = matches!(
        crate::validation::judge(f, f.evidence_data.as_ref()),
        Verdict::Confirmed(_) | Verdict::Rejected(_)
    );
    let uncertainty = if decided {
        0.0
    } else if gaps.is_empty() {
        // Undecided with nothing identified as missing is its own signal.
        0.6
    } else {
        (0.4 + 0.2 * gaps.len() as f64).min(1.0)
    };
    Assessment { uncertainty, gaps }
}

/// What a collection round should try next, in the order worth trying.
///
/// Cheap and deterministic first: a baseline is one request, a browser run
/// costs seconds and a process. Putting the expensive step first would spend
/// the budget before the cheap one had a chance to decide it.
pub fn next_actions(a: &Assessment) -> Vec<Action> {
    let mut acts: Vec<Action> = a
        .actionable()
        .into_iter()
        .map(|g| match g {
            Gap::Baseline => Action::CaptureBaseline,
            Gap::Reproduction(_) => Action::Repeat,
            Gap::SecondIdentity => Action::RequestAsSecondIdentity,
            Gap::BrowserRun => Action::RunBrowser,
            Gap::OutOfBandChannel => Action::OpenOobChannel,
            Gap::Unreachable(_) => Action::None,
        })
        .filter(|a| *a != Action::None)
        .collect();
    acts.sort_by_key(|a| a.cost());
    acts.dedup();
    acts
}

/// A concrete collection step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    CaptureBaseline,
    Repeat,
    RequestAsSecondIdentity,
    RunBrowser,
    OpenOobChannel,
    None,
}

impl Action {
    /// Rough relative cost, used only for ordering.
    pub fn cost(self) -> u8 {
        match self {
            Action::CaptureBaseline => 1,
            Action::Repeat => 2,
            Action::RequestAsSecondIdentity => 3,
            Action::RunBrowser => 6,
            Action::OpenOobChannel => 8,
            Action::None => 9,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Action::CaptureBaseline => "capture a baseline",
            Action::Repeat => "repeat the attack request",
            Action::RequestAsSecondIdentity => "request the same resource as another identity",
            Action::RunBrowser => "run the payload in a real browser",
            Action::OpenOobChannel => "open an out-of-band channel",
            Action::None => "nothing",
        }
    }
}

/// Bounded retry budget for one engagement.
#[derive(Debug)]
pub struct Rounds {
    max_per_finding: usize,
    spent: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl Default for Rounds {
    fn default() -> Self {
        // Two extra rounds: the first closes the common gap (a missing baseline
        // or a single observation), the second catches what the first revealed.
        // Beyond that the finding is not undecided, it is unprovable here.
        Rounds { max_per_finding: 2, spent: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }
}

impl Rounds {
    pub fn with_max(max_per_finding: usize) -> Self {
        Rounds { max_per_finding, ..Default::default() }
    }

    /// Take a round for this finding, if any remain.
    pub fn take(&self, finding_id: &str) -> bool {
        let mut spent = match self.spent.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let n = spent.entry(finding_id.to_string()).or_insert(0);
        if *n >= self.max_per_finding {
            return false;
        }
        *n += 1;
        true
    }

    pub fn spent(&self, finding_id: &str) -> usize {
        self.spent.lock().map(|s| s.get(finding_id).copied().unwrap_or(0)).unwrap_or(0)
    }
}

/// Record why a finding is being judged on incomplete evidence.
///
/// A `needs-review` that does not say what was missing sends a human looking
/// for it from scratch.
pub fn note_gaps(f: &mut Finding, a: &Assessment) {
    if a.gaps.is_empty() {
        return;
    }
    let detail = a.gaps.iter().map(|g| g.describe()).collect::<Vec<_>>().join("; ");
    f.review_reason = if f.review_reason.trim().is_empty() {
        format!("judged on incomplete evidence — {detail}")
    } else {
        format!("{} · missing: {detail}", f.review_reason.trim())
    };
}

/// Merge freshly collected artifacts into a finding, without discarding what
/// was already there.
pub fn merge_evidence(f: &mut Finding, fresh: Evidence) {
    let mut ev = f.evidence_data.take().unwrap_or_default();
    if ev.baseline.is_none() {
        ev.baseline = fresh.baseline;
    }
    if ev.attack.is_none() {
        ev.attack = fresh.attack;
    }
    ev.repeats.extend(fresh.repeats);
    if ev.identity_a.is_none() {
        ev.identity_a = fresh.identity_a;
    }
    if ev.identity_b.is_none() {
        ev.identity_b = fresh.identity_b;
    }
    if ev.marker.is_empty() {
        ev.marker = fresh.marker;
    }
    // Observations are monotonic: a later run that did not see the marker does
    // not unsee an earlier one that did.
    ev.marker_observed |= fresh.marker_observed;
    ev.browser_executed |= fresh.browser_executed;
    ev.callback_received |= fresh.callback_received;
    ev.notes.extend(fresh.notes);
    f.evidence_data = Some(ev);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::Exchange;

    fn f(cwe: &str, ev: Option<Evidence>) -> Finding {
        Finding { cwe: cwe.into(), title: "t".into(), evidence_data: ev, ..Default::default() }
    }
    fn ex(status: u16, body: &str) -> Exchange {
        Exchange { method: "GET".into(), url: "https://t/x".into(), status, body: body.into(), ..Default::default() }
    }

    #[test]
    fn a_missing_baseline_is_obtainable_and_a_locked_account_is_not() {
        assert!(Gap::Baseline.obtainable());
        assert!(Gap::Reproduction(1).obtainable());
        assert!(!Gap::Unreachable("no confirmed account".into()).obtainable());
    }

    #[test]
    fn sqli_without_a_baseline_wants_another_round() {
        let a = assess(&f("CWE-89", Some(Evidence { attack: Some(ex(500, "sql syntax")), ..Default::default() })));
        assert!(a.gaps.contains(&Gap::Baseline));
        assert!(a.wants_more_evidence(0.5), "uncertainty {}", a.uncertainty);
        assert_eq!(next_actions(&a)[0], Action::CaptureBaseline, "the cheapest gap is tried first");
    }

    #[test]
    fn a_decided_finding_is_not_uncertain() {
        // Reproduced difference: the validator confirms, so there is nothing to
        // be undecided about.
        let base = ex(200, "welcome");
        let attack = ex(500, "You have an error in your SQL syntax");
        let ev = Evidence {
            baseline: Some(base),
            attack: Some(attack.clone()),
            repeats: vec![attack.clone(), attack],
            ..Default::default()
        };
        let a = assess(&f("CWE-89", Some(ev)));
        assert_eq!(a.uncertainty, 0.0);
        assert!(!a.wants_more_evidence(0.5));
    }

    #[test]
    fn xss_without_a_browser_asks_for_one() {
        let a = assess(&f("CWE-79", Some(Evidence { marker: "M".into(), attack: Some(ex(200, "M")), ..Default::default() })));
        assert!(a.gaps.contains(&Gap::BrowserRun));
        assert!(next_actions(&a).contains(&Action::RunBrowser));
    }

    #[test]
    fn an_access_control_claim_with_one_identity_asks_for_the_second() {
        let a = assess(&f("CWE-639", Some(Evidence { identity_a: Some(ex(200, "owner")), ..Default::default() })));
        assert!(a.gaps.contains(&Gap::SecondIdentity));
    }

    #[test]
    fn a_class_with_no_validator_is_not_retried() {
        let a = assess(&f("CWE-1004", None));
        assert!(a.actionable().is_empty(), "more evidence cannot help a class no rule owns");
        assert!(!a.wants_more_evidence(0.3));
    }

    #[test]
    fn cheap_actions_come_before_expensive_ones() {
        let a = Assessment {
            uncertainty: 0.9,
            gaps: vec![Gap::OutOfBandChannel, Gap::BrowserRun, Gap::Baseline, Gap::Reproduction(0)],
        };
        let acts = next_actions(&a);
        assert_eq!(acts[0], Action::CaptureBaseline);
        assert_eq!(acts[acts.len() - 1], Action::OpenOobChannel);
    }

    #[test]
    fn rounds_are_bounded_per_finding() {
        let r = Rounds::with_max(2);
        assert!(r.take("F1"));
        assert!(r.take("F1"));
        assert!(!r.take("F1"), "the third round is refused");
        assert!(r.take("F2"), "a different finding has its own budget");
        assert_eq!(r.spent("F1"), 2);
    }

    #[test]
    fn merging_evidence_never_unsees_an_observation() {
        let mut finding = f("CWE-79", Some(Evidence { marker: "M".into(), browser_executed: true, marker_observed: true, ..Default::default() }));
        merge_evidence(&mut finding, Evidence { browser_executed: false, marker_observed: false, repeats: vec![ex(200, "x")], ..Default::default() });
        let ev = finding.evidence_data.unwrap();
        assert!(ev.browser_executed && ev.marker_observed, "a later blank run does not erase an earlier observation");
        assert_eq!(ev.repeats.len(), 1, "and new artifacts are added");
        assert_eq!(ev.marker, "M");
    }

    #[test]
    fn the_gap_is_written_into_the_review_reason() {
        let mut finding = f("CWE-89", None);
        let a = assess(&finding);
        note_gaps(&mut finding, &a);
        assert!(finding.review_reason.contains("baseline"), "{}", finding.review_reason);
    }
}
