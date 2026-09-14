//! Claims, evidence ledger, and the decision that separates *mechanic* from
//! *impact*.
//!
//! A live engagement produced the failure this module exists to prevent. An
//! agent proved that 25 password-reset requests were accepted with no HTTP
//! throttling, and then titled the finding "reset-email flooding". The voter
//! read one sentence, judged the claimed impact unproven, and rejected the
//! whole thing — so a real missing control vanished from the report because the
//! story told about it was too big.
//!
//! The mistake was structural, not a bad judgement call. The voter was handed a
//! prose paragraph and a single accept/reject lever, and agents reliably walk
//! this chain:
//!
//! ```text
//! control is absent  →  abuse is possible  →  impact is plausible  →  impact stated as fact
//! ```
//!
//! The chain has to be cut at the second step, and that requires the finding to
//! arrive as *separable claims* rather than a paragraph:
//!
//! - **Mechanic** — what the target actually did. "The endpoint accepted 25
//!   requests with no 429, no `Retry-After`, no `RateLimit-*`."
//! - **Impact** — what that gets an attacker. "A confirmed account's mailbox is
//!   flooded." A different claim, with its own evidence, usually absent.
//!
//! Then the outcome is a table, in code, not an instruction a model can
//! reinterpret:
//!
//! | mechanic | impact | outcome |
//! |----------|--------|---------|
//! | proven | proven | accept |
//! | proven | partial | accept, severity capped |
//! | proven | unproven | **retain**, Low/Info, needs-review |
//! | unproven | anything | reject |
//! | contradicted | anything | reject |
//!
//! `DOWNGRADE_*` can never produce a discard. That is the whole point.

use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// One observation, addressable by id so a claim can point at it.
///
/// The ledger is what makes a verdict auditable: "this claim is supported by
/// E01–E27" is checkable, "the evidence looks convincing" is not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceItem {
    /// `E01`, `E02`, … assigned in order of collection.
    pub id: String,
    /// What was observed, stated as an observation and nothing more.
    pub observed: String,
    /// Where it came from: `http`, `browser`, `replay`, `oob`, `code`, `tool`.
    #[serde(default)]
    pub source: String,
}

/// The observations behind one finding.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EvidenceLedger {
    #[serde(default)]
    pub items: Vec<EvidenceItem>,
}

impl EvidenceLedger {
    pub fn add(&mut self, observed: &str, source: &str) -> String {
        let id = format!("E{:02}", self.items.len() + 1);
        self.items.push(EvidenceItem { id: id.clone(), observed: observed.to_string(), source: source.to_string() });
        id
    }
    pub fn get(&self, id: &str) -> Option<&EvidenceItem> {
        self.items.iter().find(|e| e.id.eq_ignore_ascii_case(id))
    }
    /// Ids referenced by a claim that the ledger does not actually contain —
    /// a claim citing evidence that was never recorded is worse than one citing
    /// none, because it looks supported.
    pub fn dangling<'a>(&self, refs: &'a [String]) -> Vec<&'a String> {
        refs.iter().filter(|r| self.get(r).is_none()).collect()
    }
}

/// How well a claim is supported. Deliberately four states: collapsing
/// "unproven" and "contradicted" into one loses the difference between "we did
/// not look" and "we looked and it was false".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStatus {
    Proven,
    /// Some of the claim is supported; the rest is inference.
    Partial,
    Unproven,
    /// The evidence says the opposite.
    Contradicted,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimStatus::Proven => "proven",
            ClaimStatus::Partial => "partial",
            ClaimStatus::Unproven => "unproven",
            ClaimStatus::Contradicted => "contradicted",
        }
    }
}

/// One assertion plus the evidence ids behind it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Claim {
    pub claim: String,
    #[serde(default)]
    pub status: Option<ClaimStatus>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl Claim {
    /// The status the evidence actually supports, ignoring what was asserted.
    ///
    /// A claim with no evidence is unproven no matter how confidently it was
    /// written, and a claim that *says* proven while citing nothing is the
    /// exact failure mode this module was built for.
    pub fn effective_status(&self, ledger: &EvidenceLedger) -> ClaimStatus {
        if self.claim.trim().is_empty() {
            return ClaimStatus::Unproven;
        }
        if self.status == Some(ClaimStatus::Contradicted) {
            return ClaimStatus::Contradicted;
        }
        let supported = self.evidence.iter().filter(|id| ledger.get(id).is_some()).count();
        if supported == 0 {
            return ClaimStatus::Unproven;
        }
        match self.status {
            // An asserted status is accepted only as far as the citations go:
            // the model may downgrade itself, never upgrade past its evidence.
            Some(ClaimStatus::Proven) | None => {
                if supported < self.evidence.len() { ClaimStatus::Partial } else { ClaimStatus::Proven }
            }
            Some(s) => s,
        }
    }
}

/// What the assessment could and could not reach. Preconditions are checked
/// against this, so "we never had a confirmed account" is a fact about the test
/// rather than a silent hole in the conclusion.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TestScope {
    #[serde(default)]
    pub account_exists: bool,
    #[serde(default)]
    pub account_confirmed: bool,
    #[serde(default)]
    pub authenticated_session: bool,
    #[serde(default)]
    pub email_delivery_observed: bool,
    #[serde(default)]
    pub oob_callback_available: bool,
    #[serde(default)]
    pub browser_used: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// A finding, decomposed into what can be judged separately.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ClaimSet {
    pub mechanic: Claim,
    pub impact: Claim,
    /// What the impact *would* be if the missing preconditions were met. Kept
    /// separate from `impact` precisely so it cannot be promoted into one.
    #[serde(default)]
    pub potential_impact: String,
    #[serde(default)]
    pub test_scope: TestScope,
    #[serde(default)]
    pub ledger: EvidenceLedger,
}

/// A structured vote outcome. The old vote was accept/reject, which forced a
/// judge with a half-supported finding to pick between endorsing an
/// overstatement and deleting a real observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "decision", content = "reason")]
pub enum Decision {
    AcceptFullyProven(String),
    /// The impact was overstated; the finding is kept and rewritten.
    DowngradeUnprovenImpact(String),
    /// The test could not reach what the impact needed (no confirmed account,
    /// no OOB channel). Not the target's doing, and not a reason to delete.
    DowngradeScopeLimitation(String),
    /// The target did not do what the finding says it did.
    RejectMechanic(String),
    RejectInvalidEvidence(String),
    RejectDuplicate(String),
}

impl Decision {
    /// Does this decision remove the finding from the report?
    ///
    /// Only the three `Reject*` variants may. A downgrade that discards is the
    /// bug this module exists to make unrepresentable.
    pub fn discards(&self) -> bool {
        matches!(self, Decision::RejectMechanic(_) | Decision::RejectInvalidEvidence(_) | Decision::RejectDuplicate(_))
    }
    pub fn code(&self) -> &'static str {
        match self {
            Decision::AcceptFullyProven(_) => "ACCEPT_FULLY_PROVEN",
            Decision::DowngradeUnprovenImpact(_) => "DOWNGRADE_UNPROVEN_IMPACT",
            Decision::DowngradeScopeLimitation(_) => "DOWNGRADE_SCOPE_LIMITATION",
            Decision::RejectMechanic(_) => "REJECT_MECHANIC",
            Decision::RejectInvalidEvidence(_) => "REJECT_INVALID_EVIDENCE",
            Decision::RejectDuplicate(_) => "REJECT_DUPLICATE",
        }
    }
    pub fn reason(&self) -> &str {
        match self {
            Decision::AcceptFullyProven(r)
            | Decision::DowngradeUnprovenImpact(r)
            | Decision::DowngradeScopeLimitation(r)
            | Decision::RejectMechanic(r)
            | Decision::RejectInvalidEvidence(r)
            | Decision::RejectDuplicate(r) => r,
        }
    }
}

/// Minimum observations an impact class needs before it may be stated as fact.
///
/// "25 requests were accepted" proves throttling was not observed. It does not
/// prove 25 emails reached a mailbox — that needs an account that exists, is
/// confirmed, and delivery actually seen. Encoding the difference makes it
/// checkable instead of arguable.
pub fn impact_preconditions(impact_claim: &str) -> Vec<&'static str> {
    let t = impact_claim.to_lowercase();
    let mut need: Vec<&'static str> = Vec::new();
    if t.contains("flood") || t.contains("mail bomb") || t.contains("inbox") || (t.contains("email") && (t.contains("spam") || t.contains("abuse"))) {
        need.extend(["account_exists", "account_confirmed", "email_delivery_observed"]);
    }
    if t.contains("takeover") || t.contains("account compromise") || t.contains("full control") {
        need.extend(["authenticated_session"]);
    }
    if t.contains("exfiltrat") || t.contains("dump") || t.contains("read the database") || t.contains("sensitive data") {
        need.extend(["data_returned"]);
    }
    if t.contains("execute") || t.contains("rce") || t.contains("command") {
        need.extend(["command_output_observed"]);
    }
    if t.contains("session hijack") || t.contains("steal the session") || t.contains("cookie theft") {
        need.extend(["browser_used"]);
    }
    need.sort_unstable();
    need.dedup();
    need
}

/// Which preconditions the test could not satisfy.
pub fn unmet_preconditions(set: &ClaimSet) -> Vec<&'static str> {
    let s = &set.test_scope;
    impact_preconditions(&set.impact.claim)
        .into_iter()
        .filter(|p| match *p {
            "account_exists" => !s.account_exists,
            "account_confirmed" => !s.account_confirmed,
            "authenticated_session" => !s.authenticated_session,
            "email_delivery_observed" => !s.email_delivery_observed,
            "browser_used" => !s.browser_used,
            // Claims about returned data or command output are backed by the
            // ledger rather than by a scope flag.
            "data_returned" | "command_output_observed" => set.impact.evidence.is_empty(),
            _ => false,
        })
        .collect()
}

/// The decision table. Deliberately a pure function of two statuses so the
/// outcome cannot depend on how persuasively a finding was written.
pub fn decide(set: &ClaimSet) -> Decision {
    let mech = set.mechanic.effective_status(&set.ledger);
    let imp = set.impact.effective_status(&set.ledger);

    let dangling = set.ledger.dangling(&set.mechanic.evidence);
    if !dangling.is_empty() {
        return Decision::RejectInvalidEvidence(format!(
            "the mechanic cites evidence that was never recorded ({}) — a claim that looks supported and is not",
            dangling.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    match (mech, imp) {
        (ClaimStatus::Contradicted, _) => Decision::RejectMechanic("the evidence contradicts what the finding says the target did".into()),
        (ClaimStatus::Unproven, _) => Decision::RejectMechanic(
            "no evidence supports the mechanic — without it there is nothing to report, whatever the impact would have been".into(),
        ),
        (_, ClaimStatus::Contradicted) => Decision::DowngradeUnprovenImpact(
            "the evidence contradicts the claimed impact; the mechanic stands on its own".into(),
        ),
        (ClaimStatus::Proven, ClaimStatus::Proven) => Decision::AcceptFullyProven("mechanic and impact are both supported by recorded evidence".into()),
        (ClaimStatus::Partial, ClaimStatus::Proven) | (_, ClaimStatus::Partial) => {
            Decision::DowngradeUnprovenImpact("only part of the claim is supported — severity capped to what the evidence shows".into())
        }
        (_, ClaimStatus::Unproven) => {
            let unmet = unmet_preconditions(set);
            if unmet.is_empty() {
                Decision::DowngradeUnprovenImpact(
                    "the mechanic is demonstrated; the claimed impact is not, and is reported as potential".into(),
                )
            } else {
                // The impact was not disproven — the assessment simply could not
                // get there. That distinction belongs in the report.
                Decision::DowngradeScopeLimitation(format!(
                    "the impact needs {} which this assessment could not reach; the mechanic stands",
                    unmet.join(", ")
                ))
            }
        }
    }
}

/// Would the finding still be worth reporting with the unproven impact removed?
///
/// This is the question that decides retain-vs-reject, and for the case that
/// prompted all of this the answer is obviously yes: strip "email flooding" and
/// "the password-reset endpoint has no observable rate limiting" remains a real
/// finding.
pub fn still_security_relevant(set: &ClaimSet) -> bool {
    let m = set.mechanic.claim.to_lowercase();
    if m.trim().is_empty() {
        return false;
    }
    // A mechanic describing an absent control, an exposure, or an accepted
    // abuse is security-relevant on its own terms.
    const SIGNALS: &[&str] = &[
        "no ", "without", "missing", "absent", "not enforced", "not set", "unthrottled", "accepted",
        "disclosed", "exposed", "reflected", "differs", "difference", "leak", "returns", "allows",
        "bypass", "unauthenticated", "reused", "never", "lacks",
    ];
    SIGNALS.iter().any(|s| m.contains(s))
}

/// Rewrite a finding to exactly what the evidence supports.
///
/// Lowering severity is not enough. A report headed "Password Reset Email
/// Flooding" still asserts flooding, whatever number sits beside it — so the
/// title and the impact prose are rewritten too, and what was claimed is moved
/// into a clearly labelled potential-impact paragraph.
pub fn rewrite(f: &mut Finding, set: &ClaimSet, decision: &Decision) {
    match decision {
        Decision::AcceptFullyProven(_) => {
            f.review_status = "confirmed".into();
            f.validated = true;
            return;
        }
        d if d.discards() => return,
        _ => {}
    }

    // Title: name the control that is missing, not the attack that was imagined.
    let mech = set.mechanic.claim.trim();
    if !mech.is_empty() {
        f.title = title_from_mechanic(mech, &f.title);
    }

    let observed: Vec<String> = set
        .mechanic
        .evidence
        .iter()
        .filter_map(|id| set.ledger.get(id))
        .map(|e| format!("- {} [{}]", e.observed, e.id))
        .collect();

    let mut impact = String::new();
    impact.push_str("Observed:\n");
    if observed.is_empty() {
        impact.push_str(&format!("- {mech}\n"));
    } else {
        impact.push_str(&observed.join("\n"));
        impact.push('\n');
    }
    if !set.impact.claim.trim().is_empty() {
        impact.push_str(&format!("\nNot demonstrated: {}.\n", set.impact.claim.trim().trim_end_matches('.')));
    }
    let unmet = unmet_preconditions(set);
    if !unmet.is_empty() {
        impact.push_str(&format!(
            "The assessment could not verify {} — so this remains a potential impact rather than a demonstrated one.\n",
            unmet.join(", ").replace('_', " ")
        ));
    }
    let potential = if set.potential_impact.trim().is_empty() { set.impact.claim.trim() } else { set.potential_impact.trim() };
    if !potential.is_empty() {
        impact.push_str(&format!("\nPotential impact: {}.", potential.trim_end_matches('.')));
    }
    f.impact = impact;

    // Severity is capped, never raised: a downgrade decision cannot make a
    // finding more serious than the agent claimed.
    let cap = match decision {
        Decision::DowngradeScopeLimitation(_) => "Low",
        _ => if still_security_relevant(set) { "Low" } else { "Info" },
    };
    // A cap lowers, never raises: a downgrade decision must not be able to make
    // a finding more serious than its author claimed. The comparison was
    // inverted at first, which silently left a High finding at High — the
    // failure the cap exists to prevent.
    if sev_rank(&f.severity) > sev_rank(cap) {
        f.severity = cap.to_string();
    }
    f.validated = false;
    f.review_status = "needs-review".into();
    f.review_reason = format!("{}: {}", decision.code(), decision.reason());
    f.confidence = f.confidence.min(0.6);
}

fn sev_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        x if x.starts_with("crit") => 4,
        x if x.starts_with("high") => 3,
        x if x.starts_with("med") => 2,
        x if x.starts_with("low") => 1,
        _ => 0,
    }
}

/// Turn a mechanic sentence into a title that claims exactly it.
fn title_from_mechanic(mech: &str, fallback: &str) -> String {
    let m = mech.trim().trim_end_matches('.');
    let mut t: String = m.chars().take(110).collect();
    if m.chars().count() > 110 {
        // Cut on a word boundary rather than mid-word.
        if let Some(i) = t.rfind(' ') {
            t.truncate(i);
        }
        t.push('…');
    }
    if t.is_empty() {
        return fallback.to_string();
    }
    let mut c = t.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => fallback.to_string(),
    }
}

/// The contract text agents are held to. Rendered into exploit prompts.
pub fn claim_contract() -> String {
    String::from(
        "CLAIM CONTRACT — state the smallest claim your evidence supports.\n\
         Findings are judged as two separable claims, and inflating the second one costs you the first:\n\
         - `mechanic`: what the target DID, as an observation. \"The endpoint accepted 25 requests with no 429, no Retry-After, no RateLimit-* header.\"\n\
         - `impact`: what that gets an attacker. A DIFFERENT claim, needing its own evidence.\n\
         The title, description, impact and severity MUST NOT claim more than the evidence demonstrates. When the evidence proves a security control is absent but does not prove exploitation impact, report the MISSING CONTROL as the finding and put the consequence under `potential_impact`.\n\
         Emit alongside the finding:\n\
           \"evidence_ledger\": [{\"id\":\"E01\",\"observed\":\"POST #1 -> HTTP 302\",\"source\":\"http\"}, ...]\n\
           \"claims\": {\n\
             \"mechanic\": {\"claim\":\"...\",\"status\":\"proven\",\"evidence\":[\"E01\",\"E02\"]},\n\
             \"impact\": {\"claim\":\"...\",\"status\":\"unproven\",\"evidence\":[]},\n\
             \"potential_impact\": \"...\",\n\
             \"test_scope\": {\"account_exists\":false,\"account_confirmed\":false,\"email_delivery_observed\":false,\"authenticated_session\":false,\"browser_used\":false}\n\
           }\n\
         Every claim cites evidence ids from your own ledger. A claim citing an id you did not record is treated as invalid evidence and rejected — worse than citing none, because it looks supported.\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engagement case, verbatim: 25 unthrottled requests, "reset-email
    /// flooding" claimed, nothing about delivery observed.
    fn reset_flood_case() -> ClaimSet {
        let mut ledger = EvidenceLedger::default();
        for i in 1..=25 {
            ledger.add(&format!("POST #{i} /Account/ForgotPassword -> HTTP 302"), "http");
        }
        let e26 = ledger.add("Retry-After header absent on all 25 responses", "http");
        let e27 = ledger.add("RateLimit-* headers absent on all 25 responses", "http");
        let mech_ids: Vec<String> = ledger.items.iter().take(25).map(|e| e.id.clone()).chain([e26, e27]).collect();
        ClaimSet {
            mechanic: Claim {
                claim: "The password-reset endpoint accepted 25 consecutive requests with no HTTP throttling".into(),
                status: Some(ClaimStatus::Proven),
                evidence: mech_ids,
            },
            impact: Claim {
                claim: "Reset email flooding against a victim's mailbox".into(),
                status: Some(ClaimStatus::Proven), // the agent's overstatement
                evidence: vec![],
            },
            potential_impact: "A confirmed account could receive repeated reset emails".into(),
            test_scope: TestScope { account_exists: false, account_confirmed: false, email_delivery_observed: false, ..Default::default() },
            ledger,
        }
    }

    #[test]
    fn an_unproven_impact_downgrades_and_never_discards() {
        let set = reset_flood_case();
        let d = decide(&set);
        assert_eq!(d.code(), "DOWNGRADE_SCOPE_LIMITATION", "{d:?}");
        assert!(!d.discards(), "a downgrade that deletes the finding is the bug this exists to prevent");
    }

    #[test]
    fn an_asserted_status_cannot_outrun_its_citations() {
        let set = reset_flood_case();
        // The agent wrote status=proven with an empty evidence list.
        assert_eq!(set.impact.effective_status(&set.ledger), ClaimStatus::Unproven);
        assert_eq!(set.mechanic.effective_status(&set.ledger), ClaimStatus::Proven);
    }

    #[test]
    fn the_finding_is_rewritten_not_merely_renumbered() {
        let mut f = Finding {
            title: "Password Reset Email Flooding".into(),
            severity: "High".into(),
            confidence: 0.9,
            validated: true,
            ..Default::default()
        };
        let set = reset_flood_case();
        let d = decide(&set);
        rewrite(&mut f, &set, &d);

        assert!(!f.title.to_lowercase().contains("flooding"), "the title still asserts the unproven impact: {}", f.title);
        assert!(f.title.to_lowercase().contains("throttling") || f.title.to_lowercase().contains("accepted"), "{}", f.title);
        assert_eq!(f.severity, "Low");
        assert_eq!(f.review_status, "needs-review");
        assert!(f.impact.contains("Observed:"));
        assert!(f.impact.contains("Not demonstrated:"));
        assert!(f.impact.contains("Potential impact:"));
        assert!(f.review_reason.starts_with("DOWNGRADE_SCOPE_LIMITATION"));
    }

    #[test]
    fn a_fully_proven_finding_is_accepted_untouched() {
        let mut ledger = EvidenceLedger::default();
        let e1 = ledger.add("GET /invoice/4711 as userB -> HTTP 200 with userA's invoice body", "http");
        let set = ClaimSet {
            mechanic: Claim { claim: "userB reads userA's invoice".into(), status: Some(ClaimStatus::Proven), evidence: vec![e1.clone()] },
            impact: Claim { claim: "Cross-tenant read of another customer's invoice".into(), status: Some(ClaimStatus::Proven), evidence: vec![e1] },
            ledger,
            ..Default::default()
        };
        let d = decide(&set);
        assert_eq!(d.code(), "ACCEPT_FULLY_PROVEN");
        let mut f = Finding { title: "IDOR".into(), severity: "High".into(), ..Default::default() };
        rewrite(&mut f, &set, &d);
        assert_eq!(f.title, "IDOR", "an accepted finding is not rewritten");
        assert_eq!(f.severity, "High", "and not downgraded");
        assert!(f.validated);
    }

    #[test]
    fn an_unproven_mechanic_is_rejected_however_big_the_impact_claim() {
        let set = ClaimSet {
            mechanic: Claim { claim: "The app is vulnerable to SQL injection".into(), status: Some(ClaimStatus::Proven), evidence: vec![] },
            impact: Claim { claim: "Full database compromise".into(), status: Some(ClaimStatus::Proven), evidence: vec![] },
            ..Default::default()
        };
        let d = decide(&set);
        assert_eq!(d.code(), "REJECT_MECHANIC");
        assert!(d.discards());
    }

    #[test]
    fn citing_evidence_that_was_never_recorded_is_invalid_not_supported() {
        let mut ledger = EvidenceLedger::default();
        ledger.add("GET / -> 200", "http");
        let set = ClaimSet {
            mechanic: Claim { claim: "endpoint accepted the payload".into(), status: Some(ClaimStatus::Proven), evidence: vec!["E01".into(), "E99".into()] },
            impact: Claim::default(),
            ledger,
            ..Default::default()
        };
        let d = decide(&set);
        assert_eq!(d.code(), "REJECT_INVALID_EVIDENCE", "{d:?}");
        assert!(d.reason().contains("E99"));
    }

    #[test]
    fn contradicted_evidence_rejects_the_mechanic() {
        let mut ledger = EvidenceLedger::default();
        let e = ledger.add("attempt #21 -> HTTP 429 Too Many Requests", "http");
        let set = ClaimSet {
            mechanic: Claim { claim: "no throttling on login".into(), status: Some(ClaimStatus::Contradicted), evidence: vec![e] },
            impact: Claim::default(),
            ledger,
            ..Default::default()
        };
        assert_eq!(decide(&set).code(), "REJECT_MECHANIC");
    }

    #[test]
    fn survivability_decides_retain_versus_reject() {
        let set = reset_flood_case();
        assert!(still_security_relevant(&set), "strip the flooding claim and a missing control remains");

        let vague = ClaimSet {
            mechanic: Claim { claim: "the application responded".into(), status: Some(ClaimStatus::Proven), evidence: vec!["E01".into()] },
            ..Default::default()
        };
        assert!(!still_security_relevant(&vague), "'it responded' is not a finding");
    }

    #[test]
    fn preconditions_are_specific_to_the_impact_claimed() {
        assert_eq!(
            impact_preconditions("Reset email flooding of a victim inbox"),
            vec!["account_confirmed", "account_exists", "email_delivery_observed"]
        );
        assert!(impact_preconditions("Full account takeover").contains(&"authenticated_session"));
        assert!(impact_preconditions("Missing security header").is_empty(), "a hardening gap claims no impact preconditions");
    }

    #[test]
    fn a_partially_supported_impact_caps_rather_than_accepts() {
        let mut ledger = EvidenceLedger::default();
        let e1 = ledger.add("response contained one internal hostname", "http");
        let set = ClaimSet {
            mechanic: Claim { claim: "endpoint returns internal metadata".into(), status: Some(ClaimStatus::Proven), evidence: vec![e1.clone()] },
            impact: Claim { claim: "full internal network map disclosed".into(), status: Some(ClaimStatus::Partial), evidence: vec![e1] },
            ledger,
            ..Default::default()
        };
        let d = decide(&set);
        assert_eq!(d.code(), "DOWNGRADE_UNPROVEN_IMPACT");
        assert!(!d.discards());
    }

    #[test]
    fn every_downgrade_variant_retains_the_finding() {
        for d in [
            Decision::DowngradeUnprovenImpact(String::new()),
            Decision::DowngradeScopeLimitation(String::new()),
        ] {
            assert!(!d.discards(), "{} must never delete a finding", d.code());
        }
        for d in [
            Decision::RejectMechanic(String::new()),
            Decision::RejectInvalidEvidence(String::new()),
            Decision::RejectDuplicate(String::new()),
        ] {
            assert!(d.discards(), "{} is a rejection", d.code());
        }
    }
}
