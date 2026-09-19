//! Proof-of-concept validation — re-running a finding to see if it still holds.
//!
//! A finding is a claim about the past: *when I sent this, that happened*. The
//! report inherits that claim on trust. But between the moment an agent proved
//! something and the moment a client reads it, three things routinely change
//! the answer — the bug got hotfixed, the "proof" was a fluke that does not
//! reproduce, or the evidence was of an interaction the application never
//! actually performed. A PoC validator is the harness checking its own work
//! before it ships:
//!
//! ```text
//!   finding ──→ rebuild the request ──→ send it again ──→ compare to what
//!                                            │              was claimed
//!                                            ▼
//!                        REPRODUCED · CHANGED · GONE · UNVERIFIABLE
//! ```
//!
//! The distinction that matters is the last two. **GONE** means the request
//! ran cleanly and the effect is no longer there — a finding to demote, or a
//! remediation to confirm. **UNVERIFIABLE** means the harness could not run the
//! check at all (out of scope now, a state-changing request it will not repeat,
//! nothing recorded to replay). Collapsing those two is the classic mistake: a
//! PoC that *could not be tested* is not a PoC that *failed*, and reporting the
//! first as the second quietly drops real bugs.
//!
//! What this is **not**: it is not a second discovery pass. It re-runs what a
//! finding already recorded and asks "does this still reproduce", using the
//! same deterministic validators the pipeline used the first time. It never
//! invents a new payload, and it never *upgrades* a finding — the strongest
//! thing it can say is "still true", and the most useful is "no longer true".

use crate::replay::{ReplayEngine, ReqSpec};
use crate::scope::ScopePolicy;
use crate::types::Finding;
use crate::validation::{judge, Evidence, Verdict};
use serde::{Deserialize, Serialize};

/// What re-running a finding's proof showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reproduction {
    /// Ran again, same result. The finding stands.
    Reproduced,
    /// Ran again, a weaker or different result — worth a human's eye.
    Changed,
    /// Ran cleanly, the effect is gone. Likely fixed, or never real.
    Gone,
    /// Could not be re-run at all. NOT the same as failing.
    Unverifiable,
}

impl Reproduction {
    pub fn as_str(self) -> &'static str {
        match self {
            Reproduction::Reproduced => "reproduced",
            Reproduction::Changed => "changed",
            Reproduction::Gone => "gone",
            Reproduction::Unverifiable => "unverifiable",
        }
    }
    /// Should the finding still be reported as confirmed after this?
    ///
    /// Only a clean reproduction keeps a confirmation. `Changed` and `Gone`
    /// demote it; `Unverifiable` leaves the original verdict untouched, because
    /// failing to re-test is not evidence about the finding.
    pub fn keeps_confirmation(self) -> bool {
        self == Reproduction::Reproduced
    }
    pub fn demotes(self) -> bool {
        matches!(self, Reproduction::Changed | Reproduction::Gone)
    }
}

/// The outcome of validating one finding's PoC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocResult {
    pub finding_id: String,
    pub reproduction: Reproduction,
    /// Plain-language account, for the audit trail and the report.
    pub detail: String,
    /// The deterministic verdict on the fresh evidence, when one was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverdict: Option<String>,
    /// The exact request that was re-run, so the check is itself reproducible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replayed: Option<String>,
}

/// Validates findings by re-running the interaction each one recorded.
pub struct PocValidator {
    engine: ReplayEngine,
    /// Re-runs per finding: a single re-send can be a fluke in either
    /// direction, so a reproduction is asked to hold more than once.
    repeats: usize,
}

impl PocValidator {
    pub fn new(policy: ScopePolicy) -> Self {
        PocValidator { engine: ReplayEngine::new(policy), repeats: 2 }
    }

    pub fn with_repeats(mut self, n: usize) -> Self {
        self.repeats = n.max(1);
        self
    }

    /// Validate every finding, in order.
    pub async fn validate_all(&self, findings: &[Finding]) -> Vec<PocResult> {
        let mut out = Vec::with_capacity(findings.len());
        for f in findings {
            out.push(self.validate(f).await);
        }
        out
    }

    /// Re-run one finding's proof.
    ///
    /// The request re-run is the *attack* the finding recorded — not a fresh
    /// guess. When the finding has a baseline too, it is re-fetched as well, so
    /// the comparison the original validator made can be made again against
    /// current responses rather than against the response the baseline showed
    /// months ago.
    pub async fn validate(&self, f: &Finding) -> PocResult {
        let Some(ev) = &f.evidence_data else {
            return self.unverifiable(f, "the finding carries no recorded request to replay");
        };
        let Some(attack) = &ev.attack else {
            // A header-only or identity-pair finding may still be re-checkable
            // if it recorded those; otherwise there is nothing to send.
            return self.revalidate_headers_only(f, ev).await;
        };

        // Re-running a state-changing request to "confirm" it means doing the
        // damage a second time. The replay engine refuses these; so do we,
        // explicitly, as unverifiable rather than as a failure.
        let spec = crate::replay::spec_of(attack).with_body(&f.payload);
        if spec.is_mutating() {
            return self.unverifiable(
                f,
                &format!("{} is state-changing — re-running it to verify would repeat the side effect", spec.method),
            );
        }

        let fresh = match self.reproduce(&spec).await {
            Ok(x) => x,
            Err(reason) => return self.unverifiable(f, &reason),
        };

        // If the re-run was answered by a WAF/CDN rather than the application,
        // the PoC was NOT tested — do not report it as "no longer reproduces".
        // This is the deterministic WAF classifier running on a real exchange.
        let verdict_edge = crate::waf::classify_exchange(&fresh);
        if !verdict_edge.origin.supports_a_finding() {
            return self.unverifiable(f, &format!("re-run was answered by the edge, not the application: {}", verdict_edge.reason));
        }

        // Rebuild the evidence with the fresh responses, keep the finding's
        // markers, and ask the same deterministic judge.
        let mut fresh_ev = Evidence {
            attack: Some(fresh.clone()),
            marker: ev.marker.clone(),
            marker_observed: ev.marker_observed && fresh.body.contains(&ev.marker),
            ..Default::default()
        };
        if let Some(base) = &ev.baseline {
            let base_spec = crate::replay::spec_of(base);
            if let Ok(b) = self.engine.send(&base_spec).await {
                fresh_ev.baseline = Some(b);
            } else {
                fresh_ev.baseline = ev.baseline.clone();
            }
        }

        let verdict = judge(f, Some(&fresh_ev));
        let replayed = Some(format!("{} {}", spec.method, spec.url));
        match verdict {
            Verdict::Confirmed(r) => PocResult {
                finding_id: f.id.clone(),
                reproduction: Reproduction::Reproduced,
                detail: format!("re-ran the recorded request; the class still validates: {r}"),
                reverdict: Some(format!("confirmed: {r}")),
                replayed,
            },
            Verdict::Rejected(r) => PocResult {
                finding_id: f.id.clone(),
                // A clean re-run that no longer validates is the good news case:
                // it usually means the bug was fixed.
                reproduction: Reproduction::Gone,
                detail: format!("re-ran cleanly but the effect is no longer present: {r}"),
                reverdict: Some(format!("rejected: {r}")),
                replayed,
            },
            Verdict::NeedsReview(r) => PocResult {
                finding_id: f.id.clone(),
                reproduction: Reproduction::Changed,
                detail: format!("re-ran, but the result no longer matches the original proof: {r}"),
                reverdict: Some(format!("needs-review: {r}")),
                replayed,
            },
        }
    }

    /// A finding proven by headers or an identity pair, with no single attack
    /// request. Re-fetch what it did record and re-judge.
    async fn revalidate_headers_only(&self, f: &Finding, ev: &Evidence) -> PocResult {
        let probe = ev.identity_a.as_ref().or(ev.baseline.as_ref());
        let Some(sample) = probe else {
            return self.unverifiable(f, "nothing recorded to replay (no attack, baseline or identity sample)");
        };
        let spec = crate::replay::spec_of(sample);
        if spec.is_mutating() {
            return self.unverifiable(f, "the only recorded request is state-changing");
        }
        match self.engine.send(&spec).await {
            Ok(fresh) => {
                if !crate::waf::classify_exchange(&fresh).origin.supports_a_finding() {
                    return self.unverifiable(f, "re-fetch was answered by a WAF/CDN, not the application");
                }
                let fresh_ev = Evidence { attack: Some(fresh), baseline: ev.baseline.clone(), identity_a: ev.identity_a.clone(), identity_b: ev.identity_b.clone(), ..ev.clone() };
                match judge(f, Some(&fresh_ev)) {
                    Verdict::Confirmed(r) => PocResult { finding_id: f.id.clone(), reproduction: Reproduction::Reproduced, detail: format!("re-fetched; still validates: {r}"), reverdict: Some(r), replayed: Some(spec.url) },
                    Verdict::Rejected(r) => PocResult { finding_id: f.id.clone(), reproduction: Reproduction::Gone, detail: format!("re-fetched cleanly; the header/condition is no longer present: {r}"), reverdict: Some(r), replayed: Some(spec.url) },
                    Verdict::NeedsReview(r) => PocResult { finding_id: f.id.clone(), reproduction: Reproduction::Changed, detail: r.clone(), reverdict: Some(r), replayed: Some(spec.url) },
                }
            }
            Err(e) => self.unverifiable(f, &format!("could not re-fetch: {e}")),
        }
    }

    /// Send the request `repeats` times; the "fresh" exchange is the last one,
    /// and all of them must succeed. A single success amid failures is not a
    /// reproduction.
    async fn reproduce(&self, spec: &ReqSpec) -> Result<crate::validation::Exchange, String> {
        let (exchanges, errors) = self.engine.repeat(spec, self.repeats).await;
        if let Some(first) = errors.first() {
            return Err(first.clone());
        }
        exchanges.into_iter().last().ok_or_else(|| "no response on replay".to_string())
    }

    fn unverifiable(&self, f: &Finding, why: &str) -> PocResult {
        PocResult {
            finding_id: f.id.clone(),
            reproduction: Reproduction::Unverifiable,
            detail: format!("could not re-test: {why}"),
            reverdict: None,
            replayed: None,
        }
    }
}

/// Apply a PoC result back onto a finding.
///
/// The rule is one-directional, like the rest of the evidence machinery: this
/// can lower confidence and flag a finding for review, never raise it. A
/// finding that "still reproduces" keeps exactly the standing it already had —
/// re-running a proof does not make it more true than the first run did.
pub fn apply(f: &mut Finding, result: &PocResult) {
    match result.reproduction {
        Reproduction::Reproduced => {
            f.review_reason = format!("PoC re-validated: {}", result.detail);
        }
        Reproduction::Changed => {
            f.validated = false;
            f.review_status = "needs-review".into();
            f.review_reason = format!("PoC no longer matches the original proof: {}", result.detail);
            f.confidence = f.confidence.min(0.6);
        }
        Reproduction::Gone => {
            f.validated = false;
            f.review_status = "rejected".into();
            f.review_reason = format!("PoC no longer reproduces (likely fixed): {}", result.detail);
            f.confidence = f.confidence.min(0.3);
        }
        Reproduction::Unverifiable => {
            // Deliberately no change to validated/confidence — not re-testable
            // is not the same as not real.
            f.review_reason = format!("PoC could not be re-tested: {}", result.detail);
        }
    }
}

/// A one-line summary of a batch, for the run banner and the report.
pub fn summary(results: &[PocResult]) -> String {
    let count = |r: Reproduction| results.iter().filter(|x| x.reproduction == r).count();
    format!(
        "PoC re-validation: {} reproduced, {} changed, {} gone, {} unverifiable (of {})",
        count(Reproduction::Reproduced),
        count(Reproduction::Changed),
        count(Reproduction::Gone),
        count(Reproduction::Unverifiable),
        results.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::Exchange;

    fn finding_with_get(id: &str, url: &str) -> Finding {
        let mut ev = Evidence::default();
        ev.attack = Some(Exchange { method: "GET".into(), url: url.into(), status: 200, body: "ok".into(), ..Default::default() });
        Finding { id: id.into(), cwe: "CWE-79".into(), title: "Reflected XSS".into(), evidence_data: Some(ev), validated: true, confidence: 0.9, ..Default::default() }
    }

    #[test]
    fn a_state_changing_poc_is_unverifiable_not_failed() {
        // A DELETE proof cannot be re-run to confirm — doing so repeats the
        // deletion. It must not be reported as "no longer reproduces".
        let mut ev = Evidence::default();
        ev.attack = Some(Exchange { method: "DELETE".into(), url: "https://t.test/api/orders/9".into(), status: 200, ..Default::default() });
        let f = Finding { id: "d1".into(), cwe: "CWE-89".into(), title: "SQLi".into(), evidence_data: Some(ev), validated: true, confidence: 0.9, ..Default::default() };

        let v = PocValidator::new(ScopePolicy::for_target("https://t.test"));
        let r = futures::executor::block_on(v.validate(&f));
        assert_eq!(r.reproduction, Reproduction::Unverifiable);
        assert!(!r.reproduction.demotes(), "an untestable PoC must not demote the finding");

        let mut f2 = f.clone();
        apply(&mut f2, &r);
        assert!(f2.validated, "confidence and validated are untouched when we simply could not test");
    }

    #[test]
    fn a_finding_with_nothing_recorded_is_unverifiable() {
        let f = Finding { id: "x".into(), cwe: "CWE-79".into(), validated: true, confidence: 0.8, ..Default::default() };
        let v = PocValidator::new(ScopePolicy::for_target("https://t.test"));
        let r = futures::executor::block_on(v.validate(&f));
        assert_eq!(r.reproduction, Reproduction::Unverifiable);
    }

    #[test]
    fn an_out_of_scope_replay_is_unverifiable() {
        // The recorded request points somewhere the current scope forbids.
        let f = finding_with_get("o1", "https://not-in-scope.test/x");
        let v = PocValidator::new(ScopePolicy::for_target("https://t.test"));
        let r = futures::executor::block_on(v.validate(&f));
        assert_eq!(r.reproduction, Reproduction::Unverifiable);
        assert!(r.detail.contains("scope") || r.detail.contains("could not"));
    }

    #[test]
    fn apply_only_ever_lowers_standing() {
        let mut f = finding_with_get("a", "https://t.test/x");
        f.confidence = 0.9;

        apply(&mut f, &PocResult { finding_id: "a".into(), reproduction: Reproduction::Gone, detail: "fixed".into(), reverdict: None, replayed: None });
        assert!(!f.validated);
        assert!(f.confidence <= 0.3);

        // Reproduced does not raise a confidence that was lowered.
        let mut f2 = finding_with_get("b", "https://t.test/x");
        f2.confidence = 0.5;
        apply(&mut f2, &PocResult { finding_id: "b".into(), reproduction: Reproduction::Reproduced, detail: "still there".into(), reverdict: None, replayed: None });
        assert_eq!(f2.confidence, 0.5, "re-proving does not inflate confidence");
    }

    #[test]
    fn summary_counts_every_bucket() {
        let mk = |r: Reproduction| PocResult { finding_id: "x".into(), reproduction: r, detail: String::new(), reverdict: None, replayed: None };
        let s = summary(&[mk(Reproduction::Reproduced), mk(Reproduction::Gone), mk(Reproduction::Gone), mk(Reproduction::Unverifiable)]);
        assert!(s.contains("1 reproduced"));
        assert!(s.contains("2 gone"));
        assert!(s.contains("1 unverifiable"));
    }
}
