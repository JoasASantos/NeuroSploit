//! Evidence integrity — refusing fabricated or re-used proof.
//!
//! A finding's evidence is only worth anything if it was actually produced by
//! the action the finding claims, against the target the finding names, during
//! this engagement. Nothing in a JSON blob enforces that on its own: an agent
//! under prompt injection, a copy-paste between findings, or a hallucinated
//! receipt all produce evidence that *looks* fine. This module is the check
//! that catches the ways evidence can be wrong even when it is well-formed:
//!
//! ```text
//!   cross-target   evidence's host ≠ the finding's host        → reject
//!   reused receipt one exchange backing two different CWEs      → reject
//!   foreign marker an OAST token not minted by this build       → reject
//!   orphan claim   a confirmed finding with no evidence at all  → demote
//! ```
//!
//! Like the rest of the evidence machinery it is one-directional: it can only
//! lower a finding's standing, never raise it. A violation does not delete the
//! finding — it strips the unproven claim and flags it, so a real issue behind
//! bad bookkeeping is not lost, and a fabricated one cannot ship as confirmed.

use crate::types::Finding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// What was wrong with a finding's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Violation {
    /// The evidence was recorded against a different host than the finding names.
    CrossTarget { finding_host: String, evidence_host: String },
    /// The same recorded exchange backs another finding of a different class —
    /// a single receipt cannot prove two incompatible things.
    ReusedReceipt { other_finding: String },
    /// An OAST/OOB marker that this build did not mint — evidence from another
    /// engagement, or invented.
    ForeignMarker { marker: String },
    /// Claimed confirmed with no checkable evidence at all.
    OrphanClaim,
}

impl Violation {
    pub fn reason(&self) -> String {
        match self {
            Violation::CrossTarget { finding_host, evidence_host } =>
                format!("evidence was recorded against {evidence_host}, but the finding is about {finding_host} — proof from another target"),
            Violation::ReusedReceipt { other_finding } =>
                format!("the same recorded exchange also backs finding {other_finding} of a different class — one receipt cannot prove both"),
            Violation::ForeignMarker { marker } =>
                format!("OAST marker `{marker}` was not minted by this engagement's build — evidence from elsewhere"),
            Violation::OrphanClaim =>
                "confirmed with no checkable evidence recorded".into(),
        }
    }
    /// Every integrity violation strips the finding's proof — fabricated or
    /// misattributed evidence is never allowed to stand as confirmed.
    pub fn demotes(&self) -> bool {
        true
    }
}

/// A finding and everything wrong with its evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audit {
    pub finding_id: String,
    pub violations: Vec<Violation>,
}

impl Audit {
    pub fn clean(&self) -> bool {
        self.violations.is_empty()
    }
}

fn host(url: &str) -> String {
    crate::netguard::normalize_host(&crate::scope::host_of(url))
}

/// Fingerprint an exchange by what it actually was: method, URL and the hash of
/// the response body. Two findings citing the identical fingerprint are citing
/// the identical receipt.
fn receipt_fingerprint(ex: &crate::validation::Exchange) -> String {
    let body_hash: String = Sha256::digest(ex.body.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{} {} {}", ex.method.to_uppercase(), crate::scope::host_of(&ex.url), body_hash)
}

/// Check every finding's evidence for the ways it can be wrong.
///
/// `build` is this run's provenance build fingerprint, used to tell an OAST
/// marker minted here from one carried in from elsewhere.
pub fn audit_evidence(findings: &[Finding], build: &str) -> Vec<Audit> {
    // Map each receipt fingerprint to the (finding id, cwe) that first used it,
    // so a second, class-incompatible use is caught.
    let mut seen_receipts: HashMap<String, (String, String)> = HashMap::new();
    let mut out = Vec::with_capacity(findings.len());

    for f in findings {
        let mut violations = Vec::new();
        let fhost = host(&f.endpoint);

        match &f.evidence_data {
            None => {
                // No structured evidence. Only a problem if the finding is
                // asserting confirmation — a needs-review finding is allowed to
                // be thin, that is what the status is for.
                if f.validated && f.review_status != "needs-review" {
                    violations.push(Violation::OrphanClaim);
                }
            }
            Some(ev) => {
                // Cross-target: the exchanges must be about the finding's host.
                for ex in [ev.attack.as_ref(), ev.baseline.as_ref(), ev.identity_a.as_ref(), ev.identity_b.as_ref()].into_iter().flatten() {
                    let ehost = host(&ex.url);
                    if !ehost.is_empty() && !fhost.is_empty() && ehost != fhost {
                        violations.push(Violation::CrossTarget { finding_host: fhost.clone(), evidence_host: ehost });
                        break;
                    }
                }

                // Reused receipt across incompatible classes.
                if let Some(attack) = &ev.attack {
                    let fp = receipt_fingerprint(attack);
                    if let Some((other_id, other_cwe)) = seen_receipts.get(&fp) {
                        if other_id != &f.id && other_cwe != &f.cwe {
                            violations.push(Violation::ReusedReceipt { other_finding: other_id.clone() });
                        }
                    } else {
                        seen_receipts.insert(fp, (f.id.clone(), f.cwe.clone()));
                    }
                }

                // Foreign OAST marker: a callback-backed finding must cite a
                // marker this build minted. The sigil + build prefix is what
                // makes a marker attributable (see crate::provenance).
                if ev.callback_received && !ev.marker.trim().is_empty() {
                    let m = ev.marker.to_lowercase();
                    let ours = m.contains(&crate::provenance::SIGIL.to_lowercase()) && m.contains(&build[..build.len().min(6)]);
                    if !ours {
                        violations.push(Violation::ForeignMarker { marker: ev.marker.clone() });
                    }
                }
            }
        }

        out.push(Audit { finding_id: f.id.clone(), violations });
    }
    out
}

/// Apply an audit back onto a finding: strip the proof and flag it. Never
/// deletes — a real issue behind bad bookkeeping survives as needs-review.
pub fn apply(f: &mut Finding, audit: &Audit) {
    if audit.clean() {
        return;
    }
    let reasons: Vec<String> = audit.violations.iter().map(|v| v.reason()).collect();
    f.validated = false;
    f.review_status = "rejected".into();
    f.review_reason = format!("evidence integrity: {}", reasons.join("; "));
    f.confidence = f.confidence.min(0.2);
}

/// One-line summary for the run banner.
pub fn summary(audits: &[Audit]) -> String {
    let bad = audits.iter().filter(|a| !a.clean()).count();
    if bad == 0 {
        format!("evidence integrity: all {} finding(s) clean", audits.len())
    } else {
        format!("evidence integrity: {bad} of {} finding(s) had fabricated/reused evidence and were demoted", audits.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::{Evidence, Exchange};

    fn ex(url: &str, body: &str) -> Exchange {
        Exchange { method: "GET".into(), url: url.into(), status: 200, body: body.into(), ..Default::default() }
    }
    fn finding(id: &str, cwe: &str, endpoint: &str, ev: Option<Evidence>) -> Finding {
        Finding { id: id.into(), cwe: cwe.into(), endpoint: endpoint.into(), evidence_data: ev, validated: true, confidence: 0.9, ..Default::default() }
    }

    #[test]
    fn evidence_from_another_target_is_rejected() {
        let ev = Evidence { attack: Some(ex("https://other.test/x", "boom")), ..Default::default() };
        let f = finding("f1", "CWE-79", "https://app.example.com/x", Some(ev));
        let audits = audit_evidence(&[f], "abc123");
        assert!(!audits[0].clean());
        assert!(matches!(audits[0].violations[0], Violation::CrossTarget { .. }));
    }

    #[test]
    fn one_receipt_cannot_back_two_different_classes() {
        let shared = ex("https://app.example.com/x", "same response");
        let f1 = finding("f1", "CWE-79", "https://app.example.com/x", Some(Evidence { attack: Some(shared.clone()), ..Default::default() }));
        let f2 = finding("f2", "CWE-89", "https://app.example.com/x", Some(Evidence { attack: Some(shared), ..Default::default() }));
        let audits = audit_evidence(&[f1, f2], "abc123");
        assert!(audits[0].clean(), "the first use is fine");
        assert!(!audits[1].clean(), "the second, class-incompatible reuse is caught");
        assert!(matches!(audits[1].violations[0], Violation::ReusedReceipt { .. }));
    }

    #[test]
    fn the_same_receipt_for_the_same_class_is_fine() {
        // Re-testing the same class on the same endpoint is legitimate.
        let shared = ex("https://app.example.com/x", "resp");
        let f1 = finding("f1", "CWE-79", "https://app.example.com/x", Some(Evidence { attack: Some(shared.clone()), ..Default::default() }));
        let f2 = finding("f2", "CWE-79", "https://app.example.com/x", Some(Evidence { attack: Some(shared), ..Default::default() }));
        let audits = audit_evidence(&[f1, f2], "abc123");
        assert!(audits[0].clean() && audits[1].clean());
    }

    #[test]
    fn a_foreign_oast_marker_is_rejected() {
        // A callback-backed finding whose marker was not minted by this build.
        let ev = Evidence { attack: Some(ex("https://app.example.com/x", "")), callback_received: true, marker: "someoneelses-token-123".into(), ..Default::default() };
        let f = finding("f1", "CWE-918", "https://app.example.com/x", Some(ev));
        let audits = audit_evidence(&[f], "abcdef");
        assert!(matches!(audits[0].violations[0], Violation::ForeignMarker { .. }));

        // A marker carrying our sigil + build prefix passes.
        let good_marker = format!("{}ssrfabcdef1234", crate::provenance::SIGIL.to_lowercase());
        let ev2 = Evidence { attack: Some(ex("https://app.example.com/x", "")), callback_received: true, marker: good_marker, ..Default::default() };
        let f2 = finding("f2", "CWE-918", "https://app.example.com/x", Some(ev2));
        let audits2 = audit_evidence(&[f2], "abcdef");
        assert!(audits2[0].clean());
    }

    #[test]
    fn a_confirmed_finding_with_no_evidence_is_an_orphan() {
        let f = finding("f1", "CWE-79", "https://app.example.com/x", None);
        let audits = audit_evidence(&[f], "abc123");
        assert!(matches!(audits[0].violations[0], Violation::OrphanClaim));

        // Needs-review is allowed to be thin.
        let mut nr = finding("f2", "CWE-79", "https://app.example.com/x", None);
        nr.review_status = "needs-review".into();
        let audits2 = audit_evidence(&[nr], "abc123");
        assert!(audits2[0].clean());
    }

    #[test]
    fn apply_strips_proof_but_keeps_the_finding() {
        let ev = Evidence { attack: Some(ex("https://other.test/x", "boom")), ..Default::default() };
        let mut f = finding("f1", "CWE-79", "https://app.example.com/x", Some(ev));
        let audits = audit_evidence(&[f.clone()], "abc123");
        apply(&mut f, &audits[0]);
        assert!(!f.validated);
        assert_eq!(f.review_status, "rejected");
        assert!(f.confidence <= 0.2);
        assert!(f.review_reason.contains("integrity"));
    }
}
