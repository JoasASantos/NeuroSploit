//! CVSS — computed from evidence, not guessed by a model.
//!
//! The number on a finding decides whether someone is paged at 2am, so it has
//! to be defensible. Two failures make it not:
//!
//! 1. **A model picks the score.** Ask an LLM for "the CVSS" and it pattern-
//!    matches SQLi→9.8 whether or not anything was extracted. The number then
//!    reflects the class, not the engagement.
//! 2. **The metrics have no receipts.** `C:H` (high confidentiality impact)
//!    means data was read. If nothing shows data being read, `C:H` is a claim,
//!    not a measurement.
//!
//! So the split here is deliberate:
//!
//! ```text
//!   LLM/agent  →  proposes metrics, each pointing at an evidence id
//!   this module →  (a) recomputes the score with the FIRST v3.1 equation,
//!                      verbatim — deterministic, no model in the loop
//!                  (b) refuses any metric that raises severity without a
//!                      receipt, dropping it to the demonstrated floor
//!                  (c) keeps TWO vectors: demonstrated (what evidence proves)
//!                      and potential (what the class could reach)
//! ```
//!
//! The base-score arithmetic is the official CVSS v3.1 specification,
//! reproduced exactly and checked against FIRST's own reference vectors in the
//! tests — a score that disagrees with the calculator on first.org is a bug
//! here, by construction.

use serde::{Deserialize, Serialize};

/// Attack Vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Av { Network, Adjacent, Local, Physical }
/// Attack Complexity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ac { Low, High }
/// Privileges Required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pr { None, Low, High }
/// User Interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ui { None, Required }
/// Scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope { Unchanged, Changed }
/// Confidentiality / Integrity / Availability impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Imp { None, Low, High }

impl Av {
    fn score(self) -> f64 { match self { Av::Network => 0.85, Av::Adjacent => 0.62, Av::Local => 0.55, Av::Physical => 0.2 } }
    fn code(self) -> &'static str { match self { Av::Network => "N", Av::Adjacent => "A", Av::Local => "L", Av::Physical => "P" } }
    fn parse(c: &str) -> Option<Av> { Some(match c { "N" => Av::Network, "A" => Av::Adjacent, "L" => Av::Local, "P" => Av::Physical, _ => return None }) }
}
impl Ac {
    fn score(self) -> f64 { match self { Ac::Low => 0.77, Ac::High => 0.44 } }
    fn code(self) -> &'static str { match self { Ac::Low => "L", Ac::High => "H" } }
    fn parse(c: &str) -> Option<Ac> { Some(match c { "L" => Ac::Low, "H" => Ac::High, _ => return None }) }
}
impl Pr {
    /// PR is scope-dependent: a changed scope makes low/high privileges worth
    /// more to an attacker, so the coefficients differ.
    fn score(self, scope: Scope) -> f64 {
        match (self, scope) {
            (Pr::None, _) => 0.85,
            (Pr::Low, Scope::Unchanged) => 0.62,
            (Pr::Low, Scope::Changed) => 0.68,
            (Pr::High, Scope::Unchanged) => 0.27,
            (Pr::High, Scope::Changed) => 0.5,
        }
    }
    fn code(self) -> &'static str { match self { Pr::None => "N", Pr::Low => "L", Pr::High => "H" } }
    fn parse(c: &str) -> Option<Pr> { Some(match c { "N" => Pr::None, "L" => Pr::Low, "H" => Pr::High, _ => return None }) }
}
impl Ui {
    fn score(self) -> f64 { match self { Ui::None => 0.85, Ui::Required => 0.62 } }
    fn code(self) -> &'static str { match self { Ui::None => "N", Ui::Required => "R" } }
    fn parse(c: &str) -> Option<Ui> { Some(match c { "N" => Ui::None, "R" => Ui::Required, _ => return None }) }
}
impl Scope {
    fn code(self) -> &'static str { match self { Scope::Unchanged => "U", Scope::Changed => "C" } }
    fn parse(c: &str) -> Option<Scope> { Some(match c { "U" => Scope::Unchanged, "C" => Scope::Changed, _ => return None }) }
}
impl Imp {
    fn score(self) -> f64 { match self { Imp::None => 0.0, Imp::Low => 0.22, Imp::High => 0.56 } }
    fn code(self) -> &'static str { match self { Imp::None => "N", Imp::Low => "L", Imp::High => "H" } }
    fn parse(c: &str) -> Option<Imp> { Some(match c { "N" => Imp::None, "L" => Imp::Low, "H" => Imp::High, _ => return None }) }
}

/// A full CVSS v3.1 base vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vector {
    pub av: Av,
    pub ac: Ac,
    pub pr: Pr,
    pub ui: Ui,
    pub scope: Scope,
    pub c: Imp,
    pub i: Imp,
    pub a: Imp,
}

impl Vector {
    /// The base score, computed by the FIRST v3.1 equation. Deterministic.
    pub fn base_score(&self) -> f64 {
        // Impact Sub-Score.
        let iss = 1.0 - ((1.0 - self.c.score()) * (1.0 - self.i.score()) * (1.0 - self.a.score()));
        let impact = match self.scope {
            Scope::Unchanged => 6.42 * iss,
            Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15),
        };
        if impact <= 0.0 {
            return 0.0;
        }
        let exploitability = 8.22 * self.av.score() * self.ac.score() * self.pr.score(self.scope) * self.ui.score();
        let raw = match self.scope {
            Scope::Unchanged => (impact + exploitability).min(10.0),
            Scope::Changed => (1.08 * (impact + exploitability)).min(10.0),
        };
        roundup(raw)
    }

    /// Severity band for the score, per the FIRST qualitative scale.
    pub fn severity(&self) -> &'static str {
        band(self.base_score())
    }

    /// The canonical `CVSS:3.1/AV:…/…` string.
    pub fn vector_string(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.av.code(), self.ac.code(), self.pr.code(), self.ui.code(),
            self.scope.code(), self.c.code(), self.i.code(), self.a.code()
        )
    }

    /// Parse a `CVSS:3.1/…` vector string. Order-independent; unknown or missing
    /// metrics fail rather than default silently — a half-parsed vector would
    /// score wrong.
    pub fn parse(s: &str) -> Option<Vector> {
        let mut av = None; let mut ac = None; let mut pr = None; let mut ui = None;
        let mut scope = None; let mut c = None; let mut i = None; let mut a = None;
        for part in s.trim().split('/') {
            let (k, v) = part.split_once(':')?;
            match k.to_uppercase().as_str() {
                "CVSS" => { if !v.starts_with("3.") { return None; } }
                "AV" => av = Av::parse(v),
                "AC" => ac = Ac::parse(v),
                "PR" => pr = Pr::parse(v),
                "UI" => ui = Ui::parse(v),
                "S" => scope = Scope::parse(v),
                "C" => c = Imp::parse(v),
                "I" => i = Imp::parse(v),
                "A" => a = Imp::parse(v),
                _ => {} // temporal/environmental metrics ignored for the base
            }
        }
        Some(Vector { av: av?, ac: ac?, pr: pr?, ui: ui?, scope: scope?, c: c?, i: i?, a: a? })
    }
}

/// CVSS v3.1 roundup: the smallest number to one decimal place that is >= input.
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input as f64 / 10_000.0).floor() + 1.0) / 10.0
    }
}

/// FIRST qualitative severity bands.
pub fn band(score: f64) -> &'static str {
    match score {
        s if s == 0.0 => "None",
        s if s < 4.0 => "Low",
        s if s < 7.0 => "Medium",
        s if s < 9.0 => "High",
        _ => "Critical",
    }
}

// ===========================================================================
// Evidence-graded scoring
// ===========================================================================

/// One metric value, and the receipt behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricClaim {
    /// Metric name (`C`, `I`, `A`, `S`, …).
    pub metric: String,
    /// The proposed value (`H`, `L`, `N`, `C`, `U`, …).
    pub value: String,
    /// Evidence id that supports it, if any. A raising value with no receipt is
    /// what gets refused.
    #[serde(default)]
    pub evidence_id: Option<String>,
    /// Why this value — recorded so the score is auditable metric-by-metric.
    #[serde(default)]
    pub justification: String,
}

/// The evidence-graded result for a finding: two scores and what was uncertain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graded {
    /// What the evidence actually demonstrates. This is the reported score.
    pub demonstrated: Vector,
    pub demonstrated_score: f64,
    pub demonstrated_severity: String,
    /// What the class could reach if fully exploited — context, not the number.
    pub potential: Vector,
    pub potential_score: f64,
    pub potential_severity: String,
    /// Metrics whose raising value had no receipt and were dropped to the
    /// demonstrated floor. Non-empty means the finding needs human review of
    /// the score, not that it is wrong.
    pub uncertain: Vec<String>,
}

impl Graded {
    /// Does the score need a human's eye?
    pub fn needs_review(&self) -> bool {
        !self.uncertain.is_empty()
    }
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{:.1} {} demonstrated ({})",
            self.demonstrated_score, self.demonstrated_severity, self.demonstrated.vector_string()
        );
        if (self.potential_score - self.demonstrated_score).abs() > 0.05 {
            s.push_str(&format!(" · potential {:.1} {}", self.potential_score, self.potential_severity));
        }
        if !self.uncertain.is_empty() {
            s.push_str(&format!(" · unproven metric(s) dropped: {}", self.uncertain.join(", ")));
        }
        s
    }
}

/// Grade a proposed vector against the evidence behind each impact metric.
///
/// `has_evidence(metric)` answers "is there a receipt that this metric's value
/// is real?" — the caller wires it to the finding's evidence. Impact metrics
/// (C/I/A) that claim `High` or `Low` without a receipt are dropped to `None`
/// in the *demonstrated* vector, while the *potential* vector keeps them. The
/// gap between the two is exactly "what we could show" versus "what this class
/// can do", which is the distinction a scanner that prints one number loses.
pub fn grade<F>(proposed: Vector, has_evidence: F) -> Graded
where
    F: Fn(&str) -> bool,
{
    let mut demonstrated = proposed;
    let mut uncertain = Vec::new();
    for (name, value) in [("C", proposed.c), ("I", proposed.i), ("A", proposed.a)] {
        if value != Imp::None && !has_evidence(name) {
            uncertain.push(format!("{name}:{}", value.code()));
            match name {
                "C" => demonstrated.c = Imp::None,
                "I" => demonstrated.i = Imp::None,
                "A" => demonstrated.a = Imp::None,
                _ => {}
            }
        }
    }
    let d = demonstrated.base_score();
    let p = proposed.base_score();
    Graded {
        demonstrated,
        demonstrated_score: d,
        demonstrated_severity: band(d).into(),
        potential: proposed,
        potential_score: p,
        potential_severity: band(p).into(),
        uncertain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vector { Vector::parse(s).unwrap_or_else(|| panic!("parse {s}")) }

    #[test]
    fn base_scores_match_the_first_reference_vectors() {
        // These are the canonical scores from first.org's own calculator.
        assert_eq!(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").base_score(), 9.8);
        assert_eq!(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").base_score(), 6.1); // reflected XSS
        assert_eq!(v("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N").base_score(), 3.1);
        assert_eq!(v("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").base_score(), 7.8); // local privesc
        assert_eq!(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").base_score(), 7.5); // DoS
        assert_eq!(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").base_score(), 10.0); // scope-changed RCE
        assert_eq!(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N").base_score(), 5.3); // info leak
    }

    #[test]
    fn zero_impact_is_zero() {
        assert_eq!(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").base_score(), 0.0);
        assert_eq!(band(0.0), "None");
    }

    #[test]
    fn vector_string_roundtrips() {
        let s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
        assert_eq!(v(s).vector_string(), s);
    }

    #[test]
    fn bands_follow_the_first_scale() {
        assert_eq!(band(3.9), "Low");
        assert_eq!(band(4.0), "Medium");
        assert_eq!(band(6.9), "Medium");
        assert_eq!(band(7.0), "High");
        assert_eq!(band(8.9), "High");
        assert_eq!(band(9.0), "Critical");
    }

    #[test]
    fn a_partial_vector_refuses_to_parse() {
        // Missing A: — better to fail than to score a guess.
        assert!(Vector::parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H").is_none());
        assert!(Vector::parse("nonsense").is_none());
    }

    #[test]
    fn grading_drops_impact_without_a_receipt() {
        // SQLi proposed as C:H/I:H (full read+write) but only the read (C) has
        // a receipt. The demonstrated score keeps C, drops I.
        let proposed = v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
        let g = grade(proposed, |m| m == "C"); // only C has evidence
        assert!(g.needs_review());
        assert!(g.uncertain.contains(&"I:H".to_string()));
        assert_eq!(g.demonstrated.i, Imp::None);
        assert_eq!(g.demonstrated.c, Imp::High);
        // Demonstrated is lower than potential — the gap is the unproven write.
        assert!(g.demonstrated_score < g.potential_score);
    }

    #[test]
    fn grading_with_full_evidence_keeps_the_score() {
        let proposed = v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        let g = grade(proposed, |_| true);
        assert!(!g.needs_review());
        assert_eq!(g.demonstrated_score, 9.8);
        assert_eq!(g.demonstrated_score, g.potential_score);
    }

    #[test]
    fn sqli_without_any_extraction_is_not_critical() {
        // The article's exact example: SQLi proven (injection works) but
        // nothing extracted → no impact receipt → demonstrated impact is None,
        // so the number is NOT 9.8.
        let proposed = v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        let g = grade(proposed, |_| false); // no impact receipts at all
        assert_eq!(g.demonstrated.c, Imp::None);
        assert_eq!(g.demonstrated_score, 0.0, "class alone must not manufacture a critical");
        assert_eq!(g.potential_score, 9.8, "the potential is still recorded as context");
        assert_eq!(g.uncertain.len(), 3);
    }
}
