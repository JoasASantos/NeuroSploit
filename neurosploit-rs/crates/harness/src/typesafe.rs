//! TypeSafe — System One judgments as programming primitives.
//!
//! Most of the harness's expensive calls ask a text model a question that is
//! really a *decision*: is this finding confirmed, needs-review or rejected?
//! how severe is it? did the evidence actually demonstrate impact? A text model
//! answers in prose the harness then has to parse, and the answer is not
//! calibrated — "high confidence" is a word, not a number.
//!
//! TypeSafe's System One model ([Jev](https://docs.typesafe.ai)) answers those
//! as typed judgments with calibrated probabilities instead of text:
//!
//! ```text
//!   state (the finding's evidence) + a typed question
//!                    │
//!                    ▼
//!   Choice → one option + a probability distribution + confidence
//!   Score  → a position on an ordered scale + probabilities
//!   Noul   → probability a condition holds (0.0–1.0)
//! ```
//!
//! This is the right shape for adjudication and gating: a `Choice` over
//! `{confirmed, needs-review, rejected}` gives the pipeline a calibrated number
//! to gate on rather than a parsed adjective. It is **additive and optional** —
//! it never overrides a deterministic validator (evidence still rules), only
//! sharpens the confidence and the needs-review boundary. Enabled only when
//! `TYPESAFE_API_KEY` is set; absent, everything behaves exactly as before.
//!
//! Contract per the live docs: `POST https://api.typesafe.ai/v1/systemone`,
//! `Authorization: Bearer <key>`, `model: "jev-latest"`, `state` +
//! `questions` map; each answer carries the primitive's typed result.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
const DEFAULT_MODEL: &str = "jev-latest";

/// A question to evaluate against the state.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Question {
    /// Pick one of a defined set. Criteria: option -> description (or null).
    Choice {
        instructions: String,
        criteria: BTreeMap<String, Option<String>>,
    },
    /// Whether a condition holds. Returns the probability of "true".
    Noul {
        instructions: String,
        criteria: NoulCriteria,
    },
    /// A position on an ordered scale of described levels.
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct NoulCriteria {
    #[serde(rename = "true")]
    pub yes: String,
    #[serde(rename = "false")]
    pub no: String,
}

impl Question {
    pub fn choice(instructions: &str, options: &[(&str, &str)]) -> Question {
        let criteria = options.iter().map(|(k, v)| ((*k).to_string(), if v.is_empty() { None } else { Some((*v).to_string()) })).collect();
        Question::Choice { instructions: instructions.into(), criteria }
    }
    pub fn noul(instructions: &str, yes: &str, no: &str) -> Question {
        Question::Noul { instructions: instructions.into(), criteria: NoulCriteria { yes: yes.into(), no: no.into() } }
    }
    pub fn score(instructions: &str, levels: &[&str]) -> Question {
        Question::Score { instructions: instructions.into(), criteria: levels.iter().map(|s| s.to_string()).collect() }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Request {
    model: String,
    state: serde_json::Value,
    questions: BTreeMap<String, Question>,
}

/// One typed answer. Only the fields relevant to the primitive are populated.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Answer {
    /// Choice: the selected option.
    #[serde(default)]
    pub choice: Option<String>,
    /// Score: the probability-weighted value.
    #[serde(default)]
    pub score: Option<f64>,
    /// Noul: the probability the condition holds (0..1).
    #[serde(default)]
    pub noul: Option<f64>,
    /// Choice/Score: per-option probability distribution.
    #[serde(default)]
    pub probabilities: BTreeMap<String, f64>,
    /// Choice/Score: how concentrated the distribution is (not correctness).
    #[serde(default)]
    pub confidence: Option<f64>,
}

impl Answer {
    /// Probability mass on a named option (0.0 if absent).
    pub fn p(&self, option: &str) -> f64 {
        self.probabilities.get(option).copied().unwrap_or(0.0)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse {
    #[serde(default)]
    answers: BTreeMap<String, Answer>,
}

/// A TypeSafe client. Cheap to construct; holds the key and an HTTP client.
#[derive(Clone)]
pub struct TypeSafe {
    key: String,
    client: reqwest::Client,
    /// Endpoint to POST to. Defaults to TypeSafe's hosted API; a local backend
    /// (e.g. the Laya shim) is selected by setting `NEUROSPLOIT_DECISION_ENDPOINT`.
    endpoint: String,
    /// Model id sent in the request. `NEUROSPLOIT_DECISION_MODEL` overrides it.
    model: String,
    /// Whether to send `Authorization: Bearer`. A local backend needs no key.
    bearer: bool,
}

impl TypeSafe {
    /// Build from `TYPESAFE_API_KEY`. None when unset — the caller then skips
    /// System One entirely rather than failing.
    pub fn from_env() -> Option<TypeSafe> {
        let key = std::env::var("TYPESAFE_API_KEY").ok().filter(|k| !k.trim().is_empty());
        // A local decision backend (the Laya shim) is configured by its endpoint
        // and needs no key. The hosted TypeSafe path is unchanged: a key alone
        // still works exactly as before.
        let endpoint = std::env::var("NEUROSPLOIT_DECISION_ENDPOINT").ok().filter(|e| !e.trim().is_empty());
        if key.is_none() && endpoint.is_none() {
            return None;
        }
        let bearer = key.is_some();
        Some(TypeSafe {
            key: key.unwrap_or_default(),
            client: reqwest::Client::builder().timeout(Duration::from_secs(60)).build().unwrap_or_default(),
            endpoint: endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
            model: std::env::var("NEUROSPLOIT_DECISION_MODEL").ok().filter(|m| !m.trim().is_empty()).unwrap_or_else(|| DEFAULT_MODEL.to_string()),
            bearer,
        })
    }

    pub fn new(key: &str) -> TypeSafe {
        TypeSafe { key: key.to_string(), client: reqwest::Client::new(), endpoint: DEFAULT_ENDPOINT.to_string(), model: DEFAULT_MODEL.to_string(), bearer: true }
    }

    /// Which backend this instance talks to, for the run banner.
    pub fn backend_label(&self) -> String {
        if self.bearer { format!("TypeSafe ({})", self.model) } else { format!("local decision backend ({})", self.endpoint) }
    }

    /// Evaluate a set of independent questions over one state, in parallel (the
    /// API runs them together — they cannot see one another's answers).
    pub async fn evaluate(&self, state: serde_json::Value, questions: BTreeMap<String, Question>) -> Result<BTreeMap<String, Answer>, String> {
        let req = Request { model: self.model.clone(), state, questions };
        // A short retry on the documented transient codes (429/529).
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut rb = self.client.post(&self.endpoint).json(&req);
            if self.bearer { rb = rb.bearer_auth(&self.key); }
            let resp = rb.send().await;
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if matches!(status, 429 | 529) && attempt < 3 {
                        tokio::time::sleep(Duration::from_millis(400 * attempt as u64)).await;
                        continue;
                    }
                    if !r.status().is_success() {
                        let body = r.text().await.unwrap_or_default();
                        return Err(format!("typesafe HTTP {status}: {}", body.chars().take(200).collect::<String>()));
                    }
                    let parsed: ApiResponse = r.json().await.map_err(|e| format!("typesafe response parse: {e}"))?;
                    return Ok(parsed.answers);
                }
                Err(e) if attempt < 3 => {
                    tokio::time::sleep(Duration::from_millis(400 * attempt as u64)).await;
                    let _ = e;
                }
                Err(e) => return Err(format!("typesafe request failed: {e}")),
            }
        }
    }

    /// Adjudicate one finding: a calibrated `{confirmed, needs-review, rejected}`
    /// judgment over its evidence, plus a "was impact demonstrated" Noul. The
    /// state is the finding's own recorded facts — never the model's prose about
    /// it — so the judgment is over evidence, not narrative.
    pub async fn adjudicate(&self, state: serde_json::Value) -> Result<Adjudication, String> {
        let mut qs = BTreeMap::new();
        qs.insert(
            "verdict".to_string(),
            Question::choice(
                "Given ONLY the recorded request/response evidence in the state, does it deterministically demonstrate the claimed vulnerability class?",
                &[
                    ("confirmed", "the evidence demonstrates the class beyond reasonable doubt"),
                    ("needs-review", "plausible but the evidence is incomplete — a human should decide"),
                    ("rejected", "the evidence does not support the claim, or contradicts it"),
                ],
            ),
        );
        qs.insert(
            "impact_demonstrated".to_string(),
            Question::noul(
                "Does the evidence show REAL impact (data read/written, code executed, a boundary crossed), as opposed to only that a payload was reflected or an error appeared?",
                "concrete impact is shown in the evidence",
                "no impact is shown - only a mechanic or a reflection",
            ),
        );
        // Data type is a separate axis from "was impact demonstrated": a flaw
        // that exposes credentials or PII is severe by the KIND of data it
        // touched, even when the receipt is thin. Scored so the calibration can
        // consider it instead of collapsing purely on the impact Noul.
        qs.insert(
            "data_sensitivity".to_string(),
            Question::score(
                "Judging only by what the evidence shows was exposed or affected, how sensitive is that data?",
                &[
                    "nothing sensitive: only reflection, an error, or public content",
                    "internal or low-sensitivity data (ids, non-secret fields)",
                    "personal data (PII): emails, names, addresses, phone numbers",
                    "secrets: passwords, API keys, tokens, private keys, payment data",
                ],
            ),
        );
        let answers = self.evaluate(state, qs).await?;
        let verdict = answers.get("verdict").cloned().unwrap_or_default();
        let impact = answers.get("impact_demonstrated").and_then(|a| a.noul).unwrap_or(0.0);
        // Score returns a weighted position on the 0..3 ladder; normalise to 0..1.
        let data_sensitivity = answers.get("data_sensitivity").and_then(|a| a.score).map(|s| (s / 3.0).clamp(0.0, 1.0)).unwrap_or(0.0);
        Ok(Adjudication {
            verdict: verdict.choice.clone().unwrap_or_else(|| "needs-review".into()),
            p_confirmed: verdict.p("confirmed"),
            p_needs_review: verdict.p("needs-review"),
            p_rejected: verdict.p("rejected"),
            confidence: verdict.confidence.unwrap_or(0.0),
            impact_demonstrated: impact,
            data_sensitivity,
        })
    }
}

/// The calibrated result of adjudicating a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adjudication {
    pub verdict: String,
    pub p_confirmed: f64,
    pub p_needs_review: f64,
    pub p_rejected: f64,
    /// Distribution concentration — NOT correctness (per TypeSafe's docs).
    pub confidence: f64,
    /// Probability real impact was shown (0..1).
    pub impact_demonstrated: f64,
    /// Calibrated data-sensitivity (0..1): 1.0 = secrets/credentials exposed.
    /// A high value means the finding must NOT be recalibrated down just because
    /// the impact receipt was thin - the KIND of data is itself the impact.
    #[serde(default)]
    pub data_sensitivity: f64,
}

impl Adjudication {
    /// A calibrated confidence for the finding: the probability it is confirmed,
    /// tempered by whether impact was actually demonstrated. Bounded 0..1.
    pub fn calibrated_confidence(&self) -> f64 {
        (self.p_confirmed * (0.5 + 0.5 * self.impact_demonstrated)).clamp(0.0, 1.0)
    }
    /// Should this go to human review? Low separation between confirmed and the
    /// alternatives, or a rejected-leaning verdict on a claimed-confirmed one.
    pub fn wants_review(&self) -> bool {
        self.verdict == "needs-review" || (self.p_confirmed < 0.6 && self.p_rejected < 0.6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questions_serialize_to_the_documented_shape() {
        let q = Question::choice("Which?", &[("a", "first"), ("b", "")]);
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["type"], "choice");
        assert_eq!(v["criteria"]["a"], "first");
        assert!(v["criteria"]["b"].is_null(), "an empty description serializes as null per the API");

        let n = Question::noul("Holds?", "yes it does", "no it doesn't");
        let nv = serde_json::to_value(&n).unwrap();
        assert_eq!(nv["type"], "noul");
        assert_eq!(nv["criteria"]["true"], "yes it does");
        assert_eq!(nv["criteria"]["false"], "no it doesn't");

        let s = Question::score("Rate", &["low", "mid", "high"]);
        let sv = serde_json::to_value(&s).unwrap();
        assert_eq!(sv["type"], "score");
        assert_eq!(sv["criteria"][2], "high");
    }

    #[test]
    fn answers_parse_and_expose_probabilities() {
        let raw = r#"{
            "answers": {
                "verdict": {"choice":"confirmed","probabilities":{"confirmed":0.82,"needs-review":0.13,"rejected":0.05},"confidence":0.77},
                "impact_demonstrated": {"noul":0.9}
            }
        }"#;
        let parsed: ApiResponse = serde_json::from_str(raw).unwrap();
        let v = &parsed.answers["verdict"];
        assert_eq!(v.choice.as_deref(), Some("confirmed"));
        assert!((v.p("confirmed") - 0.82).abs() < 1e-9);
        assert_eq!(v.p("absent-option"), 0.0);
        assert_eq!(parsed.answers["impact_demonstrated"].noul, Some(0.9));
    }

    #[test]
    fn calibrated_confidence_folds_in_demonstrated_impact() {
        // High p_confirmed but NO demonstrated impact → confidence is held back.
        let a = Adjudication { verdict: "confirmed".into(), p_confirmed: 0.9, p_needs_review: 0.05, p_rejected: 0.05, confidence: 0.8, impact_demonstrated: 0.0, data_sensitivity: 0.0 };
        assert!((a.calibrated_confidence() - 0.45).abs() < 1e-9, "no impact halves the weight");

        // Same, with full impact → near p_confirmed.
        let b = Adjudication { impact_demonstrated: 1.0, ..a.clone() };
        assert!((b.calibrated_confidence() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn review_is_wanted_on_a_split_distribution() {
        let split = Adjudication { verdict: "confirmed".into(), p_confirmed: 0.45, p_needs_review: 0.3, p_rejected: 0.25, confidence: 0.4, impact_demonstrated: 0.5, data_sensitivity: 0.0 };
        assert!(split.wants_review(), "no option clears 0.6 — a human should look");
        let clear = Adjudication { verdict: "confirmed".into(), p_confirmed: 0.88, p_needs_review: 0.08, p_rejected: 0.04, confidence: 0.8, impact_demonstrated: 0.9, data_sensitivity: 1.0 };
        assert!(!clear.wants_review());
    }

    #[test]
    fn no_key_means_no_client() {
        // Deterministic only when the var is actually unset in the test env.
        if std::env::var("TYPESAFE_API_KEY").is_err() {
            assert!(TypeSafe::from_env().is_none());
        }
    }
}
