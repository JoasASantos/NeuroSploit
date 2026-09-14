//! Replay engine — the harness re-runs an interaction itself.
//!
//! The validators in [`crate::validation`] decide from recorded artifacts, and
//! the weakest link in that chain is who recorded them. An agent reporting "the
//! payload returned a 500" is still an agent's account of what happened. Replay
//! closes that gap for the part that matters most in practice: **reproducibility**.
//! SQL injection is confirmed by a difference that repeats, and a difference
//! observed once on a dynamic page is the single most common false positive in
//! the class.
//!
//! So the harness sends the request again — itself, through its own client,
//! with its own scope guard in front of it — and keeps what came back. What it
//! produces is evidence about the target, not a description of evidence.
//!
//! Three properties this module is built around:
//!
//! - **Every request passes the guard.** [`crate::scope::ScopePolicy::check_request`]
//!   runs before the socket is opened, so replay cannot be the thing that
//!   wanders off-scope while trying to verify a finding.
//! - **Replay never mutates.** A finding proven with DELETE is not re-proven by
//!   deleting the record again. Non-idempotent verbs are refused unless the
//!   operator explicitly allowed destructive actions, and even then repeats are
//!   capped at one.
//! - **Bodies are truncated.** Evidence is stored with the run and shipped in
//!   the report; a 40MB response is not evidence, it is a liability.

use crate::scope::ScopePolicy;
use serde::{Deserialize, Serialize};
use crate::validation::{Evidence, Exchange};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// A request the engine can perform.
#[derive(Debug, Clone, Default)]
pub struct ReqSpec {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// Label for the identity these credentials belong to ("userA", "anonymous").
    pub identity: String,
}

impl ReqSpec {
    pub fn get(url: &str) -> ReqSpec {
        ReqSpec { method: "GET".into(), url: url.to_string(), ..Default::default() }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.insert(k.to_string(), v.to_string());
        self
    }
    pub fn as_identity(mut self, who: &str) -> Self {
        self.identity = who.to_string();
        self
    }
    /// Set the request body, if the finding recorded a payload separately from
    /// the recorded exchange (which stores only the response body).
    pub fn with_body(mut self, body: &str) -> Self {
        if !body.trim().is_empty() {
            self.body = body.to_string();
        }
        self
    }
    /// Verbs that change state. Replay refuses these by default: re-running a
    /// destructive request to "confirm" it means doing the damage twice.
    pub fn is_mutating(&self) -> bool {
        !matches!(self.method.to_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
    }
}

/// Response bodies above this are truncated. Big enough for a page or an API
/// payload, small enough that a run's evidence stays readable and shippable.
pub const BODY_CAP: usize = 96 * 1024;

/// Why a replay could not happen. Kept as data rather than logged and dropped,
/// because "we could not verify this" belongs in the finding's review reason.
#[derive(Debug, Clone)]
pub enum ReplayError {
    OutOfScope(String),
    Mutating(String),
    Transport(String),
    NoRequest,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::OutOfScope(r) => write!(f, "scope guard refused the replay: {r}"),
            ReplayError::Mutating(m) => write!(f, "{m} is state-changing — not replayed"),
            ReplayError::Transport(e) => write!(f, "replay failed: {e}"),
            ReplayError::NoRequest => write!(f, "nothing recorded to replay"),
        }
    }
}

pub struct ReplayEngine {
    client: reqwest::Client,
    policy: ScopePolicy,
    /// Pause between repeats so verification does not look like a flood.
    pace: Duration,
}

impl ReplayEngine {
    pub fn new(policy: ScopePolicy) -> Self {
        ReplayEngine { client: crate::probe::http_client(), policy, pace: Duration::from_millis(350) }
    }

    pub fn with_pace(mut self, pace: Duration) -> Self {
        self.pace = pace;
        self
    }

    /// Perform one request and record it.
    pub async fn send(&self, req: &ReqSpec) -> Result<Exchange, ReplayError> {
        if req.url.trim().is_empty() {
            return Err(ReplayError::NoRequest);
        }
        let decision = self.policy.check_request(&req.url, &req.method, &req.body);
        if !decision.allowed() {
            return Err(ReplayError::OutOfScope(decision.reason().to_string()));
        }
        if req.is_mutating() && !self.policy.soft.allow_destructive_methods {
            return Err(ReplayError::Mutating(req.method.to_uppercase()));
        }

        let method = reqwest::Method::from_bytes(req.method.to_uppercase().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut rb = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if !req.body.is_empty() {
            rb = rb.body(req.body.clone());
        }

        let started = Instant::now();
        let resp = rb.send().await.map_err(|e| ReplayError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let mut headers = BTreeMap::new();
        for (k, v) in resp.headers().iter() {
            // Multi-value headers (notably Set-Cookie) are joined rather than
            // dropped: the cookie validators read flags out of the whole string.
            let key = k.as_str().to_lowercase();
            let val = v.to_str().unwrap_or("").to_string();
            headers
                .entry(key)
                .and_modify(|prev: &mut String| {
                    prev.push_str("; ");
                    prev.push_str(&val);
                })
                .or_insert(val);
        }
        let content_type = headers.get("content-type").cloned().unwrap_or_default();
        let body = resp.text().await.unwrap_or_default();
        let elapsed_ms = started.elapsed().as_millis() as u64;

        Ok(Exchange {
            method: req.method.to_uppercase(),
            url: req.url.clone(),
            status,
            body: truncate(&body, BODY_CAP),
            content_type,
            elapsed_ms,
            identity: req.identity.clone(),
            headers,
            request_headers: req.headers.clone(),
        })
    }

    /// Send the same request `n` extra times, pacing between them.
    ///
    /// This is what a reproducibility rule actually needs: the SQLi validator
    /// asks for the difference to hold across repeats, and only the harness can
    /// honestly produce them.
    pub async fn repeat(&self, req: &ReqSpec, n: usize) -> (Vec<Exchange>, Vec<String>) {
        let mut out = Vec::new();
        let mut notes = Vec::new();
        if req.is_mutating() {
            notes.push(format!("{} not repeated — replaying a state-changing request would act twice", req.method.to_uppercase()));
            return (out, notes);
        }
        for i in 0..n {
            if i > 0 {
                tokio::time::sleep(self.pace).await;
            }
            match self.send(req).await {
                Ok(x) => out.push(x),
                Err(e) => {
                    notes.push(e.to_string());
                    break;
                }
            }
        }
        (out, notes)
    }

    /// Fill in what a finding's evidence is missing, without inventing any of it.
    ///
    /// Only the repeats are produced here. A baseline cannot be derived from an
    /// attack request in general — removing "the payload" from an arbitrary URL
    /// is guesswork, and a guessed baseline would silently decide the verdict.
    /// When the agent recorded one, it is re-sent so both sides of the
    /// comparison come from the same moment in the target's life.
    pub async fn enrich(&self, ev: &mut Evidence, want_repeats: usize) -> Vec<String> {
        let mut notes = Vec::new();
        let Some(attack) = ev.attack.clone() else {
            notes.push("no attack request recorded — nothing to replay".into());
            return notes;
        };
        let req = spec_of(&attack);
        if ev.repeats.len() < want_repeats {
            let need = want_repeats - ev.repeats.len();
            let (mut got, mut n) = self.repeat(&req, need).await;
            ev.repeats.append(&mut got);
            notes.append(&mut n);
        }
        if let Some(base) = ev.baseline.clone() {
            // Re-measure the baseline too: comparing a fresh attack against a
            // baseline captured an hour ago attributes ordinary drift (a new
            // banner, a rotated token) to the payload.
            match self.send(&spec_of(&base)).await {
                Ok(fresh) => ev.baseline = Some(fresh),
                Err(e) => notes.push(format!("baseline not re-measured: {e}")),
            }
        }
        ev.notes.extend(notes.iter().cloned());
        notes
    }

    /// Request the same resource as two identities — the evidence an access
    /// control rule needs, produced by the harness rather than described.
    pub async fn identity_pair(&self, url: &str, a: (&str, &str), b: (&str, &str)) -> (Option<Exchange>, Option<Exchange>, Vec<String>) {
        let mut notes = Vec::new();
        let mk = |(who, auth): (&str, &str)| {
            let mut r = ReqSpec::get(url).as_identity(who);
            if !auth.is_empty() {
                let (k, v) = auth.split_once(':').unwrap_or(("Authorization", auth));
                r = r.with_header(k.trim(), v.trim());
            }
            r
        };
        let ra = match self.send(&mk(a)).await {
            Ok(x) => Some(x),
            Err(e) => {
                notes.push(format!("identity '{}' request failed: {e}", a.0));
                None
            }
        };
        tokio::time::sleep(self.pace).await;
        let rb = match self.send(&mk(b)).await {
            Ok(x) => Some(x),
            Err(e) => {
                notes.push(format!("identity '{}' request failed: {e}", b.0));
                None
            }
        };
        (ra, rb, notes)
    }
}

// ---------------------------------------------------------------------------
// Effect layers
//
// The engagement that motivated this recorded 25 accepted POSTs and concluded
// "reset email flooding". Those are different facts at different layers, and
// the pipeline had no way to say so: a request being accepted is not a state
// change, and a state change is not a message leaving the building.
//
//   request_effect      the response: status, headers, latency, body delta
//   application_effect  something changed inside: a record, a token, a queued job
//   external_effect     something left: an email delivered, a webhook fired
//
// Each layer needs its own observation. The harness can measure the first
// directly, the second with a read-back, and the third only through a channel
// it controls (a mailbox it owns, an OOB callback). Anything it cannot observe
// is recorded as NOT OBSERVED rather than inferred — which is exactly the line
// the agent crossed.
// ---------------------------------------------------------------------------

/// Which layer an observation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectLayer {
    Request,
    Application,
    External,
}

impl EffectLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            EffectLayer::Request => "request_effect",
            EffectLayer::Application => "application_effect",
            EffectLayer::External => "external_effect",
        }
    }
}

/// What was seen at one layer — or that nothing was looked at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectObservation {
    pub layer: EffectLayer,
    /// True only when the harness itself observed it.
    pub observed: bool,
    pub detail: String,
    /// Evidence ledger ids, when the caller is building a claim set.
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl EffectObservation {
    pub fn seen(layer: EffectLayer, detail: impl Into<String>) -> Self {
        EffectObservation { layer, observed: true, detail: detail.into(), evidence: Vec::new() }
    }
    /// Not observed, with the reason. "We did not look" and "we looked and saw
    /// nothing" are both recorded here, and neither is evidence of absence of
    /// the effect — only of its demonstration.
    pub fn not_seen(layer: EffectLayer, why: impl Into<String>) -> Self {
        EffectObservation { layer, observed: false, detail: why.into(), evidence: Vec::new() }
    }
}

/// Everything observed about one interaction, layer by layer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EffectReport {
    #[serde(default)]
    pub observations: Vec<EffectObservation>,
}

impl EffectReport {
    pub fn push(&mut self, o: EffectObservation) {
        self.observations.push(o);
    }
    pub fn observed(&self, layer: EffectLayer) -> bool {
        self.observations.iter().any(|o| o.layer == layer && o.observed)
    }
    /// The deepest layer actually demonstrated. This is what a severity or an
    /// impact claim may be built on — and nothing deeper.
    pub fn deepest_observed(&self) -> Option<EffectLayer> {
        [EffectLayer::External, EffectLayer::Application, EffectLayer::Request]
            .into_iter()
            .find(|l| self.observed(*l))
    }
    /// One line per layer, for the evidence section of a report.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for layer in [EffectLayer::Request, EffectLayer::Application, EffectLayer::External] {
            let line = self
                .observations
                .iter()
                .find(|o| o.layer == layer)
                .map(|o| format!("{} {}", if o.observed { "observed:" } else { "NOT observed:" }, o.detail))
                .unwrap_or_else(|| "not examined".to_string());
            out.push_str(&format!("  {:<20} {line}\n", layer.as_str()));
        }
        out
    }
}

impl ReplayEngine {
    /// Re-run an interaction and record what it did at every layer the harness
    /// can reach.
    ///
    /// `verify` is a read-back request that reveals an application effect (the
    /// record as it now stands, the account's state, the audit endpoint).
    /// `marker` is a value expected to appear there if the write took. Without
    /// a verification request the application layer is honestly reported as
    /// unexamined — the alternative, inferring it from a 200, is the mistake
    /// this whole layering exists to prevent.
    pub async fn observe_effects(
        &self,
        action: &ReqSpec,
        verify: Option<&ReqSpec>,
        marker: Option<&str>,
    ) -> (EffectReport, Option<Exchange>) {
        let mut report = EffectReport::default();

        let before = match verify {
            Some(v) => self.send(v).await.ok(),
            None => None,
        };

        let acted = match self.send(action).await {
            Ok(x) => x,
            Err(e) => {
                report.push(EffectObservation::not_seen(EffectLayer::Request, format!("the request could not be sent: {e}")));
                report.push(EffectObservation::not_seen(EffectLayer::Application, "no request, so no application effect to look for"));
                report.push(EffectObservation::not_seen(EffectLayer::External, "no request, so no external effect to look for"));
                return (report, None);
            }
        };
        report.push(EffectObservation::seen(
            EffectLayer::Request,
            format!("{} {} → {} · {} bytes · {} ms", acted.method, acted.url, acted.status, acted.len(), acted.elapsed_ms),
        ));

        match verify {
            None => report.push(EffectObservation::not_seen(
                EffectLayer::Application,
                "no read-back was performed — a response status does not show whether state changed",
            )),
            Some(v) => match self.send(v).await {
                Err(e) => report.push(EffectObservation::not_seen(EffectLayer::Application, format!("the read-back failed: {e}"))),
                Ok(after) => {
                    let marker_hit = marker.map(|m| after.body.contains(m) && !before.as_ref().map(|b| b.body.contains(m)).unwrap_or(false));
                    match marker_hit {
                        Some(true) => report.push(EffectObservation::seen(
                            EffectLayer::Application,
                            format!("the read-back now contains the injected value ({})", marker.unwrap_or("")),
                        )),
                        Some(false) => report.push(EffectObservation::not_seen(
                            EffectLayer::Application,
                            "the read-back does not contain the injected value — the request was accepted and the change was not persisted",
                        )),
                        None => {
                            // No marker to look for: fall back to whether the
                            // resource changed at all, which is weaker and says so.
                            let changed = before
                                .as_ref()
                                .map(|b| b.status != after.status || b.body != after.body)
                                .unwrap_or(false);
                            if changed {
                                report.push(EffectObservation::seen(
                                    EffectLayer::Application,
                                    format!("the resource differs after the request ({} → {}, {} → {} bytes)", before.as_ref().map(|b| b.status).unwrap_or(0), after.status, before.as_ref().map(|b| b.len()).unwrap_or(0), after.len()),
                                ));
                            } else {
                                report.push(EffectObservation::not_seen(
                                    EffectLayer::Application,
                                    "the resource is unchanged after the request",
                                ));
                            }
                        }
                    }
                }
            },
        }

        // The harness has no mailbox and no callback listener of its own yet, so
        // it cannot see this layer. Saying that plainly is the point: an
        // unobserved external effect must never be inferred from an accepted
        // request.
        report.push(EffectObservation::not_seen(
            EffectLayer::External,
            "no channel the harness controls (mailbox, OOB callback) was watching — delivery of mail, notifications or downstream jobs was not observed",
        ));

        (report, Some(acted))
    }
}

/// Rebuild a request spec from a recorded exchange.
pub fn spec_of(x: &Exchange) -> ReqSpec {
    ReqSpec {
        method: if x.method.is_empty() { "GET".into() } else { x.method.clone() },
        url: x.url.clone(),
        headers: x.request_headers.clone(),
        body: String::new(),
        identity: x.identity.clone(),
    }
}

fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    // Cut on a character boundary, then say so — a silently clipped body would
    // make a length differential meaningless.
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[truncated at {cap} bytes by the replay engine]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ScopePolicy {
        let mut p = ScopePolicy::for_target("https://app.example.com/");
        p.soft.max_requests_per_minute = 0;
        p
    }

    #[tokio::test]
    async fn a_replay_outside_scope_never_opens_a_socket() {
        let engine = ReplayEngine::new(policy());
        // other.test resolves nowhere; if the guard let it through this would
        // fail with a transport error instead, which is the distinction.
        let err = engine.send(&ReqSpec::get("https://other.test/secret")).await.unwrap_err();
        match err {
            ReplayError::OutOfScope(r) => assert!(r.contains("outside the authorized scope"), "{r}"),
            e => panic!("expected a scope refusal, got {e}"),
        }
    }

    #[tokio::test]
    async fn a_destructive_verb_is_not_replayed_by_default() {
        let engine = ReplayEngine::new(policy());
        let req = ReqSpec { method: "DELETE".into(), url: "https://app.example.com/orders/1".into(), ..Default::default() };
        match engine.send(&req).await.unwrap_err() {
            // The scope guard gets there first, which is the stronger refusal.
            ReplayError::OutOfScope(r) => assert!(r.contains("destructive"), "{r}"),
            ReplayError::Mutating(m) => assert_eq!(m, "DELETE"),
            e => panic!("a DELETE must not be replayed: {e}"),
        }
    }

    #[tokio::test]
    async fn repeats_are_refused_for_state_changing_requests() {
        let engine = ReplayEngine::new(policy());
        let req = ReqSpec { method: "POST".into(), url: "https://app.example.com/x".into(), ..Default::default() };
        let (got, notes) = engine.repeat(&req, 3).await;
        assert!(got.is_empty());
        assert!(notes[0].contains("would act twice"), "{:?}", notes);
    }

    #[tokio::test]
    async fn enrich_reports_when_there_is_nothing_to_replay() {
        let engine = ReplayEngine::new(policy());
        let mut ev = Evidence::default();
        let notes = engine.enrich(&mut ev, 2).await;
        assert!(notes[0].contains("nothing to replay"), "{:?}", notes);
        assert!(ev.repeats.is_empty(), "the engine must not fabricate repeats");
    }

    #[test]
    fn a_truncated_body_says_that_it_was_truncated() {
        let big = "a".repeat(BODY_CAP + 500);
        let t = truncate(&big, BODY_CAP);
        assert!(t.len() < big.len());
        assert!(t.contains("truncated"), "a silently clipped body makes a length diff meaningless");
        // Multi-byte safety: cutting mid-character would panic on slicing.
        let multi = "é".repeat(BODY_CAP);
        assert!(!truncate(&multi, BODY_CAP - 1).is_empty());
    }

    #[test]
    fn a_spec_rebuilt_from_an_exchange_keeps_identity_and_request_headers() {
        let mut x = Exchange { method: "GET".into(), url: "https://app.example.com/a".into(), identity: "userB".into(), ..Default::default() };
        x.request_headers.insert("Authorization".into(), "Bearer t".into());
        let spec = spec_of(&x);
        assert_eq!(spec.identity, "userB");
        assert_eq!(spec.headers.get("Authorization").map(String::as_str), Some("Bearer t"));
    }

    #[test]
    fn mutating_verbs_are_classified_correctly() {
        for m in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(ReqSpec { method: m.into(), ..Default::default() }.is_mutating(), "{m}");
        }
        for m in ["GET", "HEAD", "OPTIONS", "get"] {
            assert!(!ReqSpec { method: m.into(), ..Default::default() }.is_mutating(), "{m}");
        }
    }
}

#[cfg(test)]
mod effect_tests {
    use super::*;

    #[test]
    fn an_accepted_request_is_not_an_application_effect() {
        let mut r = EffectReport::default();
        r.push(EffectObservation::seen(EffectLayer::Request, "POST /reset → 302"));
        r.push(EffectObservation::not_seen(EffectLayer::Application, "no read-back was performed"));
        r.push(EffectObservation::not_seen(EffectLayer::External, "no mailbox watched"));
        assert!(r.observed(EffectLayer::Request));
        assert!(!r.observed(EffectLayer::Application));
        // The deepest thing demonstrated is the request — an impact claim may
        // be built on that and nothing further.
        assert_eq!(r.deepest_observed(), Some(EffectLayer::Request));
    }

    #[test]
    fn the_summary_says_not_observed_rather_than_staying_silent() {
        let mut r = EffectReport::default();
        r.push(EffectObservation::seen(EffectLayer::Request, "25 requests accepted"));
        r.push(EffectObservation::not_seen(EffectLayer::External, "no mailbox watched"));
        let s = r.summary();
        assert!(s.contains("request_effect") && s.contains("observed:"));
        assert!(s.contains("external_effect") && s.contains("NOT observed:"));
        // A layer nobody looked at must not read as a clean result.
        assert!(s.contains("application_effect") && s.contains("not examined"));
    }

    #[test]
    fn the_deepest_observed_layer_is_the_ceiling_for_a_claim() {
        let mut r = EffectReport::default();
        r.push(EffectObservation::seen(EffectLayer::Request, "POST accepted"));
        r.push(EffectObservation::seen(EffectLayer::Application, "read-back shows the new value"));
        r.push(EffectObservation::not_seen(EffectLayer::External, "no delivery channel"));
        assert_eq!(r.deepest_observed(), Some(EffectLayer::Application));
        let empty = EffectReport::default();
        assert_eq!(empty.deepest_observed(), None);
    }

    #[tokio::test]
    async fn a_refused_request_reports_every_layer_as_unobserved() {
        let mut p = ScopePolicy::for_target("https://app.example.com/");
        p.soft.max_requests_per_minute = 0;
        let engine = ReplayEngine::new(p);
        let (report, exchange) = engine.observe_effects(&ReqSpec::get("https://other.test/x"), None, None).await;
        assert!(exchange.is_none());
        for l in [EffectLayer::Request, EffectLayer::Application, EffectLayer::External] {
            assert!(!report.observed(l), "{l:?} must not be reported as observed when nothing was sent");
        }
    }
}
