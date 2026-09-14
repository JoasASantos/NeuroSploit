//! Reasoning budget — deciding where the expensive thinking goes.
//!
//! A single recon round on a real engagement cost $0.52, most of it spent
//! shipping raw HTML to a frontier model so it could tell us there were six
//! script tags. That is the shape of the problem: the harness pays premium
//! rates for work that parsing does better, and then has nothing left for the
//! two endpoints that actually deserved deep reasoning.
//!
//! So compute is rationed by signal, not spread evenly:
//!
//! ```text
//!   cheap discovery  →  map  →  risk score  →  only the interesting parts
//!                                                       ↓
//!                                              expensive reasoning
//! ```
//!
//! Two knobs, deliberately separate, because they answer different questions:
//!
//! - `--budget` — *how* to spend. Eco covers ground, aggressive goes deep.
//! - `--token-limit` — *how much* there is. A ceiling, independent of strategy.
//!
//! And one rule that matters more than either: when a phase exhausts its share,
//! the run **keeps going in cheap mode** rather than stopping. A scan that dies
//! at 70% with its findings unwritten is worse than one that finishes shallow.

use serde::{Deserialize, Serialize};

/// How to spend, independent of how much there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Cover the whole surface; reason only where the signal is strong.
    Eco,
    /// Cover the surface, investigate the suspicious parts properly.
    Balanced,
    /// Multiple hypotheses, voting, retries, deep validation.
    Aggressive,
    /// No budget logic at all — the behaviour before any of this existed, and
    /// still the default when the operator asks for nothing.
    Unlimited,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s.trim().to_lowercase().as_str() {
            "eco" | "low" | "economical" | "cheap" => Mode::Eco,
            "balanced" | "medium" | "normal" => Mode::Balanced,
            "aggressive" | "full" | "deep" | "high" => Mode::Aggressive,
            "unlimited" | "off" | "none" => Mode::Unlimited,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Eco => "eco",
            Mode::Balanced => "balanced",
            Mode::Aggressive => "aggressive",
            Mode::Unlimited => "unlimited",
        }
    }
    /// Risk above which a finding earns deep reasoning.
    pub fn reasoning_threshold(self) -> f64 {
        match self {
            Mode::Eco => 0.75,
            Mode::Balanced => 0.55,
            Mode::Aggressive => 0.3,
            Mode::Unlimited => 0.0,
        }
    }
    /// How many voters to convene.
    pub fn reviewers(self) -> usize {
        match self {
            Mode::Eco => 1,
            Mode::Balanced => 2,
            Mode::Aggressive => 3,
            Mode::Unlimited => 3,
        }
    }
    /// Extra evidence-collection rounds per finding.
    pub fn evidence_rounds(self) -> usize {
        match self {
            Mode::Eco => 0,
            Mode::Balanced => 1,
            Mode::Aggressive => 2,
            Mode::Unlimited => 2,
        }
    }
}

/// Which order to work in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Order {
    /// Map everything before investigating anything.
    CoverageFirst,
    /// Investigate a promising lead as soon as it appears.
    DepthFirst,
}

/// The phases compute is divided between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Discovery,
    Mapping,
    Hypothesis,
    Investigation,
    Validation,
    Reporting,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Discovery => "discovery",
            Phase::Mapping => "mapping",
            Phase::Hypothesis => "hypothesis",
            Phase::Investigation => "investigation",
            Phase::Validation => "validation",
            Phase::Reporting => "reporting",
        }
    }
    /// Share of the total budget. Investigation gets the largest slice because
    /// that is where findings are actually made; reporting gets the smallest
    /// because rendering is deterministic work the harness does itself.
    pub fn share(self) -> f64 {
        match self {
            Phase::Discovery => 0.15,
            Phase::Mapping => 0.15,
            Phase::Hypothesis => 0.20,
            Phase::Investigation => 0.30,
            Phase::Validation => 0.15,
            Phase::Reporting => 0.05,
        }
    }
    pub fn all() -> [Phase; 6] {
        [Phase::Discovery, Phase::Mapping, Phase::Hypothesis, Phase::Investigation, Phase::Validation, Phase::Reporting]
    }
}

/// What to do with one candidate, given its signal and what is left.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effort {
    Skip,
    CheapAnalysis,
    StandardReasoning,
    DeepReasoning,
    MultiAgentValidation,
}

impl Effort {
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Skip => "skip",
            Effort::CheapAnalysis => "cheap analysis",
            Effort::StandardReasoning => "standard reasoning",
            Effort::DeepReasoning => "deep reasoning",
            Effort::MultiAgentValidation => "multi-agent validation",
        }
    }
}

/// The engagement's budget configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub mode: Mode,
    pub order: Order,
    /// Total tokens the run may spend. 0 = no ceiling.
    pub token_limit: u64,
    /// Cap on findings that get deep treatment. 0 = no cap.
    pub max_deep_tests: usize,
    /// Sample size per endpoint family (`/api/users/{id}` is tested a few
    /// times, not two thousand).
    pub sample_per_route: usize,
    /// Summarise HTTP/HTML before it reaches a model.
    pub preprocess_responses: bool,
}

impl Default for Budget {
    fn default() -> Self {
        // No flag means the behaviour that existed before budgets did.
        Budget {
            mode: Mode::Unlimited,
            order: Order::CoverageFirst,
            token_limit: 0,
            max_deep_tests: 0,
            sample_per_route: 3,
            preprocess_responses: true,
        }
    }
}

impl Budget {
    pub fn with_mode(mode: Mode) -> Self {
        let mut b = Budget { mode, ..Default::default() };
        // Sensible ceilings per mode; an explicit --token-limit overrides them.
        b.token_limit = match mode {
            Mode::Eco => 120_000,
            Mode::Balanced => 250_000,
            Mode::Aggressive => 800_000,
            Mode::Unlimited => 0,
        };
        b.max_deep_tests = match mode {
            Mode::Eco => 8,
            Mode::Balanced => 25,
            Mode::Aggressive => 60,
            Mode::Unlimited => 0,
        };
        b
    }

    pub fn summary(&self) -> String {
        format!(
            "{} · {} · {} · deep tests {} · sample/route {}",
            self.mode.as_str(),
            if self.order == Order::CoverageFirst { "coverage-first" } else { "depth-first" },
            if self.token_limit == 0 { "no token ceiling".to_string() } else { format!("{} tokens", self.token_limit) },
            if self.max_deep_tests == 0 { "unlimited".to_string() } else { self.max_deep_tests.to_string() },
            self.sample_per_route
        )
    }
}

/// Tracks spend per phase and decides how much compute a candidate earns.
#[derive(Debug)]
pub struct Governor {
    budget: Budget,
    spent: std::sync::Mutex<std::collections::HashMap<Phase, u64>>,
    deep_tests: std::sync::atomic::AtomicUsize,
}

impl Governor {
    pub fn new(budget: Budget) -> Self {
        Governor { budget, spent: std::sync::Mutex::new(Default::default()), deep_tests: Default::default() }
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    pub fn record(&self, phase: Phase, tokens: u64) {
        if let Ok(mut s) = self.spent.lock() {
            *s.entry(phase).or_insert(0) += tokens;
        }
    }

    pub fn spent(&self, phase: Phase) -> u64 {
        self.spent.lock().map(|s| s.get(&phase).copied().unwrap_or(0)).unwrap_or(0)
    }

    pub fn total_spent(&self) -> u64 {
        self.spent.lock().map(|s| s.values().sum()).unwrap_or(0)
    }

    pub fn remaining(&self) -> u64 {
        if self.budget.token_limit == 0 {
            return u64::MAX;
        }
        self.budget.token_limit.saturating_sub(self.total_spent())
    }

    /// Has this phase used its share?
    ///
    /// Exhausting a phase is not the end of the run — the caller drops to cheap
    /// mode for that phase and continues. A scan that dies at 70% with its
    /// findings unwritten is worse than one that finishes shallow.
    pub fn phase_exhausted(&self, phase: Phase) -> bool {
        if self.budget.token_limit == 0 {
            return false;
        }
        let allowance = (self.budget.token_limit as f64 * phase.share()) as u64;
        self.spent(phase) >= allowance
    }

    /// How much compute a candidate earns.
    ///
    /// `priority = risk × novelty × exploitability × uncertainty` — a finding
    /// that is severe, unseen, easy and undecided is exactly where reasoning
    /// pays, and one that is any of those to a low degree is not.
    pub fn effort_for(&self, risk: f64, novelty: f64, exploitability: f64, uncertainty: f64) -> Effort {
        if self.budget.mode == Mode::Unlimited {
            return Effort::DeepReasoning;
        }
        let priority = risk.clamp(0.0, 1.0) * novelty.clamp(0.0, 1.0) * exploitability.clamp(0.0, 1.0) * uncertainty.clamp(0.0, 1.0);
        let threshold = self.budget.mode.reasoning_threshold();

        // Out of budget: keep covering ground cheaply rather than stopping.
        if self.remaining() == 0 {
            return if priority >= threshold { Effort::CheapAnalysis } else { Effort::Skip };
        }
        // Deep work is also capped by count, so one pathological target cannot
        // consume the whole allowance on variations of a single endpoint.
        let deep_used = self.deep_tests.load(std::sync::atomic::Ordering::Relaxed);
        let deep_left = self.budget.max_deep_tests == 0 || deep_used < self.budget.max_deep_tests;

        if priority >= threshold && deep_left {
            self.deep_tests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if priority >= threshold + 0.2 && self.budget.mode == Mode::Aggressive {
                return Effort::MultiAgentValidation;
            }
            return Effort::DeepReasoning;
        }
        if priority >= threshold * 0.5 {
            Effort::StandardReasoning
        } else if priority > 0.0 {
            Effort::CheapAnalysis
        } else {
            Effort::Skip
        }
    }

    /// One line per phase, for the operator.
    pub fn report(&self) -> String {
        let mut out = format!("budget: {}\n", self.budget.summary());
        for p in Phase::all() {
            let spent = self.spent(p);
            if self.budget.token_limit == 0 {
                out.push_str(&format!("  {:<14} {spent} tokens\n", p.as_str()));
            } else {
                let allowance = (self.budget.token_limit as f64 * p.share()) as u64;
                out.push_str(&format!(
                    "  {:<14} {spent}/{allowance} tokens{}\n",
                    p.as_str(),
                    if self.phase_exhausted(p) { " (exhausted — continued in cheap mode)" } else { "" }
                ));
            }
        }
        out
    }
}

/// Collapse `/api/users/1`, `/api/users/2`, … into `/api/users/{id}`.
///
/// A crawl finds two thousand of these and the agent should reason about the
/// shape once, then sample. Reasoning per instance is the single easiest way to
/// spend a budget on nothing.
pub fn route_family(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/') {
        if seg.is_empty() {
            out.push('/');
            continue;
        }
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(&classify_segment(seg));
    }
    if out.is_empty() {
        "/".into()
    } else {
        out
    }
}

fn classify_segment(seg: &str) -> String {
    let is_digits = !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit());
    if is_digits {
        return "{id}".into();
    }
    // UUID
    let hyphens = seg.matches('-').count();
    if seg.len() == 36 && hyphens == 4 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return "{uuid}".into();
    }
    // Long hex (object ids, hashes)
    if seg.len() >= 24 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return "{hash}".into();
    }
    // Mixed alphanumeric with digits and no vowels reads as a generated slug.
    let digits = seg.chars().filter(|c| c.is_ascii_digit()).count();
    if seg.len() >= 8 && digits >= 4 && seg.chars().all(|c| c.is_ascii_alphanumeric()) {
        return "{token}".into();
    }
    seg.to_string()
}

/// Group URLs into families and keep `sample` of each.
pub fn sample_families(urls: &[String], sample: usize) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut by_family: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for u in urls {
        let path = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
        let path = path.split_once('/').map(|(_, p)| format!("/{p}")).unwrap_or_else(|| "/".into());
        let path = path.split(['?', '#']).next().unwrap_or(&path).to_string();
        by_family.entry(route_family(&path)).or_default().push(u.clone());
    }
    by_family
        .into_values()
        .flat_map(|mut v| {
            v.sort();
            v.truncate(sample.max(1));
            v
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_means_the_behaviour_that_existed_before_budgets() {
        let g = Governor::new(Budget::default());
        assert_eq!(g.budget().mode, Mode::Unlimited);
        assert_eq!(g.remaining(), u64::MAX);
        assert!(!g.phase_exhausted(Phase::Investigation));
        // Every candidate gets full treatment, whatever its signal.
        assert_eq!(g.effort_for(0.1, 0.1, 0.1, 0.1), Effort::DeepReasoning);
    }

    #[test]
    fn modes_parse_the_words_operators_type() {
        for (s, m) in [("eco", Mode::Eco), ("LOW", Mode::Eco), ("balanced", Mode::Balanced), ("full", Mode::Aggressive), ("unlimited", Mode::Unlimited)] {
            assert_eq!(Mode::parse(s), Some(m), "{s}");
        }
        assert_eq!(Mode::parse("banana"), None);
    }

    #[test]
    fn eco_reasons_only_on_strong_signal_and_aggressive_on_most() {
        let eco = Governor::new(Budget::with_mode(Mode::Eco));
        let agg = Governor::new(Budget::with_mode(Mode::Aggressive));
        // A middling candidate: worth a look, not worth the frontier model.
        let (r, n, e, u) = (0.8, 0.8, 0.8, 0.8); // priority 0.41
        assert_eq!(eco.effort_for(r, n, e, u), Effort::StandardReasoning);
        assert_eq!(agg.effort_for(r, n, e, u), Effort::DeepReasoning);
        // Multi-agent validation is reserved for a signal well past the
        // threshold — convening a panel is the most expensive thing here.
        assert_eq!(agg.effort_for(0.95, 0.95, 0.95, 0.95), Effort::MultiAgentValidation);
        // And the same strong candidate in eco mode still does not get a panel.
        assert_eq!(eco.effort_for(0.95, 0.95, 0.95, 0.95), Effort::DeepReasoning);
    }

    #[test]
    fn an_exhausted_budget_continues_cheaply_instead_of_stopping() {
        let mut b = Budget::with_mode(Mode::Balanced);
        b.token_limit = 1000;
        let g = Governor::new(b);
        g.record(Phase::Investigation, 2000);
        assert_eq!(g.remaining(), 0);
        // The strongest candidate still gets looked at — just cheaply.
        assert_eq!(g.effort_for(1.0, 1.0, 1.0, 1.0), Effort::CheapAnalysis);
        // And a weak one is dropped rather than burning what is left.
        assert_eq!(g.effort_for(0.1, 0.1, 0.1, 0.1), Effort::Skip);
    }

    #[test]
    fn a_phase_that_runs_out_is_reported_not_fatal() {
        let mut b = Budget::with_mode(Mode::Balanced);
        b.token_limit = 100_000;
        let g = Governor::new(b);
        g.record(Phase::Discovery, 20_000); // share is 15% = 15_000
        assert!(g.phase_exhausted(Phase::Discovery));
        assert!(!g.phase_exhausted(Phase::Investigation));
        assert!(g.report().contains("exhausted — continued in cheap mode"));
    }

    #[test]
    fn deep_tests_are_capped_by_count_as_well_as_tokens() {
        let mut b = Budget::with_mode(Mode::Aggressive);
        b.max_deep_tests = 2;
        let g = Governor::new(b);
        let strong = || g.effort_for(1.0, 1.0, 1.0, 1.0);
        assert_ne!(strong(), Effort::StandardReasoning);
        assert_ne!(strong(), Effort::StandardReasoning);
        // The third falls back: one pathological target must not consume the
        // whole allowance on variations of a single endpoint.
        assert_eq!(strong(), Effort::StandardReasoning);
    }

    #[test]
    fn phase_shares_add_up_to_the_whole_budget() {
        let total: f64 = Phase::all().iter().map(|p| p.share()).sum();
        assert!((total - 1.0).abs() < 1e-9, "shares sum to {total}");
    }

    #[test]
    fn route_families_collapse_ids_uuids_and_hashes() {
        assert_eq!(route_family("/api/users/1"), "/api/users/{id}");
        assert_eq!(route_family("/api/users/2000/orders/7"), "/api/users/{id}/orders/{id}");
        assert_eq!(route_family("/v1/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "/v1/o/{uuid}");
        assert_eq!(route_family("/files/5f2b8c1d9e4a7b3c6d8e1f2a"), "/files/{hash}");
        // Real path segments must survive, or the family is useless.
        assert_eq!(route_family("/api/admin/settings"), "/api/admin/settings");
    }

    #[test]
    fn sampling_keeps_a_few_of_each_family_not_a_few_overall() {
        let urls: Vec<String> = (1..=500)
            .map(|i| format!("https://t.test/api/users/{i}"))
            .chain((1..=5).map(|i| format!("https://t.test/api/orders/{i}")))
            .chain(["https://t.test/api/admin/settings".to_string()])
            .collect();
        let sampled = sample_families(&urls, 3);
        // Two families of 3, plus the singleton admin route.
        assert_eq!(sampled.len(), 7, "{sampled:?}");
        assert!(sampled.iter().any(|u| u.contains("/api/admin/settings")), "a unique route must never be sampled away");
    }
}
