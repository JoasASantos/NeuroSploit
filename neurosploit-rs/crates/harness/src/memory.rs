//! Layered memory for the harness.
//!
//! An engagement is a long-running investigation, but every agent call starts
//! from a blank context window. Without a place to put what was learned, the
//! same facts get re-derived every round — the harness re-probes an endpoint it
//! already fingerprinted, re-tries a payload shape that already failed, and
//! forgets across runs entirely. The RL weights in [`crate::rl`] remember *which
//! agent* pays off; they cannot remember *what was true*.
//!
//! Four tiers, separated by what they are scoped to and how long they survive —
//! not by importance:
//!
//! | tier | scope | lives | example |
//! |------|-------|-------|---------|
//! | [`Tier::Working`] | one run | until the run ends | "`/admin` returned 302 to `/login`" |
//! | [`Tier::Engagement`] | one target | forever, decaying | "this host runs IIS 8.5 / ASP.NET 2.0" |
//! | [`Tier::Technique`] | one technique/agent | forever, decaying | "`sqli_error` lands on `.aspx` id params" |
//! | [`Tier::Reusable`] | nothing (generalized) | forever | "ASP.NET verbose errors leak the ViewState key" |
//!
//! Promotion is evidence-gated and moves *up* the table: a working memo repeated
//! within a run becomes engagement knowledge; engagement knowledge confirmed on
//! a second run becomes technique knowledge; a technique memo that holds on two
//! **different targets** is generalized into reusable knowledge with the
//! target-specific tokens stripped. Nothing is promoted on a single observation,
//! because one observation is exactly how a hallucination looks.
//!
//! Recall is scored, not exhaustive: prompts have a budget, so [`Memory::recall`]
//! ranks by term overlap, how often the memo preceded a real finding, and
//! recency, then [`Memory::prompt_block`] renders the top few as plain lines.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Which memory a memo belongs to. See the module docs for the scoping rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    Working,
    Engagement,
    Technique,
    Reusable,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Working => "working",
            Tier::Engagement => "engagement",
            Tier::Technique => "technique",
            Tier::Reusable => "reusable",
        }
    }
}

/// One remembered fact. Deliberately a *sentence*, not a struct of fields: the
/// consumer is a language model, and the thing that has to survive the round
/// trip is the claim, not a schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Memo {
    pub id: String,
    pub tier: Tier,
    /// Scope key — target key for engagement, technique id for technique,
    /// empty for reusable.
    #[serde(default)]
    pub key: String,
    pub text: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub source_run: String,
    #[serde(default)]
    pub target: String,
    /// Belief that the claim holds, 0..1.
    #[serde(default)]
    pub confidence: f64,
    /// Distinct runs that observed this.
    #[serde(default)]
    pub observations: u32,
    /// Times this memo was fed into a prompt.
    #[serde(default)]
    pub uses: u32,
    /// Times a run that recalled this memo went on to produce a finding.
    #[serde(default)]
    pub wins: u32,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub updated: u64,
}

impl Memo {
    /// Fraction of recalls that preceded a finding. Unused memos sit at the
    /// neutral 0.5 rather than 0 — never having been tried is not evidence of
    /// being wrong, and starting them at zero would bury them forever.
    pub fn success_rate(&self) -> f64 {
        if self.uses == 0 {
            0.5
        } else {
            self.wins as f64 / self.uses as f64
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercased alphanumeric terms of length ≥ 3, deduped. Used for both indexing
/// and query matching so a memo and a query are compared the same way.
pub fn terms(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in s.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.') {
        let t = raw.trim_matches(|c: char| c == '.' || c == '-' || c == '_').to_lowercase();
        if t.len() >= 3 && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Stable identity of a claim: same normalized wording = same memo, so repeating
/// an observation reinforces it instead of duplicating it.
fn fingerprint(tier: Tier, key: &str, text: &str) -> String {
    let norm: String = text
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in format!("{}|{}|{}", tier.as_str(), key, norm).bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{}-{:016x}", tier.as_str(), h)
}

/// Normalize a target into a stable engagement key: scheme, port, path, `www.`
/// and case all drop out, so `https://WWW.Example.com:443/login` and
/// `http://example.com/` are one engagement and not two.
pub fn engagement_key(target: &str) -> String {
    let t = target.trim().to_lowercase();
    let t = t.split_once("://").map(|(_, rest)| rest).unwrap_or(&t);
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    let t = t.rsplit_once(':').map(|(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h } else { t }).unwrap_or(t);
    t.trim_start_matches("www.").trim().to_string()
}

/// What to recall for.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Free text — agent prompt, objective, endpoint, whatever is at hand.
    pub text: String,
    /// Restrict engagement recall to this target (empty = any).
    pub target: String,
    /// Restrict technique recall to these ids (empty = any).
    pub techniques: Vec<String>,
    /// Tiers to search. Empty means all but [`Tier::Working`].
    pub tiers: Vec<Tier>,
    pub limit: usize,
}

/// A scored recall hit.
#[derive(Debug, Clone)]
pub struct Hit {
    pub memo: Memo,
    pub score: f64,
}

/// The four-tier store. Persisted under `<dir>/` as one file per tier; working
/// memory is written too, so a crashed run can be resumed with its scratchpad
/// intact instead of restarting cold.
#[derive(Default)]
pub struct Memory {
    dir: Option<PathBuf>,
    working: Vec<Memo>,
    engagement: BTreeMap<String, Vec<Memo>>,
    technique: BTreeMap<String, Vec<Memo>>,
    reusable: Vec<Memo>,
    /// Fingerprints seen this run — the promotion gate for working → engagement.
    seen_this_run: HashMap<String, u32>,
    /// Memo ids injected into prompts during this run, so a run that lands a
    /// finding can credit what it was told beforehand.
    recalled: Vec<String>,
}

/// Process-wide store for the current project.
///
/// Recall happens while prompts are built and reinforcement happens when the
/// run finishes — far apart in the call graph, with the async pipeline in
/// between. Two independently opened handles would each hold a stale copy and
/// the last one to save would silently discard the other's counters, so the
/// process shares one. The directory is bound on first call; later calls return
/// that same store regardless of the path passed, which is correct because one
/// CLI process serves one project.
pub fn shared(dir: impl AsRef<Path>) -> &'static std::sync::Mutex<Memory> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<Memory>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(Memory::open(dir)))
}

/// Working memory is a scratchpad, not a log: past this many memos the oldest
/// go, because a run that emits thousands of lines would otherwise turn recall
/// into a scan of its own noise.
const WORKING_CAP: usize = 400;
/// Confidence floor below which a never-useful memo is pruned on save.
const PRUNE_BELOW: f64 = 0.15;

impl Memory {
    /// In-memory only — used by tests and by callers with no project dir.
    pub fn ephemeral() -> Memory {
        Memory::default()
    }

    /// Open (or create) the store under `dir`, e.g. `.neurosploit/memory`.
    pub fn open(dir: impl AsRef<Path>) -> Memory {
        let dir = dir.as_ref().to_path_buf();
        let _ = std::fs::create_dir_all(&dir);
        let read = |name: &str| -> Option<String> { std::fs::read_to_string(dir.join(name)).ok() };
        Memory {
            working: read("working.json").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            engagement: read("engagement.json").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            technique: read("technique.json").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            reusable: read("reusable.json").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            dir: Some(dir),
            seen_this_run: HashMap::new(),
            recalled: Vec::new(),
        }
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.working.len(),
            self.engagement.values().map(|v| v.len()).sum(),
            self.technique.values().map(|v| v.len()).sum(),
            self.reusable.len(),
        )
    }

    fn bucket_mut(&mut self, tier: Tier, key: &str) -> &mut Vec<Memo> {
        match tier {
            Tier::Working => &mut self.working,
            Tier::Engagement => self.engagement.entry(key.to_string()).or_default(),
            Tier::Technique => self.technique.entry(key.to_string()).or_default(),
            Tier::Reusable => &mut self.reusable,
        }
    }

    /// Record a claim. Re-recording the same claim reinforces it (confidence
    /// rises toward 1, observation count grows) instead of adding a duplicate,
    /// which is what makes "seen twice" a meaningful promotion signal.
    pub fn remember(&mut self, tier: Tier, key: &str, text: &str, tags: &[&str], target: &str, run: &str, confidence: f64) -> String {
        let text = text.trim();
        if text.is_empty() {
            return String::new();
        }
        let id = fingerprint(tier, key, text);
        *self.seen_this_run.entry(id.clone()).or_insert(0) += 1;
        let ts = now();
        let bucket = self.bucket_mut(tier, key);
        if let Some(m) = bucket.iter_mut().find(|m| m.id == id) {
            // Bounded reinforcement: each repeat closes 35% of the remaining gap
            // to certainty, so a claim asymptotically approaches — but never
            // reaches — "known", which is the honest shape for an observation.
            m.confidence = (m.confidence + 0.35 * (1.0 - m.confidence)).clamp(0.0, 0.99);
            m.observations += 1;
            m.updated = ts;
            if m.source_run != run && !run.is_empty() {
                m.source_run = run.to_string();
            }
            for t in tags {
                if !m.tags.iter().any(|x| x == t) {
                    m.tags.push((*t).to_string());
                }
            }
            return id;
        }
        bucket.push(Memo {
            id: id.clone(),
            tier,
            key: key.to_string(),
            text: text.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            source_run: run.to_string(),
            target: target.to_string(),
            confidence: confidence.clamp(0.0, 0.99),
            observations: 1,
            uses: 0,
            wins: 0,
            created: ts,
            updated: ts,
        });
        if tier == Tier::Working && self.working.len() > WORKING_CAP {
            let drop = self.working.len() - WORKING_CAP;
            self.working.drain(0..drop);
        }
        id
    }

    /// Convenience: note something learned about the target during this run.
    pub fn note(&mut self, target: &str, run: &str, text: &str, tags: &[&str]) -> String {
        self.remember(Tier::Working, &engagement_key(target), text, tags, target, run, 0.5)
    }

    /// Rank memos against a query. Scoring blends three signals that answer
    /// three different questions: overlap ("is this about what I'm doing?"),
    /// success rate ("did acting on it ever pay off?") and recency ("is it
    /// still likely to be true?"). Confidence gates the whole thing, so a
    /// once-observed guess cannot outrank a repeatedly confirmed fact.
    pub fn recall(&self, q: &Query) -> Vec<Hit> {
        let qterms = terms(&q.text);
        let tkey = engagement_key(&q.target);
        let tiers: Vec<Tier> = if q.tiers.is_empty() {
            vec![Tier::Engagement, Tier::Technique, Tier::Reusable]
        } else {
            q.tiers.clone()
        };
        let ts = now();
        let mut hits: Vec<Hit> = Vec::new();

        let mut consider = |m: &Memo| {
            let mterms = terms(&format!("{} {}", m.text, m.tags.join(" ")));
            let overlap = if qterms.is_empty() || mterms.is_empty() {
                0.0
            } else {
                let inter = qterms.iter().filter(|t| mterms.contains(t)).count() as f64;
                inter / (qterms.len() as f64).sqrt().max(1.0) / (mterms.len() as f64).sqrt().max(1.0)
            };
            // Half-life of 30 days: a fingerprint from last week is worth more
            // than one from last quarter, but never worthless.
            let age_days = (ts.saturating_sub(m.updated)) as f64 / 86_400.0;
            let recency = 0.5f64.powf(age_days / 30.0);
            let score = m.confidence * (0.55 * overlap.min(1.0) + 0.25 * m.success_rate() + 0.20 * recency);
            if score > 0.0 {
                hits.push(Hit { memo: m.clone(), score });
            }
        };

        for tier in tiers {
            match tier {
                Tier::Working => self.working.iter().for_each(&mut consider),
                Tier::Engagement => {
                    for (k, v) in &self.engagement {
                        if tkey.is_empty() || *k == tkey {
                            v.iter().for_each(&mut consider);
                        }
                    }
                }
                Tier::Technique => {
                    for (k, v) in &self.technique {
                        if q.techniques.is_empty() || q.techniques.iter().any(|t| t == k) {
                            v.iter().for_each(&mut consider);
                        }
                    }
                }
                Tier::Reusable => self.reusable.iter().for_each(&mut consider),
            }
        }
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        let limit = if q.limit == 0 { 8 } else { q.limit };
        hits.truncate(limit);
        hits
    }

    /// Render recalled memos as a prompt section, and mark them used so their
    /// success rate can be scored against what the run finds. Returns an empty
    /// string when nothing is worth injecting — an empty "what you know" header
    /// is worse than none, it invites the model to invent the contents.
    pub fn prompt_block(&mut self, q: &Query) -> String {
        let hits = self.recall(q);
        if hits.is_empty() {
            return String::new();
        }
        let ids: Vec<String> = hits.iter().map(|h| h.memo.id.clone()).collect();
        self.mark_used(&ids);
        for id in &ids {
            if !self.recalled.contains(id) {
                self.recalled.push(id.clone());
            }
        }
        let mut out = String::from("## What NeuroSploit already knows (prior engagements)\n\nTreat as leads, not facts — verify before reporting.\n");
        for h in &hits {
            out.push_str(&format!(
                "- [{} · {:.0}%] {}\n",
                h.memo.tier.as_str(),
                h.memo.confidence * 100.0,
                h.memo.text
            ));
        }
        out
    }

    fn all_mut(&mut self) -> impl Iterator<Item = &mut Memo> {
        self.working
            .iter_mut()
            .chain(self.engagement.values_mut().flatten())
            .chain(self.technique.values_mut().flatten())
            .chain(self.reusable.iter_mut())
    }

    pub fn mark_used(&mut self, ids: &[String]) {
        for m in self.all_mut() {
            if ids.iter().any(|i| *i == m.id) {
                m.uses += 1;
            }
        }
    }

    /// Credit every memo recalled during a run that produced findings. This is
    /// what turns recall from a guess into a measurement over time.
    pub fn mark_win(&mut self, ids: &[String]) {
        for m in self.all_mut() {
            if ids.iter().any(|i| *i == m.id) {
                m.wins += 1;
                m.confidence = (m.confidence + 0.1).min(0.99);
            }
        }
    }

    /// Credit everything recalled during this run. Call it only when the run
    /// actually produced findings — that is the whole signal.
    pub fn credit_recalled(&mut self) {
        let ids = std::mem::take(&mut self.recalled);
        self.mark_win(&ids);
    }

    /// Promote what this run proved, then persist. Called once at the end of a
    /// run; `run` is the run id and `target` the engagement's target.
    ///
    /// Every step needs *independent* evidence, so nothing here can be triggered
    /// twice by one loud observation:
    /// - working → engagement: the claim recurred within the run;
    /// - engagement → technique: it also carries a technique tag and has been
    ///   observed in more than one run;
    /// - technique → reusable: it held on two different targets, and the
    ///   generalized copy has target-specific tokens stripped.
    pub fn consolidate(&mut self, target: &str, run: &str) -> (usize, usize, usize) {
        let key = engagement_key(target);
        let mut to_engagement: Vec<Memo> = Vec::new();
        for m in &self.working {
            if self.seen_this_run.get(&m.id).copied().unwrap_or(0) >= 2 || m.observations >= 2 {
                to_engagement.push(m.clone());
            }
        }
        let promoted_e = to_engagement.len();
        for m in to_engagement {
            let tags: Vec<&str> = m.tags.iter().map(|s| s.as_str()).collect();
            self.remember(Tier::Engagement, &key, &m.text, &tags, target, run, m.confidence.max(0.55));
        }
        self.working.clear();

        // engagement → technique
        let mut to_technique: Vec<(String, Memo)> = Vec::new();
        for memos in self.engagement.values() {
            for m in memos {
                if m.observations < 2 {
                    continue;
                }
                if let Some(t) = m.tags.iter().find(|t| t.starts_with("technique:") || t.starts_with("cwe:") || t.starts_with("agent:")) {
                    to_technique.push((t.clone(), m.clone()));
                }
            }
        }
        let promoted_t = to_technique.len();
        for (tech, m) in to_technique {
            let tags: Vec<&str> = m.tags.iter().map(|s| s.as_str()).collect();
            self.remember(Tier::Technique, &tech, &m.text, &tags, target, run, m.confidence);
        }

        // technique → reusable: needs two distinct targets.
        let mut to_reusable: Vec<Memo> = Vec::new();
        for memos in self.technique.values() {
            let mut by_text: HashMap<String, Vec<&Memo>> = HashMap::new();
            for m in memos {
                by_text.entry(generalize(&m.text)).or_default().push(m);
            }
            for (gen, group) in by_text {
                let mut targets: Vec<&str> = group.iter().map(|m| m.target.as_str()).filter(|t| !t.is_empty()).collect();
                targets.sort_unstable();
                targets.dedup();
                if targets.len() >= 2 {
                    let best = group.iter().map(|m| m.confidence).fold(0.0f64, f64::max);
                    let mut m = (*group[0]).clone();
                    m.text = gen;
                    m.confidence = best;
                    to_reusable.push(m);
                }
            }
        }
        let promoted_r = to_reusable.len();
        for m in to_reusable {
            let tags: Vec<&str> = m.tags.iter().map(|s| s.as_str()).collect();
            self.remember(Tier::Reusable, "", &m.text, &tags, "", run, m.confidence);
        }

        self.seen_this_run.clear();
        self.save();
        (promoted_e, promoted_t, promoted_r)
    }

    /// Drop memos that were never useful and have decayed — otherwise a store
    /// that only grows eventually recalls noise as readily as knowledge.
    pub fn decay(&mut self, factor: f64) {
        let f = factor.clamp(0.5, 1.0);
        for m in self.all_mut() {
            if m.wins == 0 {
                m.confidence *= f;
            }
        }
        let keep = |m: &Memo| m.confidence >= PRUNE_BELOW || m.wins > 0;
        self.working.retain(keep);
        self.reusable.retain(keep);
        for v in self.engagement.values_mut() {
            v.retain(keep);
        }
        for v in self.technique.values_mut() {
            v.retain(keep);
        }
        self.engagement.retain(|_, v| !v.is_empty());
        self.technique.retain(|_, v| !v.is_empty());
    }

    /// Forget by substring across every tier. Returns how many went.
    pub fn forget(&mut self, needle: &str) -> usize {
        let n = needle.to_lowercase();
        if n.is_empty() {
            return 0;
        }
        let before = self.counts();
        let drop = |m: &Memo| !(m.text.to_lowercase().contains(&n) || m.id == needle || m.key.to_lowercase() == n);
        self.working.retain(drop);
        self.reusable.retain(drop);
        for v in self.engagement.values_mut() {
            v.retain(drop);
        }
        for v in self.technique.values_mut() {
            v.retain(drop);
        }
        self.engagement.retain(|_, v| !v.is_empty());
        self.technique.retain(|_, v| !v.is_empty());
        let after = self.counts();
        self.save();
        (before.0 + before.1 + before.2 + before.3) - (after.0 + after.1 + after.2 + after.3)
    }

    pub fn save(&self) {
        let Some(dir) = &self.dir else { return };
        let _ = std::fs::create_dir_all(dir);
        let put = |name: &str, v: String| {
            let _ = std::fs::write(dir.join(name), v);
        };
        if let Ok(j) = serde_json::to_string_pretty(&self.working) {
            put("working.json", j);
        }
        if let Ok(j) = serde_json::to_string_pretty(&self.engagement) {
            put("engagement.json", j);
        }
        if let Ok(j) = serde_json::to_string_pretty(&self.technique) {
            put("technique.json", j);
        }
        if let Ok(j) = serde_json::to_string_pretty(&self.reusable) {
            put("reusable.json", j);
        }
    }

    /// Everything, newest first — for `/memory` in the REPL and the web console.
    pub fn dump(&self) -> Vec<Memo> {
        let mut all: Vec<Memo> = self
            .working
            .iter()
            .chain(self.engagement.values().flatten())
            .chain(self.technique.values().flatten())
            .chain(self.reusable.iter())
            .cloned()
            .collect();
        all.sort_by(|a, b| b.updated.cmp(&a.updated));
        all
    }
}

/// Strip target-specific tokens so a technique memo can be stated about the
/// class of system rather than the host it was first seen on. A claim that
/// still names one host is not a general lesson.
fn generalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for word in text.split_whitespace() {
        let w = word.trim_matches(|c: char| c == ',' || c == ';');
        let looks_like_host = w.contains("://")
            || (w.contains('.') && w.split('.').count() >= 3 && !w.ends_with('.'))
            || w.chars().filter(|c| *c == '.').count() >= 3;
        if looks_like_host {
            out.push_str("<target>");
        } else {
            out.push_str(word);
        }
        out.push(' ');
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_engagement_key_per_host_however_the_url_was_written() {
        assert_eq!(engagement_key("https://WWW.Example.com:443/login?x=1"), "example.com");
        assert_eq!(engagement_key("http://example.com/"), "example.com");
        assert_eq!(engagement_key("10.0.0.7"), "10.0.0.7");
    }

    #[test]
    fn repeating_a_claim_reinforces_it_instead_of_duplicating() {
        let mut m = Memory::ephemeral();
        m.note("http://t.test", "run1", "/admin returns 302 to /login", &["endpoint"]);
        m.note("http://t.test", "run1", "/admin returns 302 to /login", &["endpoint"]);
        assert_eq!(m.counts().0, 1);
        let memo = &m.working[0];
        assert_eq!(memo.observations, 2);
        assert!(memo.confidence > 0.5, "second observation must raise confidence");
    }

    #[test]
    fn a_claim_seen_once_is_not_promoted_but_a_repeat_is() {
        let mut m = Memory::ephemeral();
        m.note("http://t.test", "run1", "seen once only", &[]);
        m.note("http://t.test", "run1", "seen twice here", &[]);
        m.note("http://t.test", "run1", "seen twice here", &[]);
        let (to_eng, _, _) = m.consolidate("http://t.test", "run1");
        assert_eq!(to_eng, 1);
        let eng = &m.engagement["t.test"];
        assert_eq!(eng.len(), 1);
        assert_eq!(eng[0].text, "seen twice here");
        assert!(m.working.is_empty(), "working memory is cleared once consolidated");
    }

    #[test]
    fn technique_knowledge_generalizes_only_after_a_second_target() {
        let mut m = Memory::ephemeral();
        let claim = "verbose ASP.NET errors on https://a.example.com/x leak the stack trace";
        m.remember(Tier::Technique, "cwe:209", claim, &["cwe:209"], "https://a.example.com", "r1", 0.8);
        assert_eq!(m.consolidate("https://a.example.com", "r1").2, 0, "one target is not a general lesson");

        let claim2 = "verbose ASP.NET errors on https://b.other.org/y leak the stack trace";
        m.remember(Tier::Technique, "cwe:209", claim2, &["cwe:209"], "https://b.other.org", "r2", 0.8);
        assert!(m.consolidate("https://b.other.org", "r2").2 >= 1);
        assert!(
            m.reusable.iter().any(|r| r.text.contains("<target>")),
            "the reusable copy must not name a specific host: {:?}",
            m.reusable.iter().map(|r| &r.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recall_prefers_the_memo_that_matches_the_question() {
        let mut m = Memory::ephemeral();
        m.remember(Tier::Engagement, "t.test", "login.aspx is vulnerable to SQL injection in tbUsername", &["cwe:89"], "http://t.test", "r1", 0.9);
        m.remember(Tier::Engagement, "t.test", "the site serves a robots.txt with two entries", &["recon"], "http://t.test", "r1", 0.9);
        let hits = m.recall(&Query { text: "sql injection on login".into(), target: "http://t.test".into(), limit: 1, ..Default::default() });
        assert_eq!(hits.len(), 1);
        assert!(hits[0].memo.text.contains("SQL injection"));
    }

    #[test]
    fn an_empty_recall_injects_no_prompt_section() {
        let mut m = Memory::ephemeral();
        assert_eq!(m.prompt_block(&Query { text: "anything".into(), ..Default::default() }), "");
    }

    #[test]
    fn wins_raise_a_memo_above_an_equally_relevant_one() {
        let mut m = Memory::ephemeral();
        let a = m.remember(Tier::Reusable, "", "idor on numeric order ids", &[], "", "r1", 0.8);
        m.remember(Tier::Reusable, "", "idor on numeric invoice ids", &[], "", "r1", 0.8);
        m.mark_used(&[a.clone()]);
        m.mark_win(&[a.clone()]);
        let hits = m.recall(&Query { text: "idor numeric ids".into(), limit: 2, ..Default::default() });
        assert_eq!(hits[0].memo.id, a, "the memo with a win must rank first");
    }

    #[test]
    fn decay_drops_stale_never_useful_memos_and_keeps_proven_ones() {
        let mut m = Memory::ephemeral();
        let keep = m.remember(Tier::Reusable, "", "proven lesson", &[], "", "r1", 0.5);
        m.remember(Tier::Reusable, "", "never useful", &[], "", "r1", 0.2);
        m.mark_win(&[keep.clone()]);
        for _ in 0..6 {
            m.decay(0.7);
        }
        assert!(m.reusable.iter().any(|x| x.id == keep));
        assert!(!m.reusable.iter().any(|x| x.text == "never useful"));
    }

    #[test]
    fn forget_removes_matching_memos_from_every_tier() {
        let mut m = Memory::ephemeral();
        m.note("http://t.test", "r1", "secret token abc123 in page source", &[]);
        m.remember(Tier::Reusable, "", "secret token patterns leak in source maps", &[], "", "r1", 0.6);
        assert_eq!(m.forget("secret token"), 2);
        assert_eq!(m.counts(), (0, 0, 0, 0));
    }
}
