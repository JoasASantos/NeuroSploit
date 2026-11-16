//! Cold-node digests — keep the planner's context bounded on long runs.
//!
//! Inspired by Artex's "cold graph" compaction. The exploration graph only
//! grows; after hundreds of intents the planner prompt would be dominated by
//! settled history (completed probes, negative results, old facts). This module
//! classifies nodes as *hot* (still relevant to the next decision) or *cold*
//! (settled and untouched for a while), groups connected cold nodes, and lets a
//! caller replace each group with a short *digest* in prompts.
//!
//! Design rules:
//! - Pure and deterministic: no I/O, no LLM. The caller supplies the digest
//!   body (from an LLM via [`digest_prompt`], or [`heuristic_digest`] as a
//!   zero-cost fallback), so this is testable and works offline.
//! - Non-destructive: the graph is never mutated. Digests are an overlay held in
//!   [`DigestState`]; the full graph stays on disk for the report and audit.
//! - Findings, goals, pending work and unactioned hints are always hot, so a
//!   digest can never hide something the planner still has to act on.
//! - Commit-time liveness recheck: a member that became hot while a digest was
//!   being generated is dropped from the digest instead of being hidden.

use crate::exploration_graph::{ExplorationGraph, ExplorationKind, ExplorationNode, ExplorationStatus};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ColdParams {
    /// A settled node becomes cold after this many planner rounds untouched.
    pub cold_after_rounds: u64,
    /// Groups smaller than this are left alone (a digest must save space).
    pub min_group: usize,
    /// Max member snippets quoted by the heuristic digest.
    pub max_quoted: usize,
}

impl Default for ColdParams {
    fn default() -> Self {
        Self { cold_after_rounds: 3, min_group: 4, max_quoted: 6 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub id: String,
    pub members: Vec<String>,
    pub body: String,
    /// Fingerprint of the members at creation; used to reuse a body when a
    /// later regroup produces the same set.
    pub signature: String,
    pub round_made: u64,
}

/// A candidate group of cold nodes awaiting a digest body.
#[derive(Debug, Clone)]
pub struct ColdGroup {
    pub members: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DigestState {
    pub round: u64,
    last_touch: HashMap<String, u64>,
    last_status: HashMap<String, ExplorationStatus>,
    pub digests: Vec<Digest>,
    params: ColdParams,
    #[serde(default)]
    last_version: u64,
}

fn is_settled(n: &ExplorationNode) -> bool {
    match n.kind {
        // Never settle: these drive the planner's next decision.
        ExplorationKind::Goal | ExplorationKind::Finding | ExplorationKind::Hint => false,
        ExplorationKind::Intent => matches!(
            n.status,
            ExplorationStatus::Completed | ExplorationStatus::Failed | ExplorationStatus::Superseded
        ),
        ExplorationKind::Fact | ExplorationKind::Negative => true,
    }
}

fn sig_of(nodes: &[&ExplorationNode]) -> String {
    let mut h = DefaultHasher::new();
    for n in nodes {
        n.id.hash(&mut h);
        (n.status as u8).hash(&mut h);
        n.content.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

impl DigestState {
    pub fn new() -> Self { Self::default() }

    pub fn with_params(params: ColdParams) -> Self { Self { params, ..Self::default() } }

    /// Advance a round only when the graph actually changed, so many prompt
    /// builds against an unchanged graph do not age nodes artificially.
    /// Returns true if a round was run.
    pub fn maintain_if_changed(&mut self, g: &ExplorationGraph) -> bool {
        if self.round > 0 && g.version == self.last_version { return false; }
        self.last_version = g.version;
        self.maintain(g);
        true
    }

    /// Cheap bookkeeping, once per planner round. Never calls an LLM.
    /// Nodes that are new or changed status are "touched" (kept hot).
    pub fn maintain(&mut self, g: &ExplorationGraph) {
        self.round += 1;
        for n in &g.nodes {
            let changed = self.last_status.get(&n.id) != Some(&n.status);
            if changed || !self.last_touch.contains_key(&n.id) {
                self.last_touch.insert(n.id.clone(), self.round);
                self.last_status.insert(n.id.clone(), n.status);
            }
        }
        // A digest covering a node that revived must be invalidated.
        let hot_now: HashSet<String> = self.hot_ids(g, &self.params.clone());
        self.digests.retain(|d| !d.members.iter().any(|m| hot_now.contains(m)));
    }

    fn covered(&self) -> HashSet<&str> {
        self.digests.iter().flat_map(|d| d.members.iter().map(|s| s.as_str())).collect()
    }

    fn is_cold(&self, n: &ExplorationNode, p: &ColdParams) -> bool {
        if !is_settled(n) { return false; }
        let touched = self.last_touch.get(&n.id).copied().unwrap_or(self.round);
        self.round.saturating_sub(touched) >= p.cold_after_rounds
    }

    fn hot_ids(&self, g: &ExplorationGraph, p: &ColdParams) -> HashSet<String> {
        g.nodes.iter().filter(|n| !self.is_cold(n, p)).map(|n| n.id.clone()).collect()
    }

    /// Group connected cold nodes not yet covered by a digest. Siblings that
    /// share a parent are joined even if not directly linked, so many small
    /// probes under one intent collapse into one group.
    pub fn cold_groups(&self, g: &ExplorationGraph, p: &ColdParams) -> Vec<ColdGroup> {
        let covered = self.covered();
        let cold: BTreeMap<&str, &ExplorationNode> = g.nodes.iter()
            .filter(|n| self.is_cold(n, p) && !covered.contains(n.id.as_str()))
            .map(|n| (n.id.as_str(), n))
            .collect();
        // union-find over cold ids
        let ids: Vec<&str> = cold.keys().copied().collect();
        let idx: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, s)| (*s, i)).collect();
        let mut parent: Vec<usize> = (0..ids.len()).collect();
        fn find(p: &mut Vec<usize>, x: usize) -> usize {
            let mut r = x;
            while p[r] != r { r = p[r]; }
            let mut c = x;
            while p[c] != r { let n = p[c]; p[c] = r; c = n; }
            r
        }
        let mut union = |a: usize, b: usize, parent: &mut Vec<usize>| {
            let (ra, rb) = (find(parent, a), find(parent, b));
            if ra != rb { parent[ra] = rb; }
        };
        let mut by_parent: HashMap<&str, Vec<usize>> = HashMap::new();
        for e in &g.edges {
            let (f, t) = (e.from.as_str(), e.to.as_str());
            if let (Some(&a), Some(&b)) = (idx.get(f), idx.get(t)) { union(a, b, &mut parent); }
            if let Some(&b) = idx.get(t) { by_parent.entry(f).or_default().push(b); }
        }
        for kids in by_parent.values() {
            for w in kids.windows(2) { union(w[0], w[1], &mut parent); }
        }
        let mut comps: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
        for (i, id) in ids.iter().enumerate() {
            let r = find(&mut parent, i);
            comps.entry(r).or_default().push(id);
        }
        comps.into_values()
            .filter(|m| m.len() >= p.min_group)
            .map(|m| {
                let nodes: Vec<&ExplorationNode> = m.iter().map(|id| cold[id]).collect();
                ColdGroup { members: m.iter().map(|s| s.to_string()).collect(), signature: sig_of(&nodes) }
            })
            .collect()
    }

    /// Commit a digest body for a group. Members that turned hot since the
    /// group was computed are dropped; returns None if the group fell below
    /// `min_group` or the body is empty.
    pub fn commit(&mut self, g: &ExplorationGraph, group: &ColdGroup, body: &str, p: &ColdParams) -> Option<String> {
        let body = body.trim();
        if body.is_empty() { return None; }
        let live: Vec<String> = group.members.iter()
            .filter(|id| g.nodes.iter().find(|n| &n.id == *id).map_or(false, |n| self.is_cold(n, p)))
            .cloned()
            .collect();
        if live.len() < p.min_group { return None; }
        let id = format!("digest-{}", self.digests.len());
        self.digests.push(Digest {
            id: id.clone(), members: live, body: body.to_string(),
            signature: group.signature.clone(), round_made: self.round,
        });
        Some(id)
    }

    /// Reuse an existing digest body when a regroup yields an identical set.
    pub fn reusable(&self, group: &ColdGroup) -> Option<&Digest> {
        self.digests.iter().find(|d| d.signature == group.signature)
    }

    /// Prompt overlay: digests for the cold past, node lines only for the rest.
    pub fn compact_summary(&self, g: &ExplorationGraph, max_hot_lines: usize) -> String {
        let covered = self.covered();
        let mut s = String::from("EXPLORATION STATE (compacted):\n");
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
        for n in &g.nodes { *kinds.entry(format!("{:?}", n.kind)).or_default() += 1; }
        for (k, c) in &kinds { s.push_str(&format!("  {k}: {c}\n")); }
        if !self.digests.is_empty() {
            s.push_str(&format!("  Settled history ({} digests, {} nodes folded):\n",
                self.digests.len(), covered.len()));
            for d in &self.digests {
                s.push_str(&format!("    [{}] {}\n", d.id, d.body.replace('\n', " ")));
            }
        }
        let hot: Vec<&ExplorationNode> = g.nodes.iter().filter(|n| !covered.contains(n.id.as_str())).collect();
        s.push_str(&format!("  Live nodes: {}\n", hot.len()));
        for n in hot.iter().rev().take(max_hot_lines) {
            let c: String = n.content.chars().take(100).collect();
            s.push_str(&format!("    - {} {:?}/{:?}: {}\n", n.id, n.kind, n.status, c));
        }
        s
    }
}

/// Prompt asking an LLM to fold a cold group into one digest.
pub fn digest_prompt(g: &ExplorationGraph, group: &ColdGroup) -> String {
    let mut s = String::from(
        "Compress these SETTLED pentest exploration nodes into a digest of at most 4 lines.\n\
         Keep: what was tested, on which asset, and the outcome (including negative results, so they are not retried).\n\
         Drop: raw payloads, repetition, anything not needed to avoid redoing work. Output the digest only.\n\nNODES:\n");
    for id in &group.members {
        if let Some(n) = g.nodes.iter().find(|n| &n.id == id) {
            let c: String = n.content.chars().take(240).collect();
            s.push_str(&format!("- [{:?}/{:?}] {}\n", n.kind, n.status, c));
        }
    }
    s
}

/// Zero-cost fallback digest: counts plus a few quoted members. Always safe.
pub fn heuristic_digest(g: &ExplorationGraph, group: &ColdGroup, p: &ColdParams) -> String {
    let nodes: Vec<&ExplorationNode> = group.members.iter()
        .filter_map(|id| g.nodes.iter().find(|n| &n.id == id)).collect();
    let (mut neg, mut fact, mut done, mut failed) = (0, 0, 0, 0);
    for n in &nodes {
        match (n.kind, n.status) {
            (ExplorationKind::Negative, _) => neg += 1,
            (ExplorationKind::Fact, _) => fact += 1,
            (ExplorationKind::Intent, ExplorationStatus::Failed) => failed += 1,
            (ExplorationKind::Intent, _) => done += 1,
            _ => {}
        }
    }
    let mut quoted = BTreeSet::new();
    for n in nodes.iter().filter(|n| n.kind == ExplorationKind::Negative || n.kind == ExplorationKind::Intent) {
        if quoted.len() >= p.max_quoted { break; }
        quoted.insert(n.content.chars().take(70).collect::<String>());
    }
    format!("{} settled nodes ({} intents done, {} failed, {} negatives, {} facts). Examples: {}",
        nodes.len(), done, failed, neg, fact,
        quoted.into_iter().collect::<Vec<_>>().join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintain_if_changed_ages_only_on_graph_change() {
        let mut g = graph_with_settled(5);
        let mut st = DigestState::new();
        assert!(st.maintain_if_changed(&g));
        assert!(!st.maintain_if_changed(&g));
        assert_eq!(st.round, 1);
        g.add_hint("lead", "exp-0", "w");
        assert!(st.maintain_if_changed(&g));
        assert_eq!(st.round, 2);
    }

    fn graph_with_settled(n: usize) -> ExplorationGraph {
        let mut g = ExplorationGraph::new();
        let goal = g.add_goal("test auth", "planner");
        let intent = g.add_intent("probe login", &goal, "planner");
        for i in 0..n { g.add_negative(&format!("param {i} not injectable"), &intent, "w"); }
        g.set_status(&intent, ExplorationStatus::Completed);
        g
    }

    #[test]
    fn fresh_nodes_are_hot_then_go_cold() {
        let g = graph_with_settled(5);
        let mut st = DigestState::new();
        let p = ColdParams::default();
        st.maintain(&g);
        assert!(st.cold_groups(&g, &p).is_empty(), "just-touched nodes must be hot");
        for _ in 0..p.cold_after_rounds { st.maintain(&g); }
        let groups = st.cold_groups(&g, &p);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].members.len() >= 5);
    }

    #[test]
    fn findings_goals_and_pending_never_cold() {
        let mut g = graph_with_settled(5);
        let f = g.add_finding("SQLi in /login", "exp-1", "w");
        let _pending = g.add_intent("probe more", "exp-0", "planner");
        let mut st = DigestState::new();
        for _ in 0..10 { st.maintain(&g); }
        let p = ColdParams::default();
        let all: Vec<String> = st.cold_groups(&g, &p).into_iter().flat_map(|c| c.members).collect();
        assert!(!all.contains(&f));
        assert!(!all.contains(&"exp-0".to_string()));
    }

    #[test]
    fn commit_overlay_shrinks_summary_and_keeps_graph() {
        let g = graph_with_settled(8);
        let mut st = DigestState::new();
        let p = ColdParams::default();
        for _ in 0..5 { st.maintain(&g); }
        let before = st.compact_summary(&g, 50).len();
        let grp = st.cold_groups(&g, &p).remove(0);
        let body = heuristic_digest(&g, &grp, &p);
        assert!(st.commit(&g, &grp, &body, &p).is_some());
        let after = st.compact_summary(&g, 50);
        assert!(after.len() < before);
        assert!(after.contains("digest-0"));
        assert_eq!(g.nodes.len(), 10, "graph must not be mutated");
    }

    #[test]
    fn revived_member_invalidates_digest() {
        let mut g = graph_with_settled(6);
        let mut st = DigestState::new();
        let p = ColdParams::default();
        for _ in 0..5 { st.maintain(&g); }
        let grp = st.cold_groups(&g, &p).remove(0);
        st.commit(&g, &grp, "folded", &p).unwrap();
        // A negative result gets re-opened (status change = touched = hot).
        g.set_status("exp-3", ExplorationStatus::InProgress);
        st.maintain(&g);
        assert!(st.digests.is_empty());
    }

    #[test]
    fn empty_body_or_tiny_group_rejected() {
        let g = graph_with_settled(2);
        let mut st = DigestState::new();
        let p = ColdParams::default();
        for _ in 0..5 { st.maintain(&g); }
        assert!(st.cold_groups(&g, &p).is_empty());
        let fake = ColdGroup { members: vec!["exp-2".into()], signature: "x".into() };
        assert!(st.commit(&g, &fake, "x", &p).is_none());
        assert!(st.commit(&g, &fake, "  ", &p).is_none());
    }
}
