//! The attack knowledge graph: what was learned about a target, as a graph.
//!
//! [`crate::attack_graph`] maps a finding to OWASP/MITRE/stage and draws it.
//! That is a *per-run view*. This module is the durable structure underneath:
//! typed entities (asset, endpoint, weakness, technique, finding, account,
//! credential, impact) joined by typed, weighted, provenance-carrying edges, so
//! the harness can answer questions a flat finding list cannot —
//!
//! - which endpoint accumulated the most distinct weaknesses across runs;
//! - which credential a finding actually yielded, and what that credential then
//!   unlocked;
//! - what paths run from the asset to an impact node, ranked by how likely and
//!   how damaging they are;
//! - what the frontier is: entities we have observed but never proved anything
//!   about — the natural next targets for chaining.
//!
//! ## Inferred edges are marked as inferred
//!
//! Agents only sometimes populate `chains_from`. Without it a "chain" view
//! degenerates into a fan of unconnected findings, so this module also *infers*
//! progression edges between kill-chain stages. Those carry `inferred: true` and
//! a lower probability, and every renderer draws them differently, because an
//! inferred edge is a hypothesis about an attack path — presenting it as a
//! proven one would be the graph lying about its own evidence.

use crate::types::Finding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    Asset,
    Endpoint,
    Tech,
    Weakness,
    Technique,
    Finding,
    Account,
    Credential,
    Impact,
}

impl NodeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeKind::Asset => "asset",
            NodeKind::Endpoint => "endpoint",
            NodeKind::Tech => "tech",
            NodeKind::Weakness => "weakness",
            NodeKind::Technique => "technique",
            NodeKind::Finding => "finding",
            NodeKind::Account => "account",
            NodeKind::Credential => "credential",
            NodeKind::Impact => "impact",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    /// asset → endpoint
    Exposes,
    /// asset → tech
    Runs,
    /// endpoint → weakness
    Vulnerable,
    /// finding → weakness (this finding proves that weakness)
    Proves,
    /// finding → endpoint (where it was proven)
    ObservedOn,
    /// finding → technique (MITRE)
    Uses,
    /// finding → finding (attack path)
    Chains,
    /// finding → account/credential
    Grants,
    /// finding → impact
    Leads,
}

impl EdgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeKind::Exposes => "exposes",
            EdgeKind::Runs => "runs",
            EdgeKind::Vulnerable => "vulnerable",
            EdgeKind::Proves => "proves",
            EdgeKind::ObservedOn => "observed-on",
            EdgeKind::Uses => "uses",
            EdgeKind::Chains => "chains",
            EdgeKind::Grants => "grants",
            EdgeKind::Leads => "leads",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
    /// Run ids that touched this node — provenance, and the "how often" signal.
    #[serde(default)]
    pub runs: BTreeSet<String>,
    #[serde(default)]
    pub first_seen: u64,
    #[serde(default)]
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    /// Confidence that the relation holds, 0..1.
    #[serde(default)]
    pub p: f64,
    /// True when the harness derived this edge rather than an agent asserting it.
    #[serde(default)]
    pub inferred: bool,
    #[serde(default)]
    pub runs: BTreeSet<String>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    pub nodes: BTreeMap<String, Node>,
    pub edges: Vec<Edge>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sev_weight(sev: &str) -> f64 {
    match sev.to_lowercase().as_str() {
        s if s.starts_with("crit") => 1.0,
        s if s.starts_with("high") => 0.75,
        s if s.starts_with("med") => 0.5,
        s if s.starts_with("low") => 0.25,
        _ => 0.1,
    }
}

/// Kill-chain progression order. An attack moves down this list; an edge that
/// would move *up* it is not progression and is never inferred.
pub const STAGES: &[&str] = &[
    "recon",
    "discovery",
    "initial-access",
    "execution",
    "persistence",
    "privesc",
    "credential-access",
    "lateral",
    "collection",
    "exfil",
    "impact",
];

pub fn stage_rank(s: &str) -> usize {
    STAGES.iter().position(|x| *x == s).unwrap_or(STAGES.len())
}

/// Strip the query string and normalize the host so two spellings of one URL
/// collapse into a single endpoint node.
fn endpoint_key(url: &str) -> String {
    let u = url.trim();
    let no_scheme = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    let path = no_scheme.split(['?', '#']).next().unwrap_or(no_scheme);
    let path = path.trim_end_matches('/');
    let path = path.trim_start_matches("www.");
    if path.is_empty() {
        no_scheme.to_string()
    } else {
        path.to_lowercase()
    }
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: impl AsRef<Path>) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(j) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, j);
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    fn upsert(&mut self, id: &str, kind: NodeKind, label: &str, run: &str) -> String {
        let ts = now();
        let n = self.nodes.entry(id.to_string()).or_insert_with(|| Node {
            id: id.to_string(),
            kind,
            label: label.to_string(),
            meta: BTreeMap::new(),
            runs: BTreeSet::new(),
            first_seen: ts,
            last_seen: ts,
        });
        n.last_seen = ts;
        if !run.is_empty() {
            n.runs.insert(run.to_string());
        }
        if n.label.is_empty() {
            n.label = label.to_string();
        }
        id.to_string()
    }

    fn meta(&mut self, id: &str, k: &str, v: &str) {
        if v.is_empty() {
            return;
        }
        if let Some(n) = self.nodes.get_mut(id) {
            n.meta.insert(k.to_string(), v.to_string());
        }
    }

    /// Add or reinforce an edge. Re-observing an edge raises its probability
    /// toward certainty rather than appending a duplicate, and an edge first
    /// inferred but later asserted by an agent stops being marked inferred.
    pub fn link(&mut self, from: &str, to: &str, kind: EdgeKind, p: f64, inferred: bool, run: &str) {
        if from == to || !self.nodes.contains_key(from) || !self.nodes.contains_key(to) {
            return;
        }
        if let Some(e) = self.edges.iter_mut().find(|e| e.from == from && e.to == to && e.kind == kind) {
            e.p = (e.p + 0.3 * (p.max(e.p) - e.p)).clamp(0.0, 0.99);
            e.inferred = e.inferred && inferred;
            if !run.is_empty() {
                e.runs.insert(run.to_string());
            }
            return;
        }
        let mut runs = BTreeSet::new();
        if !run.is_empty() {
            runs.insert(run.to_string());
        }
        self.edges.push(Edge { from: from.into(), to: to.into(), kind, p: p.clamp(0.0, 0.99), inferred, runs });
    }

    /// Fold one run's findings into the graph.
    pub fn ingest(&mut self, target: &str, run: &str, findings: &[Finding]) {
        let akey = crate::memory::engagement_key(target);
        let asset = self.upsert(&format!("asset:{akey}"), NodeKind::Asset, if akey.is_empty() { target } else { &akey }, run);

        for f in findings {
            let fid = self.upsert(
                &format!("find:{}:{}", run, f.id),
                NodeKind::Finding,
                if f.title.is_empty() { &f.id } else { &f.title },
                run,
            );
            self.meta(&fid, "severity", &f.severity);
            self.meta(&fid, "cwe", &f.cwe);
            self.meta(&fid, "stage", &f.stage);
            self.meta(&fid, "owasp", &f.owasp);
            self.meta(&fid, "mitre", &f.mitre);
            self.meta(&fid, "exploitability", &f.exploitability);
            self.meta(&fid, "agent", &f.agent);
            self.meta(&fid, "endpoint", &f.endpoint);
            self.meta(&fid, "confidence", &format!("{:.2}", f.confidence));
            self.meta(&fid, "review_status", &f.review_status);
            self.meta(&fid, "finding_id", &f.id);

            if !f.endpoint.is_empty() {
                let ek = endpoint_key(&f.endpoint);
                let ep = self.upsert(&format!("ep:{ek}"), NodeKind::Endpoint, &ek, run);
                self.link(&asset, &ep, EdgeKind::Exposes, 0.9, false, run);
                self.link(&fid, &ep, EdgeKind::ObservedOn, 0.95, false, run);
                if !f.cwe.is_empty() {
                    let w = self.upsert(&format!("cwe:{}", f.cwe), NodeKind::Weakness, &f.cwe, run);
                    self.link(&ep, &w, EdgeKind::Vulnerable, f.confidence.max(0.5), false, run);
                }
            }
            if !f.cwe.is_empty() {
                let w = self.upsert(&format!("cwe:{}", f.cwe), NodeKind::Weakness, &f.cwe, run);
                self.link(&fid, &w, EdgeKind::Proves, f.confidence.max(0.5), false, run);
            }
            if !f.mitre.is_empty() {
                let t = self.upsert(&format!("att:{}", f.mitre), NodeKind::Technique, &f.mitre, run);
                self.link(&fid, &t, EdgeKind::Uses, 0.9, false, run);
            }
            if !f.account.is_empty() {
                let a = self.upsert(&format!("acct:{}", f.account), NodeKind::Account, &f.account, run);
                self.link(&fid, &a, EdgeKind::Grants, 0.9, false, run);
                // The secret itself never enters the graph — the graph is an
                // artifact that gets shared; the vault is where secrets live.
                if !f.secret.is_empty() {
                    let c = self.upsert(&format!("cred:{}", f.account), NodeKind::Credential, "credential (vaulted)", run);
                    self.link(&a, &c, EdgeKind::Grants, 0.9, false, run);
                }
            }
            if sev_weight(&f.severity) >= 0.75 || f.stage == "impact" {
                let label = if f.business_impact.is_empty() { f.impact.clone() } else { f.business_impact.clone() };
                let label: String = label.split_whitespace().take(12).collect::<Vec<_>>().join(" ");
                if !label.is_empty() {
                    let i = self.upsert(&format!("impact:{}:{}", run, f.id), NodeKind::Impact, &label, run);
                    self.link(&fid, &i, EdgeKind::Leads, sev_weight(&f.severity), false, run);
                }
            }
        }

        // Asserted chains first: they are evidence.
        for f in findings {
            for src in &f.chains_from {
                let a = format!("find:{}:{}", run, src);
                let b = format!("find:{}:{}", run, f.id);
                self.link(&a, &b, EdgeKind::Chains, 0.9, false, run);
            }
        }
        self.infer_chains(run, findings);
    }

    /// Connect consecutive kill-chain stages when the agents asserted nothing.
    ///
    /// Only forward moves, only between *adjacent populated* stages, and only
    /// from the strongest finding of the earlier stage — a full cross-product
    /// would draw a plausible-looking web that encodes no information at all.
    fn infer_chains(&mut self, run: &str, findings: &[Finding]) {
        let asserted: usize = findings.iter().map(|f| f.chains_from.len()).sum();
        if asserted > 0 || findings.len() < 2 {
            return;
        }
        let mut by_stage: BTreeMap<usize, Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            by_stage.entry(stage_rank(&f.stage)).or_default().push(f);
        }
        let ranks: Vec<usize> = by_stage.keys().copied().collect();
        for w in ranks.windows(2) {
            let (Some(a), Some(b)) = (by_stage.get(&w[0]), by_stage.get(&w[1])) else { continue };
            let best = a
                .iter()
                .max_by(|x, y| {
                    (sev_weight(&x.severity) * x.confidence)
                        .partial_cmp(&(sev_weight(&y.severity) * y.confidence))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied();
            let Some(src) = best else { continue };
            for dst in b {
                let from = format!("find:{}:{}", run, src.id);
                let to = format!("find:{}:{}", run, dst.id);
                self.link(&from, &to, EdgeKind::Chains, 0.35, true, run);
            }
        }
    }

    pub fn neighbors(&self, id: &str) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.from == id).collect()
    }

    /// Entities observed but never proved: endpoints with no finding on them,
    /// accounts nothing was done with. These are where chaining should look
    /// next, and the reason the graph is worth keeping between runs.
    pub fn frontier(&self) -> Vec<&Node> {
        let proven: BTreeSet<&str> = self
            .edges
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::ObservedOn | EdgeKind::Proves))
            .map(|e| e.to.as_str())
            .collect();
        let mut v: Vec<&Node> = self
            .nodes
            .values()
            .filter(|n| matches!(n.kind, NodeKind::Endpoint | NodeKind::Account | NodeKind::Credential))
            .filter(|n| !proven.contains(n.id.as_str()))
            .collect();
        v.sort_by(|a, b| b.runs.len().cmp(&a.runs.len()).then_with(|| a.id.cmp(&b.id)));
        v
    }

    /// Ranked attack paths: chains of findings ordered by kill-chain stage,
    /// scored by severity × edge probability. Returns node-id paths, longest and
    /// most damaging first.
    pub fn paths(&self, max: usize) -> Vec<(Vec<String>, f64)> {
        let findings: Vec<&Node> = self.nodes.values().filter(|n| n.kind == NodeKind::Finding).collect();
        let has_parent: BTreeSet<&str> = self
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Chains)
            .map(|e| e.to.as_str())
            .collect();
        let roots: Vec<&Node> = findings.iter().copied().filter(|n| !has_parent.contains(n.id.as_str())).collect();

        let mut out: Vec<(Vec<String>, f64)> = Vec::new();
        for r in roots {
            let mut stack = vec![(vec![r.id.clone()], self.node_score(&r.id))];
            while let Some((path, score)) = stack.pop() {
                let last = path.last().cloned().unwrap_or_default();
                let next: Vec<&Edge> = self
                    .edges
                    .iter()
                    .filter(|e| e.kind == EdgeKind::Chains && e.from == last && !path.contains(&e.to))
                    .collect();
                if next.is_empty() {
                    out.push((path, score));
                    continue;
                }
                for e in next {
                    let mut p = path.clone();
                    p.push(e.to.clone());
                    // Depth is capped: cycles are already excluded, but a long
                    // inferred tail is noise, not a deeper attack.
                    if p.len() > 12 {
                        out.push((p, score));
                        continue;
                    }
                    let s = score + self.node_score(&e.to) * e.p;
                    stack.push((p, s));
                }
            }
        }
        out.sort_by(|a, b| {
            b.0.len()
                .cmp(&a.0.len())
                .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
        });
        out.truncate(if max == 0 { 5 } else { max });
        out
    }

    fn node_score(&self, id: &str) -> f64 {
        self.nodes
            .get(id)
            .map(|n| {
                let sev = n.meta.get("severity").map(|s| sev_weight(s)).unwrap_or(0.1);
                let conf: f64 = n.meta.get("confidence").and_then(|c| c.parse().ok()).unwrap_or(0.5);
                sev * conf.clamp(0.2, 1.0)
            })
            .unwrap_or(0.0)
    }

    /// One line per kind, then the top attack paths — the `/graph` view.
    pub fn summary(&self) -> String {
        if self.nodes.is_empty() {
            return "  (knowledge graph empty — run an engagement first)".into();
        }
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        for n in self.nodes.values() {
            *by_kind.entry(n.kind.as_str()).or_insert(0) += 1;
        }
        let mut s = String::from("  ┌ knowledge graph\n");
        for (k, v) in &by_kind {
            s.push_str(&format!("  │ {:<12} {}\n", k, v));
        }
        let inferred = self.edges.iter().filter(|e| e.inferred).count();
        s.push_str(&format!("  │ {:<12} {} ({} inferred)\n", "edges", self.edges.len(), inferred));
        let paths = self.paths(3);
        if paths.iter().any(|(p, _)| p.len() > 1) {
            s.push_str("  │\n  │ top attack paths\n");
            for (p, score) in paths.iter().filter(|(p, _)| p.len() > 1) {
                let labels: Vec<&str> = p
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .map(|n| n.label.as_str())
                    .collect();
                s.push_str(&format!("  │  [{score:.2}] {}\n", labels.join(" → ")));
            }
        }
        let fr = self.frontier();
        if !fr.is_empty() {
            s.push_str(&format!("  │\n  │ frontier ({} unproven): {}\n", fr.len(),
                fr.iter().take(4).map(|n| n.label.as_str()).collect::<Vec<_>>().join(", ")));
        }
        s.push_str("  └\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, sev: &str, cwe: &str, stage: &str, endpoint: &str) -> Finding {
        Finding {
            id: id.into(),
            title: format!("finding {id}"),
            severity: sev.into(),
            cwe: cwe.into(),
            stage: stage.into(),
            endpoint: endpoint.into(),
            confidence: 0.9,
            ..Default::default()
        }
    }

    #[test]
    fn one_endpoint_node_however_the_url_was_written() {
        let mut g = KnowledgeGraph::new();
        g.ingest(
            "https://ex.com",
            "r1",
            &[
                f("a", "High", "CWE-89", "initial-access", "https://ex.com/login.aspx?id=1"),
                f("b", "Low", "CWE-200", "recon", "http://www.ex.com/login.aspx/"),
            ],
        );
        let eps: Vec<&Node> = g.nodes.values().filter(|n| n.kind == NodeKind::Endpoint).collect();
        assert_eq!(eps.len(), 1, "got {:?}", eps.iter().map(|n| &n.id).collect::<Vec<_>>());
    }

    #[test]
    fn asserted_chains_win_and_nothing_is_inferred_alongside_them() {
        let mut g = KnowledgeGraph::new();
        let mut b = f("b", "High", "CWE-89", "execution", "https://ex.com/x");
        b.chains_from = vec!["a".into()];
        g.ingest("https://ex.com", "r1", &[f("a", "Medium", "CWE-200", "recon", "https://ex.com/"), b]);
        let chains: Vec<&Edge> = g.edges.iter().filter(|e| e.kind == EdgeKind::Chains).collect();
        assert_eq!(chains.len(), 1);
        assert!(!chains[0].inferred, "an agent-asserted chain must not be marked inferred");
    }

    #[test]
    fn inferred_chains_only_move_forward_through_the_kill_chain() {
        let mut g = KnowledgeGraph::new();
        g.ingest(
            "https://ex.com",
            "r1",
            &[
                f("a", "Medium", "CWE-200", "recon", "https://ex.com/"),
                f("b", "Critical", "CWE-89", "initial-access", "https://ex.com/login"),
            ],
        );
        let chains: Vec<&Edge> = g.edges.iter().filter(|e| e.kind == EdgeKind::Chains).collect();
        assert_eq!(chains.len(), 1);
        assert!(chains[0].inferred, "a derived edge must say so");
        assert!(chains[0].from.ends_with(":a") && chains[0].to.ends_with(":b"), "recon must precede initial-access");
        assert!(chains[0].p < 0.5, "an inferred edge must carry less weight than an asserted one");
    }

    #[test]
    fn a_secret_never_lands_in_the_graph() {
        let mut g = KnowledgeGraph::new();
        let mut x = f("a", "High", "CWE-287", "credential-access", "https://ex.com/register");
        x.account = "user1".into();
        x.secret = "hunter2-super-secret".into();
        g.ingest("https://ex.com", "r1", &[x]);
        let json = g.to_json();
        assert!(!json.contains("hunter2"), "the vault holds secrets, the graph does not");
        assert!(json.contains("credential (vaulted)"));
    }

    #[test]
    fn paths_rank_the_longest_most_severe_chain_first() {
        let mut g = KnowledgeGraph::new();
        let mut b = f("b", "High", "CWE-89", "initial-access", "https://ex.com/login");
        b.chains_from = vec!["a".into()];
        let mut c = f("c", "Critical", "CWE-78", "execution", "https://ex.com/exec");
        c.chains_from = vec!["b".into()];
        g.ingest("https://ex.com", "r1", &[f("a", "Low", "CWE-200", "recon", "https://ex.com/"), b, c]);
        let paths = g.paths(3);
        assert_eq!(paths[0].0.len(), 3, "the three-step chain must rank above any single node");
    }

    #[test]
    fn re_ingesting_the_same_run_does_not_duplicate_edges() {
        let mut g = KnowledgeGraph::new();
        let fs = [f("a", "High", "CWE-89", "initial-access", "https://ex.com/login")];
        g.ingest("https://ex.com", "r1", &fs);
        let n = g.edges.len();
        g.ingest("https://ex.com", "r1", &fs);
        assert_eq!(g.edges.len(), n);
    }

    #[test]
    fn the_frontier_lists_endpoints_nothing_was_proven_on() {
        let mut g = KnowledgeGraph::new();
        g.ingest("https://ex.com", "r1", &[f("a", "High", "CWE-89", "initial-access", "https://ex.com/login")]);
        // An endpoint learned by recon, with no finding attached to it.
        let asset = "asset:ex.com".to_string();
        g.upsert("ep:ex.com/admin", NodeKind::Endpoint, "ex.com/admin", "r1");
        g.link(&asset, "ep:ex.com/admin", EdgeKind::Exposes, 0.8, false, "r1");
        let fr: Vec<&str> = g.frontier().iter().map(|n| n.id.as_str()).collect();
        assert_eq!(fr, vec!["ep:ex.com/admin"]);
    }
}
