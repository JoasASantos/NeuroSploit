//! POMDP belief-state world model (v3.6.4).
//!
//! The target is only partially observable, so we don't track booleans — we
//! track a **belief**: a property graph whose nodes (host / service / vuln /
//! credential) each carry a probability that the proposition is true. Recon
//! produces *observations* that update those beliefs via a Bayesian step; the
//! per-node Shannon entropy measures how diffuse the belief still is.
//!
//! - **Black-box**: beliefs start uncertain (~0.5) and sharpen with observation.
//! - **White-box**: the world model is built (near-)deterministically from
//!   source/SAST, so beliefs collapse toward 0/1 — the POMDP degenerates into an
//!   MDP and uncertainty migrates to *path reachability*, not state.
//!
//! This is the substrate for value-of-information planning (see `pomdp.rs`): when
//! a node's belief is diffuse, gathering an observation about it is worth more
//! than acting on it — which is also the anti-hallucination criterion.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// What a belief node is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Host,       // a host exists / is reachable
    Service,    // a service/endpoint is present
    Vuln,       // a specific weakness is present
    Exploit,    // the weakness is actually exploitable
    Credential, // a credential is valid
}

/// A single proposition with a probability of being true and the evidence count
/// behind it (used for confidence/entropy).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    pub label: String,
    /// P(proposition is true) ∈ [0,1].
    pub p: f64,
    /// number of independent observations folded in.
    pub obs: u32,
}

impl Node {
    /// Shannon entropy in bits of the Bernoulli(p) belief — 1.0 = maximally
    /// uncertain (p=0.5), 0.0 = certain.
    pub fn entropy(&self) -> f64 {
        let p = self.p.clamp(1e-6, 1.0 - 1e-6);
        -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
    }
}

/// A directed edge: "from enables/leads-to to" with a transition probability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub p: f64,
}

/// The belief: a property graph over the partially-observed target.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct WorldModel {
    pub nodes: HashMap<String, Node>,
    pub edges: Vec<Edge>,
    /// true once beliefs were built deterministically (white-box → MDP regime).
    pub deterministic: bool,
}

/// A sensed observation about a node: P(observation | true) vs P(observation | false).
/// `positive` true means the observation supports the proposition.
pub struct Observation<'a> {
    pub node: &'a str,
    pub positive: bool,
    /// sensor reliability ∈ (0.5, 1.0]; how much one observation moves the belief.
    pub reliability: f64,
}

impl WorldModel {
    pub fn new() -> Self {
        WorldModel::default()
    }

    /// Seed a node with a prior. Black-box priors are ~0.5 (unknown); white-box
    /// callers pass priors near 0/1.
    pub fn add(&mut self, id: &str, kind: Kind, label: &str, prior: f64) {
        self.nodes.entry(id.to_string()).or_insert_with(|| Node {
            id: id.to_string(),
            kind,
            label: label.to_string(),
            p: prior.clamp(0.0, 1.0),
            obs: 0,
        });
    }

    pub fn link(&mut self, from: &str, to: &str, p: f64) {
        self.edges.push(Edge { from: from.into(), to: to.into(), p: p.clamp(0.0, 1.0) });
    }

    /// Bayesian update of a node's belief from one observation. With sensor
    /// reliability r: a positive obs multiplies the odds by r/(1-r), a negative
    /// one by (1-r)/r.
    pub fn observe(&mut self, o: Observation) {
        let r = o.reliability.clamp(0.5 + 1e-6, 1.0 - 1e-6);
        if let Some(n) = self.nodes.get_mut(o.node) {
            let p = n.p.clamp(1e-6, 1.0 - 1e-6);
            let prior_odds = p / (1.0 - p);
            let lr = if o.positive { r / (1.0 - r) } else { (1.0 - r) / r };
            let post_odds = prior_odds * lr;
            n.p = post_odds / (1.0 + post_odds);
            n.obs += 1;
        }
    }

    /// Collapse a node to (near-)certainty — used by white-box when SAST/dataflow
    /// determines the proposition deterministically.
    pub fn set_known(&mut self, id: &str, truth: bool) {
        if let Some(n) = self.nodes.get_mut(id) {
            n.p = if truth { 0.98 } else { 0.02 };
            n.obs += 3;
        }
    }

    /// Mean entropy across nodes of a kind (or all). 1.0 = totally diffuse.
    pub fn uncertainty(&self, kind: Option<Kind>) -> f64 {
        let rel: Vec<&Node> = self.nodes.values()
            .filter(|n| kind.map(|k| n.kind == k).unwrap_or(true)).collect();
        if rel.is_empty() {
            return 1.0;
        }
        rel.iter().map(|n| n.entropy()).sum::<f64>() / rel.len() as f64
    }

    /// Nodes whose belief is still diffuse (entropy above `thresh`) — the recon
    /// frontier: where collecting an observation has the highest value.
    pub fn frontier(&self, thresh: f64) -> Vec<&Node> {
        let mut v: Vec<&Node> = self.nodes.values().filter(|n| n.entropy() > thresh).collect();
        v.sort_by(|a, b| b.entropy().partial_cmp(&a.entropy()).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    /// Is a proposition confident enough to *act/assert* on? (low entropy + high p)
    pub fn is_confident(&self, id: &str, min_p: f64, max_entropy: f64) -> bool {
        self.nodes.get(id).map(|n| n.p >= min_p && n.entropy() <= max_entropy).unwrap_or(false)
    }
}
