//! Internal network & Active Directory — the engagement as a graph.
//!
//! A web engagement is mostly a list: findings against endpoints, each one
//! standing on its own. An internal network is not. There, the interesting
//! result is almost never a single weakness — it is that a printer nobody owns
//! leaks a service account, that account can write to a share a helpdesk
//! machine runs scripts from, and three hops later something is Domain Admin.
//! No individual step is critical. The path is.
//!
//! So the model here is a graph with one loop at its centre, the loop every
//! internal compromise actually runs on:
//!
//! ```text
//!      credential ──→ identity ──→ permission ──→ machine
//!           ▲                                        │
//!           └──────────── new credential ────────────┘
//! ```
//!
//! Each turn of that loop is cheap; the loop is what gets you the domain. An
//! assessment that reports the four steps separately, at Medium each, has
//! described everything and explained nothing.
//!
//! ## The layers
//!
//! Every node sits in exactly one layer, and edges mostly go left to right:
//!
//! ```text
//!   Asset → Exposure → Weakness → Credential → Privilege → Movement → CrownJewel
//!                                                                          │
//!                                            BusinessImpact ←──────────────┘
//!                                            Detection · Remediation
//! ```
//!
//! The last three are not stages of an attack — they are what the client is
//! buying. `BusinessImpact` says what the crown jewel being reachable costs,
//! `Detection` says whether anything would have noticed, and `Remediation`
//! hangs off **edges** rather than nodes, because what a client fixes is a
//! relationship: a permission, a trust, a reused password. "Patch the printer"
//! is rarely the answer; "that service account should not be able to write
//! there" usually is.
//!
//! ## What makes a path real
//!
//! Every node and edge carries `proven`. An unproven edge is a hypothesis —
//! worth listing, worth testing, never worth reporting as a path. `paths()`
//! returns both kinds and says which is which, and the severity of a path is
//! capped by its weakest link, so one assumed hop cannot launder a chain into
//! a Critical.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Where a node sits in the taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    /// A thing that exists: host, service, share, database, application.
    Asset,
    /// How it is reachable: an open port, an anonymous bind, a listening SMB.
    Exposure,
    /// What is wrong with it: a missing patch, signing disabled, a default.
    Weakness,
    /// Material that authenticates: a hash, a ticket, a password, a token.
    Credential,
    /// What that material is allowed to do.
    Privilege,
    /// Getting from one place to another with it.
    Movement,
    /// What the client actually cares about losing.
    CrownJewel,
    /// What losing it costs, in the client's terms.
    BusinessImpact,
    /// Whether anything would have noticed.
    Detection,
    /// What to change so the edge stops existing.
    Remediation,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Asset => "asset",
            Layer::Exposure => "exposure",
            Layer::Weakness => "weakness",
            Layer::Credential => "credential",
            Layer::Privilege => "privilege",
            Layer::Movement => "movement",
            Layer::CrownJewel => "crown-jewel",
            Layer::BusinessImpact => "business-impact",
            Layer::Detection => "detection",
            Layer::Remediation => "remediation",
        }
    }
    /// Ordering used when laying the graph out left to right.
    pub fn rank(self) -> usize {
        match self {
            Layer::Asset => 0,
            Layer::Exposure => 1,
            Layer::Weakness => 2,
            Layer::Credential => 3,
            Layer::Privilege => 4,
            Layer::Movement => 5,
            Layer::CrownJewel => 6,
            Layer::BusinessImpact => 7,
            Layer::Detection => 8,
            Layer::Remediation => 9,
        }
    }
}

/// What a node *is*, within its layer. Kept coarse on purpose: the value is in
/// the relationships, and a taxonomy nobody can place a real object into is
/// worse than one with a few broad buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Host,
    Service,
    Share,
    Database,
    Application,
    User,
    Computer,
    ServiceAccount,
    Group,
    Acl,
    Ticket,
    Hash,
    Password,
    Token,
    Session,
    Data,
    Process,
    Control,
    Other,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Host => "host",
            Kind::Service => "service",
            Kind::Share => "share",
            Kind::Database => "database",
            Kind::Application => "application",
            Kind::User => "user",
            Kind::Computer => "computer",
            Kind::ServiceAccount => "service-account",
            Kind::Group => "group",
            Kind::Acl => "acl",
            Kind::Ticket => "ticket",
            Kind::Hash => "hash",
            Kind::Password => "password",
            Kind::Token => "token",
            Kind::Session => "session",
            Kind::Data => "data",
            Kind::Process => "process",
            Kind::Control => "control",
            Kind::Other => "other",
        }
    }
    /// Is this credential material — the thing the central loop passes along?
    pub fn is_credential(self) -> bool {
        matches!(self, Kind::Hash | Kind::Password | Kind::Ticket | Kind::Token | Kind::Session)
    }
}

/// One node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub layer: Layer,
    pub kind: Kind,
    /// Human label — what an operator would call it.
    pub label: String,
    /// Which machine or domain it belongs to, when that is meaningful.
    #[serde(default)]
    pub host: String,
    /// Evidence ids backing its existence. Empty means asserted, not observed.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// Did we actually establish this, or is it inferred?
    #[serde(default)]
    pub proven: bool,
    /// Value to the client, 0.0–1.0. Crown jewels sit near 1.0; this is what
    /// makes one path worth reporting ahead of another.
    #[serde(default)]
    pub value: f64,
}

impl Node {
    pub fn new(id: &str, layer: Layer, kind: Kind, label: &str) -> Node {
        Node {
            id: id.to_string(),
            layer,
            kind,
            label: label.to_string(),
            host: String::new(),
            evidence: Vec::new(),
            proven: false,
            value: 0.0,
        }
    }
    pub fn on(mut self, host: &str) -> Node {
        self.host = host.to_string();
        self
    }
    pub fn proven_by(mut self, evidence: &[&str]) -> Node {
        self.evidence = evidence.iter().map(|e| e.to_string()).collect();
        self.proven = !self.evidence.is_empty();
        self
    }
    pub fn worth(mut self, value: f64) -> Node {
        self.value = value.clamp(0.0, 1.0);
        self
    }
}

/// How one node leads to the next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// What was done, in the operator's words ("pass-the-hash over SMB").
    pub technique: String,
    /// ATT&CK id when there is one.
    #[serde(default)]
    pub mitre: String,
    /// Proven means: performed, observed, and reproducible. Not "should work".
    #[serde(default)]
    pub proven: bool,
    #[serde(default)]
    pub evidence: Vec<String>,
    /// What removes this edge. Remediation lives here, not on nodes, because
    /// what gets fixed is a relationship.
    #[serde(default)]
    pub remediation: String,
    /// Would the client have seen it? Empty means nobody checked, which is a
    /// different answer from "no" and is reported as such.
    #[serde(default)]
    pub detection: String,
}

impl Edge {
    pub fn new(from: &str, to: &str, technique: &str) -> Edge {
        Edge {
            from: from.to_string(),
            to: to.to_string(),
            technique: technique.to_string(),
            mitre: String::new(),
            proven: false,
            evidence: Vec::new(),
            remediation: String::new(),
            detection: String::new(),
        }
    }
    pub fn attck(mut self, id: &str) -> Edge {
        self.mitre = id.to_string();
        self
    }
    pub fn proven_by(mut self, evidence: &[&str]) -> Edge {
        self.evidence = evidence.iter().map(|e| e.to_string()).collect();
        self.proven = !self.evidence.is_empty();
        self
    }
    pub fn fix(mut self, remediation: &str) -> Edge {
        self.remediation = remediation.to_string();
        self
    }
    pub fn detected(mut self, detection: &str) -> Edge {
        self.detection = detection.to_string();
        self
    }
    fn key(&self) -> (String, String, String) {
        (self.from.clone(), self.to.clone(), self.technique.to_lowercase())
    }
}

/// A route from a starting position to something worth having.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub nodes: Vec<String>,
    pub edges: Vec<Edge>,
    /// Every hop was performed and evidenced.
    pub proven: bool,
    /// Value of the endpoint reached.
    pub value: f64,
    /// Hops that were assumed rather than performed — what to test next.
    pub assumptions: Vec<String>,
}

impl Path {
    /// Severity of the path, capped by its weakest link.
    ///
    /// A chain with one assumed hop is a hypothesis about a Critical, not a
    /// Critical. Reporting it as the latter is how an internal assessment
    /// loses the client's trust on the one finding that mattered.
    pub fn severity(&self) -> &'static str {
        if !self.proven {
            return "informational";
        }
        match self.value {
            v if v >= 0.9 => "critical",
            v if v >= 0.7 => "high",
            v if v >= 0.4 => "medium",
            _ => "low",
        }
    }
    pub fn hops(&self) -> usize {
        self.edges.len()
    }
}

/// The graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InternalGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl InternalGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node. Re-adding the same id upgrades it rather than duplicating:
    /// a node seen twice, once inferred and once proven, is one node that is
    /// now proven.
    pub fn add(&mut self, node: Node) -> &mut Self {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.id == node.id) {
            existing.proven |= node.proven;
            existing.value = existing.value.max(node.value);
            for e in node.evidence {
                if !existing.evidence.contains(&e) {
                    existing.evidence.push(e);
                }
            }
            if existing.host.is_empty() {
                existing.host = node.host;
            }
            return self;
        }
        self.nodes.push(node);
        self
    }

    /// Add an edge. Same upgrade rule, and an edge to or from a node that does
    /// not exist is dropped — a dangling edge invents a path that nobody can
    /// walk, which is the one failure mode a graph like this must not have.
    pub fn link(&mut self, edge: Edge) -> &mut Self {
        if !self.has(&edge.from) || !self.has(&edge.to) {
            return self;
        }
        if let Some(existing) = self.edges.iter_mut().find(|e| e.key() == edge.key()) {
            existing.proven |= edge.proven;
            for ev in edge.evidence {
                if !existing.evidence.contains(&ev) {
                    existing.evidence.push(ev);
                }
            }
            if existing.remediation.is_empty() {
                existing.remediation = edge.remediation;
            }
            if existing.detection.is_empty() {
                existing.detection = edge.detection;
            }
            return self;
        }
        self.edges.push(edge);
        self
    }

    pub fn has(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id == id)
    }
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }
    pub fn crown_jewels(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.layer == Layer::CrownJewel).collect()
    }

    /// Every credential currently held.
    pub fn credentials(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.kind.is_credential()).collect()
    }

    /// Turn the loop once.
    ///
    /// For each credential we hold, follow it to the identity it authenticates,
    /// the permissions that identity has, and the machines those permissions
    /// reach — and mark every machine reached as a place new credentials are
    /// harvestable. That last step is what makes it a loop rather than a tree,
    /// and it is why internal compromise is not linear: the loop's output is
    /// its own input.
    ///
    /// Returns the ids of newly reachable machines. Nothing new means the loop
    /// has converged and the graph is as large as the evidence allows.
    pub fn turn_loop(&mut self) -> Vec<String> {
        let mut discovered = Vec::new();
        // credential → identity → privilege → machine, following only edges
        // that exist. Inference here would manufacture access nobody has.
        let creds: Vec<String> = self.credentials().iter().map(|n| n.id.clone()).collect();
        for cred in creds {
            // The loop's middle is not a fixed length. Sometimes a hash goes
            // hash → account → ACL → host; sometimes the account IS local
            // admin and it is one hop shorter. Requiring the long form meant a
            // real chain turned the loop zero times, so the walk is bounded by
            // distance instead: any machine within three hops of a credential
            // we hold is a machine that credential reaches.
            for machine in self.reachable_within(&cred, 3) {
                {
                    {
                        let is_machine = matches!(self.node(&machine).map(|n| n.kind), Some(Kind::Host) | Some(Kind::Computer) | Some(Kind::Database) | Some(Kind::Share));
                        if !is_machine {
                            continue;
                        }
                        // Reaching a machine means the credentials cached on it
                        // are in play. The harvest node is a hypothesis until
                        // somebody dumps them, and is marked as one.
                        let harvest = format!("{machine}::harvest");
                        if !self.has(&harvest) {
                            let label = format!("credentials cached on {}", self.node(&machine).map(|n| n.label.clone()).unwrap_or_default());
                            self.add(Node::new(&harvest, Layer::Credential, Kind::Hash, &label).on(&machine));
                            self.link(
                                Edge::new(&machine, &harvest, "harvest cached credentials (LSASS, DPAPI, SAM)")
                                    .attck("T1003")
                                    .fix("Credential Guard, LSA protection, and no privileged logons to tier-2 hosts")
                                    .detected("EDR on LSASS handle access, 4624/4672 for privileged logons"),
                            );
                            discovered.push(harvest);
                        }
                    }
                }
            }
        }
        discovered
    }

    /// Run the loop until it stops producing anything, bounded.
    ///
    /// The bound is not a performance guard — it is a modelling one. A loop
    /// allowed to run forever will eventually "reach" everything through a
    /// chain of assumptions, which is how automated tooling produces a graph
    /// that is complete and worthless.
    pub fn expand(&mut self, max_turns: usize) -> usize {
        let mut turns = 0;
        for _ in 0..max_turns {
            if self.turn_loop().is_empty() {
                break;
            }
            turns += 1;
        }
        turns
    }

    fn successors(&self, id: &str) -> Vec<String> {
        self.edges.iter().filter(|e| e.from == id).map(|e| e.to.clone()).collect()
    }

    /// Nodes within `max_hops` edges of `id`, nearest first.
    fn reachable_within(&self, id: &str, max_hops: usize) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::from([id.to_string()]);
        let mut frontier = vec![id.to_string()];
        let mut out = Vec::new();
        for _ in 0..max_hops {
            let mut next = Vec::new();
            for cur in &frontier {
                for to in self.successors(cur) {
                    if seen.insert(to.clone()) {
                        out.push(to.clone());
                        next.push(to);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        out
    }

    /// Shortest path from `start` to every crown jewel.
    ///
    /// `proven_only` is the difference between what was demonstrated and what
    /// is believed. Both are worth having: the first is the report, the second
    /// is the next day's testing plan.
    pub fn paths(&self, start: &str, proven_only: bool) -> Vec<Path> {
        let mut out = Vec::new();
        for jewel in self.crown_jewels() {
            if let Some(p) = self.path_between(start, &jewel.id, proven_only) {
                out.push(p);
            }
        }
        // Most valuable first, then shortest: a client reads the top of the
        // list, so the top of the list has to be the thing that matters.
        out.sort_by(|a, b| {
            b.value
                .partial_cmp(&a.value)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.hops().cmp(&b.hops()))
        });
        out
    }

    /// Breadth-first, so the path returned is the shortest — which is also the
    /// one a real attacker takes.
    pub fn path_between(&self, start: &str, goal: &str, proven_only: bool) -> Option<Path> {
        if !self.has(start) || !self.has(goal) {
            return None;
        }
        let mut prev: HashMap<String, Edge> = HashMap::new();
        let mut seen: HashSet<String> = HashSet::from([start.to_string()]);
        let mut queue = VecDeque::from([start.to_string()]);
        while let Some(cur) = queue.pop_front() {
            if cur == goal {
                break;
            }
            for e in self.edges.iter().filter(|e| e.from == cur) {
                if proven_only && !e.proven {
                    continue;
                }
                if seen.insert(e.to.clone()) {
                    prev.insert(e.to.clone(), e.clone());
                    queue.push_back(e.to.clone());
                }
            }
        }
        if !seen.contains(goal) {
            return None;
        }
        let mut edges = Vec::new();
        let mut nodes = vec![goal.to_string()];
        let mut cur = goal.to_string();
        while cur != start {
            let e = prev.get(&cur)?.clone();
            cur = e.from.clone();
            nodes.push(cur.clone());
            edges.push(e);
        }
        nodes.reverse();
        edges.reverse();
        let assumptions: Vec<String> = edges
            .iter()
            .filter(|e| !e.proven)
            .map(|e| format!("{} → {} ({})", e.from, e.to, e.technique))
            .collect();
        Some(Path {
            // A path is proven when every hop was performed. Node-level
            // `proven` is about having observed the object itself, which is a
            // different question: some nodes (Domain Admins, NTDS.dit) exist by
            // definition of the domain, and requiring evidence for their
            // existence would reject a chain that was actually walked.
            proven: assumptions.is_empty(),
            value: self.node(goal).map(|n| n.value).unwrap_or(0.0),
            nodes,
            edges,
            assumptions,
        })
    }

    /// The edges worth fixing first.
    ///
    /// Not the most severe finding — the **choke point**: the single edge whose
    /// removal cuts the most paths to crown jewels. This is the question an
    /// internal assessment exists to answer, and the reason the graph is worth
    /// building at all. A list of 40 findings sorted by CVSS does not tell a
    /// client which one change buys them the most.
    pub fn choke_points(&self, start: &str) -> Vec<ChokePoint> {
        let baseline = self.paths(start, false);
        if baseline.is_empty() {
            return Vec::new();
        }
        let mut scored: Vec<ChokePoint> = Vec::new();
        let mut considered: HashSet<(String, String, String)> = HashSet::new();
        for edge in &self.edges {
            if !considered.insert(edge.key()) {
                continue;
            }
            let mut without = self.clone();
            without.edges.retain(|e| e.key() != edge.key());
            let remaining = without.paths(start, false);
            let cut = baseline.len().saturating_sub(remaining.len());
            if cut == 0 {
                continue;
            }
            // Value cut matters more than path count: severing two routes to a
            // test share is worth less than severing one to the domain.
            let value_cut: f64 = baseline.iter().map(|p| p.value).sum::<f64>()
                - remaining.iter().map(|p| p.value).sum::<f64>();
            scored.push(ChokePoint {
                edge: edge.clone(),
                paths_cut: cut,
                value_cut,
                remediation: if edge.remediation.is_empty() {
                    format!("remove the ability to {} from {} to {}", edge.technique, edge.from, edge.to)
                } else {
                    edge.remediation.clone()
                },
            });
        }
        scored.sort_by(|a, b| {
            b.value_cut
                .partial_cmp(&a.value_cut)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.paths_cut.cmp(&a.paths_cut))
        });
        scored
    }

    /// Everything reachable from here, proven hops only — the blast radius of
    /// one compromised position.
    pub fn blast_radius(&self, start: &str) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::from([start.to_string()]);
        let mut queue = VecDeque::from([start.to_string()]);
        let mut out = Vec::new();
        while let Some(cur) = queue.pop_front() {
            for e in self.edges.iter().filter(|e| e.from == cur && e.proven) {
                if seen.insert(e.to.clone()) {
                    out.push(e.to.clone());
                    queue.push_back(e.to.clone());
                }
            }
        }
        out.sort();
        out
    }

    /// Edges nobody checked for detection. Reported separately from "not
    /// detected", because an untested control is an open question, and a
    /// report that silently turns one into "no alerting" is wrong.
    pub fn detection_gaps(&self) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.proven && e.detection.trim().is_empty()).collect()
    }

    /// Mermaid rendering, grouped by layer.
    pub fn mermaid(&self) -> String {
        if self.nodes.is_empty() {
            return String::new();
        }
        let mut out = String::from("flowchart LR\n");
        let mut layers: Vec<Layer> = self.nodes.iter().map(|n| n.layer).collect();
        layers.sort_by_key(|l| l.rank());
        layers.dedup();
        for layer in layers {
            out.push_str(&format!("  subgraph {}[\"{}\"]\n", layer.as_str().replace('-', "_"), layer.as_str()));
            for n in self.nodes.iter().filter(|n| n.layer == layer) {
                out.push_str(&format!("    {}[\"{}\"]\n", mid(&n.id), esc(&n.label)));
            }
            out.push_str("  end\n");
        }
        for e in &self.edges {
            // A dashed edge is an assumption. The reader can see at a glance
            // which parts of the picture were walked and which were guessed.
            let arrow = if e.proven { "-->" } else { "-.->" };
            out.push_str(&format!("  {} {}|\"{}\"| {}\n", mid(&e.from), arrow, esc(&e.technique), mid(&e.to)));
        }
        out
    }

    /// One-screen summary for the operator.
    pub fn summary(&self, start: &str) -> String {
        let proven = self.paths(start, true);
        let all = self.paths(start, false);
        let mut s = format!(
            "{} nodes · {} edges · {} crown jewel(s) · {} proven path(s) of {} total\n",
            self.nodes.len(),
            self.edges.len(),
            self.crown_jewels().len(),
            proven.len(),
            all.len()
        );
        for p in proven.iter().take(5) {
            s.push_str(&format!("  [{}] {} hop(s): {}\n", p.severity(), p.hops(), p.nodes.join(" → ")));
        }
        for c in self.choke_points(start).iter().take(3) {
            s.push_str(&format!("  fix: {} (cuts {} path(s))\n", c.remediation, c.paths_cut));
        }
        s
    }
}

/// One edge, and what removing it buys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChokePoint {
    pub edge: Edge,
    pub paths_cut: usize,
    pub value_cut: f64,
    pub remediation: String,
}

fn mid(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}
fn esc(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ")
}

/// A starter graph for an AD engagement: the assets and crown jewels that are
/// true of almost every domain, so an operator is not typing boilerplate
/// before they can record the one thing they actually found.
pub fn ad_scaffold(domain: &str) -> InternalGraph {
    let mut g = InternalGraph::new();
    g.add(Node::new("dc", Layer::Asset, Kind::Computer, &format!("domain controller ({domain})")).on(domain));
    g.add(Node::new("domain-admins", Layer::CrownJewel, Kind::Group, "Domain Admins").on(domain).worth(1.0));
    g.add(Node::new("ntds", Layer::CrownJewel, Kind::Data, "NTDS.dit (every domain credential)").on(domain).worth(1.0));
    g.add(Node::new("dc-sync", Layer::Privilege, Kind::Acl, "DCSync (DS-Replication-Get-Changes)").on(domain));
    g.link(
        Edge::new("dc-sync", "ntds", "DCSync replication of the directory")
            .attck("T1003.006")
            .fix("remove replication rights from non-DC principals; audit with a scheduled ACL review")
            .detected("4662 on the replication GUIDs, and directory replication from a non-DC source"),
    );
    g.link(
        Edge::new("domain-admins", "dc", "administrative logon to the domain controller")
            .attck("T1078.002")
            .fix("tiered administration: no tier-0 credential ever touches a tier-1 or tier-2 host"),
    );
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The graph from a real-shaped engagement: a printer with anonymous SMB,
    /// a service account whose hash is cached on it, that account can write to
    /// a share, a jump host runs scripts from the share, and the jump host has
    /// a Domain Admin session on it.
    fn engagement() -> InternalGraph {
        let mut g = ad_scaffold("corp.local");
        g.add(Node::new("printer", Layer::Asset, Kind::Host, "print server PRN01").proven_by(&["E01"]));
        g.add(Node::new("smb-anon", Layer::Exposure, Kind::Service, "SMB with anonymous bind").proven_by(&["E02"]));
        g.add(Node::new("no-signing", Layer::Weakness, Kind::Control, "SMB signing not required").proven_by(&["E03"]));
        g.add(Node::new("svc-hash", Layer::Credential, Kind::Hash, "NTLM hash for svc_backup").proven_by(&["E04"]));
        g.add(Node::new("svc-backup", Layer::Privilege, Kind::ServiceAccount, "svc_backup").proven_by(&["E05"]));
        g.add(Node::new("share-write", Layer::Privilege, Kind::Acl, "write to \\\\FS01\\scripts").proven_by(&["E06"]));
        g.add(Node::new("jump01", Layer::Movement, Kind::Computer, "JUMP01 runs scripts from the share").proven_by(&["E07"]));
        g.add(Node::new("da-session", Layer::Credential, Kind::Session, "Domain Admin session on JUMP01").proven_by(&["E08"]));

        g.link(Edge::new("printer", "smb-anon", "port scan + null session").proven_by(&["E02"]));
        g.link(Edge::new("smb-anon", "no-signing", "SMB dialect negotiation").proven_by(&["E03"]));
        g.link(Edge::new("no-signing", "svc-hash", "NTLM relay of the backup job").attck("T1557.001").proven_by(&["E04"]).fix("require SMB signing domain-wide"));
        g.link(Edge::new("svc-hash", "svc-backup", "pass-the-hash").attck("T1550.002").proven_by(&["E05"]));
        g.link(Edge::new("svc-backup", "share-write", "effective ACL on the share").proven_by(&["E06"]));
        g.link(Edge::new("share-write", "jump01", "script replaced, executed on next run").attck("T1080").proven_by(&["E07"]).fix("scripts share should be read-only to service accounts; sign or hash-pin what JUMP01 executes"));
        g.link(Edge::new("jump01", "da-session", "token theft from the interactive session").attck("T1134").proven_by(&["E08"]));
        g.link(Edge::new("da-session", "domain-admins", "the stolen token is a member").proven_by(&["E08"]));
        g.link(Edge::new("domain-admins", "dc-sync", "Domain Admins hold replication rights").proven_by(&["E09"]));
        g
    }

    #[test]
    fn the_path_to_the_domain_is_found_and_ordered_by_value() {
        let g = engagement();
        let paths = g.paths("printer", true);
        assert!(!paths.is_empty(), "a walked chain must produce a path");
        let top = &paths[0];
        assert_eq!(top.severity(), "critical", "reaching NTDS is critical");
        assert!(top.nodes.contains(&"svc-hash".to_string()));
        assert!(top.nodes.last().unwrap() == "ntds" || top.nodes.last().unwrap() == "domain-admins");
    }

    #[test]
    fn one_assumed_hop_caps_the_whole_chain() {
        let mut g = engagement();
        // Replace the proven relay with an assumed one: same graph, one hop
        // nobody actually performed.
        g.edges.retain(|e| !(e.from == "no-signing" && e.to == "svc-hash"));
        g.link(Edge::new("no-signing", "svc-hash", "NTLM relay would yield the hash"));

        let proven = g.paths("printer", true);
        assert!(proven.is_empty(), "an assumed hop must not appear among proven paths");

        let all = g.paths("printer", false);
        assert!(!all.is_empty(), "it is still worth listing as a hypothesis");
        assert_eq!(all[0].severity(), "informational", "a hypothesis is not a critical");
        assert_eq!(all[0].assumptions.len(), 1);
    }

    #[test]
    fn the_choke_point_is_the_edge_worth_fixing_not_the_worst_finding() {
        let g = engagement();
        let choke = g.choke_points("printer");
        assert!(!choke.is_empty());
        // Every route to the domain runs through the relay and the share; the
        // top choke point has to be one of them, not the last hop before the DC.
        let top = &choke[0];
        assert!(
            matches!((top.edge.from.as_str(), top.edge.to.as_str()),
                     ("no-signing", "svc-hash") | ("svc-hash", "svc-backup") | ("svc-backup", "share-write") | ("share-write", "jump01") | ("printer", "smb-anon") | ("smb-anon", "no-signing")),
            "unexpected choke point: {} → {}", top.edge.from, top.edge.to
        );
        assert!(top.paths_cut >= 1);
        assert!(!top.remediation.is_empty(), "a choke point without a fix is an observation, not advice");
    }

    #[test]
    fn the_loop_turns_and_then_converges() {
        let mut g = engagement();
        let before = g.nodes.len();
        let turns = g.expand(5);
        assert!(turns >= 1, "reaching a machine must put its cached credentials in play");
        assert!(g.nodes.len() > before);
        // Harvest nodes are hypotheses until somebody dumps them.
        let harvest: Vec<&Node> = g.nodes.iter().filter(|n| n.id.ends_with("::harvest")).collect();
        assert!(!harvest.is_empty());
        assert!(harvest.iter().all(|n| !n.proven), "a cached-credential node is an assumption");
        // And it must stop: an unbounded loop eventually reaches everything.
        let again = g.expand(5);
        assert_eq!(again, 0, "the loop has to converge");
    }

    #[test]
    fn blast_radius_follows_only_what_was_walked() {
        let mut g = engagement();
        g.add(Node::new("fs02", Layer::Asset, Kind::Host, "FS02"));
        g.link(Edge::new("svc-backup", "fs02", "the same account probably works here"));
        let radius = g.blast_radius("svc-hash");
        assert!(radius.contains(&"share-write".to_string()));
        assert!(!radius.contains(&"fs02".to_string()), "an unproven hop is not blast radius");
    }

    #[test]
    fn dangling_edges_are_refused() {
        let mut g = InternalGraph::new();
        g.add(Node::new("a", Layer::Asset, Kind::Host, "A"));
        g.link(Edge::new("a", "ghost", "reaches something that does not exist"));
        assert!(g.edges.is_empty(), "an edge to a node that does not exist invents a path");
    }

    #[test]
    fn re_adding_a_node_upgrades_it_instead_of_duplicating() {
        let mut g = InternalGraph::new();
        g.add(Node::new("h", Layer::Asset, Kind::Host, "HOST"));
        g.add(Node::new("h", Layer::Asset, Kind::Host, "HOST").proven_by(&["E11"]).worth(0.8));
        assert_eq!(g.nodes.len(), 1);
        assert!(g.nodes[0].proven);
        assert_eq!(g.nodes[0].value, 0.8);
    }

    #[test]
    fn detection_gaps_separate_unchecked_from_unmonitored() {
        let g = engagement();
        let gaps = g.detection_gaps();
        // The relay hop carries no detection note in the fixture — it is an
        // open question, and must be reported as one rather than as "no alert".
        assert!(gaps.iter().any(|e| e.from == "no-signing" && e.to == "svc-hash"));
        // The scaffold's DCSync edge does carry one, so it is not a gap.
        assert!(!gaps.iter().any(|e| e.from == "dc-sync"));
    }

    #[test]
    fn mermaid_marks_assumptions_differently() {
        let mut g = engagement();
        g.add(Node::new("maybe", Layer::Movement, Kind::Host, "unverified host"));
        g.link(Edge::new("svc-backup", "maybe", "assumed local admin"));
        let m = g.mermaid();
        assert!(m.contains("-.->"), "an assumed edge must be visually distinct");
        assert!(m.contains("-->"));
        assert!(m.contains("subgraph"));
    }
}
