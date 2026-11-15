//! Exploration Graph — dual-graph architecture inspired by Artex.
//!
//! Two graphs track different things:
//!
//! 1. **Asset Graph** (global, shared across engagements) — the target's
//!    infrastructure: domains, subdomains, IPs, services, apps, endpoints.
//!    Agents submit raw data; the graph computes relationships and dedup.
//!
//! 2. **Exploration Graph** (per-engagement) — what was tried and what was
//!    learned: goals, intents, facts, findings, and hints. Edges encode
//!    causality: spawns, yields, derived_from, proves.
//!
//! **Anchors** tie the two: an exploration node (e.g. "test SQLi on /api/users")
//! anchors to an asset node (the /api/users endpoint). This drives the coverage
//! map — every asset knows what was explored against it.
//!
//! The planner watches the exploration graph. A graph change (new fact, new
//! finding, new asset) wakes the planner, which emits new intents.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

// ── Asset Graph ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetGraph {
    pub nodes: Vec<AssetNode>,
    pub edges: Vec<AssetEdge>,
    index: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetNode {
    pub id: String,
    pub kind: AssetKind,
    pub value: String,
    pub properties: BTreeMap<String, String>,
    pub discovered_by: String,
    pub discovered_at: u64,
    /// How many exploration nodes anchor to this asset.
    pub exploration_count: u32,
    /// How many findings are associated.
    pub finding_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetKind {
    Domain,
    Subdomain,
    IpAddress,
    Service,
    Application,
    Endpoint,
    Parameter,
    Technology,
    Credential,
    Certificate,
    CloudResource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEdge {
    pub from: String,
    pub to: String,
    pub kind: AssetRelation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetRelation {
    ParentOf,
    HostedOn,
    ServesOn,
    UsesAuth,
    UsesTech,
    ResolvesTo,
    RedirectsTo,
    LinksTo,
}

impl Default for AssetGraph {
    fn default() -> Self {
        Self { nodes: Vec::new(), edges: Vec::new(), index: HashMap::new() }
    }
}

impl AssetGraph {
    pub fn new() -> Self { Self::default() }

    /// Insert or merge an asset. Returns true if the asset was new.
    pub fn upsert(&mut self, kind: AssetKind, value: &str, properties: BTreeMap<String, String>, discovered_by: &str) -> bool {
        let dedup_key = dedup_key(kind, value);
        if let Some(&idx) = self.index.get(&dedup_key) {
            let node = &mut self.nodes[idx];
            for (k, v) in properties { node.properties.insert(k, v); }
            return false;
        }
        let id = format!("asset-{}", self.nodes.len());
        let node = AssetNode {
            id: id.clone(),
            kind,
            value: value.to_string(),
            properties,
            discovered_by: discovered_by.to_string(),
            discovered_at: now(),
            exploration_count: 0,
            finding_count: 0,
        };
        self.index.insert(dedup_key, self.nodes.len());
        self.nodes.push(node);
        true
    }

    /// Add a relationship between two assets.
    pub fn relate(&mut self, from: &str, to: &str, kind: AssetRelation) {
        if !self.edges.iter().any(|e| e.from == from && e.to == to && e.kind == kind) {
            self.edges.push(AssetEdge { from: from.into(), to: to.into(), kind });
        }
    }

    /// Find an asset by value.
    pub fn find(&self, kind: AssetKind, value: &str) -> Option<&AssetNode> {
        let key = dedup_key(kind, value);
        self.index.get(&key).and_then(|&idx| self.nodes.get(idx))
    }

    /// All endpoints under a domain/subdomain.
    pub fn endpoints_under(&self, domain: &str) -> Vec<&AssetNode> {
        let domain_ids: HashSet<&str> = self.nodes.iter()
            .filter(|n| (n.kind == AssetKind::Domain || n.kind == AssetKind::Subdomain) && n.value.contains(domain))
            .map(|n| n.id.as_str())
            .collect();

        self.nodes.iter()
            .filter(|n| n.kind == AssetKind::Endpoint && self.edges.iter().any(|e| domain_ids.contains(e.from.as_str()) && e.to == n.id))
            .collect()
    }

    /// Assets with no exploration anchored to them (untested surface).
    pub fn untested(&self) -> Vec<&AssetNode> {
        self.nodes.iter()
            .filter(|n| n.exploration_count == 0 && matches!(n.kind, AssetKind::Endpoint | AssetKind::Parameter | AssetKind::Service))
            .collect()
    }

    /// Coverage ratio: explored / total testable assets.
    pub fn coverage(&self) -> f64 {
        let testable: Vec<&AssetNode> = self.nodes.iter()
            .filter(|n| matches!(n.kind, AssetKind::Endpoint | AssetKind::Parameter | AssetKind::Service))
            .collect();
        if testable.is_empty() { return 0.0; }
        let explored = testable.iter().filter(|n| n.exploration_count > 0).count();
        explored as f64 / testable.len() as f64
    }

    /// Summary for prompt injection.
    pub fn prompt_summary(&self) -> String {
        let mut s = String::from("ASSET GRAPH SUMMARY:\n");
        let mut by_kind: BTreeMap<AssetKind, usize> = BTreeMap::new();
        for n in &self.nodes { *by_kind.entry(n.kind).or_default() += 1; }
        for (kind, count) in &by_kind {
            s.push_str(&format!("  {kind:?}: {count}\n"));
        }
        let coverage = self.coverage();
        s.push_str(&format!("  Coverage: {:.0}%\n", coverage * 100.0));
        let untested = self.untested();
        if !untested.is_empty() {
            s.push_str(&format!("  Untested assets: {}\n", untested.len()));
            for n in untested.iter().take(10) {
                s.push_str(&format!("    - [{:?}] {}\n", n.kind, n.value));
            }
        }
        s
    }
}

// ── Exploration Graph ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationGraph {
    pub nodes: Vec<ExplorationNode>,
    pub edges: Vec<ExplorationEdge>,
    pub anchors: Vec<Anchor>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationNode {
    pub id: String,
    pub kind: ExplorationKind,
    pub content: String,
    pub status: ExplorationStatus,
    pub agent: String,
    pub created_at: u64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExplorationKind {
    /// High-level testing goal (e.g. "test authentication bypass").
    Goal,
    /// Specific action to take (e.g. "send SQLi to /api/login username param").
    Intent,
    /// Observation from testing (e.g. "param reflects input unfiltered").
    Fact,
    /// A confirmed vulnerability.
    Finding,
    /// A lead worth investigating (not yet confirmed).
    Hint,
    /// A negative result (tested, not vulnerable).
    Negative,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExplorationStatus {
    #[default]
    Pending,
    InProgress,
    Completed,
    Failed,
    Blocked,
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationEdge {
    pub from: String,
    pub to: String,
    pub kind: ExplorationRelation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExplorationRelation {
    Spawns,
    Yields,
    DerivedFrom,
    Proves,
    Disproves,
    Requires,
    Supersedes,
    ChainsTo,
}

/// Links an exploration node to an asset node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub exploration_id: String,
    pub asset_id: String,
    pub direction: AnchorDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorDirection {
    /// Exploration targets this asset.
    Targets,
    /// Exploration discovered this asset.
    Discovered,
}

impl Default for ExplorationGraph {
    fn default() -> Self {
        Self { nodes: Vec::new(), edges: Vec::new(), anchors: Vec::new(), version: 0 }
    }
}

impl ExplorationGraph {
    pub fn new() -> Self { Self::default() }

    /// Add a new exploration node. Returns its id.
    pub fn add_node(&mut self, kind: ExplorationKind, content: &str, agent: &str) -> String {
        let id = format!("exp-{}", self.nodes.len());
        self.nodes.push(ExplorationNode {
            id: id.clone(),
            kind,
            content: content.to_string(),
            status: ExplorationStatus::Pending,
            agent: agent.to_string(),
            created_at: now(),
            metadata: BTreeMap::new(),
        });
        self.version += 1;
        id
    }

    /// Add a goal and decompose it into intents.
    pub fn add_goal(&mut self, goal: &str, agent: &str) -> String {
        self.add_node(ExplorationKind::Goal, goal, agent)
    }

    /// Add an intent (specific action) linked to a goal.
    pub fn add_intent(&mut self, intent: &str, goal_id: &str, agent: &str) -> String {
        let id = self.add_node(ExplorationKind::Intent, intent, agent);
        self.add_edge(goal_id, &id, ExplorationRelation::Spawns);
        id
    }

    /// Record a fact observed during testing.
    pub fn add_fact(&mut self, fact: &str, from_id: &str, agent: &str) -> String {
        let id = self.add_node(ExplorationKind::Fact, fact, agent);
        self.add_edge(from_id, &id, ExplorationRelation::Yields);
        self.version += 1;
        id
    }

    /// Record a finding linked to the intent that found it.
    pub fn add_finding(&mut self, finding: &str, from_id: &str, agent: &str) -> String {
        let id = self.add_node(ExplorationKind::Finding, finding, agent);
        self.add_edge(from_id, &id, ExplorationRelation::Proves);
        self.version += 1;
        id
    }

    /// Record a negative result (tested, not vulnerable).
    pub fn add_negative(&mut self, what: &str, from_id: &str, agent: &str) -> String {
        let id = self.add_node(ExplorationKind::Negative, what, agent);
        self.add_edge(from_id, &id, ExplorationRelation::Disproves);
        id
    }

    /// Add a hint (something worth investigating).
    pub fn add_hint(&mut self, hint: &str, from_id: &str, agent: &str) -> String {
        let id = self.add_node(ExplorationKind::Hint, hint, agent);
        self.add_edge(from_id, &id, ExplorationRelation::DerivedFrom);
        self.version += 1;
        id
    }

    pub fn add_edge(&mut self, from: &str, to: &str, kind: ExplorationRelation) {
        self.edges.push(ExplorationEdge { from: from.into(), to: to.into(), kind });
    }

    /// Anchor an exploration node to an asset.
    pub fn anchor(&mut self, exploration_id: &str, asset_id: &str, direction: AnchorDirection) {
        self.anchors.push(Anchor {
            exploration_id: exploration_id.into(),
            asset_id: asset_id.into(),
            direction,
        });
    }

    /// Update node status.
    pub fn set_status(&mut self, id: &str, status: ExplorationStatus) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.id == id) {
            node.status = status;
            self.version += 1;
        }
    }

    /// All pending intents (the planner's work queue).
    pub fn pending_intents(&self) -> Vec<&ExplorationNode> {
        self.nodes.iter()
            .filter(|n| n.kind == ExplorationKind::Intent && n.status == ExplorationStatus::Pending)
            .collect()
    }

    /// All facts derived from a specific intent.
    pub fn facts_from(&self, intent_id: &str) -> Vec<&ExplorationNode> {
        let fact_ids: HashSet<&str> = self.edges.iter()
            .filter(|e| e.from == intent_id && e.kind == ExplorationRelation::Yields)
            .map(|e| e.to.as_str())
            .collect();
        self.nodes.iter().filter(|n| fact_ids.contains(n.id.as_str())).collect()
    }

    /// All hints not yet turned into intents.
    pub fn unactioned_hints(&self) -> Vec<&ExplorationNode> {
        let actioned: HashSet<&str> = self.edges.iter()
            .filter(|e| e.kind == ExplorationRelation::Spawns || e.kind == ExplorationRelation::DerivedFrom)
            .flat_map(|e| [e.from.as_str(), e.to.as_str()])
            .collect();
        self.nodes.iter()
            .filter(|n| n.kind == ExplorationKind::Hint && !actioned.contains(n.id.as_str()))
            .collect()
    }

    /// Generate a summary for prompt injection.
    pub fn prompt_summary(&self) -> String {
        let mut s = String::from("EXPLORATION STATE:\n");
        let counts: HashMap<ExplorationKind, usize> = {
            let mut m = HashMap::new();
            for n in &self.nodes { *m.entry(n.kind).or_default() += 1; }
            m
        };
        for (kind, count) in &counts {
            s.push_str(&format!("  {kind:?}: {count}\n"));
        }

        let pending = self.pending_intents();
        if !pending.is_empty() {
            s.push_str(&format!("  Pending intents: {}\n", pending.len()));
            for p in pending.iter().take(10) {
                s.push_str(&format!("    - {}\n", &p.content[..p.content.len().min(100)]));
            }
        }

        let hints = self.unactioned_hints();
        if !hints.is_empty() {
            s.push_str(&format!("  Unactioned hints: {}\n", hints.len()));
            for h in hints.iter().take(5) {
                s.push_str(&format!("    - {}\n", &h.content[..h.content.len().min(100)]));
            }
        }

        s
    }

    /// Save to disk.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    /// Load from disk.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// Combined dual-graph with anchoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DualGraph {
    pub assets: AssetGraph,
    pub exploration: ExplorationGraph,
}

impl DualGraph {
    pub fn new() -> Self { Self::default() }

    /// Submit a discovered asset and automatically anchor the exploration that found it.
    pub fn discover_asset(
        &mut self,
        kind: AssetKind,
        value: &str,
        properties: BTreeMap<String, String>,
        discovered_by_agent: &str,
        exploration_id: Option<&str>,
    ) -> bool {
        let is_new = self.assets.upsert(kind, value, properties, discovered_by_agent);
        if let Some(exp_id) = exploration_id {
            if let Some(asset) = self.assets.find(kind, value) {
                let asset_id = asset.id.clone();
                self.exploration.anchor(exp_id, &asset_id, AnchorDirection::Discovered);
            }
        }
        is_new
    }

    /// Create an intent that targets a specific asset.
    pub fn target_asset(&mut self, intent: &str, goal_id: &str, agent: &str, asset_id: &str) -> String {
        let exp_id = self.exploration.add_intent(intent, goal_id, agent);
        self.exploration.anchor(&exp_id, asset_id, AnchorDirection::Targets);
        if let Some(node) = self.assets.nodes.iter_mut().find(|n| n.id == asset_id) {
            node.exploration_count += 1;
        }
        exp_id
    }

    /// Record a finding against an asset.
    pub fn record_finding(&mut self, finding: &str, intent_id: &str, agent: &str, asset_id: &str) -> String {
        let exp_id = self.exploration.add_finding(finding, intent_id, agent);
        self.exploration.anchor(&exp_id, asset_id, AnchorDirection::Targets);
        if let Some(node) = self.assets.nodes.iter_mut().find(|n| n.id == asset_id) {
            node.finding_count += 1;
        }
        exp_id
    }

    /// Combined prompt block for agent context.
    pub fn prompt_block(&self) -> String {
        let mut s = String::new();
        let asset_summary = self.assets.prompt_summary();
        let exp_summary = self.exploration.prompt_summary();
        if !asset_summary.is_empty() { s.push_str(&asset_summary); }
        if !exp_summary.is_empty() { s.push_str(&exp_summary); }
        s
    }

    /// Save both graphs.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(dir.join("dual-graph.json"), json)
    }

    /// Load both graphs.
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(dir.join("dual-graph.json"))?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    // ── Checkpoint / Rollback ──

    /// Create a named checkpoint (snapshot) of the entire dual-graph state.
    /// Checkpoints are stored as `<dir>/checkpoints/<label>.json`.
    /// Use before risky exploration branches so you can roll back if they fail.
    pub fn checkpoint(&self, dir: &Path, label: &str) -> std::io::Result<()> {
        let cp_dir = dir.join("checkpoints");
        std::fs::create_dir_all(&cp_dir)?;
        let json = serde_json::to_string(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let safe_label: String = label.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        std::fs::write(cp_dir.join(format!("{safe_label}.json")), json)
    }

    /// Restore from a named checkpoint. Returns the restored graph.
    /// The caller replaces `self` with the result.
    pub fn rollback(dir: &Path, label: &str) -> std::io::Result<Self> {
        let safe_label: String = label.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let path = dir.join("checkpoints").join(format!("{safe_label}.json"));
        let json = std::fs::read_to_string(&path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    /// List available checkpoints with their labels and timestamps.
    pub fn list_checkpoints(dir: &Path) -> Vec<(String, u64)> {
        let cp_dir = dir.join("checkpoints");
        let Ok(rd) = std::fs::read_dir(&cp_dir) else { return vec![] };
        let mut checkpoints = Vec::new();
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                let label = name.trim_end_matches(".json").to_string();
                let modified = entry.metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                checkpoints.push((label, modified));
            }
        }
        checkpoints.sort_by(|a, b| b.1.cmp(&a.1));
        checkpoints
    }

    /// Delete a checkpoint.
    pub fn delete_checkpoint(dir: &Path, label: &str) -> std::io::Result<()> {
        let safe_label: String = label.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        std::fs::remove_file(dir.join("checkpoints").join(format!("{safe_label}.json")))
    }

    /// Auto-checkpoint: saves a checkpoint named `phase-<N>` where N is the
    /// exploration graph version. Called automatically between pipeline phases.
    pub fn auto_checkpoint(&self, dir: &Path) -> std::io::Result<()> {
        let label = format!("phase-{}", self.exploration.version);
        self.checkpoint(dir, &label)
    }

    /// Rollback to the latest checkpoint that passes a predicate.
    /// Useful for "rollback to before this exploration branch failed".
    pub fn rollback_before(dir: &Path, predicate: impl Fn(&Self) -> bool) -> Option<Self> {
        let checkpoints = Self::list_checkpoints(dir);
        for (label, _) in &checkpoints {
            if let Ok(graph) = Self::rollback(dir, label) {
                if predicate(&graph) {
                    return Some(graph);
                }
            }
        }
        None
    }

    /// Rollback to the latest checkpoint where an exploration node doesn't exist.
    /// This lets the planner undo a failed branch of exploration.
    pub fn rollback_before_node(dir: &Path, node_id: &str) -> Option<Self> {
        Self::rollback_before(dir, |g| {
            !g.exploration.nodes.iter().any(|n| n.id == node_id)
        })
    }
}

// ── Helpers ──

fn dedup_key(kind: AssetKind, value: &str) -> String {
    let normalized = value.to_lowercase().trim_end_matches('/').to_string();
    format!("{kind:?}:{normalized}")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_dedup() {
        let mut g = AssetGraph::new();
        assert!(g.upsert(AssetKind::Endpoint, "/api/users", BTreeMap::new(), "recon"));
        assert!(!g.upsert(AssetKind::Endpoint, "/api/users", BTreeMap::new(), "recon"));
        assert_eq!(g.nodes.len(), 1);
    }

    #[test]
    fn test_dual_graph_coverage() {
        let mut dg = DualGraph::new();
        dg.assets.upsert(AssetKind::Endpoint, "/api/users", BTreeMap::new(), "recon");
        dg.assets.upsert(AssetKind::Endpoint, "/api/admin", BTreeMap::new(), "recon");
        assert_eq!(dg.assets.coverage(), 0.0);
        assert_eq!(dg.assets.untested().len(), 2);
    }

    #[test]
    fn test_exploration_flow() {
        let mut eg = ExplorationGraph::new();
        let goal = eg.add_goal("Test SQLi on all endpoints", "planner");
        let intent = eg.add_intent("Test /api/login username param", &goal, "sqli_agent");
        let _fact = eg.add_fact("Param reflects error with single quote", &intent, "sqli_agent");
        let _finding = eg.add_finding("SQL injection in username", &intent, "sqli_agent");
        assert_eq!(eg.nodes.len(), 4);
        assert_eq!(eg.edges.len(), 3);
    }
}
