//! Reactive Planner — event-driven re-planning loop.
//!
//! The current pipeline runs recon → select agents → exploit → validate once.
//! This planner watches the exploration graph and re-plans when:
//!
//! 1. **New assets discovered** — new endpoints to test
//! 2. **Facts emerge** — a reflected param means XSS agents should run
//! 3. **Findings chain** — SQLi leads to data access, which leads to privesc
//! 4. **Agents fail** — retry with different strategy or model
//! 5. **Coverage gaps** — untested surface after initial wave
//!
//! The planner is stateless per wake: it reads the current graph, compares to
//! a persistent todolist, and emits intents. Each intent is one unit of work
//! an agent can complete independently.

use crate::exploration_graph::{DualGraph, ExplorationKind, ExplorationStatus, AssetKind};
use crate::adaptive::AdaptiveEngine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A planner decision: what to do next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerIntent {
    pub id: String,
    pub action: IntentAction,
    pub target: String,
    pub agent_hint: String,
    pub priority: u32,
    pub rationale: String,
    pub depends_on: Vec<String>,
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntentAction {
    /// Run a specific exploit agent against a target.
    Exploit,
    /// Probe a parameter to understand its behavior.
    Probe,
    /// Deeper recon on a discovered asset.
    Recon,
    /// Chain from an existing finding.
    Chain,
    /// Retry a failed attempt with different strategy.
    Retry,
    /// Validate a hint before committing an exploit agent.
    Validate,
    /// Fuzz a parameter/endpoint systematically.
    Fuzz,
}

/// The persistent todolist — survives across planner wakes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TodoList {
    pub items: Vec<TodoItem>,
    pub completed: HashSet<String>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub id: String,
    pub intent: PlannerIntent,
    pub status: TodoStatus,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub assigned_agent: Option<String>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TodoStatus {
    #[default]
    Queued,
    Assigned,
    Running,
    Completed,
    Failed,
    Blocked,
    Skipped,
}

/// Configuration for the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerConfig {
    pub max_intents_per_wake: usize,
    pub max_retries: u32,
    pub coverage_target: f64,
    pub chain_depth_limit: u32,
    pub enable_fuzzing: bool,
    pub enable_probing: bool,
    pub priority_threshold: u32,
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            max_intents_per_wake: 10,
            max_retries: 3,
            coverage_target: 0.8,
            chain_depth_limit: 4,
            enable_fuzzing: true,
            enable_probing: true,
            priority_threshold: 20,
        }
    }
}

/// The planner: reads the graph, emits intents.
pub struct Planner {
    pub config: PlannerConfig,
    pub todo: TodoList,
    last_graph_version: u64,
}

impl Planner {
    pub fn new(config: PlannerConfig) -> Self {
        Self {
            config,
            todo: TodoList::default(),
            last_graph_version: 0,
        }
    }

    /// Wake the planner: inspect the graph and emit new intents.
    /// Returns empty if nothing changed since last wake.
    pub fn wake(&mut self, graph: &DualGraph, adaptive: &AdaptiveEngine) -> Vec<PlannerIntent> {
        if graph.exploration.version == self.last_graph_version {
            return vec![];
        }
        self.last_graph_version = graph.exploration.version;

        let mut intents = Vec::new();

        // 1. Coverage-driven: untested assets need exploration
        intents.extend(self.coverage_intents(graph));

        // 2. Fact-driven: new facts trigger specialized testing
        intents.extend(self.fact_driven_intents(graph, adaptive));

        // 3. Finding-driven: chain from confirmed findings
        intents.extend(self.chain_intents(graph));

        // 4. Hint-driven: investigate unactioned hints
        intents.extend(self.hint_intents(graph));

        // 5. Retry-driven: failed intents with retry budget
        intents.extend(self.retry_intents(graph));

        // Deduplicate and prioritize
        intents.sort_by(|a, b| b.priority.cmp(&a.priority));
        intents.truncate(self.config.max_intents_per_wake);

        // Add to todolist
        for intent in &intents {
            if !self.todo.completed.contains(&intent.id) {
                self.todo.items.push(TodoItem {
                    id: intent.id.clone(),
                    intent: intent.clone(),
                    status: TodoStatus::Queued,
                    created_at: now(),
                    started_at: None,
                    completed_at: None,
                    assigned_agent: None,
                    result: None,
                });
            }
        }
        self.todo.version += 1;

        intents
    }

    /// Claim the next intent from the todolist for an agent.
    pub fn claim(&mut self, agent: &str) -> Option<PlannerIntent> {
        let item = self.todo.items.iter_mut()
            .filter(|i| i.status == TodoStatus::Queued)
            .filter(|i| i.intent.depends_on.iter().all(|dep| self.todo.completed.contains(dep)))
            .max_by_key(|i| i.intent.priority)?;

        item.status = TodoStatus::Assigned;
        item.assigned_agent = Some(agent.to_string());
        item.started_at = Some(now());
        Some(item.intent.clone())
    }

    /// Mark an intent as completed.
    pub fn complete(&mut self, id: &str, result: &str) {
        if let Some(item) = self.todo.items.iter_mut().find(|i| i.id == id) {
            item.status = TodoStatus::Completed;
            item.completed_at = Some(now());
            item.result = Some(result.to_string());
            self.todo.completed.insert(id.to_string());
        }
    }

    /// Mark an intent as failed.
    pub fn fail(&mut self, id: &str, reason: &str) {
        if let Some(item) = self.todo.items.iter_mut().find(|i| i.id == id) {
            item.status = TodoStatus::Failed;
            item.result = Some(reason.to_string());
        }
    }

    /// Generate a prompt block summarizing the plan state.
    pub fn prompt_block(&self) -> String {
        let queued = self.todo.items.iter().filter(|i| i.status == TodoStatus::Queued).count();
        let running = self.todo.items.iter().filter(|i| i.status == TodoStatus::Running || i.status == TodoStatus::Assigned).count();
        let done = self.todo.items.iter().filter(|i| i.status == TodoStatus::Completed).count();
        let failed = self.todo.items.iter().filter(|i| i.status == TodoStatus::Failed).count();

        if queued + running + done + failed == 0 { return String::new(); }

        let mut s = format!("PLANNER STATE: {queued} queued, {running} running, {done} done, {failed} failed\n");

        let next: Vec<&TodoItem> = self.todo.items.iter()
            .filter(|i| i.status == TodoStatus::Queued)
            .take(5)
            .collect();
        if !next.is_empty() {
            s.push_str("Next in queue:\n");
            for item in next {
                s.push_str(&format!("  [{:?} P{}] {} -> {}\n",
                    item.intent.action, item.intent.priority,
                    item.intent.agent_hint, item.intent.target));
            }
        }

        s
    }

    /// Save todolist to disk.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.todo)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    /// Load todolist from disk.
    pub fn load_todo(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let json = std::fs::read_to_string(path)?;
        self.todo = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(())
    }

    // ── Internal intent generators ──

    fn coverage_intents(&self, graph: &DualGraph) -> Vec<PlannerIntent> {
        let coverage = graph.assets.coverage();
        if coverage >= self.config.coverage_target { return vec![]; }

        graph.assets.untested().iter()
            .take(self.config.max_intents_per_wake / 2)
            .enumerate()
            .map(|(i, asset)| {
                let agent_hint = match asset.kind {
                    AssetKind::Endpoint => suggest_agent_for_endpoint(&asset.value),
                    AssetKind::Parameter => "param_probe".to_string(),
                    AssetKind::Service => "service_scan".to_string(),
                    _ => "generic_test".to_string(),
                };
                PlannerIntent {
                    id: format!("coverage-{}-{}", asset.id, i),
                    action: if self.config.enable_probing { IntentAction::Probe } else { IntentAction::Exploit },
                    target: asset.value.clone(),
                    agent_hint,
                    priority: 60 + (100.0 * (1.0 - coverage)) as u32,
                    rationale: format!("Coverage gap: {:?} '{}' untested (coverage: {:.0}%)",
                        asset.kind, asset.value, coverage * 100.0),
                    depends_on: vec![],
                    asset_id: Some(asset.id.clone()),
                }
            })
            .collect()
    }

    fn fact_driven_intents(&self, graph: &DualGraph, adaptive: &AdaptiveEngine) -> Vec<PlannerIntent> {
        let mut intents = Vec::new();

        // Find recent facts and generate specialized intents
        let recent_facts: Vec<_> = graph.exploration.nodes.iter()
            .filter(|n| n.kind == ExplorationKind::Fact && n.status != ExplorationStatus::Superseded)
            .collect();

        for fact in recent_facts.iter().take(20) {
            let content = fact.content.to_lowercase();

            // Reflected input → XSS testing
            if content.contains("reflect") && !content.contains("filtered") {
                intents.push(PlannerIntent {
                    id: format!("fact-xss-{}", fact.id),
                    action: IntentAction::Exploit,
                    target: extract_target_from_fact(&fact.content),
                    agent_hint: "xss_reflected".to_string(),
                    priority: 80,
                    rationale: format!("Unfiltered reflection detected: {}", &fact.content[..fact.content.len().min(80)]),
                    depends_on: vec![],
                    asset_id: None,
                });
            }

            // SQL error → SQL injection testing
            if content.contains("sql") && (content.contains("error") || content.contains("syntax")) {
                intents.push(PlannerIntent {
                    id: format!("fact-sqli-{}", fact.id),
                    action: IntentAction::Exploit,
                    target: extract_target_from_fact(&fact.content),
                    agent_hint: "sqli_union".to_string(),
                    priority: 90,
                    rationale: "SQL error observed — database reachable through input".into(),
                    depends_on: vec![],
                    asset_id: None,
                });
            }

            // Stack trace → technology-specific testing
            if content.contains("stack trace") || content.contains("traceback") {
                intents.push(PlannerIntent {
                    id: format!("fact-stack-{}", fact.id),
                    action: IntentAction::Exploit,
                    target: extract_target_from_fact(&fact.content),
                    agent_hint: match_tech_agent(&adaptive.stack),
                    priority: 70,
                    rationale: "Stack trace leaks technology — target with stack-specific payloads".into(),
                    depends_on: vec![],
                    asset_id: None,
                });
            }

            // Debug/admin endpoint → deeper recon
            if content.contains("debug") || content.contains("admin") || content.contains("internal") {
                intents.push(PlannerIntent {
                    id: format!("fact-recon-{}", fact.id),
                    action: IntentAction::Recon,
                    target: extract_target_from_fact(&fact.content),
                    agent_hint: "forced_browsing".to_string(),
                    priority: 75,
                    rationale: "Administrative/debug surface discovered".into(),
                    depends_on: vec![],
                    asset_id: None,
                });
            }
        }

        intents
    }

    fn chain_intents(&self, graph: &DualGraph) -> Vec<PlannerIntent> {
        let mut intents = Vec::new();
        let findings: Vec<_> = graph.exploration.nodes.iter()
            .filter(|n| n.kind == ExplorationKind::Finding)
            .collect();

        for finding in findings.iter().take(10) {
            let content = finding.content.to_lowercase();

            // SSRF → cloud metadata chain
            if content.contains("ssrf") {
                intents.push(PlannerIntent {
                    id: format!("chain-ssrf-cloud-{}", finding.id),
                    action: IntentAction::Chain,
                    target: extract_target_from_fact(&finding.content),
                    agent_hint: "gcp_metadata_ssrf".to_string(),
                    priority: 95,
                    rationale: "SSRF confirmed — chain to cloud metadata for credential harvest".into(),
                    depends_on: vec![finding.id.clone()],
                    asset_id: None,
                });
            }

            // SQLi → data exfiltration chain
            if content.contains("sql injection") || content.contains("sqli") {
                intents.push(PlannerIntent {
                    id: format!("chain-sqli-data-{}", finding.id),
                    action: IntentAction::Chain,
                    target: extract_target_from_fact(&finding.content),
                    agent_hint: "sqli_data_exfil".to_string(),
                    priority: 90,
                    rationale: "SQLi confirmed — chain to data exfiltration and RCE".into(),
                    depends_on: vec![finding.id.clone()],
                    asset_id: None,
                });
            }

            // XSS → account takeover chain
            if content.contains("xss") || content.contains("cross-site scripting") {
                intents.push(PlannerIntent {
                    id: format!("chain-xss-ato-{}", finding.id),
                    action: IntentAction::Chain,
                    target: extract_target_from_fact(&finding.content),
                    agent_hint: "account_takeover_chain".to_string(),
                    priority: 85,
                    rationale: "XSS confirmed — chain to session hijack / account takeover".into(),
                    depends_on: vec![finding.id.clone()],
                    asset_id: None,
                });
            }

            // Auth bypass → privilege escalation
            if content.contains("auth") && (content.contains("bypass") || content.contains("broken")) {
                intents.push(PlannerIntent {
                    id: format!("chain-auth-privesc-{}", finding.id),
                    action: IntentAction::Chain,
                    target: extract_target_from_fact(&finding.content),
                    agent_hint: "privilege_escalation".to_string(),
                    priority: 92,
                    rationale: "Auth bypass confirmed — chain to privilege escalation".into(),
                    depends_on: vec![finding.id.clone()],
                    asset_id: None,
                });
            }
        }

        intents
    }

    fn hint_intents(&self, graph: &DualGraph) -> Vec<PlannerIntent> {
        graph.exploration.unactioned_hints().iter()
            .take(5)
            .enumerate()
            .map(|(i, hint)| PlannerIntent {
                id: format!("hint-{}-{}", hint.id, i),
                action: IntentAction::Validate,
                target: extract_target_from_fact(&hint.content),
                agent_hint: suggest_agent_for_hint(&hint.content),
                priority: 50,
                rationale: format!("Hint worth investigating: {}", &hint.content[..hint.content.len().min(80)]),
                depends_on: vec![],
                asset_id: None,
            })
            .collect()
    }

    fn retry_intents(&self, graph: &DualGraph) -> Vec<PlannerIntent> {
        let failed: Vec<_> = graph.exploration.nodes.iter()
            .filter(|n| n.kind == ExplorationKind::Intent && n.status == ExplorationStatus::Failed)
            .collect();

        let mut intents = Vec::new();
        for node in failed.iter().take(5) {
            let retry_count = self.todo.items.iter()
                .filter(|i| i.intent.target == node.content && i.status == TodoStatus::Failed)
                .count() as u32;

            if retry_count < self.config.max_retries {
                intents.push(PlannerIntent {
                    id: format!("retry-{}-{}", node.id, retry_count + 1),
                    action: IntentAction::Retry,
                    target: extract_target_from_fact(&node.content),
                    agent_hint: node.agent.clone(),
                    priority: 40 - retry_count * 10,
                    rationale: format!("Retry #{} after failure: {}", retry_count + 1,
                        &node.content[..node.content.len().min(60)]),
                    depends_on: vec![],
                    asset_id: None,
                });
            }
        }
        intents
    }
}

// ── Collaborative Intent Negotiation ──

/// Bid from an agent wanting to claim an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBid {
    pub agent: String,
    pub intent_id: String,
    pub score: u32,
    pub specialization: Vec<String>,
    pub current_load: u32,
}

/// Outcome of a negotiation round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResult {
    pub assignments: Vec<NegotiationAssignment>,
    pub unassigned: Vec<String>,
    pub conflicts_resolved: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationAssignment {
    pub intent_id: String,
    pub agent: String,
    pub score: u32,
    pub reason: String,
}

/// Agent capability profile for negotiation scoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentProfile {
    pub name: String,
    pub specializations: Vec<String>,
    pub completed: u32,
    pub failed: u32,
    pub active: u32,
    pub max_concurrent: u32,
}

impl AgentProfile {
    pub fn new(name: &str, specializations: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            specializations,
            completed: 0,
            failed: 0,
            active: 0,
            max_concurrent: 3,
        }
    }

    fn success_rate(&self) -> f64 {
        let total = self.completed + self.failed;
        if total == 0 { return 0.5; }
        self.completed as f64 / total as f64
    }

    fn capacity_remaining(&self) -> u32 {
        self.max_concurrent.saturating_sub(self.active)
    }
}

/// Negotiation engine — resolves multi-agent contention for intents.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Negotiator {
    pub profiles: HashMap<String, AgentProfile>,
    pub history: Vec<NegotiationResult>,
}

impl Negotiator {
    pub fn new() -> Self { Self::default() }

    pub fn register(&mut self, profile: AgentProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    pub fn unregister(&mut self, agent: &str) {
        self.profiles.remove(agent);
    }

    /// Score a bid: how well does this agent fit this intent?
    fn score_bid(&self, bid: &AgentBid, intent: &PlannerIntent) -> u32 {
        let profile = match self.profiles.get(&bid.agent) {
            Some(p) => p,
            None => return bid.score,
        };

        let mut score = bid.score;

        // Specialization match bonus (0-40 points)
        let spec_match = profile.specializations.iter()
            .any(|s| intent.agent_hint.contains(s) || s.contains(&intent.agent_hint));
        if spec_match { score += 40; }

        // Action-type match bonus (0-20 points)
        let action_specs: Vec<&str> = match intent.action {
            IntentAction::Exploit => vec!["exploit", "attack", "injection", "xss", "sqli"],
            IntentAction::Recon => vec!["recon", "scan", "discover", "enumerate"],
            IntentAction::Probe => vec!["probe", "fuzz", "test", "param"],
            IntentAction::Chain => vec!["chain", "pivot", "escalate", "privesc"],
            IntentAction::Validate => vec!["validate", "verify", "confirm"],
            IntentAction::Fuzz => vec!["fuzz", "brute", "mutate"],
            IntentAction::Retry => vec!["retry", "fallback"],
        };
        if profile.specializations.iter().any(|s| {
            let sl = s.to_lowercase();
            action_specs.iter().any(|a| sl.contains(a))
        }) {
            score += 20;
        }

        // Success rate bonus (0-30 points)
        score += (profile.success_rate() * 30.0) as u32;

        // Load penalty: busy agents score lower
        if profile.capacity_remaining() == 0 {
            score = score.saturating_sub(50);
        } else {
            score += profile.capacity_remaining() * 5;
        }

        // Historical penalty: agent already failed this target
        let target_lower = intent.target.to_lowercase();
        if profile.specializations.iter().any(|s| target_lower.contains(&s.to_lowercase())) {
            score += 10;
        }

        score
    }

    /// Run a negotiation round: given bids from multiple agents for multiple intents,
    /// resolve contention and produce assignments.
    pub fn negotiate(&mut self, bids: Vec<AgentBid>, intents: &[PlannerIntent]) -> NegotiationResult {
        let intent_map: HashMap<&str, &PlannerIntent> = intents.iter()
            .map(|i| (i.id.as_str(), i))
            .collect();

        // Score all bids
        let mut scored: Vec<(AgentBid, u32)> = bids.into_iter()
            .filter_map(|bid| {
                let intent = intent_map.get(bid.intent_id.as_str())?;
                let score = self.score_bid(&bid, intent);
                Some((bid, score))
            })
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.1.cmp(&a.1));

        let mut assignments = Vec::new();
        let mut assigned_intents: HashSet<String> = HashSet::new();
        let mut assigned_agents: HashMap<String, u32> = HashMap::new();
        let mut conflicts = 0u32;

        for (bid, score) in &scored {
            if assigned_intents.contains(&bid.intent_id) {
                conflicts += 1;
                continue;
            }

            let agent_load = assigned_agents.get(&bid.agent).copied().unwrap_or(0);
            let max = self.profiles.get(&bid.agent)
                .map(|p| p.max_concurrent)
                .unwrap_or(3);
            if agent_load >= max { continue; }

            let reason = if let Some(profile) = self.profiles.get(&bid.agent) {
                let spec = profile.specializations.iter()
                    .find(|s| bid.intent_id.to_lowercase().contains(&s.to_lowercase())
                        || intent_map.get(bid.intent_id.as_str())
                            .map(|i| i.agent_hint.contains(s.as_str()))
                            .unwrap_or(false))
                    .cloned()
                    .unwrap_or_default();
                if !spec.is_empty() {
                    format!("specialization match '{}', score {}", spec, score)
                } else {
                    format!("best available, score {}", score)
                }
            } else {
                format!("score {}", score)
            };

            assignments.push(NegotiationAssignment {
                intent_id: bid.intent_id.clone(),
                agent: bid.agent.clone(),
                score: *score,
                reason,
            });

            assigned_intents.insert(bid.intent_id.clone());
            *assigned_agents.entry(bid.agent.clone()).or_insert(0) += 1;
        }

        let unassigned: Vec<String> = intents.iter()
            .filter(|i| !assigned_intents.contains(&i.id))
            .map(|i| i.id.clone())
            .collect();

        let result = NegotiationResult {
            assignments,
            unassigned,
            conflicts_resolved: conflicts,
        };

        self.history.push(result.clone());
        result
    }

    /// Generate prompt block describing negotiation state.
    pub fn prompt_block(&self) -> String {
        if self.profiles.is_empty() { return String::new(); }

        let mut s = String::from("NEGOTIATION STATE:\n");
        s.push_str(&format!("  Registered agents: {}\n", self.profiles.len()));

        for (name, profile) in &self.profiles {
            s.push_str(&format!("  {} — specs: [{}], load: {}/{}, success: {:.0}%\n",
                name,
                profile.specializations.join(", "),
                profile.active,
                profile.max_concurrent,
                profile.success_rate() * 100.0));
        }

        if let Some(last) = self.history.last() {
            s.push_str(&format!("  Last round: {} assigned, {} unassigned, {} conflicts\n",
                last.assignments.len(), last.unassigned.len(), last.conflicts_resolved));
        }

        s
    }
}

impl Planner {
    /// Negotiate intent assignments among multiple bidding agents.
    /// Returns assignments and applies them to the todolist.
    pub fn negotiate_and_assign(
        &mut self,
        bids: Vec<AgentBid>,
        negotiator: &mut Negotiator,
    ) -> NegotiationResult {
        let queued_intents: Vec<PlannerIntent> = self.todo.items.iter()
            .filter(|i| i.status == TodoStatus::Queued)
            .map(|i| i.intent.clone())
            .collect();

        let result = negotiator.negotiate(bids, &queued_intents);

        // Apply assignments to todolist
        for assignment in &result.assignments {
            if let Some(item) = self.todo.items.iter_mut()
                .find(|i| i.id == assignment.intent_id && i.status == TodoStatus::Queued)
            {
                item.status = TodoStatus::Assigned;
                item.assigned_agent = Some(assignment.agent.clone());
                item.started_at = Some(now());
            }

            // Update agent profile load
            if let Some(profile) = negotiator.profiles.get_mut(&assignment.agent) {
                profile.active += 1;
            }
        }

        result
    }

    /// Record agent task completion and update negotiator profile.
    pub fn complete_with_profile(&mut self, id: &str, result: &str, negotiator: &mut Negotiator) {
        let agent = self.todo.items.iter()
            .find(|i| i.id == id)
            .and_then(|i| i.assigned_agent.clone());

        self.complete(id, result);

        if let Some(agent) = agent {
            if let Some(profile) = negotiator.profiles.get_mut(&agent) {
                profile.completed += 1;
                profile.active = profile.active.saturating_sub(1);
            }
        }
    }

    /// Record agent task failure and update negotiator profile.
    pub fn fail_with_profile(&mut self, id: &str, reason: &str, negotiator: &mut Negotiator) {
        let agent = self.todo.items.iter()
            .find(|i| i.id == id)
            .and_then(|i| i.assigned_agent.clone());

        self.fail(id, reason);

        if let Some(agent) = agent {
            if let Some(profile) = negotiator.profiles.get_mut(&agent) {
                profile.failed += 1;
                profile.active = profile.active.saturating_sub(1);
            }
        }
    }
}

// ── Helpers ──

fn suggest_agent_for_endpoint(endpoint: &str) -> String {
    let lower = endpoint.to_lowercase();
    if lower.contains("login") || lower.contains("auth") || lower.contains("session") {
        "auth_bypass".to_string()
    } else if lower.contains("admin") || lower.contains("manage") {
        "forced_browsing".to_string()
    } else if lower.contains("upload") || lower.contains("file") {
        "file_upload".to_string()
    } else if lower.contains("api") || lower.contains("graphql") {
        "api_bola".to_string()
    } else if lower.contains("search") || lower.contains("query") || lower.contains("filter") {
        "sqli_union".to_string()
    } else if lower.contains("redirect") || lower.contains("url") || lower.contains("goto") {
        "open_redirect".to_string()
    } else {
        "generic_probe".to_string()
    }
}

fn suggest_agent_for_hint(hint: &str) -> String {
    let lower = hint.to_lowercase();
    if lower.contains("xss") || lower.contains("reflect") { "xss_reflected".into() }
    else if lower.contains("sql") { "sqli_union".into() }
    else if lower.contains("ssrf") { "ssrf".into() }
    else if lower.contains("auth") { "auth_bypass".into() }
    else if lower.contains("idor") { "idor".into() }
    else { "generic_probe".into() }
}

fn match_tech_agent(stack: &crate::adaptive::TargetStack) -> String {
    let lang = stack.language.to_lowercase();
    let fw = stack.framework.to_lowercase();
    if lang.contains("php") || fw.contains("laravel") { "ssti".into() }
    else if lang.contains("java") || fw.contains("spring") { "log4shell_jndi".into() }
    else if lang.contains("python") || fw.contains("django") || fw.contains("flask") { "ssti".into() }
    else if lang.contains("node") || fw.contains("express") { "server_side_prototype_pollution".into() }
    else { "command_injection".into() }
}

fn extract_target_from_fact(content: &str) -> String {
    // Try to extract a URL or endpoint from the fact content
    for word in content.split_whitespace() {
        if word.starts_with("http://") || word.starts_with("https://") || word.starts_with('/') {
            return word.trim_end_matches([',', '.', ')', ']']).to_string();
        }
    }
    content.chars().take(100).collect()
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
    fn test_planner_coverage_intents() {
        let mut graph = DualGraph::new();
        graph.assets.upsert(AssetKind::Endpoint, "/api/users", BTreeMap::new(), "recon");
        graph.assets.upsert(AssetKind::Endpoint, "/api/admin", BTreeMap::new(), "recon");
        graph.exploration.version = 1;

        let mut planner = Planner::new(PlannerConfig::default());
        let intents = planner.wake(&graph, &AdaptiveEngine::new());
        assert!(!intents.is_empty());
        assert!(intents.iter().all(|i| i.action == IntentAction::Probe));
    }

    #[test]
    fn test_planner_chain_intents() {
        let mut graph = DualGraph::new();
        let goal = graph.exploration.add_goal("Test target", "planner");
        let intent = graph.exploration.add_intent("Test SQLi", &goal, "sqli_agent");
        graph.exploration.add_finding("SQL injection found in /api/users", &intent, "sqli_agent");

        let mut planner = Planner::new(PlannerConfig::default());
        let intents = planner.wake(&graph, &AdaptiveEngine::new());
        assert!(intents.iter().any(|i| i.action == IntentAction::Chain));
    }

    #[test]
    fn test_negotiation_resolves_contention() {
        let mut negotiator = Negotiator::new();
        negotiator.register(AgentProfile::new("xss_agent", vec!["xss".into(), "reflected".into()]));
        negotiator.register(AgentProfile::new("sqli_agent", vec!["sqli".into(), "injection".into()]));

        let intents = vec![
            PlannerIntent {
                id: "intent-xss-1".into(),
                action: IntentAction::Exploit,
                target: "/search".into(),
                agent_hint: "xss_reflected".into(),
                priority: 80,
                rationale: "test".into(),
                depends_on: vec![],
                asset_id: None,
            },
        ];

        let bids = vec![
            AgentBid { agent: "xss_agent".into(), intent_id: "intent-xss-1".into(), score: 50, specialization: vec!["xss".into()], current_load: 0 },
            AgentBid { agent: "sqli_agent".into(), intent_id: "intent-xss-1".into(), score: 50, specialization: vec!["sqli".into()], current_load: 0 },
        ];

        let result = negotiator.negotiate(bids, &intents);
        assert_eq!(result.assignments.len(), 1);
        assert_eq!(result.assignments[0].agent, "xss_agent");
        assert_eq!(result.conflicts_resolved, 1);
    }

    #[test]
    fn test_negotiation_respects_capacity() {
        let mut negotiator = Negotiator::new();
        let mut profile = AgentProfile::new("busy_agent", vec!["xss".into()]);
        profile.active = 3;
        profile.max_concurrent = 3;
        negotiator.register(profile);
        negotiator.register(AgentProfile::new("free_agent", vec!["generic".into()]));

        let intents = vec![
            PlannerIntent {
                id: "intent-1".into(),
                action: IntentAction::Probe,
                target: "/api".into(),
                agent_hint: "generic_probe".into(),
                priority: 60,
                rationale: "test".into(),
                depends_on: vec![],
                asset_id: None,
            },
        ];

        let bids = vec![
            AgentBid { agent: "busy_agent".into(), intent_id: "intent-1".into(), score: 80, specialization: vec!["xss".into()], current_load: 3 },
            AgentBid { agent: "free_agent".into(), intent_id: "intent-1".into(), score: 40, specialization: vec!["generic".into()], current_load: 0 },
        ];

        let result = negotiator.negotiate(bids, &intents);
        assert_eq!(result.assignments.len(), 1);
        assert_eq!(result.assignments[0].agent, "free_agent");
    }

    #[test]
    fn test_negotiate_and_assign_updates_todolist() {
        let mut planner = Planner::new(PlannerConfig::default());
        let mut negotiator = Negotiator::new();
        negotiator.register(AgentProfile::new("agent_a", vec!["sqli".into()]));

        planner.todo.items.push(TodoItem {
            id: "neg-1".into(),
            intent: PlannerIntent {
                id: "neg-1".into(),
                action: IntentAction::Exploit,
                target: "/login".into(),
                agent_hint: "sqli".into(),
                priority: 90,
                rationale: "test".into(),
                depends_on: vec![],
                asset_id: None,
            },
            status: TodoStatus::Queued,
            created_at: 0,
            started_at: None,
            completed_at: None,
            assigned_agent: None,
            result: None,
        });

        let bids = vec![
            AgentBid { agent: "agent_a".into(), intent_id: "neg-1".into(), score: 60, specialization: vec!["sqli".into()], current_load: 0 },
        ];

        let result = planner.negotiate_and_assign(bids, &mut negotiator);
        assert_eq!(result.assignments.len(), 1);

        let item = planner.todo.items.iter().find(|i| i.id == "neg-1").unwrap();
        assert_eq!(item.status, TodoStatus::Assigned);
        assert_eq!(item.assigned_agent.as_deref(), Some("agent_a"));
    }

    #[test]
    fn test_todolist_claim() {
        let mut planner = Planner::new(PlannerConfig::default());
        planner.todo.items.push(TodoItem {
            id: "test-1".into(),
            intent: PlannerIntent {
                id: "test-1".into(),
                action: IntentAction::Exploit,
                target: "/api/users".into(),
                agent_hint: "sqli".into(),
                priority: 80,
                rationale: "test".into(),
                depends_on: vec![],
                asset_id: None,
            },
            status: TodoStatus::Queued,
            created_at: 0,
            started_at: None,
            completed_at: None,
            assigned_agent: None,
            result: None,
        });
        let claimed = planner.claim("agent_1");
        assert!(claimed.is_some());
        assert_eq!(claimed.unwrap().id, "test-1");
    }
}
