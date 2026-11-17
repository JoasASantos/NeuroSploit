//! Graph-based reasoning — LLM-driven chain exploitation decisions.
//!
//! The dual graph (assets + exploration) already records what exists and what was
//! tried. This module adds the missing "what should we try next?" layer: given the
//! current graph state, ask an LLM to identify exploitation chains and decide where
//! to focus next. The graph is the shared memory; the LLM is the strategist.
//!
//! Three capabilities:
//! 1. **Chain analysis**: find multi-hop attack paths through the asset graph.
//! 2. **LLM decision**: given the graph summary and chain candidates, ask the LLM
//!    which path to pursue and why (structured output → planner intents).
//! 3. **Graph enrichment**: after a finding, trace which assets are reachable from
//!    the compromised position and mark them as high-priority targets.

use crate::exploration_graph::{AssetKind, AssetRelation, DualGraph, ExplorationKind, ExplorationStatus};
use crate::planner::{IntentAction, PlannerIntent};
use serde::{Deserialize, Serialize};

/// A candidate chain: a sequence of assets from a finding to an untested surface.
#[derive(Debug, Clone, Serialize)]
pub struct ChainCandidate {
    /// The finding that starts the chain.
    pub finding: String,
    /// Asset where the finding was confirmed.
    pub foothold: String,
    /// Assets along the path (the hops).
    pub hops: Vec<ChainHop>,
    /// The untested target at the end.
    pub target: String,
    /// Chain score (higher = more promising).
    pub score: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainHop {
    pub asset: String,
    pub kind: String,
    pub relation: String,
    pub tested: bool,
}

/// Find chain candidates: paths from findings to untested assets.
/// BFS from each finding's asset, following asset relationships up to `max_hops`.
pub fn find_chains(dg: &DualGraph, max_hops: usize) -> Vec<ChainCandidate> {
    let mut chains = Vec::new();

    // Collect assets with findings
    let finding_assets: Vec<(String, String)> = dg.exploration.nodes.iter()
        .filter(|n| n.kind == ExplorationKind::Finding)
        .filter_map(|n| {
            dg.exploration.anchors.iter()
                .find(|a| a.exploration_id == n.id)
                .and_then(|a| dg.assets.nodes.iter().find(|an| an.id == a.asset_id))
                .map(|asset| (n.content.clone(), asset.id.clone()))
        })
        .collect();

    for (finding, foothold_id) in &finding_assets {
        let foothold = dg.assets.nodes.iter().find(|a| a.id == *foothold_id);
        let foothold_name = foothold.map(|a| a.value.clone()).unwrap_or_default();

        // BFS from foothold
        let mut visited = std::collections::HashSet::new();
        visited.insert(foothold_id.clone());
        let mut queue: Vec<(String, Vec<ChainHop>)> = vec![(foothold_id.clone(), vec![])];

        while let Some((current, path)) = queue.pop() {
            if path.len() >= max_hops { continue; }

            // Find neighbors via asset edges
            for edge in &dg.assets.edges {
                let neighbor_id = if edge.from == current { &edge.to }
                                  else if edge.to == current { &edge.from }
                                  else { continue };
                if visited.contains(neighbor_id) { continue; }
                visited.insert(neighbor_id.clone());

                let neighbor = match dg.assets.nodes.iter().find(|a| a.id == *neighbor_id) {
                    Some(a) => a,
                    None => continue,
                };

                let tested = dg.exploration.anchors.iter()
                    .any(|a| a.asset_id == *neighbor_id);

                let mut new_path = path.clone();
                new_path.push(ChainHop {
                    asset: neighbor.value.clone(),
                    kind: format!("{:?}", neighbor.kind),
                    relation: format!("{:?}", edge.kind),
                    tested,
                });

                if !tested {
                    // Untested asset reachable from a finding — chain candidate
                    let score = score_chain(&new_path, neighbor);
                    chains.push(ChainCandidate {
                        finding: finding.clone(),
                        foothold: foothold_name.clone(),
                        hops: new_path.clone(),
                        target: neighbor.value.clone(),
                        score,
                    });
                }

                queue.push((neighbor_id.clone(), new_path));
            }
        }
    }

    chains.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    chains
}

fn score_chain(path: &[ChainHop], target: &crate::exploration_graph::AssetNode) -> f32 {
    let mut score = 1.0;
    // Shorter chains are better
    score += 1.0 / (path.len() as f32);
    // Endpoints and applications are higher-value targets
    match target.kind {
        AssetKind::Endpoint | AssetKind::Application => score += 2.0,
        AssetKind::Service => score += 1.5,
        AssetKind::Parameter => score += 1.0,
        _ => {}
    }
    // Assets with more exploration are more interesting (more context)
    score += (target.exploration_count as f32).min(3.0) * 0.5;
    score
}

/// Format chain candidates as an LLM prompt for decision-making.
pub fn decision_prompt(chains: &[ChainCandidate], graph_summary: &str, max_chains: usize) -> String {
    let mut prompt = String::from(
        "You are a penetration testing strategist. Analyze the current exploration state and \
         decide which attack chains to pursue next.\n\n"
    );
    prompt.push_str("CURRENT STATE:\n");
    prompt.push_str(graph_summary);
    prompt.push_str("\n\nCHAIN CANDIDATES (from confirmed findings to untested assets):\n");

    for (i, c) in chains.iter().take(max_chains).enumerate() {
        prompt.push_str(&format!(
            "\n{}. Finding: {} (foothold: {})\n   Path: {}\n   Target: {} (score: {:.1})\n",
            i + 1,
            c.finding.chars().take(80).collect::<String>(),
            c.foothold,
            c.hops.iter().map(|h| format!("{}({})", h.asset, h.relation)).collect::<Vec<_>>().join(" → "),
            c.target,
            c.score,
        ));
    }

    prompt.push_str(
        "\n\nDecide which chains to pursue. For each, respond with one line:\n\
         Intent: <action> on <target> because <rationale>\n\n\
         Actions: Exploit, Probe, Recon, Chain, Fuzz, Validate\n\
         Prioritize chains that:\n\
         - Start from high-severity findings\n\
         - Reach high-value assets (endpoints, services, applications)\n\
         - Are short (fewer hops = less chance of failure)\n\
         - Have not been attempted before\n\n\
         If no chain is worth pursuing, say: Quiescent: no actionable chains remain.\n"
    );
    prompt
}

/// Parse LLM decision response into planner intents.
pub fn parse_decision(response: &str) -> Vec<PlannerIntent> {
    let mut intents = Vec::new();
    let mut id_counter = 0u32;

    for line in response.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Intent:").or_else(|| trimmed.strip_prefix("INTENT:")) {
            let rest = rest.trim();
            // Parse: <action> on <target> because <rationale>
            let parts: Vec<&str> = rest.splitn(2, " on ").collect();
            if parts.len() < 2 { continue; }
            let action_str = parts[0].trim().to_lowercase();
            let rest = parts[1];
            let (target, rationale) = if let Some(idx) = rest.find(" because ") {
                (rest[..idx].trim(), rest[idx + 9..].trim())
            } else {
                (rest.trim(), "")
            };

            let action = match action_str.as_str() {
                "exploit" => IntentAction::Exploit,
                "probe" => IntentAction::Probe,
                "recon" => IntentAction::Recon,
                "chain" => IntentAction::Chain,
                "fuzz" => IntentAction::Fuzz,
                "validate" => IntentAction::Validate,
                _ => IntentAction::Probe,
            };

            id_counter += 1;
            intents.push(PlannerIntent {
                id: format!("chain-{id_counter}"),
                action,
                target: target.to_string(),
                agent_hint: String::new(),
                priority: (10 - id_counter.min(9)) as u32,
                rationale: rationale.to_string(),
                depends_on: vec![],
                asset_id: None,
            });
        }
    }
    intents
}

/// Build a compact graph summary for the LLM.
pub fn graph_summary(dg: &DualGraph) -> String {
    let mut s = String::new();

    let total_assets = dg.assets.nodes.len();
    let tested: usize = dg.assets.nodes.iter()
        .filter(|a| dg.exploration.anchors.iter().any(|an| an.asset_id == a.id))
        .count();
    let findings = dg.exploration.nodes.iter()
        .filter(|n| n.kind == ExplorationKind::Finding)
        .count();
    let facts = dg.exploration.nodes.iter()
        .filter(|n| n.kind == ExplorationKind::Fact)
        .count();
    let negatives = dg.exploration.nodes.iter()
        .filter(|n| n.kind == ExplorationKind::Negative)
        .count();

    s.push_str(&format!(
        "Assets: {} total, {} tested, {} untested\n\
         Findings: {}, Facts: {}, Negatives: {}\n",
        total_assets, tested, total_assets - tested,
        findings, facts, negatives,
    ));

    // List findings
    if findings > 0 {
        s.push_str("\nConfirmed findings:\n");
        for n in dg.exploration.nodes.iter().filter(|n| n.kind == ExplorationKind::Finding) {
            let asset = dg.exploration.anchors.iter()
                .find(|a| a.exploration_id == n.id)
                .and_then(|a| dg.assets.nodes.iter().find(|an| an.id == a.asset_id))
                .map(|a| a.value.as_str())
                .unwrap_or("?");
            s.push_str(&format!("  - {} on {}\n", n.content.chars().take(80).collect::<String>(), asset));
        }
    }

    // High-value untested assets
    let untested: Vec<_> = dg.assets.nodes.iter()
        .filter(|a| !dg.exploration.anchors.iter().any(|an| an.asset_id == a.id))
        .filter(|a| matches!(a.kind, AssetKind::Endpoint | AssetKind::Service | AssetKind::Application))
        .take(15)
        .collect();
    if !untested.is_empty() {
        s.push_str("\nHigh-value untested assets:\n");
        for a in &untested {
            s.push_str(&format!("  - {:?}: {}\n", a.kind, a.value));
        }
    }

    s
}

/// Enrich the graph after a finding: mark reachable assets as high-priority.
pub fn enrich_after_finding(dg: &mut DualGraph, finding_asset_id: &str) {
    // BFS from the finding's asset, bump exploration priority on neighbors
    let mut visited = std::collections::HashSet::new();
    visited.insert(finding_asset_id.to_string());
    let mut queue = vec![finding_asset_id.to_string()];

    while let Some(current) = queue.pop() {
        for edge in &dg.assets.edges {
            let neighbor = if edge.from == current { &edge.to }
                          else if edge.to == current { &edge.from }
                          else { continue };
            if visited.contains(neighbor) { continue; }
            visited.insert(neighbor.clone());
            // Bump the neighbor's exploration count to signal priority
            if let Some(node) = dg.assets.nodes.iter_mut().find(|n| n.id == *neighbor) {
                node.exploration_count += 1;
            }
            queue.push(neighbor.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exploration_graph::{AnchorDirection, AssetKind};
    use std::collections::BTreeMap;

    fn sample_graph() -> DualGraph {
        let mut dg = DualGraph::default();
        // Build a small graph: target -> endpoint -> parameter
        dg.discover_asset(AssetKind::Domain, "example.com", BTreeMap::new(), "recon", None);
        dg.discover_asset(AssetKind::Endpoint, "/api/users", BTreeMap::new(), "recon", None);
        dg.discover_asset(AssetKind::Endpoint, "/api/admin", BTreeMap::new(), "recon", None);
        dg.discover_asset(AssetKind::Parameter, "id", BTreeMap::new(), "recon", None);

        let root = dg.assets.find(AssetKind::Domain, "example.com").unwrap().id.clone();
        let users = dg.assets.find(AssetKind::Endpoint, "/api/users").unwrap().id.clone();
        let admin = dg.assets.find(AssetKind::Endpoint, "/api/admin").unwrap().id.clone();
        let param = dg.assets.find(AssetKind::Parameter, "id").unwrap().id.clone();
        dg.assets.relate(&root, &users, AssetRelation::ParentOf);
        dg.assets.relate(&root, &admin, AssetRelation::ParentOf);
        dg.assets.relate(&users, &param, AssetRelation::ParentOf);

        // Add a finding on /api/users
        let goal = dg.exploration.add_goal("test example.com", "planner");
        let intent = dg.target_asset("test IDOR", &goal, "worker", &users);
        dg.exploration.set_status(&intent, ExplorationStatus::Completed);
        dg.record_finding("IDOR on /api/users", &intent, "worker", &users);

        dg
    }

    #[test]
    fn find_chains_discovers_untested_neighbors() {
        let dg = sample_graph();
        let chains = find_chains(&dg, 3);
        assert!(!chains.is_empty(), "should find chains from IDOR finding to untested assets");
        // /api/admin and id parameter should be reachable
        let targets: Vec<&str> = chains.iter().map(|c| c.target.as_str()).collect();
        assert!(targets.contains(&"/api/admin") || targets.contains(&"id"),
                "untested neighbors should appear: {:?}", targets);
    }

    #[test]
    fn graph_summary_includes_key_stats() {
        let dg = sample_graph();
        let s = graph_summary(&dg);
        assert!(s.contains("Assets:") && s.contains("Findings:"));
        assert!(s.contains("IDOR"));
    }

    #[test]
    fn decision_prompt_is_well_formed() {
        let dg = sample_graph();
        let chains = find_chains(&dg, 3);
        let summary = graph_summary(&dg);
        let p = decision_prompt(&chains, &summary, 5);
        assert!(p.contains("CHAIN CANDIDATES"));
        assert!(p.contains("Intent:"));
    }

    #[test]
    fn parse_decision_extracts_intents() {
        let response = "Intent: Exploit on /api/admin because IDOR on sibling endpoint suggests similar vulnerability\n\
                        Intent: Probe on id parameter because parameter injection not yet tested\n\
                        Some other text that should be ignored";
        let intents = parse_decision(response);
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].action, IntentAction::Exploit);
        assert!(intents[0].target.contains("/api/admin"));
        assert!(intents[0].rationale.contains("IDOR"));
    }

    #[test]
    fn enrich_after_finding_bumps_neighbors() {
        let mut dg = sample_graph();
        let users_id = dg.assets.find(AssetKind::Endpoint, "/api/users").unwrap().id.clone();
        let admin_before = dg.assets.find(AssetKind::Endpoint, "/api/admin").unwrap().exploration_count;
        enrich_after_finding(&mut dg, &users_id);
        let admin_after = dg.assets.find(AssetKind::Endpoint, "/api/admin").unwrap().exploration_count;
        assert!(admin_after > admin_before, "neighbor should get priority bump");
    }
}
