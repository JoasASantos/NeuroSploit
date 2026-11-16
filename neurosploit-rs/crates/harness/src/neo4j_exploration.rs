//! Exploration graph in Neo4j — connected history to chain exploitation.
//!
//! `graph_memory` already stores the attack graph (findings, identities,
//! permissions, impact) in Neo4j. This module adds the *exploration* side from
//! [`crate::exploration_graph::DualGraph`]: what exists on the target (assets),
//! what was tried (goals, intents, facts, negatives, hints, findings) and how
//! they connect. Having both in one graph lets a Cypher query answer the
//! question that drives chaining: *"which untested assets sit next to something
//! I already broke?"*
//!
//! Everything that builds Cypher is pure and unit-tested. Labels and
//! relationship types come only from closed enums (never from model output), so
//! there is no Cypher injection surface; all free text travels as parameters.

use crate::exploration_graph::{AnchorDirection, DualGraph};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// `ParentOf` -> `PARENT_OF`. Input is a Debug-printed enum variant.
fn screaming(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().filter(|c| c.is_ascii_alphanumeric()).enumerate() {
        if c.is_ascii_uppercase() && i > 0 { out.push('_'); }
        out.push(c.to_ascii_uppercase());
    }
    out
}

fn asset_key(target: &str, id: &str) -> String { format!("{target}|{id}") }
fn exp_key(target: &str, run: &str, id: &str) -> String { format!("{target}|{run}|{id}") }

/// Cypher to MERGE the whole dual graph. Idempotent: re-running updates in place.
pub fn statements(dg: &DualGraph, target: &str, run: &str) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    out.push(("CREATE CONSTRAINT ns_exploration_key IF NOT EXISTS FOR (n:Exploration) REQUIRE n.key IS UNIQUE".into(), json!({})));
    out.push(("CREATE CONSTRAINT ns_asset_key IF NOT EXISTS FOR (n:AssetNode) REQUIRE n.key IS UNIQUE".into(), json!({})));

    // Asset nodes (shared across runs of the same target).
    let assets: Vec<Value> = dg.assets.nodes.iter().map(|a| json!({
        "key": asset_key(target, &a.id), "kind": format!("{:?}", a.kind), "value": a.value,
        "by": a.discovered_by, "explored": a.exploration_count, "findings": a.finding_count,
    })).collect();
    if !assets.is_empty() {
        out.push(("UNWIND $rows AS r MERGE (a:AssetNode {key: r.key}) \
                   SET a.kind = r.kind, a.value = r.value, a.discovered_by = r.by, \
                       a.exploration_count = r.explored, a.finding_count = r.findings, a.target = $target".into(),
                  json!({"rows": assets, "target": target})));
    }

    // Asset edges, one statement per relationship type (closed enum).
    let mut by_rel: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for e in &dg.assets.edges {
        by_rel.entry(screaming(&format!("{:?}", e.kind))).or_default()
            .push(json!({"from": asset_key(target, &e.from), "to": asset_key(target, &e.to)}));
    }
    for (rel, rows) in by_rel {
        out.push((format!("UNWIND $rows AS r MATCH (a:AssetNode {{key: r.from}}) MATCH (b:AssetNode {{key: r.to}}) MERGE (a)-[:{rel}]->(b)"),
                  json!({"rows": rows})));
    }

    // Exploration nodes: one statement per kind so each gets a real label.
    let mut by_kind: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for n in &dg.exploration.nodes {
        by_kind.entry(format!("{:?}", n.kind)).or_default().push(json!({
            "key": exp_key(target, run, &n.id), "content": n.content,
            "status": format!("{:?}", n.status), "agent": n.agent, "at": n.created_at,
        }));
    }
    for (kind, rows) in by_kind {
        let label: String = kind.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        out.push((format!("UNWIND $rows AS r MERGE (n:Exploration {{key: r.key}}) SET n:{label}, \
                           n.content = r.content, n.status = r.status, n.agent = r.agent, n.created_at = r.at, \
                           n.run = $run, n.target = $target"),
                  json!({"rows": rows, "run": run, "target": target})));
    }

    // Exploration edges.
    let mut ex_rel: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for e in &dg.exploration.edges {
        ex_rel.entry(screaming(&format!("{:?}", e.kind))).or_default()
            .push(json!({"from": exp_key(target, run, &e.from), "to": exp_key(target, run, &e.to)}));
    }
    for (rel, rows) in ex_rel {
        out.push((format!("UNWIND $rows AS r MATCH (a:Exploration {{key: r.from}}) MATCH (b:Exploration {{key: r.to}}) MERGE (a)-[:{rel}]->(b)"),
                  json!({"rows": rows})));
    }

    // Anchors: exploration -> asset.
    for (dir, rel) in [(AnchorDirection::Targets, "TARGETS"), (AnchorDirection::Discovered, "DISCOVERED")] {
        let rows: Vec<Value> = dg.exploration.anchors.iter().filter(|a| a.direction == dir)
            .map(|a| json!({"e": exp_key(target, run, &a.exploration_id), "a": asset_key(target, &a.asset_id)})).collect();
        if !rows.is_empty() {
            out.push((format!("UNWIND $rows AS r MATCH (e:Exploration {{key: r.e}}) MATCH (a:AssetNode {{key: r.a}}) MERGE (e)-[:{rel}]->(a)"),
                      json!({"rows": rows})));
        }
    }
    out
}

/// Untested surface: endpoints/parameters/services nothing has targeted yet.
pub const UNTESTED_QUERY: &str = "MATCH (a:AssetNode {target: $target}) \
    WHERE a.kind IN ['Endpoint','Parameter','Service','Application'] \
      AND NOT EXISTS { MATCH (:Exploration)-[:TARGETS]->(a) } \
    RETURN a.kind, a.value ORDER BY a.kind, a.value LIMIT $limit";

/// Chaining candidates: untested assets within two hops of an asset where a
/// finding already landed.
pub const CHAIN_QUERY: &str = "MATCH (f:Finding {target: $target})-[:TARGETS]->(a:AssetNode) \
    MATCH (a)-[:PARENT_OF|HOSTED_ON|SERVES_ON|LINKS_TO|USES_AUTH|USES_TECH|RESOLVES_TO|REDIRECTS_TO*1..2]-(b:AssetNode) \
    WHERE b <> a AND NOT EXISTS { MATCH (:Exploration)-[:TARGETS]->(b) } \
    RETURN a.value, f.content, b.kind, b.value LIMIT $limit";

/// Turn chain-query rows into prompt lines for the planner.
pub fn suggestion_lines(rows: &[Vec<Value>]) -> Vec<String> {
    let s = |v: Option<&Value>| v.and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for r in rows {
        let (a, f, kind, b) = (s(r.first()), s(r.get(1)), s(r.get(2)), s(r.get(3)));
        if a.is_empty() || b.is_empty() { continue; }
        let f: String = f.chars().take(80).collect();
        let line = format!("{kind} {b} is adjacent to {a}, where \"{f}\" was found and {b} is still untested");
        if seen.insert(line.clone()) { out.push(line); }
    }
    out
}

/// Prompt block for chain suggestions. Empty when there are none.
pub fn suggestion_block(lines: &[String]) -> String {
    if lines.is_empty() { return String::new(); }
    let mut s = String::from("GRAPH CHAIN LEADS (from Neo4j; unverified hypotheses, test before relying on them):\n");
    for l in lines { s.push_str(&format!("  - {l}\n")); }
    s
}

/// Push the dual graph and read back chain leads. Returns the lead lines.
pub async fn sync(n: &crate::graph_memory::Neo4j, dg: &DualGraph, target: &str, run: &str) -> anyhow::Result<Vec<String>> {
    let st = statements(dg, target, run);
    // Constraints are schema operations and must run before data, on their own.
    let (schema, data): (Vec<_>, Vec<_>) = st.into_iter().partition(|(s, _)| s.starts_with("CREATE CONSTRAINT"));
    for stmt in schema { n.run_statements(vec![stmt]).await?; }
    n.run_statements(data).await?;
    let rows = n.query_rows(CHAIN_QUERY, json!({"target": target, "limit": 15})).await?;
    Ok(suggestion_lines(&rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exploration_graph::{AssetKind, ExplorationStatus};

    fn sample() -> DualGraph {
        let mut dg = DualGraph::default();
        dg.discover_asset(AssetKind::Endpoint, "/api/users", BTreeMap::new(), "recon", None);
        dg.discover_asset(AssetKind::Endpoint, "/api/orders", BTreeMap::new(), "recon", None);
        let goal = dg.exploration.add_goal("test authz", "planner");
        let a = dg.assets.find(AssetKind::Endpoint, "/api/users").unwrap().id.clone();
        let i = dg.target_asset("probe IDOR", &goal, "planner", &a);
        dg.exploration.add_negative("id param clean", &i, "w");
        dg.exploration.set_status(&i, ExplorationStatus::Completed);
        dg.record_finding("IDOR on /api/users", &i, "w", &a);
        dg
    }

    #[test]
    fn screaming_case_conversion() {
        assert_eq!(screaming("ParentOf"), "PARENT_OF");
        assert_eq!(screaming("Spawns"), "SPAWNS");
        assert_eq!(screaming("DerivedFrom"), "DERIVED_FROM");
        assert!(screaming("X; DROP }) //").chars().all(|c| c.is_ascii_uppercase() || c == '_'), "only [A-Z_] can ever reach cypher");
    }

    #[test]
    fn statements_cover_nodes_edges_anchors_and_constraints() {
        let st = statements(&sample(), "app.example.com", "run-1");
        let all: String = st.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>().join("\n");
        assert!(all.contains("CREATE CONSTRAINT ns_exploration_key"));
        assert!(all.contains("MERGE (a:AssetNode"));
        for label in ["Goal", "Intent", "Negative", "Finding"] {
            assert!(all.contains(&format!("SET n:{label}")), "missing label {label}");
        }
        assert!(all.contains("MERGE (a)-[:SPAWNS]->(b)"));
        assert!(all.contains("MERGE (a)-[:PROVES]->(b)") && all.contains("MERGE (a)-[:DISPROVES]->(b)"));
        assert!(all.contains("MERGE (e)-[:TARGETS]->(a)"));
    }

    #[test]
    fn free_text_is_only_ever_a_parameter() {
        let mut dg = DualGraph::default();
        let g = dg.exploration.add_goal("x' }) DETACH DELETE n //", "p");
        dg.exploration.add_fact("`; MATCH (n) DELETE n", &g, "w");
        for (cypher, _) in statements(&dg, "t", "r") {
            assert!(!cypher.contains("DETACH DELETE") && !cypher.contains("MATCH (n) DELETE"),
                    "free text leaked into cypher: {cypher}");
        }
    }

    #[test]
    fn keys_are_namespaced_by_target_and_run() {
        let st = statements(&sample(), "t.com", "r9");
        let json: String = st.iter().map(|(_, p)| p.to_string()).collect();
        assert!(json.contains("t.com|r9|exp-0"), "exploration keys are per run");
        assert!(json.contains("t.com|asset-"), "asset keys are shared across runs: {json}");
    }

    #[test]
    fn suggestions_dedupe_and_skip_empty() {
        let rows = vec![
            vec![json!("/api/users"), json!("IDOR on users"), json!("Endpoint"), json!("/api/orders")],
            vec![json!("/api/users"), json!("IDOR on users"), json!("Endpoint"), json!("/api/orders")],
            vec![json!(""), json!("x"), json!("Endpoint"), json!("/y")],
        ];
        let l = suggestion_lines(&rows);
        assert_eq!(l.len(), 1);
        assert!(l[0].contains("/api/orders") && l[0].contains("still untested"));
        assert!(suggestion_block(&l).contains("unverified hypotheses"));
        assert!(suggestion_block(&[]).is_empty());
    }
}
