//! Populate the dual graph from what a run actually produced.
//!
//! The exploration graph (assets + what was tried) is consumed by the planner
//! prompt, the cold-digest overlay and the Neo4j sync, but nothing in the main
//! pipeline used to write it. This module fills it from the two things every run
//! has at each graph checkpoint: the recon JSON and the findings so far.
//!
//! Idempotent by construction: calling it again with the same recon/findings
//! changes nothing; a finding that becomes validated later updates its node's
//! status instead of adding a duplicate. Recon discovery is not authorization:
//! hosts and absolute URLs outside the hard scope are never added.

use crate::exploration_graph::{AnchorDirection, AssetKind, AssetRelation, DualGraph, ExplorationKind, ExplorationStatus};
use crate::types::Finding;
use serde_json::Value;
use std::collections::BTreeMap;

/// Hard cap on assets added per update, so a noisy recon cannot flood the graph.
const MAX_NEW_ASSETS: usize = 500;

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    hostport.rsplit_once('@').map_or(hostport, |(_, h)| h).split(':').next().unwrap_or("").to_lowercase()
}

fn is_ip(h: &str) -> bool { h.parse::<std::net::IpAddr>().is_ok() }

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key).and_then(|x| x.as_array()).map(|a| {
        a.iter().filter_map(|i| {
            i.as_str().map(str::to_string).or_else(|| {
                ["url", "path", "endpoint", "host", "name"].iter()
                    .find_map(|k| i.get(k).and_then(|x| x.as_str()).map(str::to_string))
            })
        }).collect()
    }).unwrap_or_default()
}

fn clip(s: &str, n: usize) -> String { s.trim().chars().take(n).collect() }

/// Add recon-discovered assets. Returns how many assets were new.
pub fn add_recon(dg: &mut DualGraph, target: &str, recon: &str, in_scope: &dyn Fn(&str) -> bool) -> usize {
    let (Some(s), Some(e)) = (recon.find('{'), recon.rfind('}')) else { return 0 };
    if e <= s { return 0; }
    let Ok(v) = serde_json::from_str::<Value>(&recon[s..=e]) else { return 0 };
    let thost = host_of(target);
    let mut added = 0usize;

    let kind = if is_ip(&thost) { AssetKind::IpAddress } else { AssetKind::Domain };
    added += dg.assets.upsert(kind, &thost, BTreeMap::new(), "target") as usize;
    let root_id = dg.assets.find(kind, &thost).map(|a| a.id.clone());

    for key in ["hosts", "subdomains"] {
        for raw in strings(&v, key) {
            let host = if raw.contains("://") { host_of(&raw) } else { raw.trim().trim_start_matches("*.").to_lowercase() };
            if host.is_empty() || host.contains(' ') || host == thost || !in_scope(&format!("https://{host}")) { continue; }
            if added >= MAX_NEW_ASSETS { break; }
            added += dg.assets.upsert(AssetKind::Subdomain, &host, BTreeMap::new(), "recon") as usize;
            if let (Some(root), Some(sub)) = (&root_id, dg.assets.find(AssetKind::Subdomain, &host).map(|a| a.id.clone())) {
                if host.ends_with(&format!(".{thost}")) { dg.assets.relate(root, &sub, AssetRelation::ParentOf); }
            }
        }
    }
    for key in ["endpoints", "apis"] {
        for raw in strings(&v, key) {
            let raw = clip(&raw, 200);
            if raw.is_empty() || added >= MAX_NEW_ASSETS { continue; }
            if raw.contains("://") && !in_scope(&raw) { continue; }
            added += dg.assets.upsert(AssetKind::Endpoint, &raw, BTreeMap::new(), "recon") as usize;
            if let (Some(root), Some(ep)) = (&root_id, dg.assets.find(AssetKind::Endpoint, &raw).map(|a| a.id.clone())) {
                dg.assets.relate(&ep, root, AssetRelation::HostedOn);
            }
        }
    }
    for raw in strings(&v, "params") {
        let raw = clip(&raw, 120);
        if raw.is_empty() || added >= MAX_NEW_ASSETS { continue; }
        added += dg.assets.upsert(AssetKind::Parameter, &raw, BTreeMap::new(), "recon") as usize;
    }
    added
}

/// Record findings as intent -> finding with anchors. Returns (new, updated).
pub fn add_findings(dg: &mut DualGraph, target: &str, findings: &[Finding], in_scope: &dyn Fn(&str) -> bool) -> (usize, usize) {
    // One root goal per target.
    let goal_text = format!("Assess {target}");
    let goal = match dg.exploration.nodes.iter().find(|n| n.kind == ExplorationKind::Goal && n.content == goal_text) {
        Some(g) => g.id.clone(),
        None => dg.exploration.add_goal(&goal_text, "pipeline"),
    };
    let (mut new, mut updated) = (0, 0);
    for f in findings {
        let status = if f.validated { ExplorationStatus::Completed } else { ExplorationStatus::Pending };
        if let Some(node) = dg.exploration.nodes.iter_mut()
            .find(|n| n.kind == ExplorationKind::Finding && n.metadata.get("finding_id").map(String::as_str) == Some(f.id.as_str()))
        {
            if node.status != status { node.status = status; dg.exploration.version += 1; updated += 1; }
            continue;
        }
        let intent = dg.exploration.add_intent(&format!("{}: {}", clip(&f.agent, 40), clip(&f.title, 120)), &goal, &f.agent);
        dg.exploration.set_status(&intent, ExplorationStatus::Completed);
        let fid = dg.exploration.add_finding(&format!("[{}] {}", clip(&f.severity, 12), clip(&f.title, 160)), &intent, &f.agent);
        if let Some(n) = dg.exploration.nodes.iter_mut().find(|n| n.id == fid) {
            n.metadata.insert("finding_id".into(), f.id.clone());
            n.status = status;
        }
        let ep = clip(&f.endpoint, 200);
        if !ep.is_empty() && (!ep.contains("://") || in_scope(&ep)) {
            dg.assets.upsert(AssetKind::Endpoint, &ep, BTreeMap::new(), &f.agent);
            if let Some(a) = dg.assets.find(AssetKind::Endpoint, &ep).map(|a| a.id.clone()) {
                dg.exploration.anchor(&intent, &a, AnchorDirection::Targets);
                dg.exploration.anchor(&fid, &a, AnchorDirection::Targets);
                if let Some(node) = dg.assets.nodes.iter_mut().find(|n| n.id == a) {
                    node.exploration_count += 1;
                    node.finding_count += 1;
                }
            }
        }
        new += 1;
    }
    (new, updated)
}

/// Load (or start) the graph in `dir`, apply recon and findings, save it back.
/// Best-effort: any I/O problem is returned, and callers must not fail a run on it.
pub fn update_and_save(dir: &std::path::Path, target: &str, recon: &str, findings: &[Finding],
                       in_scope: &dyn Fn(&str) -> bool) -> std::io::Result<DualGraph> {
    let mut dg = DualGraph::load(dir).unwrap_or_default();
    let before = (dg.assets.nodes.len(), dg.exploration.nodes.len(), dg.exploration.version);
    add_recon(&mut dg, target, recon, in_scope);
    add_findings(&mut dg, target, findings, in_scope);
    let after = (dg.assets.nodes.len(), dg.exploration.nodes.len(), dg.exploration.version);
    if before != after || !dir.join("dual-graph.json").exists() { dg.save(dir)?; }
    Ok(dg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECON: &str = r#"noise {"subdomains":["api.t.com","evil.com","*.dev.t.com"],
        "endpoints":["/login","https://api.t.com/v1/users",{"url":"https://other.org/x"}],
        "params":["id","q"],"hosts":["10.0.0.5"]} trailing"#;

    fn scope(u: &str) -> bool { host_of(u) == "t.com" || host_of(u).ends_with(".t.com") }

    fn finding(id: &str, ep: &str, validated: bool) -> Finding {
        serde_json::from_value(serde_json::json!({
            "id": id, "agent": "sqli", "title": "SQL injection", "severity": "high",
            "endpoint": ep, "validated": validated
        })).expect("finding")
    }

    #[test]
    fn recon_adds_only_in_scope_assets_and_is_idempotent() {
        let mut dg = DualGraph::default();
        let n = add_recon(&mut dg, "https://t.com", RECON, &scope);
        assert!(n >= 6);
        let vals: Vec<&str> = dg.assets.nodes.iter().map(|a| a.value.as_str()).collect();
        assert!(vals.contains(&"api.t.com") && vals.contains(&"dev.t.com") && vals.contains(&"/login"));
        assert!(!vals.contains(&"evil.com") && !vals.contains(&"10.0.0.5"), "out of scope must not enter");
        assert!(!vals.iter().any(|v| v.contains("other.org")));
        assert_eq!(add_recon(&mut dg, "https://t.com", RECON, &scope), 0, "re-run adds nothing");
        assert!(dg.assets.edges.iter().any(|e| e.kind == AssetRelation::ParentOf));
    }

    #[test]
    fn findings_become_intent_finding_with_anchors_and_dedupe() {
        let mut dg = DualGraph::default();
        let fs = [finding("f1", "/login", false)];
        assert_eq!(add_findings(&mut dg, "https://t.com", &fs, &scope), (1, 0));
        assert_eq!(add_findings(&mut dg, "https://t.com", &fs, &scope), (0, 0));
        assert_eq!(dg.exploration.nodes.iter().filter(|n| n.kind == ExplorationKind::Goal).count(), 1);
        assert_eq!(dg.exploration.nodes.iter().filter(|n| n.kind == ExplorationKind::Finding).count(), 1);
        assert_eq!(dg.exploration.anchors.len(), 2);
        let a = dg.assets.find(AssetKind::Endpoint, "/login").unwrap();
        assert_eq!((a.exploration_count, a.finding_count), (1, 1));
    }

    #[test]
    fn validation_updates_status_without_duplicating() {
        let mut dg = DualGraph::default();
        add_findings(&mut dg, "https://t.com", &[finding("f1", "/x", false)], &scope);
        let r = add_findings(&mut dg, "https://t.com", &[finding("f1", "/x", true)], &scope);
        assert_eq!(r, (0, 1));
        let n = dg.exploration.nodes.iter().find(|n| n.kind == ExplorationKind::Finding).unwrap();
        assert_eq!(n.status, ExplorationStatus::Completed);
    }

    #[test]
    fn out_of_scope_finding_endpoint_is_not_added_as_asset() {
        let mut dg = DualGraph::default();
        add_findings(&mut dg, "https://t.com", &[finding("f2", "https://evil.com/a", true)], &scope);
        assert!(dg.assets.nodes.iter().all(|a| !a.value.contains("evil.com")));
        assert_eq!(dg.exploration.nodes.iter().filter(|n| n.kind == ExplorationKind::Finding).count(), 1);
    }

    #[test]
    fn update_and_save_roundtrips_and_survives_garbage_recon() {
        let dir = std::env::temp_dir().join(format!("ns-dual-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dg = update_and_save(&dir, "https://t.com", RECON, &[finding("f1", "/login", true)], &scope).unwrap();
        assert!(dir.join("dual-graph.json").exists());
        let loaded = DualGraph::load(&dir).unwrap();
        assert_eq!(loaded.assets.nodes.len(), dg.assets.nodes.len());
        update_and_save(&dir, "https://t.com", "not json at all", &[], &scope).unwrap();
        assert_eq!(DualGraph::load(&dir).unwrap().assets.nodes.len(), dg.assets.nodes.len());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
