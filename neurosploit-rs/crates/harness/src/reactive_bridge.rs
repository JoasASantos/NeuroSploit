//! Bridge between the generic reactive engine and the NeuroSploit pipeline.
//!
//! `run_reactive()` has the same signature as `pipeline::run()` so the app crate
//! can call it in place of the phased pipeline when `--reactive` is active. It
//! runs basic recon, seeds the dual graph, then hands control to the reactive
//! engine with an executor that calls agents through the model pool.

use crate::exploration_graph::DualGraph;
use crate::pipeline::RunOutput;
use crate::planner::{PlannerConfig, PlannerIntent, IntentAction};
use crate::pool::ModelPool;
use crate::reactive::{self, ExecFn, ReactiveConfig, WorkCtx, WorkOutcome};
use crate::types::RunConfig;
use crate::agents::Library;
use futures::FutureExt;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

/// Extract operator constraints from run config (same logic as pipeline's private helper).
fn operator_constraints(cfg: &RunConfig) -> crate::constraints::ConstraintSet {
    let text = [cfg.objective.as_deref(), cfg.instructions.as_deref(), cfg.out_of_scope.as_deref()]
        .into_iter().flatten().collect::<Vec<_>>().join("\n");
    if text.trim().is_empty() { return crate::constraints::ConstraintSet::new(); }
    crate::constraints::extract(&text, &cfg.target, None)
}

/// Entry point for the reactive engine, matching pipeline::run()'s signature.
pub async fn run_reactive(
    mut cfg: RunConfig,
    _lib: &Library,
    pool: &ModelPool,
    tx: Sender<String>,
) -> RunOutput {
    let _ = tx.send("[reactive] starting event-driven engine".into()).await;

    // --- Setup workdir ---
    let workdir = if let Some(d) = &cfg.workdir {
        let _ = std::fs::create_dir_all(d);
        d.clone()
    } else {
        let run_name = format!("ns-reactive-{}", std::process::id());
        let d = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(&run_name)
            .display()
            .to_string();
        let _ = std::fs::create_dir_all(&d);
        cfg.workdir = Some(d.clone());
        d
    };

    // --- Recon (simplified: use pool.complete with a recon prompt) ---
    let recon_text = if !cfg.offline {
        let _ = tx.send("[reactive] running recon...".into()).await;
        let system = "You are a web reconnaissance specialist. Enumerate the target's surface: subdomains, endpoints, technologies, open ports. Return JSON with keys: subdomains, endpoints, params, hosts.";
        let user = format!("Target: {}\nPerform reconnaissance and return structured JSON results.", cfg.target);
        match pool.complete(system, &user).await {
            Ok((_, text)) => {
                let _ = tx.send(format!("[reactive] recon complete ({} chars)", text.len())).await;
                text
            }
            Err(e) => {
                let _ = tx.send(format!("[reactive] recon failed: {e} — continuing with empty surface")).await;
                String::new()
            }
        }
    } else {
        let _ = tx.send("[reactive] offline mode — skipping recon".into()).await;
        String::new()
    };

    // --- Seed dual graph from recon ---
    let graph_dir = Path::new(&workdir).join("graphs");
    let _ = std::fs::create_dir_all(&graph_dir);
    let scope = crate::pipeline::effective_scope(&cfg);
    let scope_check = move |url: &str| {
        matches!(scope.check(url, crate::scope::Action::Probe), crate::scope::Decision::Allow)
    };
    let mut graph = DualGraph::load(&graph_dir).unwrap_or_default();
    crate::dual_build::add_recon(&mut graph, &cfg.target, &recon_text, &scope_check);
    let _ = graph.save(&graph_dir);

    // --- Build reactive config ---
    let reactive_cfg = ReactiveConfig {
        target: cfg.target.clone(),
        workers: cfg.concurrency.min(8).max(1),
        deadline: None, // use token budget instead of wall-clock for now
        state_dir: Some(graph_dir.clone()),
        planner: PlannerConfig::default(),
        ..ReactiveConfig::new(&cfg.target)
    };

    // Resume from saved state if available
    let (graph, queue) = reactive::resume_state(&graph_dir)
        .map(|(g, q)| (g, Some(q)))
        .unwrap_or((graph, None));

    let handle = reactive::prepare(&reactive_cfg, graph, queue);

    // --- Load knowledge base from agent markdowns ---
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let kb = Arc::new(crate::knowledge::load(&exe_dir));
    if !kb.is_empty() {
        let _ = tx.send(format!("[reactive] knowledge base: {} entries loaded", kb.len())).await;
    }

    // --- Resolve MCP profile context ---
    let mcp_context: Arc<String> = Arc::new(match &cfg.mcp_profile {
        Some(name) => {
            let profile = match name.as_str() {
                "web" => crate::mcp_profiles::Profile::Web,
                "mobile-android" => crate::mcp_profiles::Profile::MobileAndroid,
                "mobile-ios" => crate::mcp_profiles::Profile::MobileIos,
                "binary" => crate::mcp_profiles::Profile::BinaryAnalysis,
                "burp" => crate::mcp_profiles::Profile::BurpSuite,
                "infra" | "host" => crate::mcp_profiles::Profile::Infra,
                "ad" | "internal" => crate::mcp_profiles::Profile::Ad,
                "cloud" => crate::mcp_profiles::Profile::Cloud,
                "kali" => crate::mcp_profiles::Profile::Kali,
                "nmap" => crate::mcp_profiles::Profile::Nmap,
                "full" => crate::mcp_profiles::Profile::Full,
                other => crate::mcp_profiles::Profile::Custom(other.to_string()),
            };
            let ctx = crate::mcp_profiles::prompt_context(&profile);
            let _ = tx.send(format!("[reactive] MCP profile '{}' active", name)).await;
            ctx
        }
        None => String::new(),
    });

    // --- Build the executor closure ---
    // SAFETY: pool is held alive by the caller (spawn_engagement) which owns the
    // JoinHandle that awaits this future. The wrapper makes the pointer Send+Sync.
    struct PoolHandle(*const ModelPool);
    unsafe impl Send for PoolHandle {}
    unsafe impl Sync for PoolHandle {}
    impl PoolHandle {
        fn get(&self) -> &ModelPool { unsafe { &*self.0 } }
    }
    let pool_handle = Arc::new(PoolHandle(pool as *const ModelPool));
    let cfg_arc = Arc::new(cfg.clone());
    let _constraints = Arc::new(operator_constraints(&cfg));
    let tx2 = tx.clone();

    let exec: ExecFn = Arc::new(move |intent: PlannerIntent, ctx: WorkCtx| {
        let cfg = cfg_arc.clone();
        let tx = tx2.clone();
        let pool_handle = pool_handle.clone();
        let kb = kb.clone();
        let mcp_context = mcp_context.clone();

        async move {
            let _ = tx.send(format!("[reactive] worker: {:?} on {}", intent.action, intent.target)).await;

            // Build system + user prompts based on intent action
            let system = match intent.action {
                IntentAction::Recon => {
                    "You are a web security reconnaissance specialist. Enumerate the target surface: endpoints, parameters, technologies. Report each discovery as 'Fact: ...' and each finding as 'Finding: ...'. Report negatives as 'Negative: ...'."
                }
                IntentAction::Exploit | IntentAction::Fuzz => {
                    "You are a penetration testing specialist. Test the specific vulnerability described. If confirmed, report as 'Finding: [severity] description with evidence'. If not vulnerable, report as 'Negative: tested X, not vulnerable because Y'. Report observations as 'Fact: ...'."
                }
                IntentAction::Validate => {
                    "You are a security validation specialist. Verify whether the described finding is real. Report as 'Finding: ...' if confirmed, 'Negative: ...' if disproven, 'Fact: ...' for observations."
                }
                IntentAction::Chain => {
                    "You are a privilege escalation and lateral movement specialist. Attempt to chain from the described foothold. Report progress as 'Fact: ...', findings as 'Finding: ...', dead ends as 'Negative: ...'."
                }
                IntentAction::Probe | IntentAction::Retry => {
                    "You are a security testing agent. Execute the task precisely. Report findings as 'Finding: ...', observations as 'Fact: ...', negatives as 'Negative: ...'."
                }
            };

            // Inject methodology from knowledge base when relevant
            let task_desc = format!("{:?} {}", intent.action, intent.rationale);
            let methodology = kb.methodology_for(&task_desc, 2, 3000);
            let mcp_block = if mcp_context.is_empty() { String::new() } else { format!("\n{}\n", *mcp_context) };

            let user = format!(
                "Target: {}\nTask: {:?}\nSpecific target: {}\nRationale: {}\
                 {}{}\n\
                 Execute this task. Report results using the prefixes: Finding:, Fact:, Negative:\n\
                 {}",
                cfg.target,
                intent.action,
                intent.target,
                intent.rationale,
                if methodology.is_empty() { String::new() } else { format!("\n\n{}", methodology) },
                mcp_block,
                if ctx.wrapping() { "\nWRAP-UP: Time is running out. Persist your results NOW and stop." } else { "" },
            );

            let result = pool_handle.get().complete(system, &user).await;
            let response = match result {
                Ok((model, text)) => {
                    let _ = tx.send(format!("[reactive] {} responded ({} chars)", model.model, text.len())).await;
                    text
                }
                Err(e) => {
                    let _ = tx.send(format!("[reactive] error: {e} — attempting conclude fallback")).await;
                    // Session resume / conclude fallback: try to salvage partial work
                    let mut session = crate::wrapup::SessionState::new(
                        &format!("{:?} on {}", intent.action, intent.target),
                    );
                    session.partial_output = format!("Model call failed: {e}");
                    let conclude_sys = "You are a security testing results extractor.";
                    let conclude_user = crate::wrapup::conclude_prompt(
                        crate::wrapup::Role::Worker,
                        &session.context(),
                    );
                    if let Ok((_m, text)) = pool_handle.get().complete(conclude_sys, &conclude_user).await {
                        let r = crate::wrapup::parse_conclude(&text);
                        if !r.findings.is_empty() || !r.facts.is_empty() || !r.negatives.is_empty() {
                            let _ = tx.send(format!(
                                "[reactive] conclude salvaged: {} finding(s), {} fact(s), {} negative(s)",
                                r.findings.len(), r.facts.len(), r.negatives.len()
                            )).await;
                            return WorkOutcome {
                                ok: !r.findings.is_empty() || !r.facts.is_empty(),
                                summary: format!("conclude fallback: {} finding(s), {} fact(s)", r.findings.len(), r.facts.len()),
                                facts: r.facts,
                                negatives: r.negatives,
                                findings: r.findings,
                            };
                        }
                    }
                    return WorkOutcome {
                        ok: false,
                        summary: format!("model call failed: {e}"),
                        ..Default::default()
                    };
                }
            };

            // Parse structured output
            let mut facts = Vec::new();
            let mut negatives = Vec::new();
            let mut findings = Vec::new();

            for line in response.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("Finding:").or_else(|| trimmed.strip_prefix("FINDING:")) {
                    findings.push(rest.trim().to_string());
                } else if let Some(rest) = trimmed.strip_prefix("Negative:").or_else(|| trimmed.strip_prefix("NEGATIVE:")) {
                    negatives.push(rest.trim().to_string());
                } else if let Some(rest) = trimmed.strip_prefix("Fact:").or_else(|| trimmed.strip_prefix("FACT:")) {
                    facts.push(rest.trim().to_string());
                }
            }

            // Fallback: if no structured output, check for common patterns
            if findings.is_empty() && facts.is_empty() && negatives.is_empty() {
                for line in response.lines() {
                    let lower = line.to_lowercase();
                    if lower.contains("vulnerable") && !lower.contains("not vulnerable") {
                        findings.push(line.trim().to_string());
                    } else if lower.contains("not vulnerable") || lower.contains("no vulnerability") {
                        negatives.push(line.trim().to_string());
                    } else if lower.contains("discovered") || lower.contains("found") || lower.contains("detected") {
                        facts.push(line.trim().to_string());
                    }
                }
            }

            let ok = !findings.is_empty() || !facts.is_empty() || !negatives.is_empty();
            let summary = format!(
                "{} finding(s), {} fact(s), {} negative(s)",
                findings.len(), facts.len(), negatives.len()
            );
            let _ = tx.send(format!("[reactive] result: {summary}")).await;

            WorkOutcome { ok, summary, facts, negatives, findings }
        }.boxed()
    });

    let _ = tx.send("[reactive] engine running — planner wakes on graph changes".into()).await;

    // --- Run ---
    let (report, final_graph) = reactive::run(reactive_cfg, handle, exec).await;

    // Save final graph
    let _ = final_graph.save(&graph_dir);

    let _ = tx.send(format!(
        "[reactive] done: {:?} — {} done, {} failed, {} findings, {} rounds",
        report.reason, report.done, report.failed, report.findings, report.planner_rounds
    )).await;

    // Extract findings from the graph
    let findings: Vec<crate::types::Finding> = final_graph.exploration.nodes.iter()
        .filter(|n| n.kind == crate::exploration_graph::ExplorationKind::Finding)
        .enumerate()
        .map(|(i, n)| {
            let endpoint = final_graph.exploration.anchors.iter()
                .find(|a| a.exploration_id == n.id)
                .and_then(|a| final_graph.assets.nodes.iter().find(|an| an.id == a.asset_id))
                .map(|a| a.value.clone())
                .unwrap_or_default();
            crate::types::Finding {
                id: format!("reactive-{i}"),
                agent: n.agent.clone(),
                title: n.content.clone(),
                severity: "medium".into(),
                endpoint,
                validated: n.status == crate::exploration_graph::ExplorationStatus::Completed,
                ..Default::default()
            }
        })
        .collect();

    RunOutput {
        target: cfg.target.clone(),
        findings,
        agents_ran: vec!["reactive-engine".into()],
        workdir,
        ..Default::default()
    }
}
