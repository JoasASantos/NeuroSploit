//! NeuroSploit v3.4.0 — single binary: `serve` (web dashboard) or `run` (CLI).

mod web;

use clap::{Parser, Subcommand};
use harness::{agents, models::ModelRef, pool::ModelPool, report, types::RunConfig};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "neurosploit", version, about = "NeuroSploit v3.4.0 — multi-model autonomous pentest harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the web dashboard.
    Serve {
        #[arg(long, default_value_t = 8788)]
        port: u16,
    },
    /// Run an engagement from the CLI.
    Run {
        url: String,
        /// Models as provider:model (repeatable). First is primary; rest fail over + vote.
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        /// Exercise the pipeline without calling any model API.
        #[arg(long)]
        offline: bool,
        /// Use local agentic CLI subscriptions (Claude Code / Codex / Grok)
        /// instead of HTTP API keys.
        #[arg(long)]
        subscription: bool,
    },
    /// Show agent library counts.
    Agents,
    /// List providers and models.
    Models,
}

/// Locate the repo root that holds `agents_md/` (walk up from CWD, then fall
/// back to the crate's compile-time location).
fn find_base() -> PathBuf {
    if let Ok(b) = std::env::var("NEUROSPLOIT_BASE") {
        return PathBuf::from(b);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        for _ in 0..6 {
            if dir.join("agents_md").is_dir() {
                return dir.to_path_buf();
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }
    // crate is at <root>/neurosploit-rs/app → root is two levels up
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base = find_base();

    match cli.cmd {
        Cmd::Agents => {
            let lib = agents::load(&base);
            println!("{{\"vulns\":{},\"meta\":{},\"total\":{}}}", lib.vulns.len(), lib.meta.len(), lib.total());
        }
        Cmd::Models => {
            for p in harness::providers() {
                println!("{:<4} {:<14} {} models  [{}]", p.kind, p.key, p.models.len(), p.label);
                for m in &p.models {
                    println!("      {}:{}", p.key, m);
                }
            }
        }
        Cmd::Run { url, models, max_agents, vote_n, offline, subscription } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            if !models.is_empty() {
                cfg.models = models;
            }
            let lib = agents::load(&base);
            let refs: Vec<ModelRef> = cfg.models.iter().map(|s| ModelRef::parse(s)).collect();
            let pool = ModelPool::with_auth(refs, cfg.concurrency, cfg.subscription);

            let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
            let printer = tokio::spawn(async move {
                while let Some(line) = rx.recv().await {
                    println!("  [*] {line}");
                }
            });
            let out = harness::run(cfg.clone(), &lib, &pool, tx).await;
            let _ = printer.await;

            println!("\n=== {} validated finding(s) ===", out.findings.len());
            println!("{}", serde_json::to_string_pretty(&out.findings)?);
            let html = report::html(&url, &out.findings);
            std::fs::create_dir_all(base.join("reports")).ok();
            let rp = base.join("reports").join("report_rs.html");
            std::fs::write(&rp, html).ok();
            println!("report → {}", rp.display());
        }
        Cmd::Serve { port } => {
            web::serve(base, port).await?;
        }
    }
    Ok(())
}
