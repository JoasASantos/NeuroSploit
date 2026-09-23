//! NeuroSploit v3.6.5 harness — a robust multi-model runtime for the
//! markdown-driven autonomous pentest engine.
//!
//! The harness loads the `agents_md/` library, drives a *pool* of LLM models
//! (any OpenAI-compatible provider) with concurrency + provider failover, runs
//! the specialist agents in parallel, then validates every candidate finding by
//! **N-model voting** before scoring and reporting.

pub mod agents;
pub mod assurance;
pub mod attack_graph;
pub mod audit;
pub mod belief;
pub mod browser;
pub mod budget;
pub mod capability;
pub mod chain;
pub mod claims;
pub mod compliance;
pub mod creds;
pub mod cvss;
pub mod grounding;
pub mod hygiene;
pub mod inbox;
pub mod integrations;
pub mod integrity;
pub mod internal;
pub mod knowledge_graph;
pub mod memory;
pub mod policy;
pub mod poc;
pub mod pomdp;
pub mod proxy;
pub mod prosecutor;
pub mod provenance;
pub mod models;
pub mod netguard;
pub mod oob;
pub mod pipeline;
pub mod pool;
pub mod probe;
pub mod replay;
pub mod report;
pub mod rl;
pub mod sandbox;
pub mod scope;
pub mod taint;
pub mod transport;
pub mod types;
pub mod typesafe;
pub mod typesafe_agent;
pub mod uncertainty;
pub mod validation;
pub mod waf;

pub use agents::{Agent, Library};
pub use models::{
    cli_binary_for, ensure_playwright_mcp, installed_cli_backends, mcp_supported, provider_for,
    providers, write_mcp_config, ChatClient, ModelRef, Provider,
};
pub use pipeline::{run_container, run_greybox, run_host, run_mobile, run_whitebox, RunOutput};
pub use pipeline::run;
pub use knowledge_graph::{EdgeKind, KnowledgeGraph, NodeKind};
pub use memory::{Memory, Query as MemoryQuery, Tier as MemoryTier};
pub use pool::{ModelPool, Task};
pub use audit::{AuditLog, AuditRecord, KillReason, KillSwitch};
pub use capability::{Capability, TokenError};
pub use browser::{BrowserProbe, BrowserResult};
pub use budget::{Budget, Effort, Governor, Mode as BudgetMode, Order as BudgetOrder, Phase as BudgetPhase};
pub use chain::{AttackPath, Capability as ChainCapability, Link};
pub use claims::{Claim, ClaimSet, ClaimStatus, Decision, EvidenceLedger};
pub use policy::{Act, ActionKind, BlastRadius, EngagementPolicy, Environment, Protocol, Risk, RiskDecision, SafetyPolicy};
pub use prosecutor::{ProsecutorVerdict, PROSECUTOR_SYS};
pub use replay::{ReplayEngine, ReqSpec};
pub use scope::{Action as ScopeAction, Decision as ScopeDecision, ScopePolicy};
pub use types::{Finding, RunConfig};
pub use uncertainty::{assess as assess_uncertainty, Assessment, Gap, Rounds};
pub use validation::{judge as judge_finding, CweValidator, Evidence, Verdict};


/// Download bytes over HTTPS with a bounded timeout. Used by the app to fetch
/// the pinned agent library when it is not present next to the binary.
pub async fn fetch_bytes(url: &str, timeout_secs: u64) -> anyhow::Result<Vec<u8>> {
    let b = reqwest::Client::new()
        .get(url)
        .header("user-agent", "neurosploit")
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send().await?
        .error_for_status()?
        .bytes().await?;
    Ok(b.to_vec())
}
