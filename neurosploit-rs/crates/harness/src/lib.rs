//! NeuroSploit v3.6.5 harness — a robust multi-model runtime for the
//! markdown-driven autonomous pentest engine.
//!
//! The harness loads the `agents_md/` library, drives a *pool* of LLM models
//! (any OpenAI-compatible provider) with concurrency + provider failover, runs
//! the specialist agents in parallel, then validates every candidate finding by
//! **N-model voting** before scoring and reporting.

pub mod agents;
pub mod attack_graph;
pub mod audit;
pub mod belief;
pub mod browser;
pub mod capability;
pub mod claims;
pub mod creds;
pub mod grounding;
pub mod hygiene;
pub mod integrations;
pub mod knowledge_graph;
pub mod memory;
pub mod policy;
pub mod pomdp;
pub mod models;
pub mod pipeline;
pub mod pool;
pub mod probe;
pub mod replay;
pub mod report;
pub mod rl;
pub mod scope;
pub mod types;
pub mod validation;

pub use agents::{Agent, Library};
pub use models::{
    cli_binary_for, ensure_playwright_mcp, installed_cli_backends, mcp_supported, provider_for,
    providers, write_mcp_config, ChatClient, ModelRef, Provider,
};
pub use pipeline::{run_greybox, run_host, run_whitebox, RunOutput};
pub use pipeline::run;
pub use knowledge_graph::{EdgeKind, KnowledgeGraph, NodeKind};
pub use memory::{Memory, Query as MemoryQuery, Tier as MemoryTier};
pub use pool::{ModelPool, Task};
pub use audit::{AuditLog, AuditRecord, KillReason, KillSwitch};
pub use capability::{Capability, TokenError};
pub use browser::{BrowserProbe, BrowserResult};
pub use claims::{Claim, ClaimSet, ClaimStatus, Decision, EvidenceLedger};
pub use policy::{Act, ActionKind, BlastRadius, EngagementPolicy, Environment, Protocol, Risk, RiskDecision, SafetyPolicy};
pub use replay::{ReplayEngine, ReqSpec};
pub use scope::{Action as ScopeAction, Decision as ScopeDecision, ScopePolicy};
pub use types::{Finding, RunConfig};
pub use validation::{judge as judge_finding, CweValidator, Evidence, Verdict};
