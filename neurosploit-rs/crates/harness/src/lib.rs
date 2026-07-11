//! NeuroSploit v3.6.3 harness — a robust multi-model runtime for the
//! markdown-driven autonomous pentest engine.
//!
//! The harness loads the `agents_md/` library, drives a *pool* of LLM models
//! (any OpenAI-compatible provider) with concurrency + provider failover, runs
//! the specialist agents in parallel, then validates every candidate finding by
//! **N-model voting** before scoring and reporting.

pub mod agents;
pub mod attack_graph;
pub mod belief;
pub mod creds;
pub mod grounding;
pub mod hygiene;
pub mod integrations;
pub mod pomdp;
pub mod models;
pub mod pipeline;
pub mod pool;
pub mod probe;
pub mod report;
pub mod rl;
pub mod types;

pub use agents::{Agent, Library};
pub use models::{
    cli_binary_for, ensure_playwright_mcp, installed_cli_backends, mcp_supported, provider_for,
    providers, write_mcp_config, ChatClient, ModelRef, Provider,
};
pub use pipeline::{run_greybox, run_host, run_whitebox, RunOutput};
pub use pipeline::run;
pub use pool::{ModelPool, Task};
pub use types::{Finding, RunConfig};
