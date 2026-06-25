use crate::models::{cli_binary_for, ChatClient, ModelRef};
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Task type used by the model router to pick the best model for the step.
#[derive(Clone, Copy, Debug)]
pub enum Task {
    Recon,
    Select,
    Exploit,
    Validate,
    Default,
}

/// Heuristic: is this a fast/cheap model id (good for recon/triage)?
fn is_fast(model: &str) -> bool {
    let m = model.to_lowercase();
    ["haiku", "flash", "fast", "mini", "lite", "chat", "small"].iter().any(|k| m.contains(k))
}

/// A pool of candidate models with a global concurrency cap and provider
/// failover. The same panel of models is reused for validator voting.
///
/// `subscription = true` routes each model through its local agentic CLI
/// (Claude Code / Codex / Grok login) instead of an HTTP API key.
pub struct ModelPool {
    client: ChatClient,
    sem: Arc<Semaphore>,
    pub candidates: Vec<ModelRef>,
    pub subscription: bool,
    /// Path to an `.mcp.json` (Playwright) used on the subscription/CLI path.
    pub mcp_config: Option<String>,
    /// Progress channel: when set, the subscription CLI streams structured
    /// activity (tools called, commands run, files read) here live.
    progress: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<String>>>,
    /// HARD cancellation: when set, in-flight model calls short-circuit (abort).
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// SOFT stop: stop launching new EXPLOIT agents, but let in-flight finish and
    /// VALIDATION still run — so "stop and validate what was found" works.
    soft: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ModelPool {
    pub fn new(models: Vec<ModelRef>, concurrency: usize) -> Self {
        Self::with_auth(models, concurrency, false, None)
    }

    pub fn with_auth(
        models: Vec<ModelRef>,
        concurrency: usize,
        subscription: bool,
        mcp_config: Option<String>,
    ) -> Self {
        // Subscription spawns one CLI process per call; too many in parallel
        // trips provider rate limits, so cap concurrency on that path.
        let concurrency = if subscription { concurrency.clamp(1, 3) } else { concurrency.max(1) };
        ModelPool {
            client: ChatClient::new(),
            sem: Arc::new(Semaphore::new(concurrency)),
            candidates: if models.is_empty() {
                vec![ModelRef::parse("anthropic:claude-opus-4-8")]
            } else {
                models
            },
            subscription,
            mcp_config,
            progress: std::sync::Mutex::new(None),
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            soft: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Attach a progress channel so the subscription CLI streams structured
    /// activity (commands run, files read, tools called) live.
    pub fn set_progress(&self, tx: tokio::sync::mpsc::Sender<String>) {
        if let Ok(mut g) = self.progress.lock() {
            *g = Some(tx);
        }
    }

    fn progress(&self) -> Option<tokio::sync::mpsc::Sender<String>> {
        self.progress.lock().ok().and_then(|g| g.clone())
    }

    /// Handle to request HARD cancellation (abort all model calls).
    pub fn cancel_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.cancel.clone()
    }
    /// Handle to request a SOFT stop (stop launching new exploit agents; keep
    /// validation running).
    pub fn soft_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.soft.clone()
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Should the exploit phase stop launching new agents? (hard OR soft stop)
    pub fn stop_exploiting(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
            || self.soft.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// One completion for a model, via subscription CLI (optionally with MCP) or
    /// HTTP API, with a short retry/backoff. `label` (e.g. the agent name) tags
    /// the streamed activity so each command/tool is attributable.
    async fn one(&self, label: &str, m: &ModelRef, system: &str, user: &str) -> Result<String> {
        if self.is_cancelled() {
            return Err(anyhow!("cancelled"));
        }
        let use_cli = self.subscription && cli_binary_for(&m.provider).is_some();
        let progress = self.progress();
        let mut last = anyhow::anyhow!("no attempt");
        for attempt in 0..3u64 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1500 * attempt * attempt.max(1))).await;
            }
            let r = if use_cli {
                self.client
                    .chat_cli(label, &m.provider, &m.model, system, user, self.mcp_config.as_deref(), progress.clone())
                    .await
            } else {
                self.client.chat(m, system, user).await
            };
            match r {
                Ok(t) => return Ok(t),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Complete a prompt, trying each candidate model until one succeeds.
    pub async fn complete(&self, system: &str, user: &str) -> Result<(ModelRef, String)> {
        self.complete_routed(Task::Default, "", system, user).await
    }

    /// Router-aware completion. `label` tags streamed activity (agent name).
    pub async fn complete_routed(&self, task: Task, label: &str, system: &str, user: &str) -> Result<(ModelRef, String)> {
        let _permit = self.sem.acquire().await.expect("semaphore closed");
        let order = self.route(task);
        let mut last = anyhow!("no candidate models");
        for m in &order {
            match self.one(label, m, system, user).await {
                Ok(text) => return Ok((m.clone(), text)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Reorder candidates for a task. With a single-model panel this is a no-op.
    pub fn route(&self, task: Task) -> Vec<ModelRef> {
        let mut order = self.candidates.clone();
        if order.len() < 2 {
            return order;
        }
        match task {
            // Prefer a fast/cheap model for recon & selection.
            Task::Recon | Task::Select => {
                order.sort_by_key(|m| !is_fast(&m.model)); // fast first
            }
            // Strongest (panel order = primary first) for exploitation.
            Task::Exploit | Task::Default => {}
            // Validation handled by vote() rotation (different model than finder).
            Task::Validate => {}
        }
        order
    }

    /// Ask up to `n` distinct models the same yes/no validation question and
    /// return (confirmations, total_votes). A model answering "yes"/"confirmed"
    /// counts as a confirmation. Used to cut false positives.
    ///
    /// `skip` names the model that produced the finding; when the panel has more
    /// than one model, that model is moved to the back so a DIFFERENT model
    /// adjudicates first (cross-model false-positive validation).
    pub async fn vote(&self, system: &str, user: &str, n: usize, skip: Option<&str>) -> (usize, usize) {
        let mut ordered: Vec<ModelRef> = self.candidates.clone();
        if let Some(finder) = skip {
            if ordered.len() > 1 {
                ordered.sort_by_key(|m| m.label() == finder); // finder (true) sorts last
            }
        }
        let panel: Vec<ModelRef> = ordered.into_iter().take(n.max(1)).collect();
        let mut confirmed = 0usize;
        let mut total = 0usize;
        for m in &panel {
            let _permit = match self.sem.acquire().await {
                Ok(p) => p,
                Err(_) => break,
            };
            if let Ok(text) = self.one("validate", m, system, user).await {
                total += 1;
                let t = text.to_lowercase();
                if t.contains("\"verdict\": \"confirmed\"")
                    || t.trim_start().starts_with("yes")
                    || t.contains("confirmed: true")
                    || t.contains("is_real\": true")
                {
                    confirmed += 1;
                }
            }
        }
        (confirmed, total)
    }
}
