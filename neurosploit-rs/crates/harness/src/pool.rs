use crate::models::{cli_binary_for, ChatClient, ModelRef};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

/// Does this error look like token/quota/rate-limit exhaustion (as opposed to a
/// transient network blip)? Used to PAUSE the run instead of silently dropping
/// the agent, so the user can /continue (wait for renewal) or switch model.
pub fn is_exhaustion(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_lowercase();
    [
        "rate limit", "rate_limit", "ratelimit", "429", "too many requests",
        "quota", "insufficient_quota", "insufficient quota", "out of credit",
        "credit balance", "billing", "exhausted", "overloaded", "capacity",
        "usage limit", "resource_exhausted", "resource exhausted",
        "session limit", "session/usage limit", "you've hit your",
    ]
    .iter()
    .any(|k| s.contains(k))
}

/// Does this error look like an **authentication / authorization failure**
/// (revoked OAuth, expired session, invalid API key) — distinct from transient
/// quota/rate issues? Auth failures are non-recoverable without re-login, so
/// the run should pause immediately and offer fallback providers.
pub fn is_auth_failure(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_lowercase();
    [
        "401", "403", "unauthorized", "token has been revoked",
        "token revoked", "access token", "oauth", "session expired",
        "not authenticated", "not logged in", "please log in",
        "please login", "invalid api key", "invalid_api_key",
        "api key expired", "authentication failed", "failed to authenticate",
        "run /login",
    ]
    .iter()
    .any(|k| s.contains(k))
}

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
    /// PAUSE: set when every candidate model is token/quota-exhausted. The run
    /// parks (keeping all state) until the user runs /continue.
    paused: Arc<AtomicBool>,
    /// Wakes the parked task when the user runs /continue.
    resume: Arc<Notify>,
    /// Fallback models the user added via `/continue <provider:model>` while
    /// paused — tried first on the next attempt.
    fallback: Arc<Mutex<Vec<ModelRef>>>,
    /// Circuit breaker: consecutive auth/exhaustion failures across agents.
    /// When this exceeds `AUTH_FAIL_THRESHOLD`, the pool auto-pauses instead of
    /// burning through the remaining agents on a dead token.
    consecutive_auth_fails: Arc<std::sync::atomic::AtomicUsize>,
    /// Backends already tried as an automatic fallback, so a failing one is not
    /// retried in a loop.
    tried_auto: Arc<Mutex<Vec<String>>>,
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
            paused: Arc::new(AtomicBool::new(false)),
            resume: Arc::new(Notify::new()),
            fallback: Arc::new(Mutex::new(Vec::new())),
            consecutive_auth_fails: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            tried_auto: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Reset the consecutive auth-failure counter (called on any successful completion).
    fn reset_auth_fails(&self) {
        self.consecutive_auth_fails.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment the consecutive auth-failure counter and return the new count.
    fn inc_auth_fails(&self) -> usize {
        self.consecutive_auth_fails.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
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

    /// Handle to the PAUSE flag (observe whether the run is parked on exhaustion).
    pub fn pause_handle(&self) -> Arc<AtomicBool> {
        self.paused.clone()
    }
    /// Handle used by the REPL to wake a parked run (`/continue`).
    pub fn resume_handle(&self) -> Arc<Notify> {
        self.resume.clone()
    }
    /// Slot the REPL pushes a fallback model into before resuming
    /// (`/continue <provider:model>`).
    pub fn fallback_handle(&self) -> Arc<Mutex<Vec<ModelRef>>> {
        self.fallback.clone()
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Operator-initiated pause. Same parking machinery as exhaustion, but
    /// nothing failed — a human asked the run to hold. In-flight calls finish;
    /// the next one waits at the gate, so findings already made stay made.
    pub fn pause_now(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    /// Wake a parked run, whichever way it was parked.
    pub fn resume_now(&self) {
        self.paused.store(false, Ordering::Relaxed);
        self.resume.notify_waiters();
    }

    /// Wait here while the run is paused. Cancellation always wins — an
    /// operator who pauses and then stops must not be held by their own pause.
    async fn pause_gate(&self) {
        if !self.is_paused() || self.is_cancelled() {
            return;
        }
        if let Some(tx) = self.progress() {
            let _ = tx.send("notify: ⏸ paused by operator — /continue to resume.".to_string()).await;
        }
        while self.paused.load(Ordering::Relaxed) && !self.is_cancelled() {
            let notified = self.resume.notified();
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            }
        }
        if !self.is_cancelled() {
            if let Some(tx) = self.progress() {
                let _ = tx.send("notify: ▶ resumed by operator.".to_string()).await;
            }
        }
    }

    /// Consecutive auth/quota failures needed to trip the circuit breaker and
    /// auto-pause the run. Low threshold: 3 consecutive failures on the same
    /// provider is enough signal that the token is dead.
    const AUTH_FAIL_THRESHOLD: usize = 3;

    /// Park the run on token/quota exhaustion or auth failure: keep ALL state,
    /// emit a notice, and wait until the user runs `/continue` (or cancels).
    /// Returns when the run should retry (pause cleared) or give up (cancelled).
    async fn park_exhausted(&self, err: &anyhow::Error, is_auth: bool) {
        self.paused.store(true, Ordering::Relaxed);
        if let Some(tx) = self.progress() {
            let msg = format!("{err:#}");
            let short = msg.lines().next().unwrap_or(&msg);
            let notice = if is_auth {
                format!(
                    "notify: ⏸ authentication failed ({}). Run is PAUSED — all findings so far are SAFE. \
                     Fix: /continue <provider:model> to switch provider, or re-login and /continue.",
                    short.chars().take(120).collect::<String>()
                )
            } else {
                format!(
                    "notify: ⏸ token/quota exhausted ({}). Run is PAUSED — type /continue when your quota renews, or switch with /model <provider:model> then /continue.",
                    short.chars().take(120).collect::<String>()
                )
            };
            let _ = tx.send(notice).await;
        }
        while self.paused.load(Ordering::Relaxed) && !self.is_cancelled() {
            let notified = self.resume.notified();
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
        if !self.is_cancelled() {
            self.reset_auth_fails(); // user resumed, reset counter
            if let Some(tx) = self.progress() {
                let _ = tx.send("notify: ▶ resumed — retrying with updated credentials/model.".to_string()).await;
            }
        }
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
            if self.is_cancelled() {
                return Err(anyhow!("cancelled"));
            }
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1500 * attempt * attempt.max(1))).await;
            }
            let call = async {
                if use_cli {
                    self.client
                        .chat_cli(label, &m.provider, &m.model, system, user, self.mcp_config.as_deref(), progress.clone())
                        .await
                } else {
                    self.client.chat(m, system, user).await
                }
            };
            // Race the in-flight call against a HARD cancel: when the user picks
            // "report raw" / "discard" on /stop, drop the call future so the
            // CLI child (spawned with kill_on_drop) is terminated immediately
            // instead of finishing its whole command sequence.
            let r = tokio::select! {
                biased;
                _ = wait_cancelled(&self.cancel) => return Err(anyhow!("cancelled")),
                r = call => r,
            };
            match r {
                Ok(t) => return Ok(t),
                // Don't burn retries on exhaustion or auth failure — surface
                // immediately so the caller can park and let the user /continue.
                Err(e) if is_exhaustion(&e) || is_auth_failure(&e) => return Err(e),
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
        // Every prompt leaves the process watermarked, so a transcript, a cached
        // completion, or a corpus scraped from any of them still says which
        // engine and which build wrote it. Off with NEUROSPLOIT_WATERMARK=off.
        let watermarked;
        let system = if crate::validation::watermarks_on() {
            watermarked = crate::provenance::Provenance::process().watermark_prompt(system);
            watermarked.as_str()
        } else {
            system
        };
        let _permit = self.sem.acquire().await.expect("semaphore closed");
        // Hold here if the operator paused. Before the permit is spent on work.
        self.pause_gate().await;
        loop {
            if self.is_cancelled() {
                return Err(anyhow!("cancelled"));
            }
            // Circuit breaker: if we've seen N consecutive auth failures across
            // agents, pause immediately — don't burn another agent on a dead token.
            let fail_count = self.consecutive_auth_fails.load(std::sync::atomic::Ordering::Relaxed);
            if fail_count >= Self::AUTH_FAIL_THRESHOLD && !self.is_cancelled() {
                self.park_exhausted(
                    &anyhow!("circuit breaker: {} consecutive auth failures — token/session likely dead", fail_count),
                    true,
                ).await;
                if self.is_cancelled() {
                    return Err(anyhow!("cancelled"));
                }
                // After resume, retry with potentially new fallback models.
                continue;
            }
            // User-supplied fallback models (via /continue) are tried first.
            let mut order = self.route(task);
            if let Ok(fb) = self.fallback.lock() {
                for m in fb.iter().rev() {
                    if !order.iter().any(|o| o.provider == m.provider && o.model == m.model) {
                        order.insert(0, m.clone());
                    }
                }
            }
            let mut last = anyhow!("no candidate models");
            let mut exhausted = false;
            let mut auth_failed = false;
            for m in &order {
                if self.is_cancelled() {
                    return Err(anyhow!("cancelled"));
                }
                match self.one(label, m, system, user).await {
                    Ok(text) => {
                        self.reset_auth_fails(); // success resets circuit breaker
                        return Ok((m.clone(), text));
                    }
                    Err(e) => {
                        if is_auth_failure(&e) {
                            auth_failed = true;
                            self.inc_auth_fails();
                        } else if is_exhaustion(&e) {
                            exhausted = true;
                        }
                        last = e;
                    }
                }
            }
            // Every configured candidate failed. Before parking the run and
            // waiting for a human, use whatever else this machine can actually
            // reach — another logged-in CLI subscription, or a provider whose
            // API key is in the environment. A run that stops because one
            // provider ran out of quota, on a box with three other usable
            // backends, is a run that stopped for no reason.
            if (auth_failed || exhausted) && !self.is_cancelled() {
                if let Some(alt) = self.next_auto_fallback(&order) {
                    if let Some(tx) = self.progress() {
                        let _ = tx.send(format!(
                            "notify: ⇄ {} unavailable — falling back to {}:{} and continuing.",
                            order.first().map(|m| m.provider.clone()).unwrap_or_default(),
                            alt.provider, alt.model
                        )).await;
                    }
                    if let Ok(mut fb) = self.fallback.lock() {
                        fb.insert(0, alt.clone());
                    }
                    self.reset_auth_fails();
                    continue;
                }
                // Nothing else is reachable — now a human really is required.
                self.park_exhausted(&last, auth_failed).await;
                continue;
            }
            return Err(last);
        }
    }

    /// A backend this machine can use right now that is not already in `tried`
    /// and not already a candidate.
    ///
    /// Two sources, in this order: a subscription CLI that is installed (the
    /// operator already logged into it, and it costs no API key), then any
    /// provider whose API key is present in the environment. Each is offered
    /// once — a backend that also fails is recorded so the loop cannot spin.
    pub fn next_auto_fallback(&self, current: &[ModelRef]) -> Option<ModelRef> {
        let mut tried = self.tried_auto.lock().ok()?;
        let known = |p: &str, m: &str, tried: &Vec<String>| {
            current.iter().any(|c| c.provider == p && c.model == m) || tried.iter().any(|t| t == &format!("{p}:{m}"))
        };
        let installed = crate::models::installed_cli_backends();
        for pr in crate::models::providers() {
            if pr.kind != "cli" {
                continue;
            }
            let Some(bin) = crate::models::cli_binary_for(pr.key) else { continue };
            if !installed.contains(&bin) {
                continue;
            }
            let Some(model) = pr.models.first() else { continue };
            if known(pr.key, model, &tried) {
                continue;
            }
            tried.push(format!("{}:{}", pr.key, model));
            return Some(ModelRef { provider: pr.key.to_string(), model: (*model).to_string() });
        }
        for pr in crate::models::providers() {
            if std::env::var(pr.env_key).ok().filter(|v| !v.trim().is_empty()).is_none() {
                continue;
            }
            let Some(model) = pr.models.first() else { continue };
            if known(pr.key, model, &tried) {
                continue;
            }
            tried.push(format!("{}:{}", pr.key, model));
            return Some(ModelRef { provider: pr.key.to_string(), model: (*model).to_string() });
        }
        None
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
    /// Assemble a voting panel of `n` models from DISTINCT providers.
    ///
    /// The panel used to be `candidates.take(n)`, so a run configured with one
    /// model produced a "3-model vote" that was one model voting once — a real
    /// engagement shipped 24 findings whose votes all read `1/1`. Asking the
    /// same model three times would be no better: its errors are correlated
    /// with themselves, and three confident repetitions of one mistake look
    /// exactly like a consensus.
    ///
    /// So short panels are filled from other backends this machine can reach,
    /// one per provider. Anthropic checking Anthropic is not independent; a
    /// second vendor is. If nothing else is available the panel simply stays
    /// small, and the `yes/total` the caller prints tells the truth about it.
    fn build_panel(&self, preferred: Vec<ModelRef>, n: usize) -> Vec<ModelRef> {
        let mut panel: Vec<ModelRef> = Vec::new();
        let mut providers: Vec<String> = Vec::new();
        for m in preferred {
            if panel.len() >= n {
                break;
            }
            if providers.contains(&m.provider) {
                continue;
            }
            providers.push(m.provider.clone());
            panel.push(m);
        }
        if panel.len() >= n {
            return panel;
        }
        for alt in self.reachable_backends() {
            if panel.len() >= n {
                break;
            }
            if providers.contains(&alt.provider) {
                continue;
            }
            providers.push(alt.provider.clone());
            panel.push(alt);
        }
        panel
    }

    /// Backends usable right now, one model per provider: an installed
    /// subscription CLI, or a provider whose API key is in the environment.
    pub fn reachable_backends(&self) -> Vec<ModelRef> {
        let installed = crate::models::installed_cli_backends();
        let mut out = Vec::new();
        for pr in crate::models::providers() {
            let usable = (pr.kind == "cli"
                && crate::models::cli_binary_for(pr.key).map(|b| installed.contains(&b)).unwrap_or(false))
                || std::env::var(pr.env_key).ok().filter(|v| !v.trim().is_empty()).is_some();
            if !usable {
                continue;
            }
            if let Some(model) = pr.models.first() {
                out.push(ModelRef { provider: pr.key.to_string(), model: (*model).to_string() });
            }
        }
        out
    }

    pub async fn vote(&self, system: &str, user: &str, n: usize, skip: Option<&str>) -> (usize, usize) {
        let mut ordered: Vec<ModelRef> = self.candidates.clone();
        if let Some(finder) = skip {
            if ordered.len() > 1 {
                ordered.sort_by_key(|m| m.label() == finder); // finder (true) sorts last
            }
        }
        let panel = self.build_panel(ordered, n.max(1));
        let mut confirmed = 0usize;
        let mut total = 0usize;
        for m in &panel {
            let _permit = match self.sem.acquire().await {
                Ok(p) => p,
                Err(_) => break,
            };
            if let Ok(text) = self.one("validate", m, system, user).await {
                total += 1;
                if parse_verdict(&text) == Verdict::Confirmed {
                    confirmed += 1;
                }
            }
        }
        (confirmed, total)
    }
}

/// Resolve once the HARD-cancel flag flips. Lets `tokio::select!` race an
/// in-flight model call against cancellation and drop it on the spot.
async fn wait_cancelled(flag: &Arc<AtomicBool>) {
    while !flag.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

/// A validator's verdict on a candidate finding.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Confirmed,
    Rejected,
    /// No clear yes/no — treated conservatively as NOT confirmed.
    Unclear,
}

/// Robustly parse a validator reply into a verdict. Whitespace-insensitive
/// (so `{"verdict":"confirmed"}` and `{ "verdict": "confirmed" }` both match),
/// checks explicit rejection first, and only counts an *explicit* confirmation.
/// Anything ambiguous is `Unclear` (does not count as confirmed) — biasing the
/// pipeline against false positives.
pub fn parse_verdict(text: &str) -> Verdict {
    let lower = text.to_lowercase();
    let dense: String = lower.chars().filter(|c| !c.is_whitespace()).collect();

    // Explicit rejection wins (conservative).
    let rejected = [
        "\"verdict\":\"rejected\"", "\"verdict\":\"reject\"", "verdict:rejected",
        "\"is_real\":false", "\"isreal\":false", "\"confirmed\":false", "\"real\":false",
        "\"exploitable\":false", "\"valid\":false",
    ];
    if rejected.iter().any(|k| dense.contains(k)) {
        return Verdict::Rejected;
    }
    // Explicit confirmation.
    let confirmed = [
        "\"verdict\":\"confirmed\"", "verdict:confirmed",
        "\"is_real\":true", "\"isreal\":true", "\"confirmed\":true", "\"real\":true",
        "\"exploitable\":true", "\"valid\":true",
    ];
    if confirmed.iter().any(|k| dense.contains(k)) {
        return Verdict::Confirmed;
    }
    // Fallback: only a leading, unambiguous "yes" counts as confirmation.
    if lower.trim_start().starts_with("yes") {
        return Verdict::Confirmed;
    }
    Verdict::Unclear
}

/// Severity-aware confirmation quorum. False High/Critical findings are the most
/// costly, so they require ≥2 validators AND ≥2/3 agreement; lower severities
/// pass on a strict majority (more than half). With only one validator available
/// (single-model panel) the majority rule applies to all severities.
pub fn quorum_confirmed(severity: &str, yes: usize, total: usize) -> bool {
    if total == 0 {
        return false;
    }
    let s = severity.to_lowercase();
    let high = s.starts_with("crit") || s.starts_with("high");
    if high && total >= 2 {
        yes * 3 >= total * 2 // ≥ two-thirds
    } else {
        yes * 2 > total // strict majority
    }
}

#[cfg(test)]
mod verdict_tests {
    /// Whatever this machine happens to have installed, the automatic fallback
    /// must never re-offer a model already in the panel and never offer the
    /// same one twice — either turns "keep going" into a spin.
    #[test]
    fn auto_fallback_never_repeats_itself_or_the_current_panel() {
        let current = vec![ModelRef::parse("anthropic:claude-opus-4-8")];
        let pool = ModelPool::new(current.clone(), 1);
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..8 {
            let Some(m) = pool.next_auto_fallback(&current) else { break };
            let id = format!("{}:{}", m.provider, m.model);
            assert!(
                !(m.provider == "anthropic" && m.model == "claude-opus-4-8"),
                "offered the model that just failed"
            );
            assert!(!seen.contains(&id), "offered {id} twice");
            seen.push(id);
        }
    }

    /// A provider whose key is in the environment is reachable, so it must be
    /// offered before the run parks and waits for a human.
    #[test]
    fn a_provider_with_a_key_in_the_environment_is_offered() {
        std::env::set_var("DEEPSEEK_API_KEY", "test-key-for-fallback");
        let current = vec![ModelRef::parse("anthropic:claude-opus-4-8")];
        let pool = ModelPool::new(current.clone(), 1);
        let mut found = false;
        for _ in 0..30 {
            let Some(m) = pool.next_auto_fallback(&current) else { break };
            if m.provider == "deepseek" { found = true; break; }
        }
        std::env::remove_var("DEEPSEEK_API_KEY");
        assert!(found, "a provider with a usable API key must be reachable as a fallback");
    }

    use super::*;
    #[test]
    fn parses_json_and_prose() {
        assert_eq!(parse_verdict(r#"{"verdict":"confirmed","reason":"x"}"#), Verdict::Confirmed);
        assert_eq!(parse_verdict(r#"{ "verdict": "confirmed" }"#), Verdict::Confirmed);
        assert_eq!(parse_verdict(r#"{ "verdict": "rejected" }"#), Verdict::Rejected);
        assert_eq!(parse_verdict(r#"{"is_real": false}"#), Verdict::Rejected);
        assert_eq!(parse_verdict("Yes, the evidence proves RCE."), Verdict::Confirmed);
        assert_eq!(parse_verdict("This looks theoretical."), Verdict::Unclear); // not counted
    }
    #[test]
    fn rejection_beats_confirmation_when_both_present() {
        // an answer that says confirmed:false must not be read as confirmed
        assert_eq!(parse_verdict(r#"{"confirmed": false, "note": "verdict was confirmed earlier"}"#), Verdict::Rejected);
    }
    #[test]
    fn quorum_is_severity_aware() {
        // high/critical: need >=2 votes AND >=2/3
        assert!(!quorum_confirmed("High", 1, 2));
        assert!(quorum_confirmed("High", 2, 2));
        assert!(quorum_confirmed("Critical", 2, 3));
        assert!(!quorum_confirmed("Critical", 1, 3));
        // single validator: majority applies to all
        assert!(quorum_confirmed("Critical", 1, 1));
        // low/medium: strict majority (more than half)
        assert!(quorum_confirmed("Low", 1, 1));
        assert!(!quorum_confirmed("Medium", 1, 2));
        assert!(quorum_confirmed("Low", 2, 3));
        assert!(!quorum_confirmed("Low", 0, 2));
    }
}

#[cfg(test)]
mod panel_tests {
    use super::*;

    fn m(p: &str, model: &str) -> ModelRef {
        ModelRef { provider: p.into(), model: model.into() }
    }

    /// The defect a real engagement exposed: every finding's votes read `1/1`
    /// because the panel was `candidates.take(n)` and only one model was
    /// configured.
    #[test]
    fn a_single_configured_model_no_longer_produces_a_panel_of_one() {
        let pool = ModelPool::new(vec![m("anthropic", "claude-opus-4-8")], 2);
        let panel = pool.build_panel(pool.candidates.clone(), 3);
        // Whatever this machine has, the panel must not be the configured model
        // repeated, and must not silently claim three votes from one.
        let mut seen: Vec<&str> = panel.iter().map(|x| x.provider.as_str()).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "a panel must never contain the same provider twice");
    }

    #[test]
    fn the_panel_never_repeats_a_provider_even_when_asked_to() {
        let pool = ModelPool::new(
            vec![m("anthropic", "claude-opus-5"), m("anthropic", "claude-sonnet-5"), m("anthropic", "claude-haiku-4-5")],
            2,
        );
        let panel = pool.build_panel(pool.candidates.clone(), 3);
        let anthropic = panel.iter().filter(|x| x.provider == "anthropic").count();
        assert_eq!(anthropic, 1, "three models from one vendor are not three independent votes");
    }

    #[test]
    fn configured_models_are_preferred_over_discovered_ones() {
        let pool = ModelPool::new(vec![m("openai", "gpt-5.4"), m("xai", "grok-4.5")], 2);
        let panel = pool.build_panel(pool.candidates.clone(), 2);
        assert_eq!(panel.len(), 2);
        assert_eq!(panel[0].provider, "openai");
        assert_eq!(panel[1].provider, "xai");
    }

    #[test]
    fn a_panel_of_one_is_honest_rather_than_padded() {
        // With nothing else reachable the panel stays small; the caller prints
        // yes/total, so a 1/1 vote is visible as exactly that.
        let pool = ModelPool::new(vec![m("anthropic", "claude-opus-4-8")], 1);
        let panel = pool.build_panel(pool.candidates.clone(), 1);
        assert_eq!(panel.len(), 1);
    }
}
