//! Execution resilience: transient-retry with classified backoff, tool-call
//! output limiting, context compaction, and crash-state salvage.
//!
//! Inspired by production patterns in Strix's execution engine, adapted to
//! NeuroSploit's Rust/tokio architecture and single-shot agent model.

use std::time::Duration;

// ---------------------------------------------------------------------------
// 1. Transient error classification + exponential backoff
// ---------------------------------------------------------------------------

/// Whether an LLM provider error is transient (worth retrying) vs permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Timeout, connection reset, 429, 500+, overloaded — retry with backoff.
    Transient,
    /// Auth failure (401/403), invalid key — stop immediately.
    Auth,
    /// Quota/billing exhaustion — pause the run for operator action.
    Exhaustion,
    /// Context window overflow — needs compaction, not retry.
    ContextOverflow,
    /// Bad request that won't change on retry (400 with non-overflow reason).
    Permanent,
    /// Image/multimodal rejection — scrub images, retry.
    ImageRejection,
    /// Content policy / guardrail refusal.
    ContentRefusal,
}

/// Classify an error string from an LLM provider into an actionable category.
pub fn classify_error(err: &str) -> ErrorClass {
    let lower = err.to_lowercase();

    // Auth first — most specific.
    if ["401", "403", "unauthorized", "token has been revoked",
        "invalid api key", "invalid_api_key", "not authenticated",
        "authentication failed", "please log in", "please login",
        "token revoked", "session expired"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::Auth;
    }

    // Exhaustion / billing.
    if ["quota", "insufficient_quota", "out of credit", "credit balance",
        "billing", "usage limit", "resource_exhausted"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::Exhaustion;
    }

    // Context overflow (must check before generic 400).
    if ["context length", "context window", "context_length_exceeded",
        "prompt is too long", "input is too long", "maximum prompt length",
        "reduce the length", "too many tokens", "token limit exceeded"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::ContextOverflow;
    }

    // Image rejection (before generic 400).
    if ["no endpoints found that support image",
        "image_url is only supported by certain models",
        "is not a multimodal model", "at most 0 image",
        "does not support image input",
        "doesn't support the image field"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::ImageRejection;
    }

    // Content policy / guardrail.
    if ["content policy", "content_policy", "safety", "harmful",
        "i cannot", "i can't help with", "refusal"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::ContentRefusal;
    }

    // Rate limit (transient).
    if ["rate limit", "rate_limit", "ratelimit", "429", "too many requests",
        "overloaded", "capacity", "service unavailable", "503"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::Transient;
    }

    // Server errors (transient).
    if ["500", "502", "504", "timeout", "timed out", "connection reset",
        "connection refused", "connection error", "eof", "broken pipe",
        "network", "dns", "resolve"]
        .iter().any(|k| lower.contains(k))
    {
        return ErrorClass::Transient;
    }

    // Everything else is permanent.
    ErrorClass::Permanent
}

/// Retry configuration for transient errors.
pub const MAX_TRANSIENT_RETRIES: u32 = 5;
const BASE_DELAY_MS: u64 = 2_000;
const MAX_DELAY_MS: u64 = 90_000;

/// Compute exponential backoff delay for attempt N (1-indexed).
pub fn retry_delay(attempt: u32) -> Duration {
    let delay = BASE_DELAY_MS * 2u64.pow(attempt.saturating_sub(1));
    Duration::from_millis(delay.min(MAX_DELAY_MS))
}

/// Should we retry this error class?
pub fn is_retryable(class: ErrorClass) -> bool {
    matches!(class, ErrorClass::Transient)
}

// ---------------------------------------------------------------------------
// 2. Tool-call output limiter (blast-radius cap)
// ---------------------------------------------------------------------------

/// Limits how many tool calls from a single model response are honoured.
/// A degenerate generation can emit hundreds of tool calls (e.g. a
/// poll/wait loop written out ahead of time); executing all of them makes
/// the agent unresponsive for hours. Keeping only the first `limit` bounds
/// that blast radius.
pub struct ToolCallLimiter {
    limit: usize,
    kept: usize,
    pub dropped: usize,
}

impl ToolCallLimiter {
    pub fn new(limit: usize) -> Self {
        Self { limit, kept: 0, dropped: 0 }
    }

    /// Whether the next tool call should be executed.
    pub fn allow(&mut self) -> bool {
        if self.limit == 0 {
            return true; // unlimited
        }
        if self.kept < self.limit {
            self.kept += 1;
            true
        } else {
            self.dropped += 1;
            false
        }
    }

    /// Filter a list of items, keeping only the first `limit`.
    pub fn filter<T>(&mut self, items: Vec<T>) -> Vec<T> {
        if self.limit == 0 || items.len() <= self.limit {
            self.kept += items.len();
            return items;
        }
        self.dropped += items.len() - self.limit;
        self.kept += self.limit;
        items.into_iter().take(self.limit).collect()
    }
}

// ---------------------------------------------------------------------------
// 3. Context compaction (prompt truncation with structured summary)
// ---------------------------------------------------------------------------

use crate::pool::ModelPool;

/// Approximate token count (4 chars per token heuristic, same as most
/// tokenizer estimates for English text + code).
pub fn approx_tokens(text: &str) -> usize {
    text.len() / 4
}

/// Maximum context tokens before compaction triggers.
const COMPACT_THRESHOLD_TOKENS: usize = 100_000;
/// Tokens to keep verbatim from the end of the conversation.
const KEEP_RECENT_TOKENS: usize = 30_000;

const COMPACT_SYSTEM: &str = "\
You are compacting the earlier part of an autonomous security-testing agent's \
conversation so it fits the model context window. Produce a dense, factual \
record that lets the agent continue with no loss of important state.\n\n\
This is a security engagement: dropped findings mean lost vulnerabilities. Be \
EXHAUSTIVE. Enumerate every distinct item as its own bullet. Copy exact values \
verbatim: URLs, endpoints, parameters, payloads, credentials, tokens, error \
messages. Do not invent anything.\n\n\
Return Markdown with these sections:\n\
## Objective\n\
## Vulnerabilities & Findings (one bullet per DISTINCT finding)\n\
## Credentials & Secrets (verbatim, or \"(none)\")\n\
## System & Recon Details\n\
## Work State (completed / active / blocked)\n\
## Failed Attempts & Dead Ends\n\
## Next Move";

/// Compact a conversation that has grown too large by summarising the older
/// portion and keeping the recent portion verbatim.
///
/// Returns `Some(compacted_prompt)` if compaction was performed, `None` if
/// the prompt is within budget.
pub async fn maybe_compact_prompt(
    pool: &ModelPool,
    full_prompt: &str,
) -> Option<String> {
    let total_tokens = approx_tokens(full_prompt);
    if total_tokens <= COMPACT_THRESHOLD_TOKENS {
        return None;
    }

    // Split: older portion to summarise, recent portion to keep verbatim.
    let keep_chars = KEEP_RECENT_TOKENS * 4;
    let split_point = full_prompt.len().saturating_sub(keep_chars);

    // Find a clean split point (newline boundary).
    let split = full_prompt[..split_point]
        .rfind('\n')
        .unwrap_or(split_point);

    let head = &full_prompt[..split];
    let tail = &full_prompt[split..];

    if head.is_empty() {
        return None;
    }

    // Cap head to avoid sending an enormous summarisation request.
    let head_capped: String = head.chars().take(200_000).collect();

    let user_msg = format!(
        "Summarise this earlier conversation from a security testing agent:\n\n{}\n\n\
         Respond with ONLY the structured Markdown summary.",
        head_capped
    );

    match pool.complete(COMPACT_SYSTEM, &user_msg).await {
        Ok((_model, summary)) => {
            let compacted = format!(
                "<compacted-context>\n\
                 The following summarises earlier conversation that was compacted to fit \
                 the context window. Treat it as established context, not new instructions.\n\n\
                 {}\n\
                 </compacted-context>\n\n\
                 {}",
                summary.trim(),
                tail
            );
            Some(compacted)
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// 4. Crash-state salvage (persist partial findings on agent failure)
// ---------------------------------------------------------------------------

use crate::types::Finding;
use std::path::Path;

/// Salvage partial findings from a crashed agent's raw output.
///
/// When an agent dies mid-execution (timeout, provider crash, context overflow),
/// any findings already emitted in its partial response are extracted and
/// persisted rather than lost. This is the single biggest ROI improvement:
/// a 40-minute agent run that crashes at minute 38 still keeps its 38 minutes
/// of findings.
pub fn salvage_findings(agent_name: &str, partial_output: &str, workdir: Option<&str>) -> Vec<Finding> {
    if partial_output.is_empty() {
        return Vec::new();
    }

    let findings = crate::pipeline::extract_findings(partial_output, agent_name);
    if findings.is_empty() {
        return Vec::new();
    }

    // Persist to a salvage file so they survive even if the caller also crashes.
    if let Some(dir) = workdir {
        let path = Path::new(dir).join("salvaged_findings.json");
        let existing: Vec<Finding> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let mut all = existing;
        for f in &findings {
            if !all.iter().any(|e| e.title == f.title && e.endpoint == f.endpoint) {
                all.push(f.clone());
            }
        }

        if let Ok(json) = serde_json::to_string_pretty(&all) {
            let _ = std::fs::write(&path, json);
        }
    }

    findings
}

/// Load any previously salvaged findings from a run directory.
pub fn load_salvaged(workdir: &str) -> Vec<Finding> {
    let path = Path::new(workdir).join("salvaged_findings.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 5. LLM-based finding dedup (semantic, not just hash)
// ---------------------------------------------------------------------------

const DEDUP_SYSTEM: &str = "\
You are a vulnerability dedup judge. Given a CANDIDATE finding and EXISTING findings, \
decide if the candidate is a duplicate.\n\n\
SAME vulnerability means: same root cause, same affected endpoint/file, same exploitation \
method, would be fixed by the same code change.\n\n\
NOT duplicates if: different endpoints even with same vuln type, different parameters in \
same endpoint, different root causes (stored XSS vs reflected XSS), different auth context.\n\n\
ARE duplicates even if: titles differ, descriptions vary in detail, PoC uses different \
payloads but exploits same issue, one report is more thorough.\n\n\
Respond with ONLY a JSON object:\n\
{\"is_duplicate\": true/false, \"match_index\": <0-based index or -1>, \"confidence\": 0.0-1.0, \"reason\": \"...\"}\n\
No prose, no code fences.";

/// Check if a candidate finding duplicates any existing finding using LLM judgment.
/// Returns `Some(index)` of the matched existing finding, or `None` if unique.
pub async fn llm_dedup_check(
    pool: &ModelPool,
    candidate: &Finding,
    existing: &[Finding],
) -> Option<usize> {
    if existing.is_empty() {
        return None;
    }

    // Fast-path: exact title+endpoint match (deterministic, no LLM call).
    for (i, ex) in existing.iter().enumerate() {
        if ex.title == candidate.title && ex.endpoint == candidate.endpoint {
            return Some(i);
        }
    }

    // Fast-path: same CWE + same endpoint key = very likely duplicate.
    let cand_cwe = cwe_number(&candidate.cwe);
    if cand_cwe != 0 {
        for (i, ex) in existing.iter().enumerate() {
            if cwe_number(&ex.cwe) == cand_cwe
                && normalize_endpoint(&ex.endpoint) == normalize_endpoint(&candidate.endpoint)
            {
                return Some(i);
            }
        }
    }

    // LLM dedup for fuzzy cases: different wording, different CWE but same root cause.
    let existing_summary: Vec<String> = existing
        .iter()
        .enumerate()
        .take(30) // cap to avoid context overflow
        .map(|(i, f)| format!("[{i}] {} | {} | {} | CWE-{}", f.title, f.severity, f.endpoint, f.cwe))
        .collect();

    let user_msg = format!(
        "CANDIDATE:\ntitle: {}\nseverity: {}\nendpoint: {}\ncwe: {}\nevidence: {}\n\nEXISTING:\n{}\n\nRespond with ONLY the JSON object.",
        candidate.title, candidate.severity, candidate.endpoint, candidate.cwe,
        &candidate.evidence[..candidate.evidence.len().min(500)],
        existing_summary.join("\n")
    );

    match pool.complete(DEDUP_SYSTEM, &user_msg).await {
        Ok((_model, response)) => parse_dedup_response(&response),
        Err(_) => None, // LLM failed, treat as unique (safe default)
    }
}

fn parse_dedup_response(text: &str) -> Option<usize> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start { return None; }
    let json: serde_json::Value = serde_json::from_str(&text[start..=end]).ok()?;
    if json.get("is_duplicate")?.as_bool()? {
        let idx = json.get("match_index")?.as_i64()?;
        if idx >= 0 { Some(idx as usize) } else { None }
    } else {
        None
    }
}

fn cwe_number(cwe: &str) -> u32 {
    cwe.trim_start_matches("CWE-")
        .trim_start_matches("cwe-")
        .parse()
        .unwrap_or(0)
}

fn normalize_endpoint(ep: &str) -> String {
    ep.split(['?', '#']).next().unwrap_or(ep)
        .trim_end_matches('/')
        .to_lowercase()
}

// ---------------------------------------------------------------------------
// 6. Budget warnings (progressive alerts at 70/85/95%)
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicU8, Ordering};

/// Thresholds at which to warn the operator about budget usage.
const WARN_THRESHOLDS: &[u8] = &[70, 85, 95];

/// Tracks which budget warning levels have already been emitted.
pub struct BudgetWarner {
    last_warned: AtomicU8,
}

impl BudgetWarner {
    pub fn new() -> Self {
        Self { last_warned: AtomicU8::new(0) }
    }

    /// Check if a warning should fire. Returns `Some(pct)` with the threshold
    /// crossed, or `None` if already warned at this level.
    pub fn check(&self, spent: u64, limit: u64) -> Option<u8> {
        if limit == 0 {
            return None; // unlimited budget
        }
        let pct = ((spent as f64 / limit as f64) * 100.0) as u8;
        let last = self.last_warned.load(Ordering::Relaxed);

        for &threshold in WARN_THRESHOLDS {
            if pct >= threshold && last < threshold {
                self.last_warned.store(threshold, Ordering::Relaxed);
                return Some(threshold);
            }
        }
        None
    }

    /// Format a warning message for the given threshold.
    pub fn message(threshold: u8, spent: u64, limit: u64, remaining_agents: usize) -> String {
        let pct = if limit > 0 { (spent as f64 / limit as f64) * 100.0 } else { 0.0 };
        match threshold {
            70 => format!(
                "⚠ budget {pct:.0}% used ({spent}/{limit} tokens). {} agents still running. Consider: reduce concurrency or switch to cheaper model.",
                remaining_agents
            ),
            85 => format!(
                "⚠⚠ budget {pct:.0}% used ({spent}/{limit} tokens). Entering conservation mode — new agents use cheap analysis only."
            ),
            95 => format!(
                "🛑 budget {pct:.0}% used ({spent}/{limit} tokens). Reserving remaining tokens for validation of findings already collected. No new exploit agents."
            ),
            _ => format!("⚠ budget {pct:.0}% used ({spent}/{limit} tokens)"),
        }
    }

    /// At 90%+ budget, should we reserve tokens for sub-agent work (validation)?
    pub fn should_reserve_for_validation(spent: u64, limit: u64) -> bool {
        if limit == 0 { return false; }
        let pct = (spent as f64 / limit as f64) * 100.0;
        pct >= 90.0
    }

    /// At 95%+, should we stop spawning new exploit agents?
    pub fn should_stop_new_agents(spent: u64, limit: u64) -> bool {
        if limit == 0 { return false; }
        let pct = (spent as f64 / limit as f64) * 100.0;
        pct >= 95.0
    }
}

// ---------------------------------------------------------------------------
// 7. Agent lifecycle nudge (retry failed agents with simplified prompt)
// ---------------------------------------------------------------------------

const MAX_NUDGE_ATTEMPTS: usize = 3;

const NUDGE_PREFIX: &str = "\
Your previous attempt failed or produced no results. This is a RETRY with a \
simplified prompt. Focus on the MOST LIKELY vulnerability for your speciality. \
Be direct, test one thing, and report what you find.\n\n";

/// Retry a failed single-shot agent with progressively simplified prompts.
/// Returns findings from the first successful retry, or empty if all fail.
pub async fn nudge_agent(
    pool: &ModelPool,
    agent_name: &str,
    system: &str,
    original_user: &str,
    task: crate::pool::Task,
) -> Vec<Finding> {
    for attempt in 1..=MAX_NUDGE_ATTEMPTS {
        let simplified = match attempt {
            1 => format!("{NUDGE_PREFIX}{original_user}"),
            2 => {
                // Trim recon context to reduce noise.
                let trimmed: String = original_user.chars().take(2000).collect();
                format!("{NUDGE_PREFIX}SIMPLIFIED:\n{trimmed}")
            }
            _ => {
                // Final attempt: bare minimum prompt.
                let core: String = original_user.lines()
                    .filter(|l| l.contains("target") || l.contains("AUTHORIZED") || l.contains("Reply ONLY"))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!("{NUDGE_PREFIX}LAST ATTEMPT — minimal context:\n{core}")
            }
        };

        match pool.complete_routed(task, agent_name, system, &simplified).await {
            Ok((_model, text)) => {
                let findings = crate::pipeline::extract_findings(&text, agent_name);
                if !findings.is_empty() {
                    return findings;
                }
                // Got a response but no findings — try next simplification.
            }
            Err(_) => {
                // Complete failure — try next simplification.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// 8. Image budget enforcement (cap screenshots in context)
// ---------------------------------------------------------------------------

/// Strip base64 image data from a prompt to reduce token usage.
/// Keeps the first `max_images` image references and replaces the rest
/// with `[image elided]`.
pub fn enforce_image_budget(text: &str, max_images: usize) -> String {
    let mut result = String::with_capacity(text.len());
    let mut images_kept = 0;
    let mut remaining = text;

    while let Some(start) = remaining.find("data:image/") {
        result.push_str(&remaining[..start]);

        // Find the end of the base64 data.
        let after = &remaining[start..];
        let end = after.find('"')
            .or_else(|| after.find('\''))
            .or_else(|| after.find('\n'))
            .or_else(|| after.find(' '))
            .unwrap_or(after.len());

        if images_kept < max_images {
            result.push_str(&remaining[start..start + end]);
            images_kept += 1;
        } else {
            result.push_str("[screenshot elided to bound context]");
        }

        remaining = &remaining[start + end..];
    }
    result.push_str(remaining);
    result
}

/// Strip all base64 images from text (useful for image-rejection recovery).
pub fn strip_all_images(text: &str) -> String {
    enforce_image_budget(text, 0)
}

// ---------------------------------------------------------------------------
// 9. Run snapshot/resume (persist state for interrupted runs)
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// Snapshot of an in-progress run, serializable to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSnapshot {
    pub target: String,
    pub recon: String,
    pub agents_completed: Vec<String>,
    pub agents_pending: Vec<String>,
    pub findings_so_far: Vec<Finding>,
    pub phase: String,
    pub timestamp: String,
}

impl RunSnapshot {
    pub fn new(target: &str, recon: &str) -> Self {
        Self {
            target: target.to_string(),
            recon: recon.to_string(),
            agents_completed: Vec::new(),
            agents_pending: Vec::new(),
            findings_so_far: Vec::new(),
            phase: "init".to_string(),
            timestamp: chrono_now(),
        }
    }

    pub fn mark_agent_done(&mut self, name: &str, findings: &[Finding]) {
        self.agents_pending.retain(|n| n != name);
        if !self.agents_completed.contains(&name.to_string()) {
            self.agents_completed.push(name.to_string());
        }
        for f in findings {
            if !self.findings_so_far.iter().any(|e| e.title == f.title && e.endpoint == f.endpoint) {
                self.findings_so_far.push(f.clone());
            }
        }
        self.timestamp = chrono_now();
    }

    pub fn set_phase(&mut self, phase: &str) {
        self.phase = phase.to_string();
        self.timestamp = chrono_now();
    }

    /// Persist snapshot to the run's workdir.
    pub fn save(&self, workdir: &str) -> std::io::Result<()> {
        let path = Path::new(workdir).join("run_snapshot.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    /// Load a previous snapshot from a workdir.
    pub fn load(workdir: &str) -> Option<Self> {
        let path = Path::new(workdir).join("run_snapshot.json");
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Agents that haven't completed yet (for resume).
    pub fn remaining_agents(&self) -> &[String] {
        &self.agents_pending
    }

    /// Has this agent already been run in a prior invocation?
    pub fn already_ran(&self, agent_name: &str) -> bool {
        self.agents_completed.iter().any(|n| n == agent_name)
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_transient_errors() {
        assert_eq!(classify_error("Connection timed out"), ErrorClass::Transient);
        assert_eq!(classify_error("Error 429: Too Many Requests"), ErrorClass::Transient);
        assert_eq!(classify_error("502 Bad Gateway"), ErrorClass::Transient);
        assert_eq!(classify_error("Service Unavailable"), ErrorClass::Transient);
    }

    #[test]
    fn classify_auth_errors() {
        assert_eq!(classify_error("401 Unauthorized"), ErrorClass::Auth);
        assert_eq!(classify_error("Invalid API key"), ErrorClass::Auth);
        assert_eq!(classify_error("Token has been revoked"), ErrorClass::Auth);
    }

    #[test]
    fn classify_exhaustion() {
        assert_eq!(classify_error("insufficient_quota"), ErrorClass::Exhaustion);
        assert_eq!(classify_error("Out of credit"), ErrorClass::Exhaustion);
    }

    #[test]
    fn classify_context_overflow() {
        assert_eq!(classify_error("context_length_exceeded"), ErrorClass::ContextOverflow);
        assert_eq!(classify_error("This model's maximum context length is 128000 tokens"), ErrorClass::ContextOverflow);
        assert_eq!(classify_error("prompt is too long"), ErrorClass::ContextOverflow);
    }

    #[test]
    fn classify_permanent() {
        assert_eq!(classify_error("invalid JSON in request body"), ErrorClass::Permanent);
        assert_eq!(classify_error("unknown model gpt-99"), ErrorClass::Permanent);
    }

    #[test]
    fn retry_delay_exponential() {
        assert_eq!(retry_delay(1), Duration::from_millis(2_000));
        assert_eq!(retry_delay(2), Duration::from_millis(4_000));
        assert_eq!(retry_delay(3), Duration::from_millis(8_000));
        assert_eq!(retry_delay(4), Duration::from_millis(16_000));
        assert_eq!(retry_delay(5), Duration::from_millis(32_000));
        // Capped at 90s.
        assert_eq!(retry_delay(10), Duration::from_millis(90_000));
    }

    #[test]
    fn tool_call_limiter_caps_output() {
        let mut limiter = ToolCallLimiter::new(3);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
        assert!(!limiter.allow());
        assert_eq!(limiter.dropped, 2);
    }

    #[test]
    fn tool_call_limiter_zero_is_unlimited() {
        let mut limiter = ToolCallLimiter::new(0);
        for _ in 0..100 {
            assert!(limiter.allow());
        }
        assert_eq!(limiter.dropped, 0);
    }

    #[test]
    fn tool_call_limiter_filter() {
        let mut limiter = ToolCallLimiter::new(2);
        let items = vec![1, 2, 3, 4, 5];
        let filtered = limiter.filter(items);
        assert_eq!(filtered, vec![1, 2]);
        assert_eq!(limiter.dropped, 3);
    }

    #[test]
    fn approx_tokens_reasonable() {
        let text = "hello world this is a test"; // 26 chars
        assert_eq!(approx_tokens(text), 6); // 26/4 = 6
    }

    #[test]
    fn compact_threshold_is_sane() {
        assert!(COMPACT_THRESHOLD_TOKENS > KEEP_RECENT_TOKENS);
    }

    // --- Dedup helpers ---
    #[test]
    fn cwe_number_parses() {
        assert_eq!(cwe_number("CWE-79"), 79);
        assert_eq!(cwe_number("cwe-89"), 89);
        assert_eq!(cwe_number("89"), 89);
        assert_eq!(cwe_number(""), 0);
    }

    #[test]
    fn normalize_endpoint_strips_query() {
        assert_eq!(normalize_endpoint("/api/users?id=1"), "/api/users");
        assert_eq!(normalize_endpoint("/API/Users/"), "/api/users");
    }

    // --- Budget warner ---
    #[test]
    fn budget_warner_fires_at_thresholds() {
        let w = BudgetWarner::new();
        assert_eq!(w.check(50, 100), None);       // 50% — no warning
        assert_eq!(w.check(70, 100), Some(70));    // 70% — first warning
        assert_eq!(w.check(72, 100), None);        // 72% — already warned at 70
        assert_eq!(w.check(85, 100), Some(85));    // 85% — second warning
        assert_eq!(w.check(95, 100), Some(95));    // 95% — final warning
        assert_eq!(w.check(99, 100), None);        // 99% — already warned at 95
    }

    #[test]
    fn budget_warner_unlimited_never_fires() {
        let w = BudgetWarner::new();
        assert_eq!(w.check(999999, 0), None);
    }

    #[test]
    fn budget_reserve_triggers_at_90() {
        assert!(!BudgetWarner::should_reserve_for_validation(80, 100));
        assert!(BudgetWarner::should_reserve_for_validation(91, 100));
        assert!(!BudgetWarner::should_reserve_for_validation(91, 0)); // unlimited
    }

    #[test]
    fn budget_stop_agents_at_95() {
        assert!(!BudgetWarner::should_stop_new_agents(94, 100));
        assert!(BudgetWarner::should_stop_new_agents(96, 100));
    }

    // --- Image budget ---
    #[test]
    fn image_budget_keeps_n_images() {
        let text = r#"before data:image/png;base64,AAA" middle data:image/jpg;base64,BBB" end"#;
        let result = enforce_image_budget(text, 1);
        assert!(result.contains("data:image/png;base64,AAA"));
        assert!(result.contains("[screenshot elided"));
        assert!(!result.contains("BBB"));
    }

    #[test]
    fn strip_all_images_removes_all() {
        let text = r#"img data:image/png;base64,AAAA" done"#;
        let result = strip_all_images(text);
        assert!(!result.contains("AAAA"));
        assert!(result.contains("[screenshot elided"));
    }

    // --- Run snapshot ---
    #[test]
    fn snapshot_tracks_agents() {
        let mut snap = RunSnapshot::new("https://target.test", "{}");
        snap.agents_pending = vec!["sqli".into(), "xss".into(), "csrf".into()];
        assert!(!snap.already_ran("sqli"));
        snap.mark_agent_done("sqli", &[]);
        assert!(snap.already_ran("sqli"));
        assert_eq!(snap.agents_pending.len(), 2);
        assert_eq!(snap.agents_completed.len(), 1);
    }

    #[test]
    fn dedup_response_parsing() {
        let good = r#"{"is_duplicate": true, "match_index": 2, "confidence": 0.95, "reason": "same vuln"}"#;
        assert_eq!(parse_dedup_response(good), Some(2));

        let not_dup = r#"{"is_duplicate": false, "match_index": -1, "confidence": 0.9, "reason": "different"}"#;
        assert_eq!(parse_dedup_response(not_dup), None);

        let garbage = "not json at all";
        assert_eq!(parse_dedup_response(garbage), None);
    }
}
