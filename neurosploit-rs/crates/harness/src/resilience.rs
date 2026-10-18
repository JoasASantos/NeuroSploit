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
        Err(e) => {
            None
        }
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
        // 100k tokens * 4 chars = 400k chars before compaction triggers.
        assert!(COMPACT_THRESHOLD_TOKENS > KEEP_RECENT_TOKENS);
    }
}
