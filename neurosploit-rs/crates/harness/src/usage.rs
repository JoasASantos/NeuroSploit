//! Per-agent token ledger.
//!
//! `ModelPool::tokens_used` approximates spend as `response_chars / 4`, which
//! counts output only and cannot say whether a prompt change saved anything.
//! This ledger records what the provider actually reported — input, output and
//! cache-hit tokens — keyed by agent label, so a run can show where its tokens
//! went and a prompt-layout change can be measured instead of assumed.
//!
//! It is observational only: nothing here feeds the budget gates, so enabling
//! or ignoring it cannot change which agents run.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Usage {
    pub calls: u64,
    pub input: u64,
    pub output: u64,
    /// Input tokens served from the provider's prompt cache.
    pub cached: u64,
}

fn ledger() -> &'static Mutex<BTreeMap<String, Usage>> {
    static L: OnceLock<Mutex<BTreeMap<String, Usage>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Add one call's usage under `label` (empty label → `"(unlabelled)"`).
pub fn record(label: &str, input: u64, output: u64, cached: u64) {
    let key = if label.is_empty() { "(unlabelled)" } else { label };
    if let Ok(mut l) = ledger().lock() {
        let e = l.entry(key.to_string()).or_default();
        e.calls += 1;
        e.input += input;
        e.output += output;
        e.cached += cached;
    }
}

/// Pull `(input, output, cached)` out of an OpenAI-compatible `usage` object.
/// Handles the field spellings seen across providers: `prompt_tokens` /
/// `input_tokens`, `completion_tokens` / `output_tokens`, and the cache-hit
/// counters (`prompt_tokens_details.cached_tokens`, `prompt_cache_hit_tokens`,
/// `cache_read_input_tokens`).
pub fn parse(usage: &Value) -> Option<(u64, u64, u64)> {
    let num = |p: &str| usage.pointer(p).and_then(|x| x.as_u64());
    let input = num("/prompt_tokens").or_else(|| num("/input_tokens"));
    let output = num("/completion_tokens").or_else(|| num("/output_tokens"));
    if input.is_none() && output.is_none() {
        return None;
    }
    let cached = num("/prompt_tokens_details/cached_tokens")
        .or_else(|| num("/prompt_cache_hit_tokens"))
        .or_else(|| num("/cache_read_input_tokens"))
        .unwrap_or(0);
    Some((input.unwrap_or(0), output.unwrap_or(0), cached))
}

pub fn snapshot() -> Vec<(String, Usage)> {
    ledger().lock().map(|l| l.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
}

pub fn total() -> Usage {
    snapshot().into_iter().fold(Usage::default(), |mut a, (_, u)| {
        a.calls += u.calls;
        a.input += u.input;
        a.output += u.output;
        a.cached += u.cached;
        a
    })
}

/// Human summary: totals, cache-hit share, and the five heaviest agents.
/// Empty when nothing was recorded (e.g. a provider that reports no usage).
pub fn report() -> String {
    let t = total();
    if t.calls == 0 {
        return String::new();
    }
    let hit = if t.input > 0 { t.cached as f64 * 100.0 / t.input as f64 } else { 0.0 };
    let mut rows = snapshot();
    rows.sort_by(|a, b| (b.1.input + b.1.output).cmp(&(a.1.input + a.1.output)));
    let mut s = format!(
        "token usage: {} call(s) · in {} · out {} · cached {} ({:.0}% of input)",
        t.calls, t.input, t.output, t.cached, hit
    );
    for (k, u) in rows.iter().take(5) {
        s.push_str(&format!("\n  {k}: in {} out {} cached {} ({} call(s))", u.input, u.output, u.cached, u.calls));
    }
    s
}

/// Write `usage.json` into `dir`. Best effort — never fails the run.
pub fn write_json(dir: &Path) {
    let rows = snapshot();
    if rows.is_empty() {
        return;
    }
    let doc = serde_json::json!({ "total": total(), "agents": rows.into_iter().collect::<BTreeMap<_, _>>() });
    if let Ok(s) = serde_json::to_string_pretty(&doc) {
        let _ = std::fs::write(dir.join("usage.json"), s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openai_and_deepseek_and_anthropic_spellings() {
        let oa = serde_json::json!({"prompt_tokens": 1200, "completion_tokens": 80,
            "prompt_tokens_details": {"cached_tokens": 1024}});
        assert_eq!(parse(&oa), Some((1200, 80, 1024)));
        let ds = serde_json::json!({"prompt_tokens": 900, "completion_tokens": 10, "prompt_cache_hit_tokens": 512});
        assert_eq!(parse(&ds), Some((900, 10, 512)));
        let an = serde_json::json!({"input_tokens": 50, "output_tokens": 7, "cache_read_input_tokens": 30});
        assert_eq!(parse(&an), Some((50, 7, 30)));
    }

    #[test]
    fn missing_usage_is_none_not_zero() {
        assert_eq!(parse(&serde_json::json!({})), None);
    }

    #[test]
    fn ledger_accumulates_per_label() {
        record("usage_test_agent", 100, 10, 40);
        record("usage_test_agent", 50, 5, 0);
        let u = snapshot().into_iter().find(|(k, _)| k == "usage_test_agent").unwrap().1;
        assert_eq!(u, Usage { calls: 2, input: 150, output: 15, cached: 40 });
        assert!(report().contains("usage_test_agent"));
    }
}
