//! Noise Governor — adaptive rate limiting and request pacing.
//!
//! Aggressive scanning triggers WAFs, rate limits, and IP bans. The governor
//! observes responses and dynamically adjusts request pacing:
//!
//! 1. **Rate detection** — identifies rate limit headers and 429 responses
//! 2. **Adaptive backoff** — exponential backoff on throttle signals
//! 3. **Request budgeting** — per-host request quotas
//! 4. **Stealth pacing** — jitter and delay patterns that avoid detection
//! 5. **Response caching** — dedup identical requests across agents
//!
//! The governor sits between agents and the network. Every outbound request
//! passes through it; responses feed back to adjust pacing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The governor: tracks per-host state and throttling.
#[derive(Debug)]
pub struct NoiseGovernor {
    pub config: GovernorConfig,
    hosts: HashMap<String, HostState>,
    cache: HashMap<u64, CachedResponse>,
    global_stats: GlobalStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Base delay between requests to the same host (ms).
    pub base_delay_ms: u64,
    /// Maximum delay after backoff (ms).
    pub max_delay_ms: u64,
    /// Maximum requests per minute per host.
    pub max_rpm: u32,
    /// Jitter range (0.0 to 1.0) — randomization of delay.
    pub jitter: f64,
    /// Cache TTL for identical requests (seconds).
    pub cache_ttl_secs: u64,
    /// Enable stealth mode (longer delays, more jitter).
    pub stealth: bool,
    /// Global concurrent request limit.
    pub max_concurrent: u32,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 200,
            max_delay_ms: 30_000,
            max_rpm: 60,
            jitter: 0.3,
            cache_ttl_secs: 300,
            stealth: false,
            max_concurrent: 10,
        }
    }
}

impl GovernorConfig {
    pub fn stealth() -> Self {
        Self {
            base_delay_ms: 1000,
            max_delay_ms: 60_000,
            max_rpm: 20,
            jitter: 0.5,
            cache_ttl_secs: 600,
            stealth: true,
            max_concurrent: 3,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            base_delay_ms: 50,
            max_delay_ms: 10_000,
            max_rpm: 200,
            jitter: 0.1,
            cache_ttl_secs: 120,
            stealth: false,
            max_concurrent: 20,
        }
    }
}

#[derive(Debug)]
struct HostState {
    last_request: Instant,
    requests_this_minute: u32,
    minute_start: Instant,
    backoff_level: u32,
    consecutive_429s: u32,
    consecutive_503s: u32,
    rate_limit_remaining: Option<u32>,
    rate_limit_reset: Option<u64>,
    total_requests: u64,
    total_throttled: u64,
    blocked: bool,
    block_reason: String,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            last_request: Instant::now(),
            requests_this_minute: 0,
            minute_start: Instant::now(),
            backoff_level: 0,
            consecutive_429s: 0,
            consecutive_503s: 0,
            rate_limit_remaining: None,
            rate_limit_reset: None,
            total_requests: 0,
            total_throttled: 0,
            blocked: false,
            block_reason: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedResponse {
    body_hash: u64,
    status: u16,
    cached_at: Instant,
    hit_count: u32,
}

#[derive(Debug, Default)]
struct GlobalStats {
    total_requests: u64,
    total_cached: u64,
    total_throttled: u64,
    total_blocked: u64,
    active_requests: u32,
}

/// Decision the governor makes for a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestDecision {
    /// Proceed immediately.
    Allow,
    /// Wait this many milliseconds before proceeding.
    Delay(u64),
    /// Use cached response instead.
    UseCached { status: u16, body_hash: u64 },
    /// Request blocked — host is rate-limited or banned.
    Block { reason: String },
}

/// What happened when a response came back.
#[derive(Debug, Clone)]
pub struct ResponseSignal {
    pub host: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub elapsed_ms: u64,
    pub request_hash: u64,
    pub body_hash: u64,
}

impl NoiseGovernor {
    pub fn new(config: GovernorConfig) -> Self {
        Self {
            config,
            hosts: HashMap::new(),
            cache: HashMap::new(),
            global_stats: GlobalStats::default(),
        }
    }

    /// Ask the governor whether to proceed with a request.
    pub fn check(&mut self, host: &str, request_hash: u64) -> RequestDecision {
        // Check cache first
        if let Some(cached) = self.cache.get(&request_hash) {
            if cached.cached_at.elapsed() < Duration::from_secs(self.config.cache_ttl_secs) {
                self.global_stats.total_cached += 1;
                return RequestDecision::UseCached {
                    status: cached.status,
                    body_hash: cached.body_hash,
                };
            }
        }

        let state = self.hosts.entry(host.to_string()).or_default();

        // Host is blocked
        if state.blocked {
            self.global_stats.total_blocked += 1;
            return RequestDecision::Block {
                reason: state.block_reason.clone(),
            };
        }

        // Check concurrent limit
        if self.global_stats.active_requests >= self.config.max_concurrent {
            return RequestDecision::Delay(100);
        }

        // Reset per-minute counter
        if state.minute_start.elapsed() >= Duration::from_secs(60) {
            state.requests_this_minute = 0;
            state.minute_start = Instant::now();
        }

        // RPM limit
        if state.requests_this_minute >= self.config.max_rpm {
            let wait = 60_000u64.saturating_sub(state.minute_start.elapsed().as_millis() as u64);
            return RequestDecision::Delay(wait.max(1000));
        }

        // Rate limit header tracking
        if let Some(remaining) = state.rate_limit_remaining {
            if remaining == 0 {
                let reset = state.rate_limit_reset.unwrap_or(30);
                return RequestDecision::Delay(reset * 1000);
            }
        }

        // Backoff delay
        let base = if self.config.stealth { self.config.base_delay_ms * 2 } else { self.config.base_delay_ms };
        let backoff_delay = if state.backoff_level > 0 {
            (base * 2u64.pow(state.backoff_level.min(6))).min(self.config.max_delay_ms)
        } else {
            base
        };

        // Time since last request
        let since_last = state.last_request.elapsed().as_millis() as u64;
        if since_last < backoff_delay {
            let jitter = jitter_ms(self.config.jitter, backoff_delay);
            return RequestDecision::Delay(backoff_delay - since_last + jitter);
        }

        // Good to go
        state.last_request = Instant::now();
        state.requests_this_minute += 1;
        state.total_requests += 1;
        self.global_stats.total_requests += 1;
        self.global_stats.active_requests += 1;

        RequestDecision::Allow
    }

    /// Feed a response back to the governor.
    pub fn observe(&mut self, signal: ResponseSignal) {
        self.global_stats.active_requests = self.global_stats.active_requests.saturating_sub(1);

        let state = self.hosts.entry(signal.host.clone()).or_default();

        // Parse rate limit headers
        if let Some(remaining) = signal.headers.get("x-ratelimit-remaining")
            .or_else(|| signal.headers.get("ratelimit-remaining"))
            .or_else(|| signal.headers.get("x-rate-limit-remaining"))
        {
            state.rate_limit_remaining = remaining.parse().ok();
        }
        if let Some(reset) = signal.headers.get("x-ratelimit-reset")
            .or_else(|| signal.headers.get("ratelimit-reset"))
            .or_else(|| signal.headers.get("x-rate-limit-reset"))
        {
            state.rate_limit_reset = reset.parse().ok();
        }
        if let Some(retry_after) = signal.headers.get("retry-after") {
            if let Ok(secs) = retry_after.parse::<u64>() {
                state.rate_limit_reset = Some(secs);
            }
        }

        match signal.status {
            429 => {
                state.consecutive_429s += 1;
                state.backoff_level = (state.backoff_level + 1).min(8);
                state.total_throttled += 1;
                self.global_stats.total_throttled += 1;

                if state.consecutive_429s >= 10 {
                    state.blocked = true;
                    state.block_reason = "Too many 429 responses — host rate-limiting aggressively".into();
                }
            }
            503 => {
                state.consecutive_503s += 1;
                state.backoff_level = (state.backoff_level + 1).min(6);

                if state.consecutive_503s >= 5 {
                    state.blocked = true;
                    state.block_reason = "Service unavailable — backing off to avoid DoS".into();
                }
            }
            200..=399 => {
                state.consecutive_429s = 0;
                state.consecutive_503s = 0;
                if state.backoff_level > 0 { state.backoff_level -= 1; }
            }
            _ => {
                state.consecutive_429s = 0;
            }
        }

        // Cache the response
        self.cache.insert(signal.request_hash, CachedResponse {
            body_hash: signal.body_hash,
            status: signal.status,
            cached_at: Instant::now(),
            hit_count: 0,
        });
    }

    /// Reset backoff for a host (e.g. after a manual delay).
    pub fn reset_host(&mut self, host: &str) {
        if let Some(state) = self.hosts.get_mut(host) {
            state.backoff_level = 0;
            state.consecutive_429s = 0;
            state.consecutive_503s = 0;
            state.blocked = false;
            state.block_reason.clear();
        }
    }

    /// Generate a statistics summary.
    pub fn stats_summary(&self) -> GovernorStats {
        GovernorStats {
            total_requests: self.global_stats.total_requests,
            total_cached: self.global_stats.total_cached,
            total_throttled: self.global_stats.total_throttled,
            total_blocked: self.global_stats.total_blocked,
            active_requests: self.global_stats.active_requests,
            hosts_tracked: self.hosts.len(),
            hosts_blocked: self.hosts.values().filter(|h| h.blocked).count(),
            cache_entries: self.cache.len(),
        }
    }

    /// Generate a prompt block summarizing throttling state.
    pub fn prompt_block(&self) -> String {
        let stats = self.stats_summary();
        if stats.total_requests == 0 { return String::new(); }

        let mut s = format!("NOISE GOVERNOR: {} requests, {} cached, {} throttled",
            stats.total_requests, stats.total_cached, stats.total_throttled);

        let throttled_hosts: Vec<(&String, &HostState)> = self.hosts.iter()
            .filter(|(_, h)| h.backoff_level > 0 || h.blocked)
            .collect();

        if !throttled_hosts.is_empty() {
            s.push_str("\nThrottled hosts:\n");
            for (host, state) in &throttled_hosts {
                if state.blocked {
                    s.push_str(&format!("  {host}: BLOCKED — {}\n", state.block_reason));
                } else {
                    s.push_str(&format!("  {host}: backoff level {} ({} throttled)\n",
                        state.backoff_level, state.total_throttled));
                }
            }
            s.push_str("IMPORTANT: Adapt request patterns — use different endpoints, vary timing, try alternative encodings.\n");
        }

        s
    }

    /// Clean up expired cache entries.
    pub fn gc(&mut self) {
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        self.cache.retain(|_, v| v.cached_at.elapsed() < ttl);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorStats {
    pub total_requests: u64,
    pub total_cached: u64,
    pub total_throttled: u64,
    pub total_blocked: u64,
    pub active_requests: u32,
    pub hosts_tracked: usize,
    pub hosts_blocked: usize,
    pub cache_entries: usize,
}

fn jitter_ms(jitter_factor: f64, base: u64) -> u64 {
    if jitter_factor <= 0.0 { return 0; }
    let max_jitter = (base as f64 * jitter_factor) as u64;
    if max_jitter == 0 { return 0; }
    // Simple deterministic jitter based on current time nanos
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    nanos % max_jitter
}

/// Compute a stable hash for a request (method + url + body).
pub fn request_hash(method: &str, url: &str, body: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    method.hash(&mut hasher);
    url.hash(&mut hasher);
    body.hash(&mut hasher);
    hasher.finish()
}

/// Compute a hash for a response body.
pub fn body_hash(body: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governor_allow() {
        let mut gov = NoiseGovernor::new(GovernorConfig { base_delay_ms: 0, ..Default::default() });
        let decision = gov.check("example.com", 12345);
        assert!(matches!(decision, RequestDecision::Allow));
    }

    #[test]
    fn test_governor_backoff_on_429() {
        let mut gov = NoiseGovernor::new(GovernorConfig::default());
        gov.observe(ResponseSignal {
            host: "example.com".into(),
            status: 429,
            headers: HashMap::new(),
            elapsed_ms: 100,
            request_hash: 1,
            body_hash: 1,
        });
        let state = gov.hosts.get("example.com").unwrap();
        assert_eq!(state.backoff_level, 1);
        assert_eq!(state.consecutive_429s, 1);
    }

    #[test]
    fn test_governor_block_after_many_429s() {
        let mut gov = NoiseGovernor::new(GovernorConfig::default());
        for i in 0..10 {
            gov.observe(ResponseSignal {
                host: "example.com".into(),
                status: 429,
                headers: HashMap::new(),
                elapsed_ms: 100,
                request_hash: i,
                body_hash: i,
            });
        }
        let state = gov.hosts.get("example.com").unwrap();
        assert!(state.blocked);
    }

    #[test]
    fn test_governor_cache_hit() {
        let mut gov = NoiseGovernor::new(GovernorConfig { base_delay_ms: 0, ..Default::default() });
        gov.observe(ResponseSignal {
            host: "example.com".into(),
            status: 200,
            headers: HashMap::new(),
            elapsed_ms: 100,
            request_hash: 42,
            body_hash: 99,
        });
        let decision = gov.check("example.com", 42);
        assert!(matches!(decision, RequestDecision::UseCached { .. }));
    }

    #[test]
    fn test_request_hash_deterministic() {
        let h1 = request_hash("GET", "https://example.com/api", "");
        let h2 = request_hash("GET", "https://example.com/api", "");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_stealth_config() {
        let cfg = GovernorConfig::stealth();
        assert!(cfg.base_delay_ms >= 1000);
        assert!(cfg.max_rpm <= 20);
        assert!(cfg.stealth);
    }
}
