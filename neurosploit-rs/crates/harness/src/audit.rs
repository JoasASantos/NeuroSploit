//! Mandatory audit trail and hard kill conditions.
//!
//! An autonomous tool acting against someone else's systems has to be able to
//! answer, afterwards and in detail: *what did you do, to what, under whose
//! authority, and what happened?* Logs written for humans do not answer that —
//! they are prose, they are lossy, and they are trivially reordered. So every
//! action records one structured line:
//!
//! ```json
//! {"timestamp":"…","agent":"yaga","hypothesis":"H-023","action":"…",
//!  "target":"…","policy_decision":"…","operator":null,"tool":"…",
//!  "result":"…","evidence_hash":"…","capability_token":"…"}
//! ```
//!
//! Two design decisions make it worth having:
//!
//! - **It is hash-chained.** Each record carries the hash of the one before it,
//!   so a record cannot be removed or altered after the fact without breaking
//!   every hash that follows. An append-only file that anyone can edit proves
//!   nothing; [`AuditLog::verify`] is what turns it into evidence.
//! - **It records refusals too.** A trail containing only what happened cannot
//!   show restraint. "The policy denied this, and the agent stopped" is exactly
//!   what an operator needs to demonstrate afterwards.
//!
//! ## Hard kill conditions
//!
//! [`KillSwitch`] aborts the whole run, immediately and without negotiation,
//! when something happens that no amount of clever reasoning should be allowed
//! to continue through: the target stopped answering after our traffic, an
//! out-of-scope host was contacted, a forbidden industrial function code was
//! attempted, the capability token expired mid-run. These are *conditions*, not
//! heuristics — each one either happened or it did not, and each one ends the
//! engagement with an audit record explaining why.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One recorded action. The field set is fixed on purpose: an audit format that
/// varies per call site cannot be queried, and a record that omits the decision
/// or the authority does not answer the question the trail exists for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    /// RFC3339 UTC.
    pub timestamp: String,
    /// Which agent acted.
    pub agent: String,
    /// The hypothesis this action was testing ("H-023"), so a trail can be read
    /// as reasoning rather than as a list of requests.
    pub hypothesis: String,
    pub action: String,
    pub target: String,
    /// `allow` · `confirm: …` · `deny: …` — the policy's verdict, verbatim.
    pub policy_decision: String,
    /// Who approved, when approval was required. `None` means unattended, which
    /// is a materially different claim from "someone approved it".
    pub operator: Option<String>,
    pub tool: String,
    pub result: String,
    /// SHA-256 of the evidence this action produced. The evidence itself lives
    /// with the run; the hash is what proves the two belong together.
    pub evidence_hash: String,
    /// Id of the grant that authorized it (never the token itself — the trail
    /// is shared, and a token in it would be a credential leak).
    pub capability_token: String,
    /// Position in the chain, from 1.
    #[serde(default)]
    pub seq: u64,
    /// Hash of the previous record; empty for the first.
    #[serde(default)]
    pub prev_hash: String,
    /// Hash of this record's content plus `prev_hash`.
    #[serde(default)]
    pub hash: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn rfc3339_utc() -> String {
    // The chain needs an ordered, unambiguous stamp and nothing more; pulling a
    // date library in for that would be a dependency for cosmetics.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", tod / 3600, (tod % 3600) / 60, tod % 60)
}

/// Howard Hinnant's days-from-civil, inverted. Exact for the whole proleptic
/// Gregorian range, which is more than a run log needs but costs nothing.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl AuditRecord {
    /// A record with the fixed fields filled and the chain fields empty —
    /// [`AuditLog::append`] seals it.
    pub fn new(agent: &str, action: &str, target: &str) -> AuditRecord {
        AuditRecord {
            timestamp: rfc3339_utc(),
            agent: agent.to_string(),
            hypothesis: String::new(),
            action: action.to_string(),
            target: target.to_string(),
            policy_decision: String::new(),
            operator: None,
            tool: String::new(),
            result: String::new(),
            evidence_hash: String::new(),
            capability_token: String::new(),
            seq: 0,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }
    pub fn hypothesis(mut self, h: &str) -> Self {
        self.hypothesis = h.to_string();
        self
    }
    pub fn decision(mut self, d: &str) -> Self {
        self.policy_decision = d.to_string();
        self
    }
    pub fn operator(mut self, who: Option<&str>) -> Self {
        self.operator = who.map(|s| s.to_string());
        self
    }
    pub fn tool(mut self, t: &str) -> Self {
        self.tool = t.to_string();
        self
    }
    pub fn result(mut self, r: &str) -> Self {
        self.result = r.to_string();
        self
    }
    pub fn evidence(mut self, bytes: &[u8]) -> Self {
        self.evidence_hash = sha256_hex(bytes);
        self
    }
    pub fn capability(mut self, id: &str) -> Self {
        self.capability_token = id.to_string();
        self
    }

    /// The bytes the chain hash covers: every meaningful field plus the
    /// previous hash. `hash` itself is excluded, or it would be hashing itself.
    fn digest_input(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.seq,
            self.prev_hash,
            self.timestamp,
            self.agent,
            self.hypothesis,
            self.action,
            self.target,
            self.policy_decision,
            self.operator.clone().unwrap_or_else(|| "null".into()),
            self.tool,
            self.result,
            self.evidence_hash,
            self.capability_token
        )
    }
}

/// Append-only, hash-chained trail on disk (JSON Lines).
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<(u64, String)>, // (last seq, last hash)
}

impl AuditLog {
    /// Open (or create) the trail, resuming the chain from what is already on
    /// disk so a restarted run continues the same chain instead of forking it.
    pub fn open(path: impl AsRef<Path>) -> AuditLog {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut last = (0u64, String::new());
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(r) = serde_json::from_str::<AuditRecord>(line) {
                    last = (r.seq, r.hash);
                }
            }
        }
        AuditLog { path, state: Mutex::new(last) }
    }

    /// Seal a record into the chain and write it.
    pub fn append(&self, mut rec: AuditRecord) -> AuditRecord {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        rec.seq = guard.0 + 1;
        rec.prev_hash = guard.1.clone();
        rec.hash = sha256_hex(rec.digest_input().as_bytes());
        if let Ok(line) = serde_json::to_string(&rec) {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
                let _ = writeln!(f, "{line}");
            }
        }
        *guard = (rec.seq, rec.hash.clone());
        rec
    }

    pub fn read_all(&self) -> Vec<AuditRecord> {
        std::fs::read_to_string(&self.path)
            .map(|t| t.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
            .unwrap_or_default()
    }

    /// Re-derive every hash. Returns the first sequence number that does not
    /// match — a record that was altered or removed after it was written.
    pub fn verify(&self) -> Result<usize, String> {
        let records = self.read_all();
        let mut prev = String::new();
        for (i, r) in records.iter().enumerate() {
            let expect_seq = i as u64 + 1;
            if r.seq != expect_seq {
                return Err(format!("record {} is out of sequence (claims #{}) — an entry was removed or reordered", i + 1, r.seq));
            }
            if r.prev_hash != prev {
                return Err(format!("record #{} does not follow the previous one — the chain was broken", r.seq));
            }
            if r.hash != sha256_hex(r.digest_input().as_bytes()) {
                return Err(format!("record #{} was altered after it was written", r.seq));
            }
            prev = r.hash.clone();
        }
        Ok(records.len())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sign the current chain head and record an anchor.
    ///
    /// This is P4: a hash chain proves a record was not altered *relative to its
    /// neighbours*, but says nothing against someone who rebuilds the whole file
    /// consistently, or truncates its tail. An anchor is a signed statement —
    /// "at phase X the chain had N records ending in hash H" — written to a
    /// separate file and, when `NEUROSPLOIT_ANCHOR_DIR` is set, to external
    /// (ideally WORM/Object-Lock) storage. A later truncation or silent rebuild
    /// then contradicts an anchor the attacker cannot forge without the key.
    pub fn checkpoint(&self, key: &[u8], phase: &str) -> Anchor {
        let records = self.read_all();
        let count = records.len() as u64;
        let head = records.last().map(|r| r.hash.clone()).unwrap_or_default();
        let ts = now();
        let body = format!("{count}|{head}|{phase}|{ts}");
        let anchor = Anchor {
            phase: phase.to_string(),
            count,
            chain_hash: head,
            at: ts,
            signature: hmac_hex(key, body.as_bytes()),
        };
        if let Ok(line) = serde_json::to_string(&anchor) {
            use std::io::Write;
            let ap = self.anchors_path();
            if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(&ap) {
                let _ = writeln!(fh, "{line}");
            }
            // External copy: append-only, so a local tamper cannot also rewrite
            // the off-box record. WORM/Object-Lock is the operator's to enforce
            // on that directory; we just write there.
            if let Ok(dir) = std::env::var("NEUROSPLOIT_ANCHOR_DIR") {
                if !dir.trim().is_empty() {
                    let _ = std::fs::create_dir_all(&dir);
                    let name = self.path.file_stem().and_then(|s| s.to_str()).unwrap_or("audit");
                    if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(std::path::Path::new(&dir).join(format!("{name}.anchors.jsonl"))) {
                        let _ = writeln!(fh, "{line}");
                    }
                }
            }
        }
        anchor
    }

    fn anchors_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("audit.jsonl").to_string();
        p.set_file_name(format!("{name}.anchors"));
        p
    }

    /// Read the anchors recorded for this trail (local file).
    pub fn anchors(&self) -> Vec<Anchor> {
        std::fs::read_to_string(self.anchors_path())
            .map(|t| t.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
            .unwrap_or_default()
    }

    /// Verify the chain AND every anchor against it.
    ///
    /// Catches the two attacks a bare chain misses: **truncation** (the chain is
    /// now shorter than an anchor's `count`, so the tail was removed) and a
    /// **silent rebuild** (an anchor's `chain_hash` no longer matches the record
    /// at that position). With `key`, anchor signatures are verified too, so a
    /// forged anchor is caught as well.
    pub fn verify_anchored(&self, key: Option<&[u8]>) -> Result<AnchorReport, String> {
        let n = self.verify()?; // chain integrity first
        let records = self.read_all();
        let anchors = self.anchors();
        let mut checked = 0usize;
        for a in &anchors {
            if let Some(k) = key {
                let body = format!("{}|{}|{}|{}", a.count, a.chain_hash, a.phase, a.at);
                if !constant_time_eq(hmac_hex(k, body.as_bytes()).as_bytes(), a.signature.as_bytes()) {
                    return Err(format!("anchor for phase '{}' (#{} records) has an invalid signature", a.phase, a.count));
                }
            }
            if (records.len() as u64) < a.count {
                return Err(format!(
                    "TRUNCATION: an anchor attests {} record(s) but the chain now has {} — the tail was removed",
                    a.count, records.len()
                ));
            }
            let at_pos = records.get(a.count.saturating_sub(1) as usize).map(|r| r.hash.clone()).unwrap_or_default();
            if a.count > 0 && at_pos != a.chain_hash {
                return Err(format!(
                    "REBUILD: the chain hash at record #{} does not match its anchor — the log was rewritten",
                    a.count
                ));
            }
            checked += 1;
        }
        Ok(AnchorReport { records: n, anchors: checked, signed: key.is_some() })
    }
}

/// A signed statement about the chain at a moment in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    /// Which phase produced it (a checkpoint per phase, plus one at the end).
    pub phase: String,
    /// How many records the chain had.
    pub count: u64,
    /// The hash of the last record — the chain head.
    pub chain_hash: String,
    /// Unix seconds.
    pub at: u64,
    /// HMAC over `count|chain_hash|phase|at`.
    pub signature: String,
}

/// The result of an anchored verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReport {
    pub records: usize,
    pub anchors: usize,
    pub signed: bool,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Why a run was killed. Each variant is a condition that either occurred or
/// did not — none of them is a judgement call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "condition", content = "detail")]
pub enum KillReason {
    /// The target stopped answering after we started sending traffic.
    TargetUnresponsive(String),
    /// Error responses crossed the threshold — we are breaking it, not testing it.
    ErrorRateExceeded(String),
    /// A request left the authorized scope.
    OutOfScope(String),
    /// An industrial function code on the forbidden list was attempted.
    ForbiddenFunctionCode(u16),
    /// A safety instrumented system was addressed.
    SafetySystemTouched(String),
    /// The grant expired or was revoked while the run was in flight.
    CapabilityInvalid(String),
    /// The agent kept attempting things the policy refuses.
    RepeatedPolicyViolations(usize),
    /// Wall-clock or budget ceiling.
    BudgetExhausted(String),
    /// A human stopped it.
    OperatorStop(String),
}

impl KillReason {
    pub fn explain(&self) -> String {
        match self {
            KillReason::TargetUnresponsive(d) => format!("target stopped responding after our traffic ({d}) — continuing risks an outage we caused"),
            KillReason::ErrorRateExceeded(d) => format!("error rate above the threshold ({d}) — the target is failing, not revealing"),
            KillReason::OutOfScope(h) => format!("a request was directed at {h}, outside the authorized scope"),
            KillReason::ForbiddenFunctionCode(c) => format!("industrial function code {c} is on the forbidden list — it can stop a process"),
            KillReason::SafetySystemTouched(h) => format!("a safety instrumented system was addressed ({h})"),
            KillReason::CapabilityInvalid(d) => format!("the capability token is no longer valid ({d}) — authorization ended mid-run"),
            KillReason::RepeatedPolicyViolations(n) => format!("{n} refused actions were attempted — the run is not respecting its policy"),
            KillReason::BudgetExhausted(d) => format!("budget exhausted ({d})"),
            KillReason::OperatorStop(w) => format!("stopped by {w}"),
        }
    }
}

/// Conditions that end a run outright.
#[derive(Debug)]
pub struct KillSwitch {
    /// Consecutive transport failures tolerated after the target has answered
    /// at least once.
    pub max_consecutive_failures: usize,
    /// Fraction of 5xx responses that counts as breaking the target.
    pub max_error_rate: f64,
    /// Minimum responses before the error rate means anything — 2 failures out
    /// of 2 requests is noise, not a trend.
    pub error_rate_floor: usize,
    /// Refused actions tolerated before the run is stopped.
    pub max_policy_violations: usize,
    state: Mutex<KillState>,
}

#[derive(Debug, Default)]
struct KillState {
    responded_once: bool,
    consecutive_failures: usize,
    responses: usize,
    errors: usize,
    violations: usize,
    killed: Option<KillReason>,
}

impl Default for KillSwitch {
    fn default() -> Self {
        KillSwitch {
            max_consecutive_failures: 5,
            max_error_rate: 0.6,
            error_rate_floor: 10,
            max_policy_violations: 5,
            state: Mutex::new(KillState::default()),
        }
    }
}

impl KillSwitch {
    /// OT runs are stopped far sooner: a device that misses a few requests may
    /// already be struggling, and "let's see if it recovers" is not a decision
    /// anyone should make on a live process.
    pub fn ot() -> KillSwitch {
        KillSwitch {
            max_consecutive_failures: 2,
            max_error_rate: 0.3,
            error_rate_floor: 5,
            max_policy_violations: 1,
            state: Mutex::new(KillState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, KillState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Record a response. Returns a kill reason the moment one is tripped.
    pub fn note_response(&self, status: u16) -> Option<KillReason> {
        let mut s = self.lock();
        s.responded_once = true;
        s.consecutive_failures = 0;
        s.responses += 1;
        if status >= 500 {
            s.errors += 1;
        }
        if s.responses >= self.error_rate_floor {
            let rate = s.errors as f64 / s.responses as f64;
            if rate > self.max_error_rate {
                let r = KillReason::ErrorRateExceeded(format!("{:.0}% of {} responses were 5xx", rate * 100.0, s.responses));
                s.killed = Some(r.clone());
                return Some(r);
            }
        }
        None
    }

    /// Record a transport failure (connection refused, timeout).
    pub fn note_failure(&self, what: &str) -> Option<KillReason> {
        let mut s = self.lock();
        s.consecutive_failures += 1;
        // Before the target ever answered, failures mean "wrong address" or
        // "nothing listening" — not "we knocked it over".
        if s.responded_once && s.consecutive_failures >= self.max_consecutive_failures {
            let r = KillReason::TargetUnresponsive(format!("{} consecutive failures ({what})", s.consecutive_failures));
            s.killed = Some(r.clone());
            return Some(r);
        }
        None
    }

    /// Record an action the policy refused.
    pub fn note_violation(&self, _what: &str) -> Option<KillReason> {
        let mut s = self.lock();
        s.violations += 1;
        if s.violations >= self.max_policy_violations {
            let r = KillReason::RepeatedPolicyViolations(s.violations);
            s.killed = Some(r.clone());
            return Some(r);
        }
        None
    }

    /// Conditions with no threshold: one occurrence ends the run.
    pub fn trip(&self, reason: KillReason) -> KillReason {
        let mut s = self.lock();
        s.killed = Some(reason.clone());
        reason
    }

    pub fn killed(&self) -> Option<KillReason> {
        self.lock().killed.clone()
    }

    pub fn is_killed(&self) -> bool {
        self.lock().killed.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ns-audit-{}-{}.jsonl", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_record_carries_every_field_the_format_promises() {
        let log = AuditLog::open(tmp("fields"));
        let rec = log.append(
            AuditRecord::new("yaga", "GET /admin", "https://app.test/admin")
                .hypothesis("H-023")
                .decision("allow")
                .operator(None)
                .tool("replay")
                .result("200, 4kb")
                .evidence(b"raw response bytes")
                .capability("cap-001"),
        );
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        for k in ["timestamp", "agent", "hypothesis", "action", "target", "policy_decision", "operator", "tool", "result", "evidence_hash", "capability_token"] {
            assert!(json.get(k).is_some(), "{k} missing from the record");
        }
        assert!(json["operator"].is_null(), "unattended must be null, not an empty string");
        assert_eq!(rec.evidence_hash, sha256_hex(b"raw response bytes"));
        let _ = std::fs::remove_file(log.path());
    }

    #[test]
    fn the_chain_verifies_and_notices_tampering() {
        let path = tmp("chain");
        let log = AuditLog::open(&path);
        for i in 0..5 {
            log.append(AuditRecord::new("yaga", &format!("action {i}"), "https://app.test/").decision("allow"));
        }
        assert_eq!(log.verify(), Ok(5));

        // Rewrite one line the way someone hiding an action would.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let mut rec: AuditRecord = serde_json::from_str(&lines[2]).unwrap();
        rec.target = "https://somewhere-else.test/".into();
        lines[2] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let reopened = AuditLog::open(&path);
        match reopened.verify() {
            Err(e) => assert!(e.contains("altered"), "{e}"),
            Ok(_) => panic!("an edited record must break the chain"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn removing_a_record_breaks_the_chain_too() {
        let path = tmp("removed");
        let log = AuditLog::open(&path);
        for i in 0..4 {
            log.append(AuditRecord::new("yaga", &format!("a{i}"), "t"));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| l).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        assert!(AuditLog::open(&path).verify().is_err(), "a deleted entry must not go unnoticed");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopening_continues_the_same_chain() {
        let path = tmp("resume");
        {
            let log = AuditLog::open(&path);
            log.append(AuditRecord::new("a", "one", "t"));
            log.append(AuditRecord::new("a", "two", "t"));
        }
        let log = AuditLog::open(&path);
        let third = log.append(AuditRecord::new("a", "three", "t"));
        assert_eq!(third.seq, 3, "a restart must not fork the chain");
        assert_eq!(log.verify(), Ok(3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refusals_are_recorded_not_just_actions() {
        let log = AuditLog::open(tmp("deny"));
        let rec = log.append(AuditRecord::new("yaga", "DELETE /orders/1", "https://app.test/orders/1").decision("deny: destructive actions are disabled"));
        assert!(rec.policy_decision.starts_with("deny"), "a trail that omits refusals cannot show restraint");
        let _ = std::fs::remove_file(log.path());
    }

    #[test]
    fn failures_before_the_first_response_are_not_an_outage_we_caused() {
        let k = KillSwitch::default();
        for _ in 0..10 {
            assert!(k.note_failure("connection refused").is_none(), "nothing listening is not the same as knocked over");
        }
        assert!(!k.is_killed());
    }

    #[test]
    fn losing_a_target_after_it_answered_kills_the_run() {
        let k = KillSwitch::default();
        assert!(k.note_response(200).is_none());
        let mut tripped = None;
        for _ in 0..k.max_consecutive_failures {
            tripped = k.note_failure("timeout");
        }
        match tripped {
            Some(KillReason::TargetUnresponsive(_)) => {}
            other => panic!("expected a kill, got {other:?}"),
        }
        assert!(k.is_killed());
    }

    #[test]
    fn a_few_errors_are_not_a_trend() {
        let k = KillSwitch::default();
        assert!(k.note_response(500).is_none());
        assert!(k.note_response(500).is_none(), "2 of 2 is noise, not a trend");
        for _ in 0..8 {
            k.note_response(500);
        }
        assert!(k.is_killed(), "a sustained 5xx rate means we are breaking it");
    }

    #[test]
    fn ot_stops_far_sooner_than_a_web_run() {
        let k = KillSwitch::ot();
        k.note_response(200);
        assert!(k.note_failure("timeout").is_none());
        assert!(k.note_failure("timeout").is_some(), "a PLC missing two requests already warrants stopping");
    }

    #[test]
    fn conditions_without_a_threshold_trip_on_the_first_occurrence() {
        let k = KillSwitch::default();
        let r = k.trip(KillReason::SafetySystemTouched("sis-01".into()));
        assert!(r.explain().contains("safety instrumented"));
        assert!(k.is_killed());
    }

    #[test]
    fn the_timestamp_is_a_sane_rfc3339_date() {
        let ts = rfc3339_utc();
        assert!(ts.ends_with('Z') && ts.len() == 20, "{ts}");
        let year: i64 = ts[..4].parse().unwrap();
        assert!((2020..2100).contains(&year), "{ts}");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn anchoring_detects_truncation_and_rebuild() {
        let dir = std::env::temp_dir().join(format!("ns-audit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(dir.join("audit.jsonl.anchors"));
        let key = b"anchor-key";

        let log = AuditLog::open(&path);
        for i in 0..5 {
            log.append(AuditRecord::new("a", "act", &format!("t{i}")));
        }
        let a = log.checkpoint(key, "phase-1");
        assert_eq!(a.count, 5);

        // Clean state verifies, signature checked.
        let rep = log.verify_anchored(Some(key)).expect("clean");
        assert_eq!(rep.records, 5);
        assert_eq!(rep.anchors, 1);
        assert!(rep.signed);

        // Truncate the tail: remove the last two records from the file.
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(3).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        let reopened = AuditLog::open(&path);
        let err = reopened.verify_anchored(Some(key)).unwrap_err();
        assert!(err.contains("TRUNCATION"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_forged_anchor_is_caught_by_the_signature() {
        let dir = std::env::temp_dir().join(format!("ns-audit-forge-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(dir.join("audit.jsonl.anchors"));
        let log = AuditLog::open(&path);
        log.append(AuditRecord::new("a", "act", "t"));
        log.checkpoint(b"real-key", "p");
        // Verifying under a different key rejects the anchor.
        let err = log.verify_anchored(Some(b"wrong-key")).unwrap_err();
        assert!(err.contains("invalid signature"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

}
