//! Risk model and engagement policies.
//!
//! [`crate::scope`] answers *may we touch this address*. That is necessary and
//! nowhere near sufficient: an in-scope action can still be the wrong action.
//! Reading a web page and writing a holding register on a PLC are both "in
//! scope" against an authorized host, and only one of them can stop a physical
//! process.
//!
//! So risk is computed per action, from factors the operator declares:
//!
//! ```text
//! effective_risk = (action_risk
//!                 + asset_criticality
//!                 + protocol_risk
//!                 + privilege_level
//!                 + blast_radius) × environment_multiplier
//! ```
//!
//! Each of the five terms is 0.0–1.0, so the sum is 0–5, and the multiplier
//! places that sum in its context: the same write is a different act on a lab
//! bench and on a live substation. The result is a number the [`SafetyPolicy`]
//! can refuse, and — more usefully — a number the operator can *read*, because
//! every term is named and comes from a declaration rather than a model's
//! judgement.
//!
//! Three policies sit on top, each answering a different question:
//!
//! - [`SafetyPolicy`] — *what may be done to the target?* Ceilings, approval
//!   thresholds, and the hard prohibitions that make OT/ICS testing survivable.
//! - [`ReasoningPolicy`] — *how must the agent think?* Baseline before payload,
//!   a bounded number of hypotheses, evidence before escalation, and explicit
//!   stop conditions so a run ends on purpose rather than on exhaustion.
//! - [`ProofOfImpactPolicy`] — *what may be claimed?* The evidence a severity
//!   has to carry before it is allowed to be that severity.
//!
//! ## Why OT/ICS is not "web testing with different ports"
//!
//! Industrial protocols were designed without authentication, on the assumption
//! of a physically isolated network. A Modbus write function is not an exploit
//! — it is the protocol working as intended, addressed to a device that may be
//! holding a valve. Scanners routinely crash PLCs simply by sending unexpected
//! data at line rate. So [`SafetyProfile::ot_conservative`] blocks writes and
//! fuzzing outright, caps the request rate to something the device tolerates,
//! and refuses the function codes that stop a CPU — and those refusals are not
//! advisory text in a prompt, they are checks.

use serde::{Deserialize, Serialize};

fn clamp01(v: f64) -> f64 {
    v.clamp(0.0, 1.0)
}

/// What the action itself does, independent of where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    /// Read something already exposed.
    Read,
    /// Enumerate, fingerprint, map.
    Enumerate,
    /// Send a payload intended to prove a weakness, without changing state.
    ProbeExploit,
    /// Authenticate, create a session, use a credential.
    Authenticate,
    /// Write, update, or create application state.
    Write,
    /// Delete state, restart a service, change a device's operating mode.
    Disruptive,
}

impl ActionKind {
    pub fn risk(self) -> f64 {
        match self {
            ActionKind::Read => 0.05,
            ActionKind::Enumerate => 0.15,
            ActionKind::ProbeExploit => 0.45,
            ActionKind::Authenticate => 0.35,
            ActionKind::Write => 0.8,
            ActionKind::Disruptive => 1.0,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Read => "read",
            ActionKind::Enumerate => "enumerate",
            ActionKind::ProbeExploit => "probe-exploit",
            ActionKind::Authenticate => "authenticate",
            ActionKind::Write => "write",
            ActionKind::Disruptive => "disruptive",
        }
    }
}

/// The protocol carrying the action. Industrial protocols rank high not because
/// they are hard to speak but because they are trivial to speak — they have no
/// authentication and the devices behind them are fragile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Http,
    Https,
    Dns,
    Smb,
    Ssh,
    Rdp,
    Database,
    /// Modbus, DNP3, S7comm, EtherNet/IP, BACnet, OPC-UA…
    Industrial,
    /// Safety instrumented systems — the layer that exists to stop the process
    /// safely. Touching it is never routine.
    SafetySystem,
    Other,
}

impl Protocol {
    pub fn risk(self) -> f64 {
        match self {
            Protocol::Https => 0.1,
            Protocol::Http => 0.15,
            Protocol::Dns => 0.15,
            Protocol::Database => 0.5,
            Protocol::Smb => 0.45,
            Protocol::Ssh => 0.4,
            Protocol::Rdp => 0.45,
            Protocol::Industrial => 0.9,
            Protocol::SafetySystem => 1.0,
            Protocol::Other => 0.3,
        }
    }
    pub fn is_ot(self) -> bool {
        matches!(self, Protocol::Industrial | Protocol::SafetySystem)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Dns => "dns",
            Protocol::Smb => "smb",
            Protocol::Ssh => "ssh",
            Protocol::Rdp => "rdp",
            Protocol::Database => "database",
            Protocol::Industrial => "industrial",
            Protocol::SafetySystem => "safety-system",
            Protocol::Other => "other",
        }
    }
    /// Best-effort classification from a port, used when the operator did not
    /// declare one. Industrial ports are recognised so an unlabelled 502/20000
    /// does not get treated as an ordinary service.
    pub fn from_port(port: u16) -> Protocol {
        match port {
            80 | 8080 | 8000 => Protocol::Http,
            443 | 8443 => Protocol::Https,
            53 => Protocol::Dns,
            22 => Protocol::Ssh,
            3389 => Protocol::Rdp,
            139 | 445 => Protocol::Smb,
            1433 | 3306 | 5432 | 1521 | 27017 => Protocol::Database,
            // Modbus, DNP3, EtherNet/IP, S7comm(-plus), BACnet, OPC-UA, FL-net.
            502 | 802 | 20000 | 44818 | 2222 | 102 | 47808 | 4840 | 55000 => Protocol::Industrial,
            _ => Protocol::Other,
        }
    }
}

/// How far the consequences reach if the action goes wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlastRadius {
    /// One request, one object, trivially reversible.
    SingleObject,
    /// One account or one session.
    SingleAccount,
    /// One host or service instance.
    SingleHost,
    /// A shared service many consumers depend on.
    SharedService,
    /// A network segment, a cell, a production line.
    Segment,
    /// A physical process, or an organisation-wide system.
    PhysicalProcess,
}

impl BlastRadius {
    pub fn risk(self) -> f64 {
        match self {
            BlastRadius::SingleObject => 0.05,
            BlastRadius::SingleAccount => 0.2,
            BlastRadius::SingleHost => 0.4,
            BlastRadius::SharedService => 0.65,
            BlastRadius::Segment => 0.85,
            BlastRadius::PhysicalProcess => 1.0,
        }
    }
}

/// Where this is running. The multiplier is the honest place for "same action,
/// different consequence" — it scales the whole sum rather than hiding inside
/// one term.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Lab,
    Development,
    Staging,
    Production,
    /// Production that runs a physical process.
    OtProduction,
}

impl Environment {
    pub fn multiplier(self) -> f64 {
        match self {
            Environment::Lab => 0.3,
            Environment::Development => 0.5,
            Environment::Staging => 0.7,
            Environment::Production => 1.0,
            Environment::OtProduction => 1.6,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Lab => "lab",
            Environment::Development => "development",
            Environment::Staging => "staging",
            Environment::Production => "production",
            Environment::OtProduction => "ot-production",
        }
    }
    pub fn parse(s: &str) -> Option<Environment> {
        Some(match s.trim().to_lowercase().as_str() {
            "lab" => Environment::Lab,
            "dev" | "development" => Environment::Development,
            "stg" | "staging" => Environment::Staging,
            "prod" | "production" => Environment::Production,
            "ot" | "ot-prod" | "ot-production" | "ics" | "scada" => Environment::OtProduction,
            _ => return None,
        })
    }
}

/// One action, described in the terms the risk formula needs.
#[derive(Debug, Clone)]
pub struct Act {
    pub what: ActionKind,
    pub protocol: Protocol,
    pub blast: BlastRadius,
    /// How privileged the identity performing it is, 0 (anonymous) to 1 (domain
    /// admin / engineering workstation).
    pub privilege: f64,
    /// Declared importance of the asset, 0 (scratch) to 1 (crown jewels).
    pub asset_criticality: f64,
    /// Human-readable target, for the audit line.
    pub target: String,
}

impl Default for Act {
    fn default() -> Self {
        Act {
            what: ActionKind::Read,
            protocol: Protocol::Https,
            blast: BlastRadius::SingleObject,
            privilege: 0.2,
            asset_criticality: 0.5,
            target: String::new(),
        }
    }
}

/// The computed risk, with every term kept so the number can be explained.
/// A score whose derivation is invisible gets argued with instead of acted on.
#[derive(Debug, Clone, PartialEq)]
pub struct Risk {
    pub action_risk: f64,
    pub asset_criticality: f64,
    pub protocol_risk: f64,
    pub privilege_level: f64,
    pub blast_radius: f64,
    pub environment_multiplier: f64,
    pub effective: f64,
}

impl Risk {
    /// `(action + asset + protocol + privilege + blast) × environment`.
    pub fn compute(act: &Act, env: Environment) -> Risk {
        let action_risk = act.what.risk();
        let asset_criticality = clamp01(act.asset_criticality);
        let protocol_risk = act.protocol.risk();
        let privilege_level = clamp01(act.privilege);
        let blast_radius = act.blast.risk();
        let environment_multiplier = env.multiplier();
        let effective =
            (action_risk + asset_criticality + protocol_risk + privilege_level + blast_radius) * environment_multiplier;
        Risk {
            action_risk,
            asset_criticality,
            protocol_risk,
            privilege_level,
            blast_radius,
            environment_multiplier,
            effective,
        }
    }

    /// The derivation, one line, for the audit log and the operator.
    pub fn explain(&self) -> String {
        format!(
            "effective_risk {:.2} = (action {:.2} + asset {:.2} + protocol {:.2} + privilege {:.2} + blast {:.2}) × env {:.2}",
            self.effective,
            self.action_risk,
            self.asset_criticality,
            self.protocol_risk,
            self.privilege_level,
            self.blast_radius,
            self.environment_multiplier
        )
    }
}

/// What the harness is allowed to do to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyPolicy {
    pub environment: Environment,
    /// Refuse any action above this effective risk.
    pub max_effective_risk: f64,
    /// Above this, act only with a human's explicit approval.
    pub confirm_above: f64,
    /// Writes of any kind.
    pub allow_write: bool,
    /// Actions that can stop or restart something.
    pub allow_disruptive: bool,
    /// Malformed/random input. On OT this is the classic way to crash a PLC
    /// that has done nothing wrong.
    pub allow_fuzzing: bool,
    /// Ceiling on request rate, per protocol family. Industrial devices answer
    /// one request at a time and fall over when treated like a web server.
    pub max_requests_per_minute: u32,
    /// Protocols that may not be touched at all.
    pub forbidden_protocols: Vec<Protocol>,
    /// Industrial function codes that must never be sent (Modbus write/
    /// diagnostic codes, S7 stop, DNP3 cold restart…).
    pub forbidden_function_codes: Vec<u16>,
    /// Free-text conditions for the operator's own record (maintenance window,
    /// contact on call). Not enforceable, and kept separate so nobody mistakes
    /// prose for a control.
    pub notes: Vec<String>,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        SafetyPolicy::web_standard(Environment::Production)
    }
}

/// Named starting points an operator can pick and then adjust.
pub struct SafetyProfile;

impl SafetyProfile {
    /// Ordinary web application testing.
    pub fn web_standard(env: Environment) -> SafetyPolicy {
        SafetyPolicy::web_standard(env)
    }
    /// OT/ICS/SCADA: read-only, slow, and with the dangerous primitives removed
    /// rather than discouraged.
    pub fn ot_conservative() -> SafetyPolicy {
        SafetyPolicy::ot_conservative()
    }
}

impl SafetyPolicy {
    pub fn web_standard(environment: Environment) -> SafetyPolicy {
        SafetyPolicy {
            environment,
            max_effective_risk: 3.5,
            confirm_above: 2.5,
            allow_write: environment != Environment::Production,
            allow_disruptive: false,
            allow_fuzzing: environment == Environment::Lab || environment == Environment::Development,
            max_requests_per_minute: 240,
            forbidden_protocols: vec![Protocol::SafetySystem],
            forbidden_function_codes: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// The profile for live industrial environments.
    ///
    /// Everything here is a refusal rather than a warning, because the failure
    /// mode is physical: a stopped CPU, a tripped line, a safety system that
    /// was mid-test when it was needed. Discovery is still possible — passive
    /// reads and enumeration — and that is usually where the findings are
    /// anyway, since these protocols authenticate nothing.
    pub fn ot_conservative() -> SafetyPolicy {
        SafetyPolicy {
            environment: Environment::OtProduction,
            // Calibration matters here, and the obvious setting is wrong: a
            // plain READ of a critical PLC scores 3.6 on this formula, so a
            // tight ceiling refuses exactly the observation that OT findings
            // come from. In an industrial environment it is the KIND of action
            // that is forbidden (see the ProbeExploit/Write rules below), not
            // the arithmetic. The ceiling catches the extremes; the low
            // approval threshold means anything past trivial observation is a
            // human's decision.
            max_effective_risk: 5.0,
            confirm_above: 3.0,
            allow_write: false,
            allow_disruptive: false,
            allow_fuzzing: false,
            // Roughly one request per second: what a small PLC tolerates while
            // still serving its real traffic.
            max_requests_per_minute: 60,
            forbidden_protocols: vec![Protocol::SafetySystem],
            forbidden_function_codes: vec![
                5,    // Modbus: write single coil
                6,    // Modbus: write single register
                8,    // Modbus: diagnostics (includes "restart communications")
                15,   // Modbus: write multiple coils
                16,   // Modbus: write multiple registers
                22,   // Modbus: mask write register
                23,   // Modbus: read/write multiple registers
                43,   // Modbus: encapsulated interface transport
                0x29, // S7comm: PLC stop
                0x28, // S7comm: PLC start/warm restart
                13,   // DNP3: cold restart
                14,   // DNP3: warm restart
                18,   // DNP3: stop application
            ],
            notes: vec![
                "OT profile: observation only. Any write, restart, or mode change requires a human, a maintenance window, and the process owner present.".into(),
            ],
        }
    }

    /// The decision for one action.
    pub fn check(&self, act: &Act) -> RiskDecision {
        let risk = Risk::compute(act, self.environment);

        if self.forbidden_protocols.contains(&act.protocol) {
            return RiskDecision::deny(risk, format!("{} is a forbidden protocol for this engagement", act.protocol.as_str()));
        }
        if act.what == ActionKind::Write && !self.allow_write {
            return RiskDecision::deny(risk, "writes are disabled by the safety policy".into());
        }
        if act.what == ActionKind::Disruptive && !self.allow_disruptive {
            return RiskDecision::deny(risk, "disruptive actions (stop/restart/mode change) are disabled by the safety policy".into());
        }
        if act.protocol.is_ot() && act.what == ActionKind::ProbeExploit && !self.allow_fuzzing {
            // Exploit payloads at an industrial device are how scanners crash
            // PLCs that have done nothing wrong: malformed input on a protocol
            // with no input validation, answered by a CPU with no spare cycles.
            return RiskDecision::deny(risk, "exploit payloads over industrial protocols are refused — malformed input is how these devices crash".into());
        }
        if act.protocol.is_ot() && matches!(act.what, ActionKind::Write | ActionKind::Disruptive) {
            // Belt and braces: even with writes enabled, an industrial write is
            // its own decision and never a side effect of a permissive flag.
            return RiskDecision::deny(risk, "writing over an industrial protocol requires an explicit, separate authorization".into());
        }
        if risk.effective > self.max_effective_risk {
            return RiskDecision::deny(
                risk.clone(),
                format!("{} exceeds the ceiling of {:.2}", risk.explain(), self.max_effective_risk),
            );
        }
        if risk.effective > self.confirm_above {
            return RiskDecision::confirm(risk.clone(), format!("{} — above the approval threshold {:.2}", risk.explain(), self.confirm_above));
        }
        RiskDecision::allow(risk)
    }

    /// Is this industrial function code refused outright?
    pub fn function_code_allowed(&self, code: u16) -> bool {
        !self.forbidden_function_codes.contains(&code)
    }

    pub fn summary(&self) -> String {
        format!(
            "env {} · ceiling {:.2} · confirm above {:.2} · write {} · disruptive {} · fuzz {} · {} req/min{}",
            self.environment.as_str(),
            self.max_effective_risk,
            self.confirm_above,
            if self.allow_write { "allowed" } else { "blocked" },
            if self.allow_disruptive { "allowed" } else { "blocked" },
            if self.allow_fuzzing { "allowed" } else { "blocked" },
            self.max_requests_per_minute,
            if self.forbidden_function_codes.is_empty() { String::new() } else { format!(" · {} function code(s) blocked", self.forbidden_function_codes.len()) }
        )
    }
}

/// Allow / ask a human / refuse — with the arithmetic attached either way.
#[derive(Debug, Clone, PartialEq)]
pub enum RiskDecision {
    Allow(Risk),
    Confirm(Risk, String),
    Deny(Risk, String),
}

impl RiskDecision {
    fn allow(r: Risk) -> Self {
        RiskDecision::Allow(r)
    }
    fn confirm(r: Risk, why: String) -> Self {
        RiskDecision::Confirm(r, why)
    }
    fn deny(r: Risk, why: String) -> Self {
        RiskDecision::Deny(r, why)
    }
    pub fn allowed(&self) -> bool {
        !matches!(self, RiskDecision::Deny(..))
    }
    pub fn needs_human(&self) -> bool {
        matches!(self, RiskDecision::Confirm(..))
    }
    pub fn risk(&self) -> &Risk {
        match self {
            RiskDecision::Allow(r) | RiskDecision::Confirm(r, _) | RiskDecision::Deny(r, _) => r,
        }
    }
    pub fn reason(&self) -> String {
        match self {
            RiskDecision::Allow(r) => r.explain(),
            RiskDecision::Confirm(_, w) | RiskDecision::Deny(_, w) => w.clone(),
        }
    }
}

/// How the agent is required to reason — the loop, made into rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningPolicy {
    /// Capture the unmodified behaviour before sending a payload. Without it
    /// there is nothing to compare against and every difference is a guess.
    pub require_baseline_first: bool,
    /// Hypotheses allowed in flight at once. Unbounded breadth is how a run
    /// spends its budget touching everything shallowly.
    pub max_open_hypotheses: usize,
    /// Observations to gather before escalating from probe to exploit.
    pub min_observations_before_exploit: usize,
    /// Prefer the cheapest action that most reduces uncertainty (value of
    /// information) over the most spectacular one.
    pub voi_ordering: bool,
    /// Give up on a hypothesis after this many failed attempts and write down
    /// why, instead of retrying the same thing with different words.
    pub max_attempts_per_hypothesis: usize,
    /// End the run when no new information has arrived for this many rounds.
    pub stop_after_idle_rounds: usize,
    /// Re-derive nothing that the memory already knows.
    pub consult_memory: bool,
}

impl Default for ReasoningPolicy {
    fn default() -> Self {
        ReasoningPolicy {
            require_baseline_first: true,
            max_open_hypotheses: 8,
            min_observations_before_exploit: 2,
            voi_ordering: true,
            max_attempts_per_hypothesis: 3,
            stop_after_idle_rounds: 3,
            consult_memory: true,
        }
    }
}

impl ReasoningPolicy {
    /// Rendered into prompts. These are expectations the harness also checks
    /// where it can (baseline capture, evidence contract), not decoration.
    pub fn prompt_block(&self) -> String {
        let mut s = String::from("REASONING POLICY — how this engagement is expected to proceed:\n");
        if self.require_baseline_first {
            s.push_str("  - Capture the baseline BEFORE sending any payload. A difference without a baseline is not evidence.\n");
        }
        s.push_str(&format!("  - Keep at most {} hypotheses open; close one before opening another.\n", self.max_open_hypotheses));
        s.push_str(&format!("  - Gather at least {} independent observation(s) before escalating from probing to exploitation.\n", self.min_observations_before_exploit));
        if self.voi_ordering {
            s.push_str("  - Choose the cheapest interaction that most reduces uncertainty, not the most impressive one.\n");
        }
        s.push_str(&format!("  - After {} failed attempts at the same hypothesis, record WHY it failed and move on — do not retry it reworded.\n", self.max_attempts_per_hypothesis));
        s.push_str(&format!("  - If {} rounds pass with no new information, stop and report.\n", self.stop_after_idle_rounds));
        if self.consult_memory {
            s.push_str("  - Use what is already known about this target (provided above) instead of re-deriving it.\n");
        }
        s
    }
}

/// What a finding must carry before it may claim a given severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfImpactPolicy {
    /// Critical/High need a deterministic validator verdict, not a vote.
    pub require_validator_for_high: bool,
    /// Repeats required before a behavioural difference counts.
    pub min_reproductions: usize,
    /// A state change must be read back; claiming a write that was never
    /// verified is the most expensive kind of false positive.
    pub require_read_back_for_writes: bool,
    /// Impact must name data or a capability actually reached.
    pub require_named_impact: bool,
    /// Severity ceiling applied when proof is missing, instead of dropping the
    /// finding — an unproven lead is still worth a human's time.
    pub unproven_severity_cap: String,
    /// Refuse to report at all when nothing at all backs the claim.
    pub drop_unevidenced: bool,
}

impl Default for ProofOfImpactPolicy {
    fn default() -> Self {
        ProofOfImpactPolicy {
            require_validator_for_high: true,
            min_reproductions: 2,
            require_read_back_for_writes: true,
            require_named_impact: true,
            unproven_severity_cap: "Medium".into(),
            drop_unevidenced: false,
        }
    }
}

impl ProofOfImpactPolicy {
    pub fn prompt_block(&self) -> String {
        let mut s = String::from("PROOF-OF-IMPACT POLICY — what a claim must carry:\n");
        if self.require_validator_for_high {
            s.push_str("  - High/Critical requires proof the harness can verify deterministically (see the evidence contract). A model's confidence is not proof.\n");
        }
        s.push_str(&format!("  - A behavioural difference counts only if it reproduces at least {} time(s).\n", self.min_reproductions));
        if self.require_read_back_for_writes {
            s.push_str("  - A state change must be READ BACK. A 200 on the write proves the request was accepted, not that anything changed.\n");
        }
        if self.require_named_impact {
            s.push_str("  - Impact must name the data or capability actually reached in THIS application. No generic consequences.\n");
        }
        s.push_str(&format!("  - Without that proof the finding is reported at most as {} and flagged for review — do not inflate it.\n", self.unproven_severity_cap));
        s
    }
}

/// The three policies plus the environment, carried together.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngagementPolicy {
    #[serde(default)]
    pub safety: SafetyPolicy,
    #[serde(default)]
    pub reasoning: ReasoningPolicy,
    #[serde(default)]
    pub proof: ProofOfImpactPolicy,
}

impl EngagementPolicy {
    pub fn web(env: Environment) -> Self {
        EngagementPolicy { safety: SafetyPolicy::web_standard(env), ..Default::default() }
    }

    /// OT: conservative safety, patient reasoning, and proof requirements that
    /// do not push an agent toward "just try the write and see".
    pub fn ot() -> Self {
        EngagementPolicy {
            safety: SafetyPolicy::ot_conservative(),
            reasoning: ReasoningPolicy {
                min_observations_before_exploit: 4,
                max_open_hypotheses: 4,
                ..Default::default()
            },
            proof: ProofOfImpactPolicy {
                // On a live process, "prove it by doing it" is not available,
                // so a documented reachable capability is the ceiling of proof.
                require_read_back_for_writes: false,
                unproven_severity_cap: "High".into(),
                ..Default::default()
            },
        }
    }

    pub fn prompt_block(&self) -> String {
        let mut s = self.reasoning.prompt_block();
        s.push('\n');
        s.push_str(&self.proof.prompt_block());
        s.push('\n');
        s.push_str(&format!("SAFETY POLICY — enforced by the harness: {}\n", self.safety.summary()));
        for n in &self.safety.notes {
            s.push_str(&format!("  note: {n}\n"));
        }
        if self.safety.environment == Environment::OtProduction {
            s.push_str(
                "  This is a LIVE INDUSTRIAL environment. Industrial protocols authenticate nothing: a write is not an exploit, it is the protocol working — addressed to a device that may be holding a valve. Observe, document reachability, and never act on the process.\n",
            );
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_formula_is_the_sum_of_five_terms_times_the_environment() {
        let act = Act {
            what: ActionKind::Read,              // 0.05
            protocol: Protocol::Https,           // 0.10
            blast: BlastRadius::SingleObject,    // 0.05
            privilege: 0.2,
            asset_criticality: 0.5,
            target: "https://app.test".into(),
        };
        let r = Risk::compute(&act, Environment::Production); // ×1.0
        assert!((r.effective - 0.90).abs() < 1e-9, "{}", r.explain());
        let lab = Risk::compute(&act, Environment::Lab); // ×0.3
        assert!((lab.effective - 0.27).abs() < 1e-9, "{}", lab.explain());
    }

    #[test]
    fn the_same_action_costs_more_on_a_live_process() {
        let act = Act { what: ActionKind::Enumerate, protocol: Protocol::Industrial, blast: BlastRadius::Segment, privilege: 0.2, asset_criticality: 0.9, target: "10.0.0.5".into() };
        let staging = Risk::compute(&act, Environment::Staging).effective;
        let ot = Risk::compute(&act, Environment::OtProduction).effective;
        assert!(ot > staging * 2.0, "staging {staging:.2} vs ot {ot:.2}");
    }

    #[test]
    fn an_explanation_names_every_term() {
        let r = Risk::compute(&Act::default(), Environment::Production);
        for t in ["action", "asset", "protocol", "privilege", "blast", "env"] {
            assert!(r.explain().contains(t), "{} missing from: {}", t, r.explain());
        }
    }

    #[test]
    fn ot_refuses_a_write_even_when_writes_were_enabled() {
        let mut p = SafetyPolicy::ot_conservative();
        p.allow_write = true; // operator loosened the flag
        let act = Act { what: ActionKind::Write, protocol: Protocol::Industrial, blast: BlastRadius::PhysicalProcess, privilege: 0.3, asset_criticality: 1.0, target: "plc-1".into() };
        match p.check(&act) {
            RiskDecision::Deny(_, why) => assert!(why.contains("separate authorization"), "{why}"),
            d => panic!("an industrial write must never ride on a permissive flag: {d:?}"),
        }
    }

    #[test]
    fn ot_still_allows_looking_but_asks_first() {
        let p = SafetyPolicy::ot_conservative();
        let act = Act { what: ActionKind::Read, protocol: Protocol::Industrial, blast: BlastRadius::SingleHost, privilege: 0.1, asset_criticality: 0.8, target: "plc-1".into() };
        let d = p.check(&act);
        assert!(d.allowed(), "observation is where OT findings come from: {}", d.reason());
        assert!(d.needs_human(), "touching a live process at all is a human's call: {}", d.reason());
    }

    #[test]
    fn ot_refuses_exploit_payloads_even_though_they_change_nothing() {
        let p = SafetyPolicy::ot_conservative();
        let act = Act { what: ActionKind::ProbeExploit, protocol: Protocol::Industrial, blast: BlastRadius::SingleHost, privilege: 0.1, asset_criticality: 0.5, target: "plc-1".into() };
        match p.check(&act) {
            RiskDecision::Deny(_, why) => assert!(why.contains("malformed input"), "{why}"),
            d => panic!("malformed input is how PLCs crash: {d:?}"),
        }
    }

    #[test]
    fn the_ceiling_refuses_and_the_threshold_asks() {
        let p = SafetyPolicy::web_standard(Environment::Production);
        let low = Act { what: ActionKind::Read, ..Default::default() };
        assert!(matches!(p.check(&low), RiskDecision::Allow(_)));

        let mid = Act { what: ActionKind::ProbeExploit, protocol: Protocol::Database, blast: BlastRadius::SharedService, privilege: 0.6, asset_criticality: 0.8, ..Default::default() };
        let d = p.check(&mid);
        assert!(d.needs_human(), "{:?} → {}", d, d.reason());
        assert!(d.allowed(), "asking for approval is not a refusal");

        let high = Act { what: ActionKind::Disruptive, protocol: Protocol::Industrial, blast: BlastRadius::PhysicalProcess, privilege: 1.0, asset_criticality: 1.0, ..Default::default() };
        assert!(!p.check(&high).allowed());
    }

    #[test]
    fn a_safety_system_is_never_in_play() {
        for env in [Environment::Lab, Environment::Production, Environment::OtProduction] {
            let p = SafetyPolicy::web_standard(env);
            let act = Act { what: ActionKind::Read, protocol: Protocol::SafetySystem, ..Default::default() };
            match p.check(&act) {
                RiskDecision::Deny(_, why) => assert!(why.contains("forbidden protocol"), "{why}"),
                d => panic!("safety instrumented systems are off limits in {}: {d:?}", env.as_str()),
            }
        }
    }

    #[test]
    fn dangerous_industrial_function_codes_are_refused() {
        let p = SafetyPolicy::ot_conservative();
        for code in [5, 6, 8, 15, 16, 0x29] {
            assert!(!p.function_code_allowed(code), "function code {code} must be blocked");
        }
        for code in [1, 2, 3, 4] {
            assert!(p.function_code_allowed(code), "read code {code} must stay available");
        }
    }

    #[test]
    fn industrial_ports_are_recognised_without_a_declaration() {
        assert_eq!(Protocol::from_port(502), Protocol::Industrial);
        assert_eq!(Protocol::from_port(20000), Protocol::Industrial);
        assert_eq!(Protocol::from_port(102), Protocol::Industrial);
        assert_eq!(Protocol::from_port(443), Protocol::Https);
        assert!(Protocol::from_port(502).is_ot());
    }

    #[test]
    fn ot_paces_itself() {
        assert!(SafetyPolicy::ot_conservative().max_requests_per_minute <= 60);
        assert!(!SafetyPolicy::ot_conservative().allow_fuzzing, "fuzzing a PLC crashes devices that have done nothing wrong");
    }

    #[test]
    fn policies_render_into_a_prompt_that_states_the_rules() {
        let p = EngagementPolicy::ot();
        let block = p.prompt_block();
        assert!(block.contains("REASONING POLICY"));
        assert!(block.contains("PROOF-OF-IMPACT POLICY"));
        assert!(block.contains("SAFETY POLICY"));
        assert!(block.contains("LIVE INDUSTRIAL"), "an OT engagement must say so in the prompt");
    }

    #[test]
    fn environment_parses_the_words_operators_actually_type() {
        for (s, want) in [("prod", Environment::Production), ("SCADA", Environment::OtProduction), ("ics", Environment::OtProduction), ("staging", Environment::Staging), ("lab", Environment::Lab)] {
            assert_eq!(Environment::parse(s), Some(want), "{s}");
        }
        assert_eq!(Environment::parse("banana"), None);
    }
}
