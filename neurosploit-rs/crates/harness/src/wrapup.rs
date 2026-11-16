//! Wrap-up (settlement) — never lose work when a run is cut off.
//!
//! When an agent hits its turn cap or wall-clock limit, whatever it has
//! identified but not yet written back is lost. Instead of killing it cold, the
//! runtime grants a small *settlement* budget with a prompt that says exactly:
//! persist what you already know, do not start anything new.
//!
//! This module holds the policy only (when to wrap, what to say, how many turns,
//! which tools stay open); the pipeline decides how to drive the model with it.
//! Pure and deterministic so it is unit-testable.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    TurnsExhausted,
    TimeExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Planner,
    Worker,
    Validator,
    Reporter,
}

/// Limits for one agent run.
#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    pub max_turns: u32,   // 0 = unlimited
    pub max_time: Duration, // ZERO = unlimited
    /// Start wrapping this many turns *before* the hard cap, so the wrap-up
    /// itself is not starved of budget.
    pub reserve_turns: u32,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self { max_turns: 0, max_time: Duration::ZERO, reserve_turns: 0 }
    }
}

/// Decide whether the run must switch to wrap-up now.
pub fn should_wrap(limits: &RunLimits, turn: u32, elapsed: Duration) -> Option<Reason> {
    if limits.max_turns > 0 && turn + limits.reserve_turns >= limits.max_turns {
        return Some(Reason::TurnsExhausted);
    }
    if limits.max_time > Duration::ZERO && elapsed >= limits.max_time {
        return Some(Reason::TimeExhausted);
    }
    None
}

/// Turns granted to the settlement phase itself.
pub fn settlement_turns(role: Role) -> u32 {
    match role {
        Role::Planner | Role::Worker => 10,
        Role::Validator | Role::Reporter => 6,
    }
}

/// Tools that must stay closed during settlement: anything that touches the
/// target or starts new exploration. Only persistence tools remain.
pub fn is_blocked_in_settlement(tool: &str) -> bool {
    const ALLOWED: &[&str] = &[
        "report_finding", "record_fact", "record_negative", "add_hint", "record_result",
        "update_todo", "write_file", "memory_write",
    ];
    !ALLOWED.contains(&tool)
}

/// The settlement prompt for a role.
pub fn prompt(role: Role, reason: Reason) -> String {
    let why = match reason {
        Reason::TurnsExhausted => "your turn budget is almost spent",
        Reason::TimeExhausted => "your time budget is spent",
    };
    let body = match role {
        Role::Worker => "Persist what you have, then stop. (1) Write every confirmed finding with its evidence. \
(2) Record facts you observed and negative results (what you tested that was NOT vulnerable) so they are not retried. \
(3) If the intent is incomplete, state exactly what remains. Do NOT start new tests or send new requests to the target.",
        Role::Planner => "This is the end of THIS planning round only - the planner will be woken again when the graph changes, \
so this is not the end of the engagement and you do not need to wrap up the whole plan. Land what you have already decided: \
(1) submit the intents you judged worth running now, in one batch; (2) mark goals proven by existing findings; \
(3) note any multi-step chain in the todo list for the next wake. Do not invent intents to look busy - zero is a valid result.",
        Role::Validator => "Record your verdict for each claim you finished checking, with the evidence you saw. \
For claims you did not finish, mark them inconclusive and say what was missing. Do not send new requests.",
        Role::Reporter => "Save the sections you have completed and list the sections still missing. Do not fabricate content for them.",
    };
    format!("WRAP-UP: {why}. {body} Finish with one short line summarising what was saved.")
}

/// What survives from a cut-off run, for the run log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settlement {
    pub reason: Option<Reason>,
    pub findings_saved: u32,
    pub facts_saved: u32,
    pub incomplete: bool,
}

impl Settlement {
    pub fn line(&self) -> String {
        match self.reason {
            None => "completed normally".into(),
            Some(r) => format!("{:?}: saved {} finding(s), {} fact(s){}", r, self.findings_saved,
                self.facts_saved, if self.incomplete { "; intent INCOMPLETE" } else { "" }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_before_hard_cap_using_reserve() {
        let l = RunLimits { max_turns: 20, max_time: Duration::ZERO, reserve_turns: 3 };
        assert_eq!(should_wrap(&l, 16, Duration::ZERO), None);
        assert_eq!(should_wrap(&l, 17, Duration::ZERO), Some(Reason::TurnsExhausted));
    }

    #[test]
    fn wraps_on_time_and_unlimited_never_wraps() {
        let l = RunLimits { max_turns: 0, max_time: Duration::from_secs(60), reserve_turns: 0 };
        assert_eq!(should_wrap(&l, 999, Duration::from_secs(59)), None);
        assert_eq!(should_wrap(&l, 999, Duration::from_secs(60)), Some(Reason::TimeExhausted));
        assert_eq!(should_wrap(&RunLimits::default(), 10_000, Duration::from_secs(10_000)), None);
    }

    #[test]
    fn settlement_closes_target_facing_tools() {
        assert!(is_blocked_in_settlement("http_request"));
        assert!(is_blocked_in_settlement("bash"));
        assert!(!is_blocked_in_settlement("report_finding"));
        assert!(!is_blocked_in_settlement("record_negative"));
    }

    #[test]
    fn prompts_forbid_new_work_and_planner_is_not_terminal() {
        assert!(prompt(Role::Worker, Reason::TurnsExhausted).contains("Do NOT start new tests"));
        let p = prompt(Role::Planner, Reason::TurnsExhausted);
        assert!(p.contains("THIS planning round only") && p.contains("zero is a valid result"));
        assert!(prompt(Role::Reporter, Reason::TimeExhausted).contains("Do not fabricate"));
        assert_eq!(settlement_turns(Role::Worker), 10);
    }

    #[test]
    fn settlement_line() {
        let s = Settlement { reason: Some(Reason::TimeExhausted), findings_saved: 2, facts_saved: 5, incomplete: true };
        assert!(s.line().contains("2 finding(s)") && s.line().contains("INCOMPLETE"));
        assert_eq!(Settlement::default().line(), "completed normally");
    }
}
