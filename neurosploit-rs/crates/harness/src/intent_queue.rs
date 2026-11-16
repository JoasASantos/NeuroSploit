//! Intent queue with a single generator.
//!
//! The planner is the *only* component allowed to create intents; workers claim
//! one, complete it, and write facts back — they never invent new directions.
//! That separation (borrowed from Artex) stops workers from wandering and makes
//! the work log auditable: every unit of work traces to a planner decision.
//!
//! The rule is enforced by the API, not by convention: [`IntentQueue::push`]
//! requires a [`Producer`] and rejects anything that is not [`Producer::Planner`].
//! Workers that notice a lead call [`IntentQueue::suggest`], which records a
//! hint for the planner's next wake instead of queueing work.
//!
//! Also provided: dedupe (same action+target never queued twice while live),
//! priority-ordered claiming that respects `depends_on`, and retry accounting.

use crate::planner::{IntentAction, PlannerIntent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Producer {
    Planner,
    Worker,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    NotPlanner(&'static str),
    Duplicate(String),
    UnknownIntent(String),
    NotClaimedBy { id: String, agent: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Queued,
    Claimed,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub intent: PlannerIntent,
    pub state: State,
    pub claimed_by: Option<String>,
    pub attempts: u32,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentQueue {
    entries: Vec<Entry>,
    /// Leads proposed by workers; drained by the planner on its next wake.
    suggestions: Vec<String>,
    pub max_attempts: u32,
}

fn key(i: &PlannerIntent) -> String {
    format!("{:?}|{}", i.action, i.target.trim().to_lowercase())
}

impl IntentQueue {
    pub fn new(max_attempts: u32) -> Self {
        Self { max_attempts: max_attempts.max(1), ..Self::default() }
    }

    /// Queue an intent. Only the planner (or the operator, who steers it) may.
    pub fn push(&mut self, by: Producer, intent: PlannerIntent) -> Result<(), QueueError> {
        match by {
            Producer::Planner | Producer::Operator => {}
            Producer::Worker => return Err(QueueError::NotPlanner(
                "workers cannot create intents; use suggest() so the planner decides")),
        }
        let k = key(&intent);
        if self.entries.iter().any(|e| key(&e.intent) == k && matches!(e.state, State::Queued | State::Claimed | State::Done)) {
            return Err(QueueError::Duplicate(k));
        }
        self.entries.push(Entry { intent, state: State::Queued, claimed_by: None, attempts: 0, result: None });
        Ok(())
    }

    /// A worker's lead. Becomes a planner input, never work.
    pub fn suggest(&mut self, lead: &str) {
        let lead = lead.trim();
        if !lead.is_empty() && !self.suggestions.iter().any(|s| s == lead) {
            self.suggestions.push(lead.to_string());
        }
    }

    pub fn drain_suggestions(&mut self) -> Vec<String> { std::mem::take(&mut self.suggestions) }

    fn done_ids(&self) -> HashSet<&str> {
        self.entries.iter().filter(|e| e.state == State::Done).map(|e| e.intent.id.as_str()).collect()
    }

    /// Claim the highest-priority runnable intent (dependencies satisfied).
    pub fn claim(&mut self, agent: &str) -> Option<PlannerIntent> {
        let done = self.done_ids();
        let pick = self.entries.iter().enumerate()
            .filter(|(_, e)| e.state == State::Queued && e.intent.depends_on.iter().all(|d| done.contains(d.as_str())))
            .max_by_key(|(i, e)| (e.intent.priority, std::cmp::Reverse(*i)))
            .map(|(i, _)| i)?;
        let e = &mut self.entries[pick];
        e.state = State::Claimed;
        e.claimed_by = Some(agent.to_string());
        e.attempts += 1;
        Some(e.intent.clone())
    }

    fn find(&mut self, id: &str, agent: &str) -> Result<&mut Entry, QueueError> {
        let e = self.entries.iter_mut().find(|e| e.intent.id == id)
            .ok_or_else(|| QueueError::UnknownIntent(id.into()))?;
        if e.claimed_by.as_deref() != Some(agent) || e.state != State::Claimed {
            return Err(QueueError::NotClaimedBy { id: id.into(), agent: agent.into() });
        }
        Ok(e)
    }

    pub fn complete(&mut self, id: &str, agent: &str, result: &str) -> Result<(), QueueError> {
        let e = self.find(id, agent)?;
        e.state = State::Done;
        e.result = Some(result.to_string());
        Ok(())
    }

    /// Fail an intent. Re-queued until `max_attempts`, then terminally Failed.
    /// Returns true if it will be retried.
    pub fn fail(&mut self, id: &str, agent: &str, reason: &str) -> Result<bool, QueueError> {
        let max = self.max_attempts;
        let e = self.find(id, agent)?;
        e.result = Some(reason.to_string());
        if e.attempts < max {
            e.state = State::Queued;
            e.claimed_by = None;
            Ok(true)
        } else {
            e.state = State::Failed;
            Ok(false)
        }
    }

    /// Return a claimed intent to the queue without counting a failure (e.g.
    /// the worker was cut off by wrap-up). The attempt is refunded.
    pub fn release(&mut self, id: &str, agent: &str) -> Result<(), QueueError> {
        let e = self.find(id, agent)?;
        e.state = State::Queued;
        e.claimed_by = None;
        e.attempts = e.attempts.saturating_sub(1);
        Ok(())
    }

    pub fn counts(&self) -> HashMap<&'static str, usize> {
        let mut m = HashMap::new();
        for e in &self.entries {
            let k = match e.state { State::Queued => "queued", State::Claimed => "claimed", State::Done => "done", State::Failed => "failed" };
            *m.entry(k).or_insert(0) += 1;
        }
        m
    }

    pub fn entries(&self) -> &[Entry] { &self.entries }
}

/// Convenience constructor used by tests and callers building simple intents.
pub fn intent(id: &str, action: IntentAction, target: &str, priority: u32) -> PlannerIntent {
    PlannerIntent {
        id: id.into(), action, target: target.into(), agent_hint: String::new(),
        priority, rationale: String::new(), depends_on: vec![], asset_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_cannot_push() {
        let mut q = IntentQueue::new(2);
        let r = q.push(Producer::Worker, intent("a", IntentAction::Probe, "/x", 50));
        assert!(matches!(r, Err(QueueError::NotPlanner(_))));
        assert!(q.entries().is_empty());
        q.suggest("looks like IDOR on /orders");
        q.suggest("looks like IDOR on /orders");
        assert_eq!(q.drain_suggestions().len(), 1);
        assert!(q.drain_suggestions().is_empty());
    }

    #[test]
    fn dedupes_live_work_but_allows_retry_after_terminal_failure() {
        let mut q = IntentQueue::new(1);
        q.push(Producer::Planner, intent("a", IntentAction::Probe, "/X", 50)).unwrap();
        assert!(matches!(q.push(Producer::Planner, intent("b", IntentAction::Probe, "/x", 50)),
                         Err(QueueError::Duplicate(_))));
        q.claim("w1").unwrap();
        assert!(!q.fail("a", "w1", "boom").unwrap());
        q.push(Producer::Planner, intent("c", IntentAction::Probe, "/x", 50)).unwrap();
    }

    #[test]
    fn claims_by_priority_and_respects_dependencies() {
        let mut q = IntentQueue::new(2);
        let mut dep = intent("dep", IntentAction::Exploit, "/a", 90);
        dep.depends_on = vec!["base".into()];
        q.push(Producer::Planner, dep).unwrap();
        q.push(Producer::Planner, intent("base", IntentAction::Recon, "/a", 10)).unwrap();
        q.push(Producer::Planner, intent("mid", IntentAction::Probe, "/b", 50)).unwrap();
        assert_eq!(q.claim("w").unwrap().id, "mid"); // dep blocked despite priority 90
        assert_eq!(q.claim("w").unwrap().id, "base");
        q.complete("base", "w", "ok").unwrap();
        assert_eq!(q.claim("w").unwrap().id, "dep");
    }

    #[test]
    fn only_claimer_can_complete_and_retries_are_bounded() {
        let mut q = IntentQueue::new(2);
        q.push(Producer::Planner, intent("a", IntentAction::Fuzz, "/f", 50)).unwrap();
        q.claim("w1").unwrap();
        assert!(matches!(q.complete("a", "w2", "x"), Err(QueueError::NotClaimedBy { .. })));
        assert!(q.fail("a", "w1", "t1").unwrap()); // attempt 1 of 2 -> retry
        q.claim("w2").unwrap();
        assert!(!q.fail("a", "w2", "t2").unwrap()); // attempt 2 -> terminal
        assert_eq!(q.counts().get("failed"), Some(&1));
    }

    #[test]
    fn release_refunds_attempt() {
        let mut q = IntentQueue::new(1);
        q.push(Producer::Operator, intent("a", IntentAction::Probe, "/p", 50)).unwrap();
        q.claim("w").unwrap();
        q.release("a", "w").unwrap();
        assert!(q.claim("w").is_some(), "released work is claimable again");
    }
}
