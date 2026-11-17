//! Reactive engine — an event-driven alternative to the phased pipeline.
//!
//! Opt-in (`--reactive`). Instead of recon -> exploit -> validate once, a
//! planner is woken whenever the exploration graph changes, turns the change
//! into intents, and a pool of workers claims and runs them. Results are written
//! back to the graph, which wakes the planner again, until nothing runnable is
//! left, the budget is spent, or the deadline hits.
//!
//! Roles are strict (see [`crate::intent_queue`]): only the planner creates
//! intents; workers run exactly one and write facts back.
//!
//! The engine is generic over the executor (`ExecFn`), so it is fully testable
//! without any model. The real pipeline supplies an executor that runs an agent.
//!
//! Operational properties:
//! - deadline: at expiry workers are told to wrap up ([`WorkCtx::wrapping`]),
//!   given a drain grace, then cancelled; their intents go back to the queue
//!   (attempt refunded) so a resumed run continues them;
//! - control: pause (no new claims), resume, stop one intent, steer one intent;
//! - loop guards: a total-intent budget and a per-target failure cap stop a
//!   planner that keeps re-proposing the same failing work;
//! - durability: state is saved after every change and [`resume_state`] reloads it.

use crate::adaptive::AdaptiveEngine;
use crate::exploration_graph::{AnchorDirection, DualGraph, ExplorationKind, ExplorationStatus};
use crate::intent_queue::{IntentQueue, Producer};
use crate::planner::{IntentAction, Planner, PlannerConfig, PlannerIntent};
use crate::wrapup::{Reason, Settlement};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// What a worker reports for one intent.
#[derive(Debug, Clone, Default)]
pub struct WorkOutcome {
    pub ok: bool,
    pub summary: String,
    pub facts: Vec<String>,
    pub negatives: Vec<String>,
    pub findings: Vec<String>,
}

/// Handed to every executor call.
pub struct WorkCtx {
    pub intent_id: String,
    wrap: Arc<AtomicBool>,
    steer: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl WorkCtx {
    /// True once the deadline hit: persist what you have and stop (see `wrapup`).
    pub fn wrapping(&self) -> bool { self.wrap.load(Ordering::Relaxed) }
    /// Operator guidance queued for this intent since the last call.
    pub fn take_steer(&self) -> Vec<String> {
        self.steer.lock().unwrap().remove(&self.intent_id).unwrap_or_default()
    }
}

pub type ExecFn = Arc<dyn Fn(PlannerIntent, WorkCtx) -> BoxFuture<'static, WorkOutcome> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct ReactiveConfig {
    pub target: String,
    pub workers: usize,
    pub deadline: Option<Duration>,
    pub intent_timeout: Duration,
    pub debounce: Duration,
    pub heartbeat: Duration,
    pub drain_grace: Duration,
    pub max_total_intents: usize,
    pub max_failures_per_target: u32,
    pub state_dir: Option<PathBuf>,
    pub planner: PlannerConfig,
}

impl ReactiveConfig {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.into(), workers: 4, deadline: None,
            intent_timeout: Duration::from_secs(600), debounce: Duration::from_millis(300),
            heartbeat: Duration::from_secs(30), drain_grace: Duration::from_secs(20),
            max_total_intents: 200, max_failures_per_target: 3, state_dir: None,
            planner: PlannerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndReason { Quiescent, Deadline, Stopped, Budget }

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub reason: EndReason,
    pub done: usize,
    pub failed: usize,
    pub stopped: usize,
    pub released: usize,
    pub findings: usize,
    pub planner_rounds: u64,
    pub hints_injected: usize,
    pub settlement: Settlement,
}

struct Shared {
    graph: Mutex<DualGraph>,
    queue: Mutex<IntentQueue>,
    wake: Notify,
    paused: AtomicBool,
    stop_all: AtomicBool,
    wrap: Arc<AtomicBool>,
    inflight: AtomicUsize,
    steer: Arc<Mutex<HashMap<String, Vec<String>>>>,
    stops: Mutex<HashMap<String, Arc<Notify>>>,
    stopped_ids: Mutex<HashSet<String>>,
    counters: Mutex<Counters>,
    heartbeats: Mutex<HashMap<String, std::time::Instant>>,
    hints_injected: AtomicUsize,
}

#[derive(Default)]
struct Counters { done: usize, failed: usize, stopped: usize, released: usize, findings: usize, rounds: u64, pushed: usize,
                  fails_by_key: HashMap<String, u32> }

/// Control surface for a running engine. Cheap to clone.
#[derive(Clone)]
pub struct Handle { s: Arc<Shared> }

impl Handle {
    pub fn pause(&self) { self.s.paused.store(true, Ordering::Relaxed); }
    pub fn resume(&self) { self.s.paused.store(false, Ordering::Relaxed); self.s.wake.notify_waiters(); }
    /// End the run; running intents are cancelled and returned to the queue.
    pub fn stop(&self) { self.s.stop_all.store(true, Ordering::Relaxed); self.s.wake.notify_waiters(); self.cancel_all(); }
    /// Cancel one running intent; it is marked stopped and not retried.
    pub fn stop_intent(&self, id: &str) {
        self.s.stopped_ids.lock().unwrap().insert(id.to_string());
        if let Some(n) = self.s.stops.lock().unwrap().get(id) { n.notify_one(); }
    }
    /// Queue guidance for a running intent (read via `WorkCtx::take_steer`).
    pub fn steer(&self, id: &str, msg: &str) {
        self.s.steer.lock().unwrap().entry(id.to_string()).or_default().push(msg.to_string());
    }
    /// Inject an operator hint into the exploration graph. Triggers a replan.
    pub fn hint(&self, text: &str) {
        let mut g = self.s.graph.lock().unwrap();
        // Find or create the root goal for operator hints
        let goal_text = "operator-hints";
        let goal = g.exploration.nodes.iter()
            .find(|n| n.kind == crate::exploration_graph::ExplorationKind::Goal && n.content == goal_text)
            .map(|n| n.id.clone())
            .unwrap_or_else(|| g.exploration.add_goal(goal_text, "operator"));
        g.exploration.add_hint(text, &goal, "operator");
        drop(g);
        self.s.hints_injected.fetch_add(1, Ordering::Relaxed);
        self.s.wake.notify_waiters(); // trigger replan
    }
    /// Operator-created intent (allowed alongside the planner).
    pub fn push_operator_intent(&self, intent: PlannerIntent) -> bool {
        let ok = self.s.queue.lock().unwrap().push(Producer::Operator, intent).is_ok();
        if ok { self.s.wake.notify_waiters(); }
        ok
    }
    fn cancel_all(&self) { for n in self.s.stops.lock().unwrap().values() { n.notify_one(); } }
}

fn new_shared(graph: DualGraph, queue: IntentQueue) -> Arc<Shared> {
    Arc::new(Shared {
        graph: Mutex::new(graph), queue: Mutex::new(queue), wake: Notify::new(),
        paused: AtomicBool::new(false), stop_all: AtomicBool::new(false), wrap: Arc::new(AtomicBool::new(false)),
        inflight: AtomicUsize::new(0), steer: Arc::new(Mutex::new(HashMap::new())),
        stops: Mutex::new(HashMap::new()), stopped_ids: Mutex::new(HashSet::new()),
        counters: Mutex::new(Counters::default()),
        heartbeats: Mutex::new(HashMap::new()),
        hints_injected: AtomicUsize::new(0),
    })
}

#[derive(Serialize, Deserialize)]
struct Persisted { queue: IntentQueue, graph: DualGraph }

const STATE_FILE: &str = "reactive-state.json";

fn save(s: &Shared, dir: &Option<PathBuf>) {
    let Some(d) = dir else { return };
    let p = Persisted { queue: s.queue.lock().unwrap().clone(), graph: s.graph.lock().unwrap().clone() };
    if std::fs::create_dir_all(d).is_ok() {
        if let Ok(j) = serde_json::to_string(&p) {
            // write-then-rename so a crash never leaves half a file
            let tmp = d.join(format!("{STATE_FILE}.tmp"));
            if std::fs::write(&tmp, j).is_ok() { let _ = std::fs::rename(&tmp, d.join(STATE_FILE)); }
        }
    }
}

/// Reload a saved run. Claimed work is returned to the queue.
pub fn resume_state(dir: &std::path::Path) -> Option<(DualGraph, IntentQueue)> {
    let p: Persisted = serde_json::from_str(&std::fs::read_to_string(dir.join(STATE_FILE)).ok()?).ok()?;
    let mut q = p.queue;
    q.requeue_claimed();
    Some((p.graph, q))
}

/// Create the control handle and engine state together.
pub fn prepare(cfg: &ReactiveConfig, graph: DualGraph, queue: Option<IntentQueue>) -> Handle {
    let q = queue.unwrap_or_else(|| IntentQueue::new(2));
    Handle { s: new_shared(graph, q) }
}

fn goal_id(g: &mut DualGraph, target: &str) -> String {
    let text = format!("Assess {target}");
    match g.exploration.nodes.iter().find(|n| n.kind == ExplorationKind::Goal && n.content == text) {
        Some(n) => n.id.clone(),
        None => g.exploration.add_goal(&text, "reactive"),
    }
}

fn key_of(i: &PlannerIntent) -> String { format!("{:?}|{}", i.action, i.target.to_lowercase()) }

/// Run until quiescent, out of budget, stopped, or past the deadline.
pub async fn run(cfg: ReactiveConfig, handle: Handle, exec: ExecFn) -> (RunReport, DualGraph) {
    let s = handle.s.clone();
    { let mut g = s.graph.lock().unwrap(); goal_id(&mut g, &cfg.target); }
    let cfg = Arc::new(cfg);

    let mut worker_tasks = Vec::new();
    for n in 0..cfg.workers.max(1) {
        let (s2, c2, e2) = (s.clone(), cfg.clone(), exec.clone());
        worker_tasks.push(tokio::spawn(async move { worker_loop(format!("worker-{n}"), s2, c2, e2).await }));
    }

    let planner_task = { let (s2, c2) = (s.clone(), cfg.clone()); tokio::spawn(async move { planner_loop(s2, c2).await }) };

    // Deadline coordinator races the planner (which ends the run on quiescence/budget/stop).
    let mut reason;
    let mut settlement = Settlement::default();
    let mut planner_task = planner_task;
    let planner_reason = match cfg.deadline {
        Some(d) => tokio::select! {
            r = &mut planner_task => Some(r.unwrap_or(EndReason::Stopped)),
            _ = tokio::time::sleep(d) => None,
        },
        None => Some((&mut planner_task).await.unwrap_or(EndReason::Stopped)),
    };
    match planner_reason {
        Some(r) => reason = r,
        None => {
            reason = EndReason::Deadline;
            settlement.reason = Some(Reason::TimeExhausted);
            s.wrap.store(true, Ordering::Relaxed); // ask workers to persist and stop
            s.wake.notify_waiters();
            let t0 = tokio::time::Instant::now();
            while s.inflight.load(Ordering::Relaxed) > 0 && t0.elapsed() < cfg.drain_grace {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            s.stop_all.store(true, Ordering::Relaxed);
            handle.cancel_all(); // hard cancel whatever is left
            s.wake.notify_waiters();
            planner_task.abort();
        }
    }
    s.stop_all.store(true, Ordering::Relaxed);
    s.wake.notify_waiters();
    for t in worker_tasks { let _ = t.await; }

    // Anything still claimed was cut off without a worker reaching its release
    // path (aborted task, process-level cut): sweep it back too.
    let swept = s.queue.lock().unwrap().requeue_claimed();
    let released = s.counters.lock().unwrap().released + swept;
    settlement.incomplete = released > 0;
    if reason == EndReason::Stopped && s.wrap.load(Ordering::Relaxed) { reason = EndReason::Deadline; }
    save(&s, &cfg.state_dir);

    let c = s.counters.lock().unwrap();
    settlement.findings_saved = c.findings as u32;
    let report = RunReport { reason, done: c.done, failed: c.failed, stopped: c.stopped, released,
        findings: c.findings, planner_rounds: c.rounds,
        hints_injected: s.hints_injected.load(Ordering::Relaxed), settlement };
    let graph = s.graph.lock().unwrap().clone();
    (report, graph)
}

async fn planner_loop(s: Arc<Shared>, cfg: Arc<ReactiveConfig>) -> EndReason {
    let mut planner = Planner::new(cfg.planner.clone());
    let adaptive = AdaptiveEngine::new();
    let mut last_signature: (u64, usize, usize) = (0, 0, 0); // (graph_version, fact_count, hint_count)
    loop {
        // wake on a graph change or the heartbeat, then coalesce bursts
        let _ = tokio::time::timeout(cfg.heartbeat, s.wake.notified()).await;
        tokio::time::sleep(cfg.debounce).await;
        if s.stop_all.load(Ordering::Relaxed) { return EndReason::Stopped; }
        if s.paused.load(Ordering::Relaxed) || s.wrap.load(Ordering::Relaxed) { continue; }

        // Intelligent reason trigger: skip replanning if nothing changed
        let sig = {
            let g = s.graph.lock().unwrap();
            let facts = g.exploration.nodes.iter().filter(|n| matches!(n.kind, ExplorationKind::Fact | ExplorationKind::Finding | ExplorationKind::Negative)).count();
            let hints = g.exploration.nodes.iter().filter(|n| n.kind == ExplorationKind::Hint).count();
            (g.exploration.version, facts, hints)
        };
        // Skip replanning if nothing changed and there's no new work
        let runnable = s.queue.lock().unwrap().runnable();
        if sig == last_signature && runnable > 0 && s.inflight.load(Ordering::Relaxed) > 0 {
            continue; // workers still busy, nothing new — save the LLM call
        }
        last_signature = sig;

        let intents = { let g = s.graph.lock().unwrap(); planner.wake(&g, &adaptive) };
        s.counters.lock().unwrap().rounds += 1;
        {
            let mut q = s.queue.lock().unwrap();
            let mut c = s.counters.lock().unwrap();
            for i in intents {
                if c.pushed >= cfg.max_total_intents { return EndReason::Budget; }
                if c.fails_by_key.get(&key_of(&i)).copied().unwrap_or(0) >= cfg.max_failures_per_target { continue; }
                if q.push(Producer::Planner, i).is_ok() { c.pushed += 1; }
            }
            // worker leads become hints, i.e. planner input (never work)
            let leads = q.drain_suggestions();
            drop(q);
            drop(c);
            if !leads.is_empty() {
                let mut g = s.graph.lock().unwrap();
                let goal = goal_id(&mut g, &cfg.target);
                for l in leads { g.exploration.add_hint(&l, &goal, "worker"); }
            }
        }
        save(&s, &cfg.state_dir);
        s.wake.notify_waiters(); // new intents -> idle workers

        // Heartbeat sweep: release intents whose workers went silent
        let stale_cutoff = std::time::Instant::now() - cfg.intent_timeout * 2;
        let stale: Vec<String> = s.heartbeats.lock().unwrap().iter()
            .filter(|(_, t)| **t < stale_cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            s.heartbeats.lock().unwrap().remove(id);
            // Cancel the stale worker
            if let Some(n) = s.stops.lock().unwrap().get(id) { n.notify_one(); }
        }

        // quiescent: nothing running, nothing claimable, and the last wake produced nothing new
        let idle = s.inflight.load(Ordering::Relaxed) == 0 && s.queue.lock().unwrap().runnable() == 0;
        if idle {
            // one extra look: a worker may have just written results that the planner has not seen
            let v = s.graph.lock().unwrap().exploration.version;
            let mut again = { let g = s.graph.lock().unwrap(); planner.wake(&g, &adaptive) };

            // Graph reasoning: when the planner itself produces nothing, look for
            // multi-hop chains from confirmed findings to untested assets.
            if again.is_empty() {
                let chain_intents = {
                    let g = s.graph.lock().unwrap();
                    let chains = crate::graph_reasoning::find_chains(&g, 3);
                    if !chains.is_empty() {
                        let summary = crate::graph_reasoning::graph_summary(&g);
                        let prompt = crate::graph_reasoning::decision_prompt(&chains, &summary, 5);
                        // Parse the prompt itself won't generate intents — we build
                        // them directly from the top-scored chains instead of calling
                        // an LLM in the planner loop (that's the worker's job).
                        chains.iter().take(3).enumerate().map(|(i, c)| {
                            PlannerIntent {
                                id: format!("chain-{}-{}", s.counters.lock().unwrap().rounds, i),
                                action: IntentAction::Chain,
                                target: c.target.clone(),
                                agent_hint: String::new(),
                                priority: ((c.score * 10.0) as u32).min(10),
                                rationale: format!("chain from finding '{}' via {}", c.finding.chars().take(60).collect::<String>(), c.foothold),
                                depends_on: vec![],
                                asset_id: None,
                            }
                        }).collect::<Vec<_>>()
                    } else {
                        vec![]
                    }
                };
                again = chain_intents;
            }

            if again.is_empty() && s.graph.lock().unwrap().exploration.version == v
                && s.queue.lock().unwrap().runnable() == 0 && s.inflight.load(Ordering::Relaxed) == 0
            {
                return EndReason::Quiescent;
            }
            let mut q = s.queue.lock().unwrap();
            for i in again { let _ = q.push(Producer::Planner, i); }
            s.wake.notify_waiters();
        }
    }
}

async fn worker_loop(name: String, s: Arc<Shared>, cfg: Arc<ReactiveConfig>, exec: ExecFn) {
    loop {
        if s.stop_all.load(Ordering::Relaxed) { return; }
        let claimed = if s.paused.load(Ordering::Relaxed) || s.wrap.load(Ordering::Relaxed) { None }
                      else { s.queue.lock().unwrap().claim(&name) };
        let Some(intent) = claimed else {
            let _ = tokio::time::timeout(Duration::from_millis(200), s.wake.notified()).await;
            continue;
        };
        s.inflight.fetch_add(1, Ordering::Relaxed);
        s.heartbeats.lock().unwrap().insert(intent.id.clone(), std::time::Instant::now());
        let stop = Arc::new(Notify::new());
        s.stops.lock().unwrap().insert(intent.id.clone(), stop.clone());
        s.heartbeats.lock().unwrap().insert(intent.id.clone(), std::time::Instant::now());

        // record the intent in the exploration graph
        let exp_id = {
            let mut g = s.graph.lock().unwrap();
            let goal = goal_id(&mut g, &cfg.target);
            let id = g.exploration.add_intent(&format!("{:?} {}", intent.action, intent.target), &goal, &name);
            g.exploration.set_status(&id, ExplorationStatus::InProgress);
            if let Some(a) = &intent.asset_id { g.exploration.anchor(&id, a, AnchorDirection::Targets); }
            id
        };

        let ctx = WorkCtx { intent_id: intent.id.clone(), wrap: s.wrap.clone(), steer: s.steer.clone() };
        let fut = exec(intent.clone(), ctx);
        enum R { Out(WorkOutcome), TimedOut, Cancelled }
        let r = tokio::select! {
            o = fut => R::Out(o),
            _ = tokio::time::sleep(cfg.intent_timeout) => R::TimedOut,
            _ = stop.notified() => R::Cancelled,
        };
        s.stops.lock().unwrap().remove(&intent.id);

        let was_stopped = s.stopped_ids.lock().unwrap().contains(&intent.id);
        match r {
            R::Out(o) => {
                let mut g = s.graph.lock().unwrap();
                for f in &o.facts { g.exploration.add_fact(f, &exp_id, &name); }
                for n in &o.negatives { g.exploration.add_negative(n, &exp_id, &name); }
                let mut nf = 0;
                for f in &o.findings {
                    match &intent.asset_id {
                        Some(a) => { g.record_finding(f, &exp_id, &name, a); }
                        None => { g.exploration.add_finding(f, &exp_id, &name); }
                    }
                    nf += 1;
                }
                g.exploration.set_status(&exp_id, if o.ok { ExplorationStatus::Completed } else { ExplorationStatus::Failed });
                // Enrich graph after findings: bump priority on reachable assets
                if nf > 0 {
                    if let Some(a) = &intent.asset_id {
                        crate::graph_reasoning::enrich_after_finding(&mut g, a);
                    }
                }
                drop(g);
                let mut q = s.queue.lock().unwrap();
                let mut c = s.counters.lock().unwrap();
                c.findings += nf;
                if o.ok {
                    let _ = q.complete(&intent.id, &name, &o.summary);
                    c.done += 1;
                } else {
                    *c.fails_by_key.entry(key_of(&intent)).or_default() += 1;
                    let retry = q.fail(&intent.id, &name, &o.summary).unwrap_or(false);
                    if !retry { c.failed += 1; }
                }
            }
            R::TimedOut | R::Cancelled => {
                let mut g = s.graph.lock().unwrap();
                let mut q = s.queue.lock().unwrap();
                let mut c = s.counters.lock().unwrap();
                if was_stopped {
                    g.exploration.set_status(&exp_id, ExplorationStatus::Blocked);
                    let _ = q.fail(&intent.id, &name, "stopped by operator");
                    // a stopped intent is terminal: burn remaining attempts
                    while q.fail_if_queued(&intent.id, "stopped by operator") {}
                    c.stopped += 1;
                } else if matches!(r, R::TimedOut) {
                    g.exploration.set_status(&exp_id, ExplorationStatus::Failed);
                    *c.fails_by_key.entry(key_of(&intent)).or_default() += 1;
                    if !q.fail(&intent.id, &name, "timed out").unwrap_or(false) { c.failed += 1; }
                } else {
                    // cut off by stop/deadline: resumable, no failure counted.
                    // release() requeues it immediately, so count it here —
                    // the final requeue_claimed() sweep would see nothing left.
                    g.exploration.set_status(&exp_id, ExplorationStatus::Pending);
                    let _ = q.release(&intent.id, &name);
                    c.released += 1;
                }
            }
        }
        s.heartbeats.lock().unwrap().remove(&intent.id);
        s.inflight.fetch_sub(1, Ordering::Relaxed);
        save(&s, &cfg.state_dir);
        s.wake.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exploration_graph::AssetKind;
    use std::collections::BTreeMap;

    fn graph_with_assets(n: usize) -> DualGraph {
        let mut g = DualGraph::default();
        for i in 0..n { g.discover_asset(AssetKind::Endpoint, &format!("/e{i}"), BTreeMap::new(), "recon", None); }
        g
    }

    fn fast(target: &str) -> ReactiveConfig {
        let mut c = ReactiveConfig::new(target);
        c.debounce = Duration::from_millis(5);
        c.heartbeat = Duration::from_millis(50);
        c.drain_grace = Duration::from_millis(100);
        c.intent_timeout = Duration::from_secs(5);
        c
    }

    fn ok_exec() -> ExecFn {
        Arc::new(|i: PlannerIntent, _c: WorkCtx| Box::pin(async move {
            WorkOutcome { ok: true, summary: format!("did {}", i.target), negatives: vec![format!("{} clean", i.target)], ..Default::default() }
        }))
    }

    #[tokio::test]
    async fn runs_until_quiescent_and_records_results_in_the_graph() {
        let cfg = fast("t.com");
        let h = prepare(&cfg, graph_with_assets(4), None);
        let (rep, g) = tokio::time::timeout(Duration::from_secs(20), run(cfg, h, ok_exec())).await.expect("no hang");
        assert_eq!(rep.reason, EndReason::Quiescent);
        assert!(rep.done >= 1 && rep.planner_rounds >= 1);
        assert!(g.exploration.nodes.iter().any(|n| n.kind == ExplorationKind::Negative));
        assert!(g.exploration.nodes.iter().any(|n| n.kind == ExplorationKind::Intent && n.status == ExplorationStatus::Completed));
    }

    #[tokio::test]
    async fn deadline_asks_workers_to_wrap_then_cancels_and_requeues() {
        let mut cfg = fast("t.com");
        cfg.deadline = Some(Duration::from_millis(150));
        let h = prepare(&cfg, graph_with_assets(3), None);
        let saw_wrap = Arc::new(AtomicBool::new(false));
        let sw = saw_wrap.clone();
        let exec: ExecFn = Arc::new(move |_i, c: WorkCtx| { let sw = sw.clone(); Box::pin(async move {
            for _ in 0..500 { if c.wrapping() { sw.store(true, Ordering::Relaxed); } tokio::time::sleep(Duration::from_millis(10)).await; }
            WorkOutcome { ok: true, ..Default::default() }
        })});
        let (rep, _) = tokio::time::timeout(Duration::from_secs(20), run(cfg, h, exec)).await.expect("no hang");
        assert_eq!(rep.reason, EndReason::Deadline);
        assert!(saw_wrap.load(Ordering::Relaxed), "workers must see the wrap-up signal");
        assert!(rep.released >= 1 && rep.settlement.incomplete, "cut-off work goes back to the queue");
    }

    #[tokio::test]
    async fn per_target_failure_cap_stops_a_replanning_loop() {
        let mut cfg = fast("t.com");
        cfg.max_failures_per_target = 2;
        let h = prepare(&cfg, graph_with_assets(2), None);
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let exec: ExecFn = Arc::new(move |_i, _c| { let c2 = c2.clone(); Box::pin(async move {
            c2.fetch_add(1, Ordering::Relaxed);
            WorkOutcome { ok: false, summary: "boom".into(), ..Default::default() }
        })});
        let (rep, _) = tokio::time::timeout(Duration::from_secs(20), run(cfg, h, exec)).await.expect("no hang");
        assert!(matches!(rep.reason, EndReason::Quiescent | EndReason::Budget));
        assert!(calls.load(Ordering::Relaxed) < 40, "bounded, not an endless retry loop: {}", calls.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn stop_cancels_running_work_and_resumes_from_saved_state() {
        let dir = std::env::temp_dir().join(format!("ns-reactive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = fast("t.com");
        cfg.state_dir = Some(dir.clone());
        let h = prepare(&cfg, graph_with_assets(3), None);
        let h2 = h.clone();
        let exec: ExecFn = Arc::new(|_i, _c| Box::pin(async { tokio::time::sleep(Duration::from_secs(30)).await; WorkOutcome { ok: true, ..Default::default() } }));
        let t = tokio::spawn(run(cfg.clone(), h, exec));
        tokio::time::sleep(Duration::from_millis(300)).await;
        h2.stop();
        let (rep, _) = tokio::time::timeout(Duration::from_secs(20), t).await.expect("no hang").unwrap();
        assert_eq!(rep.reason, EndReason::Stopped);
        assert!(rep.released >= 1);
        let (g, q) = resume_state(&dir).expect("state saved");
        assert!(q.runnable() >= 1, "interrupted work is claimable again after resume");
        let cfg2 = fast("t.com");
        let h3 = prepare(&cfg2, g, Some(q));
        let (rep2, _) = tokio::time::timeout(Duration::from_secs(20), run(cfg2, h3, ok_exec())).await.expect("no hang");
        assert_eq!(rep2.reason, EndReason::Quiescent);
        assert!(rep2.done >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn steer_reaches_the_running_intent() {
        let cfg = fast("t.com");
        let h = prepare(&cfg, graph_with_assets(1), None);
        let h2 = h.clone();
        let got = Arc::new(Mutex::new(Vec::<String>::new()));
        let g2 = got.clone();
        let exec: ExecFn = Arc::new(move |i, c: WorkCtx| { let (g2, h2) = (g2.clone(), h2.clone()); Box::pin(async move {
            h2.steer(&i.id, "focus on the id param");
            g2.lock().unwrap().extend(c.take_steer());
            WorkOutcome { ok: true, ..Default::default() }
        })});
        let _ = tokio::time::timeout(Duration::from_secs(20), run(cfg, h, exec)).await.expect("no hang");
        assert_eq!(got.lock().unwrap().first().map(String::as_str), Some("focus on the id param"));
    }
}
