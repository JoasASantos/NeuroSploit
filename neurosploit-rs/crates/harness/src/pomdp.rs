//! POMDP decision layer (v3.5.2): value-of-information planning + the
//! anti-hallucination gate.
//!
//! The choice "scan more vs exploit now" is **not** a heuristic here — it falls
//! out of the belief. When a target node's belief is diffuse (high entropy), the
//! expected value of an observation (recon) exceeds that of an exploit, because
//! the observation is expected to sharpen the belief by more than the exploit's
//! risk-adjusted payoff. That same criterion is the anti-hallucination rule: the
//! agent must not assert exploitability while the belief about the target state
//! is diffuse — it must collect more observation first.

use crate::belief::{Kind, WorldModel};

/// What the planner recommends doing next.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Gather an observation about a still-diffuse node (recon).
    Recon { node: String, voi: f64 },
    /// Act on a node the belief is confident about (exploit/report).
    Exploit { node: String, ev: f64 },
    /// Belief is sharp and nothing actionable remains.
    Stop,
}

/// Decision thresholds (tunable; could be learned later).
pub struct Policy {
    /// Above this belief entropy, recon dominates exploit (value-of-information).
    pub explore_entropy: f64,
    /// Minimum P(true) to allow asserting/acting.
    pub assert_min_p: f64,
    /// Maximum entropy to allow asserting/acting (the anti-hallucination ceiling).
    pub assert_max_entropy: f64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { explore_entropy: 0.6, assert_min_p: 0.7, assert_max_entropy: 0.4 }
    }
}

/// Expected value of an observation about a node ≈ how much entropy it can
/// remove, weighted by the node's relevance (Exploit/Credential nodes matter
/// most). A sharp belief has ~0 VoI; a diffuse one has VoI≈1×weight.
pub fn value_of_information(wm: &WorldModel, node_id: &str) -> f64 {
    let Some(n) = wm.nodes.get(node_id) else { return 0.0 };
    let weight = match n.kind {
        Kind::Exploit | Kind::Credential => 1.0,
        Kind::Vuln => 0.8,
        Kind::Service => 0.5,
        Kind::Host => 0.4,
    };
    n.entropy() * weight
}

/// Risk-adjusted expected value of exploiting a node now: only worthwhile when
/// the belief is both high and sharp.
fn exploit_ev(wm: &WorldModel, node_id: &str, pol: &Policy) -> f64 {
    let Some(n) = wm.nodes.get(node_id) else { return 0.0 };
    if n.entropy() > pol.assert_max_entropy {
        return 0.0; // too uncertain — exploiting now is gambling
    }
    n.p
}

/// Decide the next macro-action from the current belief: recon the highest-VoI
/// diffuse node, or exploit the most-confident node, whichever wins.
pub fn decide(wm: &WorldModel, pol: &Policy) -> Action {
    // Best recon candidate by value-of-information.
    let best_recon = wm.nodes.keys()
        .map(|id| (id.clone(), value_of_information(wm, id)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    // Best exploit candidate by risk-adjusted EV.
    let best_exploit = wm.nodes.values()
        .filter(|n| matches!(n.kind, Kind::Exploit | Kind::Vuln | Kind::Credential))
        .map(|n| (n.id.clone(), exploit_ev(wm, &n.id, pol)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    match (best_recon, best_exploit) {
        (Some((rid, voi)), exp) => {
            let ev = exp.as_ref().map(|(_, e)| *e).unwrap_or(0.0);
            // Value-of-information dominates while the belief is diffuse.
            if voi >= ev && voi > (1.0 - pol.explore_entropy) {
                Action::Recon { node: rid, voi }
            } else if let Some((eid, e)) = exp.filter(|(_, e)| *e > 0.0) {
                Action::Exploit { node: eid, ev: e }
            } else {
                Action::Recon { node: rid, voi }
            }
        }
        (None, Some((eid, e))) if e > 0.0 => Action::Exploit { node: eid, ev: e },
        _ => Action::Stop,
    }
}

/// Anti-hallucination gate. A claim of exploitability about `node` may only be
/// asserted when the belief is confident AND sharp. Returns Ok(()) to allow the
/// claim, or Err(reason) to force "collect more observation first".
pub fn may_assert(wm: &WorldModel, node_id: &str, pol: &Policy) -> Result<(), String> {
    match wm.nodes.get(node_id) {
        None => Err("no belief about this target — observe first".into()),
        Some(n) if n.entropy() > pol.assert_max_entropy =>
            Err(format!("belief diffuse (entropy {:.2} > {:.2}) — recon before asserting exploitability",
                n.entropy(), pol.assert_max_entropy)),
        Some(n) if n.p < pol.assert_min_p =>
            Err(format!("belief too low (p {:.2} < {:.2}) — not exploitable on current evidence",
                n.p, pol.assert_min_p)),
        Some(_) => Ok(()),
    }
}
