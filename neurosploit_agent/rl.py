"""
Reinforcement-learning engine for NeuroSploit v3.3.0.

A lightweight, persisted reward loop that biases agent selection across runs.
It is deliberately model-free and explainable: each specialist agent carries a
weight in [0.05, 1.0] plus per-tech-stack affinity, updated after every run from
validated findings (positive reward) and rejected false positives (negative).

This mirrors `agents_md/meta/rl_feedback.md`: the markdown agent reasons about
rewards qualitatively; this module applies them deterministically so the state
file is reproducible and auditable.
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(ROOT, "data", "rl_state.json")

SEVERITY_REWARD = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.05}
FP_PENALTY = 0.3
IDLE_PENALTY = 0.05      # ran, found nothing, cost budget
ALPHA = 0.3             # learning rate
WMIN, WMAX = 0.05, 1.0


@dataclass
class Outcome:
    agent: str
    validated: List[str]        # severities of validated findings
    false_positives: int = 0
    ran: bool = True
    skipped_correctly: bool = False
    tech: Optional[str] = None


def _clamp(x: float) -> float:
    return max(WMIN, min(WMAX, x))


class RLEngine:
    def __init__(self, path: str = STATE_PATH):
        self.path = path
        self.state = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                return json.load(open(self.path, encoding="utf-8"))
            except Exception:
                pass
        return {"version": 1, "agents": {}}

    def weights(self) -> Dict[str, float]:
        return {name: rec.get("weight", 0.5) for name, rec in self.state.get("agents", {}).items()}

    def weight(self, agent: str, tech: Optional[str] = None) -> float:
        rec = self.state.get("agents", {}).get(agent)
        if not rec:
            return 0.5
        w = rec.get("weight", 0.5)
        if tech:
            w = max(w, rec.get("tech_affinity", {}).get(tech, 0.0) or 0.0)
        return w

    def reward(self, o: Outcome) -> float:
        if o.skipped_correctly:
            return 0.0
        if not o.ran:
            return 0.0
        r = sum(SEVERITY_REWARD.get(s.lower(), 0.2) for s in o.validated)
        r -= FP_PENALTY * o.false_positives
        if not o.validated and not o.false_positives:
            r -= IDLE_PENALTY
        return max(-1.0, min(1.0, r))

    def update(self, outcomes: List[Outcome], target: str = "") -> dict:
        agents = self.state.setdefault("agents", {})
        for o in outcomes:
            rec = agents.setdefault(o.agent, {
                "weight": 0.5, "runs": 0, "validated_hits": 0,
                "false_positives": 0, "reward_last": 0.0, "tech_affinity": {},
            })
            r = self.reward(o)
            old = rec["weight"]
            rec["weight"] = _clamp(old + ALPHA * (r - old))
            rec["reward_last"] = round(r, 3)
            if o.ran and not o.skipped_correctly:
                rec["runs"] += 1
            rec["validated_hits"] += len(o.validated)
            rec["false_positives"] += o.false_positives
            if o.tech:
                ta = rec.setdefault("tech_affinity", {})
                ta[o.tech] = _clamp((ta.get(o.tech, 0.5)) + ALPHA * (r - ta.get(o.tech, 0.5)))
        self.state["updated_for"] = target
        return self.state

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        json.dump(self.state, open(self.path, "w", encoding="utf-8"), indent=2)


def outcomes_from_findings(findings: List[dict], ran_agents: List[str],
                           tech: Optional[str] = None) -> List[Outcome]:
    """Build per-agent Outcomes from a run's findings + the agents that ran."""
    by_agent: Dict[str, Outcome] = {
        a: Outcome(agent=a, validated=[], false_positives=0, ran=True, tech=tech)
        for a in ran_agents
    }
    for f in findings:
        a = f.get("agent")
        if a not in by_agent:
            by_agent[a] = Outcome(agent=a, validated=[], false_positives=0, ran=True, tech=tech)
        if f.get("validated"):
            by_agent[a].validated.append(f.get("severity", "Low"))
        elif f.get("verdict") == "false_positive":
            by_agent[a].false_positives += 1
    return list(by_agent.values())


if __name__ == "__main__":
    rl = RLEngine()
    print(json.dumps(rl.weights(), indent=2))
