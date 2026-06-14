"""
Orchestrator for NeuroSploit v3.3.0.

Ties the pieces together: load the agent library, apply RL weights to pick and
rank specialist agents for the target, compose the single master prompt (the
`meta/orchestrator` playbook + the recon-aware agent catalog + the operating
contract), hand it to the chosen CLI backend with Playwright MCP, then read back
artifacts and feed the RL loop.
"""

import json
import os
from typing import Dict, List, Optional

from . import backends, mcp, models
from .agent_loader import AgentLibrary
from .config import RunConfig, PATHS, ensure_dirs
from .rl import RLEngine, outcomes_from_findings


def compose_master_prompt(cfg: RunConfig, lib: AgentLibrary, rl: RLEngine,
                          recon: Optional[dict]) -> str:
    weights = rl.weights() if cfg.use_rl else {}
    ranked = lib.ranked(recon, weights)
    if cfg.max_agents > 0:
        ranked = ranked[:cfg.max_agents]
    agent_index = lib.index_markdown(ranked, weights)
    rl_weights_txt = json.dumps({n: round(weights.get(n, 0.5), 2) for n in ranked[:40]}, indent=0)

    orch = lib.render("orchestrator", cfg.target,
                      recon_json=json.dumps(recon or {}), collaborator=cfg.collaborator) \
        if "orchestrator" in lib.meta else ""

    header = f"""# NeuroSploit v3.3.0 — Autonomous Engagement

You are running an AUTHORIZED, autonomous web penetration test.

TARGET: {cfg.target}
SCOPE: {cfg.scope or cfg.target}
RULES OF ENGAGEMENT: {cfg.rules_of_engagement}
OOB COLLABORATOR: {cfg.collaborator or '(none provided — skip OOB-only confirmations)'}
WORKDIR: {cfg.resolved_workdir()}

You have Playwright MCP (browser automation, JS execution, DOM/network capture,
screenshots) and local shell tools. Use the browser to PROVE client-side
execution; use the collaborator to PROVE blind/OOB issues.

## Specialist agent library
The `agents_md/` directory holds {lib.counts()['vulns']} vulnerability playbooks
and {lib.counts()['meta']} meta playbooks. For each specialist you choose to run,
open its file under `agents_md/vulns/<name>.md`, substitute the target and recon,
and follow its methodology and (strict) anti-false-positive System Prompt.

### Recon-ranked candidate agents (by RL priority)
{agent_index}

### RL priors (higher = historically more productive on similar targets)
{rl_weights_txt}
"""

    contract = f"""
## Required pipeline (follow in order)
1. Run `agents_md/meta/recon.md` → write `results/recon.json`.
2. Re-rank the candidate agents above using recon + RL priors; skip agents with
   no applicable surface.
3. Execute each selected specialist; gather candidate findings WITH evidence.
4. For every candidate: `meta/exploit_validator.md` → `meta/false_positive_filter.md`.
   Discard anything not reproducibly exploitable.
5. Score survivors: `meta/severity_assessor.md` then `meta/impact_evaluator.md`.
6. `meta/reporter.md` → write `results/findings.json` AND `reports/report.md`.
7. `meta/rl_feedback.md` → write/merge `data/rl_state.json`.

## Output contract (MANDATORY)
Write `results/findings.json` as a JSON array of objects:
{{"id","agent","title","severity","cvss","cwe","endpoint","payload","evidence","impact","remediation","confidence","validated"}}
Only include findings with `validated: true`. If you find nothing, write `[]`.
Also write `results/agents_ran.json` as a JSON array of the agent names you executed.

Stay strictly in scope. Never run destructive/DoS payloads unless ROE permits.
Report ONLY proven, reproducible findings.
"""
    return "\n".join(x for x in (header, orch, contract) if x.strip())


def collect_results(workdir: str) -> Dict:
    findings, ran = [], []
    fpath = os.path.join(workdir, "findings.json")
    rpath = os.path.join(workdir, "agents_ran.json")
    # The backend may write under results/<slug>/ or results/ — check both.
    for base in (workdir, PATHS["results"]):
        for name, sink in (("findings.json", "findings"), ("agents_ran.json", "ran")):
            p = os.path.join(base, name)
            if os.path.exists(p):
                try:
                    data = json.load(open(p, encoding="utf-8"))
                    if sink == "findings" and not findings:
                        findings = data
                    elif sink == "ran" and not ran:
                        ran = data
                except Exception:
                    pass
    return {"findings": findings, "agents_ran": ran}


def run_engagement(cfg: RunConfig, recon: Optional[dict] = None,
                   progress=lambda m: None) -> Dict:
    ensure_dirs()
    workdir = cfg.resolved_workdir()
    os.makedirs(workdir, exist_ok=True)

    lib = AgentLibrary(PATHS["agents"])
    rl = RLEngine(PATHS["rl_state"])
    progress(f"Loaded {lib.counts()['total']} agents "
             f"({lib.counts()['vulns']} vuln / {lib.counts()['meta']} meta)")

    backend = backends.get(cfg.backend)
    if not backend or not backend.available():
        avail = [b.key for b in backends.detect()]
        raise RuntimeError(f"Backend '{cfg.backend}' not available. Installed: {avail or 'none'}")

    mcp_cfg = None
    if cfg.use_mcp and mcp.playwright_available():
        mcp_cfg = mcp.write_mcp_config(workdir)
        progress("Playwright MCP configured")
    elif cfg.use_mcp:
        progress("WARNING: npx not found — Playwright MCP disabled; browser-proof agents degraded")

    prompt = compose_master_prompt(cfg, lib, rl, recon)
    env = models.resolve_env(cfg.provider, cfg.model)

    progress(f"Launching {backend.label} ({cfg.model}) — autonomous={cfg.autonomous}")
    res = backends.run(backend, prompt, workdir, model=cfg.model,
                       autonomous=cfg.autonomous, mcp_config=mcp_cfg, env=env,
                       timeout=cfg.timeout, dry_run=cfg.dry_run)
    progress(f"Backend exited rc={res.returncode}; log: {res.log_path}")

    out = collect_results(workdir)
    findings = out["findings"] or []
    ran = out["agents_ran"] or []
    progress(f"Collected {len(findings)} validated finding(s) from {len(ran)} agent(s)")

    if cfg.use_rl and not cfg.dry_run:
        tech = ((recon or {}).get("tech", {}) or {}).get("framework", "") or None
        outcomes = outcomes_from_findings(findings, ran, tech=tech)
        rl.update(outcomes, target=cfg.target)
        rl.save()
        progress("RL state updated → data/rl_state.json")

    return {"workdir": workdir, "returncode": res.returncode,
            "findings": findings, "agents_ran": ran, "log": res.log_path}
