# Legacy (pre-v3.3.0) Python orchestration

These files are the **previous** orchestration architecture, retired in
NeuroSploit v3.3.0 when the pentest agent was re-modeled into an autonomous,
markdown-driven engine that delegates execution to a local agentic CLI backend.

Kept for reference and migration only — **not** used by the v3.3.0 engine.

| Path | What it was |
|------|-------------|
| `neurosploit_legacy.py` | The 2,500-line monolithic CLI/orchestrator (`NeuroSploitv2`) |
| `agents_python/` | Hand-coded Python agent classes (web/exploitation/lateral/privesc/persistence/recon) |
| `custom_agents/` | Example custom Python agent |

## What replaced it

- **`neurosploit` + `neurosploit_agent/`** — the lean autonomous engine
  (`orchestrator`, `agent_loader`, `backends`, `rl`, `mcp`, `models`, `cli`).
- **`agents_md/`** — 213 curated markdown agents (196 vuln specialists + 17
  meta-agents) that the engine composes into a master prompt.
- The engine runs **Claude Code / Codex / Grok CLI** (or a Claude subscription)
  as the autonomous runtime, with **Playwright MCP** for browser-based proof and
  a **reinforcement-learning** loop that adapts agent selection across runs.

Run `./neurosploit` (interactive) or `./neurosploit run <url>` to use the new engine.
