# NeuroSploit v3.3.0

![NeuroSploit](https://img.shields.io/badge/NeuroSploit-Autonomous%20AI%20Pentest-blueviolet)
![Version](https://img.shields.io/badge/Version-3.3.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Agents](https://img.shields.io/badge/MD%20Agents-213-red)
![Backends](https://img.shields.io/badge/CLI%20Backends-Claude%20%7C%20Codex%20%7C%20Grok-informational)
![MCP](https://img.shields.io/badge/MCP-Playwright-orange)

**Autonomous, markdown-driven AI penetration testing.**

NeuroSploit v3.3.0 is a ground-up re-model of the pentest agent. Instead of a
monolithic Python orchestrator, it is now a **lean engine that turns a URL into
an autonomous engagement**: it composes a master prompt from a curated library
of **213 markdown agents** and hands execution to whichever **agentic CLI
backend** you have installed — **Claude Code, Codex, or Grok CLI** (or a Claude
subscription) — augmented with **Playwright MCP** for real browser-based proof,
and a **reinforcement-learning** loop that gets smarter every run.

> The previous Python orchestration now lives in [`legacy/`](legacy/README.md).

---

## Why this architecture

| Old (≤ v3.2.4) | New (v3.3.0) |
|----------------|-------------|
| 2,500-line Python orchestrator + hand-coded agent classes | Markdown agents + thin engine |
| One embedded LLM loop | Pluggable agentic CLI backends (Claude/Codex/Grok) |
| Provider SDK juggling | Backend owns the agent loop; engine just composes & collects |
| Static agent list | RL-weighted, recon-aware agent selection |
| Reflection-based "evidence" | Playwright MCP proof-of-execution + adversarial validation |

---

## How it works

```
          ┌──────────────────────────────────────────────────────────────┐
   URL ──▶ │  neurosploit (terminal)                                       │
          │     │                                                          │
          │     ▼                                                          │
          │  orchestrator ── loads agents_md/ (213) ── applies RL weights  │
          │     │                                                          │
          │     ▼  composes ONE master prompt                              │
          │  backend (Claude Code | Codex | Grok)  ◀── Playwright MCP      │
          │     │  autonomously runs the pipeline below                    │
          │     ▼                                                          │
          │  recon → select agents → exploit → VALIDATE → filter FPs       │
          │        → severity → impact → report → RL feedback              │
          └──────────────────────────────────────────────────────────────┘
                       │                          │
                       ▼                          ▼
              results/findings.json        data/rl_state.json (learns)
```

The engine never fabricates findings: every candidate is independently
re-exploited (`meta/exploit_validator`), run through an adversarial skeptic
(`meta/false_positive_filter`), and only then scored and reported.

---

## The agent library (`agents_md/`)

**213 agents** — see [`agents_md/REGISTRY.md`](agents_md/REGISTRY.md).

- **196 vulnerability specialists** (`agents_md/vulns/`) — each a self-contained
  playbook with a real methodology, payloads, CWE mapping, and a strict
  anti-false-positive `## System Prompt`. Coverage includes the classic OWASP
  web set **plus modern classes**:
  - **LLM/AI security** (OWASP LLM Top 10): prompt injection (direct/indirect),
    jailbreak, system-prompt leak, insecure output handling, RAG poisoning,
    tool-invocation/function-calling abuse, excessive agency, PII leakage…
  - **Cloud/K8s/containers**: IMDS SSRF (AWS/GCP/Azure), kubelet/dashboard
    exposure, container & docker-socket escape, bucket takeover, IAM privesc…
  - **Modern API/auth**: JWT alg/kid/jwk confusion, OAuth PKCE downgrade, SAML
    XSW, OIDC, CSWSH, refresh-token & MFA bypass, account-takeover chains…
  - **Advanced injection**: SSTI (Jinja2/FreeMarker/Velocity/Thymeleaf), SSPP,
    XXE OOB, YAML/pickle deserialization, JNDI, XSLT…
  - **Protocol/cache/smuggling**: HTTP/2 & CL.TE/TE.CL desync, h2c, web cache
    deception/poisoning, response splitting, path-confusion…
  - **Logic/crypto/supply-chain**: dependency confusion, padding oracle, weak
    JWT secret, price/coupon/workflow abuse, exposed `.git`/`.env`/CI secrets…

- **17 meta-agents** (`agents_md/meta/`): `orchestrator`, `recon`,
  `exploit_validator`, `false_positive_filter`, `severity_assessor`,
  `impact_evaluator`, `reporter`, `rl_feedback`, plus migrated expert roles.

Add your own by dropping a `.md` into `agents_md/vulns/` (or extend the
data-driven builder, `scripts/build_agents.py`). It is picked up automatically.

---

## Quickstart

```bash
# 1. Have at least one agentic CLI installed: Claude Code, Codex, or Grok CLI
#    (Playwright MCP needs Node/npx)
./neurosploit backends          # show what's detected
./neurosploit agents            # {'vulns': 196, 'meta': 17, 'total': 213}

# 2. Interactive: enter a URL, pick a backend + model, go
./neurosploit

# 3. Or one-shot:
./neurosploit run https://target.example \
    --backend claude --model claude-opus-4-8 \
    --collaborator oob.your-collab.net

# 4. Preview the composed master prompt without executing the backend:
./neurosploit run https://target.example --dry-run
```

Outputs land in `results/<target>/findings.json` and `reports/`, and the RL
state updates in `data/rl_state.json`.

### Backends

| Backend | Binary | Autonomy flag | Subscription |
|---------|--------|---------------|--------------|
| Claude Code | `claude` | `--dangerously-skip-permissions` | ✅ via Claude login |
| Codex CLI | `codex` | `--dangerously-bypass-approvals-and-sandbox` | — |
| Grok CLI | `grok` | `--yolo` | — |

The engine auto-detects installed backends and only offers those. In the
interactive flow, answering **yes** to "Use Claude subscription" runs Claude Code
against your logged-in subscription instead of an API key.

### Models

Latest models per provider live in `neurosploit_agent/models.py`, including the
**NVIDIA NIM** provider (PR #28, OpenAI-compatible at
`https://integrate.api.nvidia.com/v1`, `nvapi-` keys), Anthropic Claude 4.x,
OpenAI, xAI Grok, Gemini, OpenRouter, and local Ollama.

---

## Reinforcement learning

Every run produces per-agent reward signals (`meta/rl_feedback` +
`neurosploit_agent/rl.py`): validated findings reward an agent (weighted by
severity), rejected false positives penalize it, correct skips stay neutral.
Weights are bounded `[0.05, 1.0]` and carry per-tech-stack affinity, so the
engine learns, e.g., to prioritize `ssti_jinja2` on Flask targets. State is
explainable and persisted to `data/rl_state.json`.

---

## Safety & authorization

NeuroSploit is for **authorized** security testing only. Every agent's system
prompt enforces scope and proof-of-exploitation; DoS-class agents refuse to
flood and require explicit rules-of-engagement. You are responsible for having
written permission for any target you point it at.

---

## Repository layout

```
neurosploit                 # launcher (./neurosploit)
neurosploit_agent/          # the v3.3.0 engine
  cli.py  orchestrator.py  agent_loader.py  backends.py  rl.py  mcp.py  models.py  config.py
agents_md/
  vulns/   (196)            # vulnerability specialist agents
  meta/    (17)             # orchestrator, recon, validator, scorers, reporter, RL, roles
  REGISTRY.md               # generated index
scripts/build_agents.py     # data-driven agent builder
legacy/                     # retired pre-v3.3.0 Python orchestration
```

See [`RELEASE.md`](RELEASE.md) for the full v3.3.0 changelog.

---

## License

MIT.
