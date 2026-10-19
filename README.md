<h1 align="center">🧠 NeuroSploit v4.4.0</h1>

<p align="center">
  <a href="https://github.com/JoasASantos/NeuroSploit/stargazers"><img src="https://img.shields.io/github/stars/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=8b5cf6" alt="Stars"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/network/members"><img src="https://img.shields.io/github/forks/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=a855f7" alt="Forks"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/issues"><img src="https://img.shields.io/github/issues/JoasASantos/NeuroSploit?style=for-the-badge&color=22d3ee" alt="Issues"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-4.4.0-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Harness-Rust%20%7C%20tokio-e6b673?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/MD%20Agents-486-red?style=flat-square">
  <img src="https://img.shields.io/badge/Modes-Black%20%7C%20White%20%7C%20Grey%20%7C%20Host%20%7C%20AI%20%7C%20Mobile%20%7C%20Container-9cf?style=flat-square">
</p>

<p align="center">
  <a href="https://neurosploitai.github.io/"><img src="https://img.shields.io/badge/Website-neurosploitai.github.io-8b5cf6?style=for-the-badge&logo=githubpages&logoColor=white" alt="Website"></a>
  <a href="https://neurosploitai.github.io/docs.html"><img src="https://img.shields.io/badge/Docs-Tutorial%20%26%20Guide-22d3ee?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Docs"></a>
</p>

<p align="center"><b>Autonomous, multi-model penetration-testing harness — Rust, CLI-first.</b><br>
<i>by Joas A Santos &amp; Red Team Leaders</i></p>

---

## What is NeuroSploit?

**NeuroSploit is an autonomous penetration-testing tool.** You point it at a
target; it does the security assessment on its own and hands you a report —
recon, exploitation, chaining findings into real impact, and validation, with no
human driving each step.

The key idea: **the harness is the pentester, not the model.** Instead of asking
one LLM to "hack this", a Rust engine runs the methodology — it picks the right
specialist agents for what it finds, runs them in parallel, re-sends every claim
over the wire to confirm it's real, and has a second model check each finding
before it's reported. The LLMs are the hands; the harness is the discipline that
keeps them honest. That's why it finds more and invents less than running a model
directly.

It's **CLI-first** (with a web console and a TUI), **open source (MIT)**, and runs
on **your own API keys or a local subscription** — nothing about your targets
leaves your machine unless you send it.

---

Give NeuroSploit a **URL, a source repo, a running app, or a host/IP**. A Rust
harness (`tokio`) drives a **pool of LLMs** — via **API key** or local
**subscription** (Claude Code / Codex / Gemini / Grok) — and runs the whole
engagement for you:

```
recon ─▶ pick only the agents that fit the surface ─▶ exploit in parallel
      ─▶ wire-check every claim ─▶ cross-model vote ─▶ chain into deeper impact ─▶ report
```

It won't invent findings: **every claim needs a receipt** (raw tool output or a
`file:line`), is **re-sent by the harness itself** to confirm it reproduces, and
is adjudicated by a **second model** before it reaches the report.

> ⭐ Useful? **Star the repo.**
> 🌐 Website & live docs: **[neurosploitai.github.io](https://neurosploitai.github.io/)** · **[Tutorial & Guide](https://neurosploitai.github.io/docs.html)**
> 📖 Deep dive: **[TUTORIAL.md](TUTORIAL.md)** · changelog: **[RELEASE.md](RELEASE.md)** · honest comparison: **[BENCHMARK.md](BENCHMARK.md)**

## Install

**Linux / macOS** (x64 & arm64):
```bash
curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
```
**Windows** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
```
The installer sets up Rust if missing, builds the release binary, and links
`neurosploit` onto your PATH. Build by hand instead:
```bash
git clone https://github.com/JoasASantos/NeuroSploit && cd NeuroSploit/neurosploit-rs
cargo build --release      # → target/release/neurosploit
```

## Quick start

```bash
# just run it — the interactive session asks everything, in plain language:
neurosploit

# black-box, subscription login (no API key):
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v

# white-box — review a source repo (file:line evidence):
neurosploit whitebox /path/to/repo --subscription --model anthropic:claude-opus-4-8 -v

# web console — a browser UI over the same CLI:
cd web && npm start     # → http://localhost:4173
```

No subscription? Use an **API key** for any provider instead — see [TUTORIAL.md](TUTORIAL.md#authentication).

## Modes

| Mode | Command | What it does |
|------|---------|-------------|
| **Black-box** | `neurosploit run <url>` | recon → select → exploit → vote → report |
| **White-box** | `neurosploit whitebox <repo>` | source / SAST review (file:line evidence) |
| **Grey-box** | `neurosploit greybox <repo> --url <app>` | code review **+** live exploitation together |
| **Host / Infra** | `neurosploit host <ip> --creds creds.yaml` | Linux / Windows / AD + cloud (AWS/GCP/Azure) |
| **AI / LLM** | `neurosploit aitest <ai-url>` | jailbreaks, prompt injection, OWASP LLM Top 10 / MCP |
| **Mobile / Binary** | `neurosploit mobile <app.apk\|.ipa\|bin>` | RE a local artifact (Ghidra / MobSF / Frida) |
| **Container** | `neurosploit container <image:tag>` | OCI image scan + SBOM (trivy/grype/syft) |
| **Mission Control** | `neurosploit tui <url>` | live TUI panels + a composer you type in mid-run |

## What makes it different

- **The harness is the pentester.** Agent selection is recon-driven; findings
  **chain** (reduce a foothold to a primitive — exec / read / write / SSRF /
  identity / secret — then pivot), each stage proven and non-destructive.
- **Wire-bound evidence** — every reported exchange is re-sent through a
  scope-guarded replay engine and checked against recorded traffic. A claim the
  wire contradicts can't stand as confirmed.
- **Attack knowledge graph (Neo4j optional)** — the run is a typed graph of
  hosts, services, findings, credentials and impact, spanning **web and internal
  network**. It directs the next move during the run and is written to `graph/`
  even without a database.
- **Deterministic validation** — per-CWE validators judge the measured
  request/response bytes, not the model's prose. Grounding gate, POMDP belief and
  an anti-hallucination check demote anything the evidence doesn't support.
- **Secrets never leak the report** — credentials the agents observe become
  `$SECRET_n` in every human-facing report; raw values stay in the run's vault for
  re-testing only.
- **Execution resilience** — classified error handling (7 error types), exponential
  backoff (5 retries, 2s–90s), crash-state salvage (partial findings survive agent
  failure), agent lifecycle nudge (3 retries with simplified prompts), progressive
  budget warnings (70/85/95%), and run snapshot/resume so interrupted engagements
  pick up where they left off.
- **LLM-powered dedup** — deterministic fast-path for exact matches, plus a
  semantic LLM judge for findings with different wording but the same root cause.
- **486 markdown agents** across web, code (SAST), AI, infra/AD/cloud, chains and
  recon — each a self-contained playbook you can read, edit or add to.
- **Run via API key or subscription**, 19 providers, including local & CPU-only
  (`ollama:` / `llamacpp:`) with no data leaving the host.

## Web console

```bash
cd web && npm start     # → http://localhost:4173
```
A browser UI that drives the **same CLI** — no second engine. Launch and watch a
run live, then per finding:

- **Attack graph** — host → service → finding → credential → impact, every edge
  marked confirmed / needs-validation / hypothesis, ordered by kill-chain stage.
- **Wire evidence** — the real request/response pairs behind a finding (baseline
  vs. attack, the identity pair, matrix probes, the oracle), each tagged with its
  wire provenance — the proof as bytes, not prose.
- **Re-test one finding** — re-run its proof through the replay engine; the dated
  history shows a finding drift to "gone" over time.
- **Transcript viewer** — any agent's run, split into navigable blocks; search
  spans every agent.
- Chains, dependency todolist, recorded traffic, deliverables, PDF export.

## What a run leaves behind

Every run is a self-contained folder, `runs/ns-<ts>-<target>/`:

| File | Contents |
|------|----------|
| `report.html` · `report.pdf` · `report.md` | the report (PDF via Typst), secrets redacted |
| `findings.json` / `findings.md` | validated findings (raw, for tools & re-testing) |
| `report.sarif` | SARIF 2.1.0 for CI code-scanning |
| `graph/` | attack chains, dependency todolist, Cypher + JSON export |
| `recon.json` · `exploitation.md` · `traces/` | surface, transcript, per-agent traces |
| `pocs/` · `evidence/` | runnable PoCs and proof screenshots |

## Integrations

GitHub / GitLab PR review gate (`neurosploit pr <repo> <n> --fail-on critical`),
`@neurosploit` mention bot, one Jira card per finding, MCP server
(`neurosploit mcp`), compliance mapping (PCI-DSS / HIPAA / SOC 2 / GDPR). See
**[TUTORIAL.md](TUTORIAL.md)**.

## Safety

For **authorized** testing only. Agents stay in scope, never run destructive / DoS
actions, and require proof of exploitation. You are responsible for having
permission for every target.

## Credits & license

**Joas A Santos** & **Red Team Leaders** — MIT.

> This is the slim, **Rust-only** distribution (`neurosploit-rs/` + `agents_md/`).
> The older Python engine and web GUIs live on the `v3.4.0` branch.
