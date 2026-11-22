<div align="center">

<img src="web/public/logo.svg" width="120" alt="NeuroSploit">

# NeuroSploit

**Autonomous penetration-testing harness — Rust, multi-model, CLI-first.**

[![Stars](https://img.shields.io/github/stars/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=8b5cf6)](https://github.com/JoasASantos/NeuroSploit/stargazers)
[![Forks](https://img.shields.io/github/forks/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=a855f7)](https://github.com/JoasASantos/NeuroSploit/network/members)
[![Issues](https://img.shields.io/github/issues/JoasASantos/NeuroSploit?style=for-the-badge&color=22d3ee)](https://github.com/JoasASantos/NeuroSploit/issues)

<br>

[![Rust](https://img.shields.io/badge/Rust-tokio%20async-e6b673?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Agents](https://img.shields.io/badge/MD%20Agents-486-red?style=flat-square)](agents_md/)
[![Modes](https://img.shields.io/badge/Modes-8-9cf?style=flat-square)](#modes)
[![MCP Profiles](https://img.shields.io/badge/MCP%20Profiles-12-f59e0b?style=flat-square)](#mcp-profiles)
[![Providers](https://img.shields.io/badge/LLM%20Providers-19-38bdf8?style=flat-square)](#providers)

<br>

[**Website**](https://neurosploitai.github.io/) · [**Docs & Tutorial**](https://neurosploitai.github.io/docs.html) · [**TUTORIAL.md**](TUTORIAL.md) · [**BENCHMARK.md**](BENCHMARK.md)

</div>

---

## What is NeuroSploit?

Point it at a target. It runs the security assessment autonomously and hands you a report — recon, exploitation, chaining, validation — no human driving each step.

**The harness is the pentester, not the model.** A Rust engine runs the methodology: picks specialist agents for what it finds, runs them in parallel, re-sends every claim over the wire to confirm it's real, and has a second model check each finding before reporting. The LLMs are the hands; the harness is the discipline.

```
recon ─▶ select agents ─▶ exploit in parallel ─▶ wire-check ─▶ cross-model vote ─▶ chain ─▶ report
```

---

## Install

```bash
# Linux / macOS (x64 & arm64)
curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex

# From source
git clone https://github.com/JoasASantos/NeuroSploit && cd NeuroSploit/neurosploit-rs
cargo build --release      # → target/release/neurosploit
```

## Quick Start

```bash
# Interactive wizard (asks everything):
neurosploit

# Black-box with subscription:
neurosploit run http://target.com --subscription --model anthropic:claude-opus-4-8 -v

# White-box source review:
neurosploit whitebox /path/to/repo --subscription --model anthropic:claude-opus-4-8 -v

# Host / AD / infra:
neurosploit host 10.0.0.5 --subscription --model anthropic:claude-opus-4-8 -v

# Web console:
cd web && npm start     # → http://localhost:3000
```

---

## Modes

| Mode | Command | Surface |
|:-----|:--------|:--------|
| **Black-box** | `neurosploit run <url>` | Web apps, APIs — recon → exploit → vote → report |
| **White-box** | `neurosploit whitebox <repo>` | Source / SAST review (`file:line` evidence) |
| **Grey-box** | `neurosploit greybox <repo> --url <app>` | Code review **+** live exploitation |
| **Host / Infra** | `neurosploit host <ip>` | Linux, Windows, AD, cloud (AWS/GCP/Azure) |
| **AI / LLM** | `neurosploit aitest <ai-url>` | Jailbreaks, prompt injection, OWASP LLM Top 10 |
| **Mobile** | `neurosploit mobile <app.apk\|.ipa>` | APK/IPA RE (Ghidra / MobSF / Frida) |
| **Container** | `neurosploit container <image:tag>` | OCI scan + SBOM (trivy/grype/syft) |
| **Mission Control** | `neurosploit tui <url>` | Live TUI with mid-run composer |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     NeuroSploit Harness                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │  Recon   │─▶│  Select  │─▶│ Parallel │─▶│  Validate  │  │
│  │  Engine  │  │  486 MDs │  │  Exploit │  │  Wire+Vote │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
│       │              │              │              │         │
│       ▼              ▼              ▼              ▼         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          Attack Knowledge Graph (Neo4j opt.)         │   │
│  │   Host → Service → Finding → Credential → Impact    │   │
│  └──────────────────────────────────────────────────────┘   │
│       │                                      │              │
│       ▼                                      ▼              │
│  ┌──────────┐                        ┌────────────┐         │
│  │  Chain   │                        │   Report   │         │
│  │  Engine  │                        │ HTML·PDF·MD│         │
│  └──────────┘                        └────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  LLM Pool: Claude · GPT · Gemini · Grok · GLM · DeepSeek  │
│  Qwen · Kimi · Mistral · Ollama · LiteLLM · 19 providers  │
└─────────────────────────────────────────────────────────────┘
```

---

## MCP Profiles

Built-in profiles swap the tool surface at runtime:

| Profile | Tools | Use Case |
|:--------|:------|:---------|
| `Web` | Playwright browser automation | Web app testing |
| `MobileAndroid` / `MobileIos` | REA reverse engineering | APK/IPA analysis |
| `BinaryAnalysis` | REA decompiler, call graphs | Native binary RE |
| `BurpSuite` | Burp REST API | Proxy-driven testing |
| `CobaltStrike` | Official CS MCP (team server) | C2 integration |
| `Infra` / `Nmap` | Nmap MCP server | Network discovery |
| `AD` / `Kali` | Kali MCP (80+ tools) | AD / full toolkit |
| `Cloud` | Trivy, Prowler, ScoutSuite | Cloud posture |

```bash
neurosploit run http://target.com --mcp-profile web
neurosploit host 10.0.0.5 --mcp-profile ad
```

---

## Toolbox & C2

- **Toolbox (225 tools):** nmap, rustscan, httpx, nuclei, ffuf, netexec, impacket, bloodhound, trivy, apktool, ghidra and more. `neurosploit tools list`
- **MCP servers:** `neurosploit tools mcp add nmap` then `--mcp`
- **C2 & WebShell:** Authorized engagements only. Listeners, sessions, tasks, payloads, audit trail under `.neurosploit/c2/`
- **Pivot Proxy:** Multi-hop tunnel engine through compromised hosts — portproxy, chisel, SOCKS. `--pivot-proxy auto`

---

## What Makes It Different

| Feature | How |
|:--------|:----|
| **Wire-bound evidence** | Every claim re-sent through scope-guarded replay engine |
| **Attack knowledge graph** | Typed graph: hosts, services, findings, credentials, impact |
| **Per-CWE validators** | Deterministic judgment on measured bytes, not prose |
| **Secret redaction** | Credentials become `$SECRET_n` in reports; raw in vault only |
| **Execution resilience** | 7 error types, exponential backoff, crash-state salvage, resume |
| **LLM-powered dedup** | Fast-path exact + semantic judge for same root cause |
| **Multi-hop pivoting** | Auto-detect unreachable subnets, establish tunnel chains |
| **Universal cache** | Identical prompts served from memory/disk — token savings |

---

## Providers

19 LLM providers supported — API key or local subscription:

`anthropic` · `openai` · `gemini` · `azure` · `xai` · `nvidia_nim` · `deepseek` · `mistral` · `qwen` · `zai` · `moonshot` · `groq` · `together` · `openrouter` · `opencode` · `nous` · `ollama` · `litellm`

Multi-model voting: `--model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3`

---

## Web Console

```bash
cd web && npm start     # → http://localhost:3000
```

- **Attack graph** — host → service → finding → credential → impact, with clickable filters
- **Wire evidence** — real request/response pairs with wire provenance
- **Re-test** — re-run proof through replay engine
- **Chains & todo** — attack chains with validation status
- **Transcript viewer** — per-agent run split into navigable blocks
- **PDF export** — via Typst

---

## Run Output

Every run → `runs/ns-<ts>-<target>/`:

| File | Contents |
|:-----|:---------|
| `report.html` · `.pdf` · `.md` | Report (PDF via Typst), secrets redacted |
| `findings.json` / `.md` | Validated findings for tooling & re-testing |
| `report.sarif` | SARIF 2.1.0 for CI code-scanning |
| `graph/` | Attack chains, todo, Cypher + JSON export |
| `attack-paths.json` · `.mmd` | Cross-domain paths (graph + Mermaid) |
| `loot.json` | Credentials, tokens, hosts, endpoints |
| `pocs/` · `evidence/` | Runnable PoCs and proof screenshots |

---

## Integrations

GitHub / GitLab PR review gate · `@neurosploit` mention bot · Jira cards per finding · MCP server (`neurosploit mcp`) · Compliance mapping (PCI-DSS / HIPAA / SOC 2 / GDPR) · Neo4j graph · OpenSearch logs

---

## Safety

For **authorized** testing only. Agents stay in scope, never run destructive/DoS actions, and require proof of exploitation. You are responsible for having permission for every target.

---

<div align="center">

**Joas A Santos** & **Red Team Leaders** — MIT License

</div>
