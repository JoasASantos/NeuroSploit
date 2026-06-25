# NeuroSploit — Tutorial & User Guide (v3.5.1)

A complete, hands-on guide to installing, configuring and running NeuroSploit —
the autonomous, multi-model penetration-testing harness.

> ⚠️ **Authorized testing only.** Every agent is instructed to stay in scope and
> never run destructive/DoS actions. You are responsible for having written
> permission for any target you point it at.

---

## Table of contents

1. [Concepts in 60 seconds](#1-concepts-in-60-seconds)
2. [Install](#2-install)
3. [Authentication: API key vs subscription](#3-authentication-api-key-vs-subscription)
4. [Choosing models](#4-choosing-models)
5. [Engagement modes](#5-engagement-modes)
   - [Black-box (URL)](#51-black-box-url)
   - [White-box (source repo)](#52-white-box-source-repo)
   - [Grey-box (code + live app)](#53-grey-box-code--live-app)
   - [Host / Infra (Linux / Windows / AD)](#54-host--infra-linux--windows--ad)
6. [The interactive REPL](#6-the-interactive-repl)
7. [Mission Control TUI](#7-mission-control-tui)
8. [Credentials (`creds.yaml`)](#8-credentials-credsyaml)
9. [Steering the tests (focus & instructions)](#9-steering-the-tests)
10. [Outputs, reports & artifacts](#10-outputs-reports--artifacts)
11. [Per-project memory & resume](#11-per-project-memory--resume)
12. [How it decides: POMDP, grounding, chaining](#12-how-it-decides)
13. [The agent library](#13-the-agent-library)
14. [Playwright MCP & extra tools](#14-playwright-mcp--extra-tools)
15. [Tips, tuning & troubleshooting](#15-tips-tuning--troubleshooting)
16. [Command & flag reference](#16-command--flag-reference)

---

## 1. Concepts in 60 seconds

You give NeuroSploit a **target** (URL, repo, app, or host/IP). It:

1. **Recons** the target with real tools (curl/nmap/…).
2. **Intelligently selects** only the agents whose preconditions match the recon
   (it does *not* blindly run all 329).
3. **Exploits** in parallel — each agent works in a ReAct loop and must prove its
   claim with a **tool receipt** (raw output).
4. **Validates** every candidate by **cross-model voting** (a different model
   adjudicates) and a **grounding gate** (no claim without a receipt).
5. **Chains** confirmed findings into deeper impact (SQLi→RCE→LPE, SSRF→cloud…).
6. **Reports** — HTML + Typst PDF + JSON/MD, with an attack-graph / kill-chain
   mapped to OWASP / CWE / MITRE ATT&CK.

It runs on a **pool of LLMs** you choose, authenticated either by **API key** or
your local **subscription** (Claude Code / Codex / Gemini / Grok CLI).

---

## 2. Install

### One-liner

**Linux / macOS** (x64 & arm64):
```bash
curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
```

**Windows** (PowerShell, x64 & arm64):
```powershell
irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
```

The installer detects your OS/arch, installs the Rust toolchain if needed, clones
the repo, builds the release binary and puts `neurosploit` on your PATH. Re-run it
any time to update. Env knobs: `NEUROSPLOIT_REF` (branch/tag), `NEUROSPLOIT_DIR`,
`PREFIX`.

### Manual build

```bash
git clone https://github.com/JoasASantos/NeuroSploit
cd NeuroSploit/neurosploit-rs
cargo build --release        # → target/release/neurosploit
```

### Recommended runtime

Run inside **Kali Linux** (or the Docker image) so the offensive tools the agents
use are already present:

```bash
docker run -it --rm kalilinux/kali-rolling
apt update && apt install -y curl nmap ffuf nodejs npm
# optional: cargo install rustscan ; cargo install typst-cli
```

Agents **degrade gracefully**: if `rustscan` is absent they use `nmap`; if neither,
`curl`. With Playwright MCP present they drive a real browser; otherwise `curl`.

### Verify

```bash
neurosploit --version          # neurosploit 3.5.1
neurosploit agents             # {"vulns":196,...,"chains":12,"total":329}
neurosploit models             # all providers & models
```

---

## 3. Authentication: API key vs subscription

You pick **per run**. They're independent.

### A) Via API key

Export the key for each provider you'll use, then run **without** `--subscription`:

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # anthropic:claude-*
export OPENAI_API_KEY=sk-...             # openai:gpt-*
export GEMINI_API_KEY=AIza...            # gemini:gemini-*
export XAI_API_KEY=xai-...               # xai:grok-*
export NVIDIA_NIM_API_KEY=nvapi-...      # nvidia_nim:*
export DEEPSEEK_API_KEY=...              # deepseek:*
export MISTRAL_API_KEY=...               # mistral:*
export DASHSCOPE_API_KEY=...             # qwen:*  (Alibaba DashScope)
export GROQ_API_KEY=...                  # groq:*
export TOGETHER_API_KEY=...              # together:*
export OPENROUTER_API_KEY=...            # openrouter:*
# ollama: no key (local)

neurosploit run http://testphp.vulnweb.com/ --model anthropic:claude-opus-4-8 --vote-n 3 -v
```

Or put them in a `.env` and source it (`cp .env.example .env`; edit; `set -a; . ./.env; set +a`).
In the REPL you can also run `/key anthropic sk-ant-...` (it lists which providers
your selected models need).

### B) Via subscription (no API key)

Install and log into a local agentic CLI, then pass `--subscription`:

| `--model` prefix | CLI | Login |
|------------------|-----|-------|
| `anthropic:` | Claude Code (`claude`) | `claude` → `/login` |
| `openai:` | Codex (`codex`) | codex login |
| `gemini:` | Gemini (`gemini`) | gemini login |
| `xai:` | Grok (`grok`) | grok login |

```bash
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp -v
```

---

## 4. Choosing models

`--model provider:model` is **repeatable**. The **first** model is the primary
(does recon & exploitation); the **rest fail over** if it errors **and** form the
**validator voting jury** (a different model adjudicates each finding → fewer false
positives).

```bash
# single model
--model anthropic:claude-opus-4-8

# voting panel (Opus finds, GPT-5.5 + Gemini-3 adjudicate)
--model anthropic:claude-opus-4-8 --model openai:gpt-5.5 --model gemini:gemini-3-pro
```

A built-in **router** sends fast/cheap models to recon & triage and the strongest
to exploitation, to save tokens. See `neurosploit models` for the full list
(Claude 4.x, GPT-5.x incl. Codex, Gemini 3/2.5, Grok, NVIDIA NIM, DeepSeek,
Mistral, Qwen, Groq, Together, OpenRouter, Ollama).

---

## 5. Engagement modes

### 5.1 Black-box (URL)

```bash
neurosploit run http://testphp.vulnweb.com/ \
  --subscription --model anthropic:claude-opus-4-8 \
  --focus "injection and broken access control" --mcp -v
```

### 5.2 White-box (source repo)

```bash
git clone https://github.com/digininja/DVWA /tmp/DVWA
neurosploit whitebox /tmp/DVWA --subscription --model anthropic:claude-opus-4-8 -v
```

Findings carry `file:line` evidence; grounding is **symbolic** (the location must
exist in the reviewed source).

### 5.3 Grey-box (code + live app)

Best of both: review the source **and** prove issues against the running app —
code findings become *leads* for live exploitation.

```bash
neurosploit greybox /tmp/DVWA --url http://localhost:8080/ \
  --creds creds.yaml --focus "auth and IDOR" --subscription --model anthropic:claude-opus-4-8 -v
```

### 5.4 Host / Infra (Linux / Windows / AD)

Target an IP/host with SSH or Windows/AD credentials from `creds.yaml`:

```bash
neurosploit host 10.0.0.10 --creds creds.yaml \
  --focus "privilege escalation and AD" --subscription --model anthropic:claude-opus-4-8 -v
```

Runs infra agents: port/service scan, SMB enum, Linux privesc/sudo/cron/SSH,
Windows privesc/SMB-signing/WinRM, and AD kerberoasting / AS-REP / ACL abuse /
DCSync / default-creds.

---

## 6. The interactive REPL

Run with **no arguments** for a persistent session:

```bash
neurosploit
```

A context bar shows `model auth · cwd · mode▸target`. Key commands:

```
/model [a:b,..]     set models (no arg → arrow-key multi-select)
/key [prov key]     configure API keys for your models (no arg → guided)
/sub on|off         use subscription login instead of API key
/target <url>       black-box target           /repo <path>   add a repo (repo+target = greybox)
/auth <value>       send an auth header         /creds <file>  load creds.yaml
/focus <text>       steer the tests (or just type the instruction)
@path  @dir  @f:1-20   attach a file/folder/line-range to context (Tab → menu)
/mcp on|off   /offline on|off   /votes <n>   /agents <n>   /theme color|mono
/run                launch the engagement
/runs   /results [n]   /report [n]   /status [n]
/diff               what changed vs the previous run
/retest [n]         re-verify a past run's findings
/quit
```

Line editing: **↑/↓** history, **Tab** completes commands & `@paths`, **Ctrl-A/E/K**,
end a line with **`\`** for multiline.

---

## 7. Mission Control TUI

A live dashboard with concurrent panels and a composer you can type in **while the
run streams**:

```bash
neurosploit tui http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp
# greybox: add --repo /path/to/repo
```

- **Header**: target · mode · model · phase · elapsed · 🪙 tokens/cost · findings · ⏸
- **Activity feed** (color-coded), **Findings** panel (live), **Targets** map
- **Composer** (non-blocking): `summary` (partial summary), `pause` (graceful
  stop), `errors` (filter), `clear`, or a free-text note
- **Esc / Ctrl-C** → graceful stop; the report is generated on exit

---

## 8. Credentials (`creds.yaml`)

One file covers web auth, SSH and Windows/AD. See `neurosploit-rs/creds.example.yaml`.

```yaml
# --- web auth (pick one) ---
jwt: eyJhbGciOi...                 # → Authorization: Bearer <jwt>
# header: "X-Api-Key: abc123"
# cookie: "session=deadbeef"

# --- OR an automated login the harness performs to capture a live session ---
login:
  url: http://localhost:8080/login
  method: POST
  username_field: username
  password_field: password
  username: admin
  password: password
  success: Logout                  # text shown on a successful login

# --- Linux host (SSH) ---
ssh:
  host: 10.0.0.5
  port: 22
  user: ubuntu
  password: s3cret                 # or:
  key: /home/op/id_ed25519

# --- Windows / Active Directory ---
windows:
  host: 10.0.0.10
  domain: CORP
  user: jdoe
  password: Winter2026!            # or pass-the-hash:
  hash: aad3b435b51404eeaad3b435b51404ee:NThashhere
```

- `jwt`/`header`/`cookie` are used as-is.
- A `login:` block is **executed** (real HTTP) to capture a live session
  cookie/token; if it fails, agents are told to authenticate themselves.
- `ssh:` / `windows:` tell host agents how to authenticate.

Use with `--creds creds.yaml` on `run` / `greybox` / `host`, or `/creds` in the REPL.

---

## 9. Steering the tests

Tell the harness what to prioritise — it biases both agent **selection** and
**execution**:

```bash
--focus "find injection and broken access control"
```

In the REPL just type the instruction (no slash) or use `/focus`. Attach scope or a
stack trace with `@file`, `@folder`, or `@file:10-40`.

---

## 10. Outputs, reports & artifacts

Every run writes a self-contained folder `runs/ns-<ts>-<target>/`:

| File | Contents |
|------|----------|
| `status.json` | `running` → `complete`/`stopped` with a summary |
| `recon.json` / `recon.md` | mapped attack surface |
| `exploitation.md` | raw per-agent transcript (the receipts) |
| `findings.json` / `findings.md` | validated findings (reuse by other tools/AIs) |
| `report.html` | HTML report **+ Mermaid attack-graph / kill-chain** |
| `report.typ` / `report.pdf` | Typst source + compiled PDF (if `typst` installed) |

The CLI prints a severity summary, an ASCII kill-chain, and the token/cost total.

---

## 11. Per-project memory & resume

When you launch the REPL in a project directory, NeuroSploit creates
`<cwd>/.neurosploit/`:

```
.neurosploit/
  session.json   # your config (models, target, repo, auth, focus)
  runs.json      # run history (for /runs, /results, /report, /diff, /retest)
  history.txt    # command history (↑/↓)
```

Close and reopen in the same folder → it **resumes** automatically
(`↻ resumed project session`). No database needed — it's structured state.

---

## 12. How it decides

NeuroSploit treats the target as **partially observable** (a POMDP):

- **Belief world model** — a property graph whose nodes (host/service/vuln/
  exploit/credential) carry *probabilities*, updated by observations.
- **Value-of-information** — "scan more vs exploit now" falls out of belief
  entropy: when a node's belief is diffuse, recon is worth more than exploiting.
- **Anti-hallucination gate** (`may_assert`) — the agent may **not** claim
  exploitability while the belief is diffuse; it must observe more first.
- **Grounding** — **no claim without a tool receipt**: empirical for black-box
  (real HTTP/OOB/error output), symbolic (`file:line`) for white-box. Ungrounded
  claims are demoted and flagged.
- **Chaining** — confirmed findings are chained into deeper impact, each stage
  proven before advancing.

White-box collapses the POMDP toward a near-deterministic MDP (the world model is
built from SAST/dataflow), so uncertainty becomes *path reachability*, not state.

---

## 13. The agent library

`agents_md/` holds **329** markdown agents in categories:

| Category | Dir | Count | Purpose |
|----------|-----|-------|---------|
| Vulnerability specialists | `vulns/` | 196 | exploit a specific class |
| Recon | `recon/` | 12 | information gathering |
| Code (SAST) | `code/` | 78 | white-box source review |
| Infra | `infra/` | 14 | Linux / Windows / AD host testing |
| Chains | `chains/` | 12 | multi-stage exploitation chains |
| Meta | `meta/` | 17 | orchestrator, validator, scorers, reporter, RL |

Each agent is a self-contained playbook (`## User Prompt` methodology + `## System
Prompt` strict anti-false-positive rules). **Add your own** by dropping a `.md` into
the matching folder — it's picked up automatically.

---

## 14. Playwright MCP & extra tools

`--mcp` (subscription path) drives a real **Playwright** browser for JS-heavy pages
and to *prove* client-side issues (XSS firing, DOM, screenshots). It's
auto-provisioned via `npx` when available; backends that don't support MCP fall
back to `curl`. You can add more MCP servers by placing a `mcp.servers.json`
(`{ "mcpServers": { ... } }`) in the project root — they're merged into the run.

---

## 15. Tips, tuning & troubleshooting

- **No findings on a live target?** It may be unreachable from your network, or the
  app is genuinely static — the harness refuses to fabricate. Check `recon.md`.
- **Quick smoke test:** `neurosploit run http://x --offline` exercises the pipeline
  without calling any model.
- **Cost control:** start with `--max-agents 4 --vote-n 1`; scale up later. The
  router already routes cheap models to recon.
- **Rate limits (subscription):** the harness retries with backoff and caps
  parallel CLI processes; if you hit your 5-hour quota, add more models to the
  panel or switch to an API key.
- **Run as root:** the harness sets `IS_SANDBOX=1` so Claude Code's autonomy works.
- **Stuck?** Ctrl-C once for a graceful stop (→ keep/discard report); twice aborts.

---

## 16. Command & flag reference

```
neurosploit                       # interactive REPL (resumes per project)
neurosploit run <url>             # black-box
neurosploit whitebox <repo>       # white-box source review
neurosploit greybox <repo> --url <app>   # code + live
neurosploit host <ip>             # Linux/Windows/AD (with --creds)
neurosploit tui <url>             # Mission Control TUI (--repo for greybox)
neurosploit agents                # library counts
neurosploit models                # providers & models
neurosploit --help                # full help
```

Common flags (run / greybox / host / tui):

```
--model provider:model   repeatable; 1st = primary, rest = failover + voting jury
--subscription           use local CLI login instead of an API key
--mcp                    enable Playwright MCP browser (subscription path)
--creds <file.yaml>      jwt/header/cookie/login + ssh/windows credentials
--focus "<text>"         steer agent selection & execution
--vote-n <n>             validator votes per finding (default 3)
--max-agents <n>         cap agents (0 = all matching)
--offline                pipeline self-test, no model calls
-v, --verbose            log each agent, recon, votes
```

---

*NeuroSploit — by Joas A Santos & Red Team Leaders. MIT licensed. Authorized testing only.*
