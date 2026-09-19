<h1 align="center">🧠 NeuroSploit v4.0.0</h1>

<p align="center">
  <a href="https://github.com/JoasASantos/NeuroSploit/stargazers"><img src="https://img.shields.io/github/stars/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=8b5cf6" alt="Stars"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/network/members"><img src="https://img.shields.io/github/forks/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=a855f7" alt="Forks"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/issues"><img src="https://img.shields.io/github/issues/JoasASantos/NeuroSploit?style=for-the-badge&color=22d3ee" alt="Issues"></a>
  <img src="https://img.shields.io/github/last-commit/JoasASantos/NeuroSploit?style=for-the-badge&color=34d399" alt="Last commit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-4.0.0-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Harness-Rust%20%7C%20tokio-e6b673?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/MD%20Agents-435-red?style=flat-square">
  <img src="https://img.shields.io/badge/Models-18%20providers-success?style=flat-square">
  <img src="https://img.shields.io/badge/Modes-Black%20%7C%20White%20%7C%20Grey%20%7C%20Host%20%7C%20AI-9cf?style=flat-square">
  <img src="https://img.shields.io/badge/Auth-API%20key%20%7C%20Subscription-orange?style=flat-square">
</p>

<p align="center"><b>Autonomous, multi-model penetration-testing harness — Rust, CLI-only.</b><br>
<i>by Joas A Santos &amp; Red Team Leaders</i></p>

> ⭐ If this is useful, **star the repo** — it helps a lot.
>
> 📖 **New here? Read the [full Tutorial & User Guide →](TUTORIAL.md)** — every mode, flag, config and example explained. Version-by-version changes live in [RELEASE.md](RELEASE.md).

---

**NeuroSploit** turns a URL, a source repository, a running app, or a host/IP into
an autonomous security engagement. A Rust harness (`tokio`) drives a **pool of
LLMs** — via **API key** or local **subscription** (Claude Code / Codex / Gemini /
Grok) — recons the target, **intelligently selects only the agents that match the
discovered surface**, runs them in parallel, **chains** findings into deeper
impact, and **validates every claim by cross-model voting + tool-receipt
grounding** before reporting. It ships **435 markdown agents** and a **Mission
Control TUI**.

### Engagement modes

| Mode | Command | What it does |
|------|---------|-------------|
| **Black-box** | `neurosploit run <url>` | recon → select → exploit → vote → report |
| **White-box** | `neurosploit whitebox <repo>` | source/SAST review (file:line evidence) |
| **Grey-box** | `neurosploit greybox <repo> --url <app>` | code review **+** live exploitation together |
| **Host/Infra** | `neurosploit host <ip> --creds creds.yaml` | Linux / Windows / AD **and cloud** (AWS/GCP/Azure) testing |
| **AI / LLM red-team** | `neurosploit aitest <ai-url>` | jailbreaks & prompt injection + OWASP LLM Top 10 / MCP against a live AI agent |
| **AI Skills / n8n** | `neurosploit skills <file\|folder>` | white-box audit of Skill/plugin & n8n workflow definitions |
| **Mission Control** | `neurosploit tui <url>` | live TUI panels + composer during the run |
| **Interactive** | `neurosploit` | persistent REPL session (resumes per project) |

### Highlights

- 🧠 **POMDP belief + value-of-information** — the target is partially observable,
  so findings aren't booleans: a property-graph **belief** carries probabilities,
  and "scan more vs exploit now" falls out of belief entropy. The `may_assert`
  gate is a **mathematical anti-hallucination rule** (don't claim exploitability
  while the belief is diffuse).
- 🧾 **Grounding** — hard rule: **no claim without a receipt** (evidence, not
  paraphrase). Empirical (raw tool output) for black-box/host/AI, **symbolic**
  (`file:line` into the reviewed source — a code citation *is* the receipt) for
  white-box SAST & skills audits, and **either** for grey-box; ungrounded claims
  are demoted.
- 🔬 **Deterministic HTTP probe** — before the model recon, the harness runs a
  **real** request/response analysis (status/redirects, security headers, cookie
  flags, CORS reflection, tech fingerprint, linked JS, 404 baseline, high-signal
  paths) and feeds those observed facts into recon, so agent selection and
  exploitation decisions are grounded in evidence — not the model's guess.
- 🔗 **Attack chaining — any primitive pivots.** 13 multi-stage chain agents
  (SQLi→RCE→LPE, SSRF→cloud creds, upload→LFI→RCE→LPE, CVE→RCE→pivot, …) **plus a
  chaining doctrine** that turns *any* confirmed foothold into the next step:
  reduce it to a primitive (exec / read / write / request-forgery / identity /
  secret) and pivot — file-upload→RCE, SSRF→metadata creds, IDOR→takeover — reusing
  looted creds and reasoning about **business logic** (payment/tenancy/workflow
  abuse). Each stage proven; strictly non-destructive (no data loss, no DB
  overwrite, no DoS).
- ☁️ **Cloud testing** — AWS / GCP / Azure agents that drive the provider CLIs
  (`aws`/`gcloud`/`az`). Connect via `creds.yaml`: AWS keys, a Google
  service-account JSON, or an Azure service principal — see
  [Cloud credentials](#cloud-credentials-awsgcpazure).
- 🤖 **LLM red-teaming** — 30 AI agents that jailbreak & prompt-inject a live AI
  system across scenarios: **AdvPrefix**, **PAIR**, **TAP**, **Crescendo**,
  many-shot, persona/DAN, encoding/obfuscation, refusal-suppression; plus
  **indirect injection** (RAG/web/email/tool output), **goal hijacking**,
  tool/function-call abuse, and system-prompt exfiltration. Each runs an
  attacker→**LLM-judge** loop (baseline refusal → technique → verdict) and proves
  the bypass with a **benign, redacted** receipt. Maps to OWASP LLM Top 10 (2025),
  MCP threats & OWASP AI Exchange; Skill/plugin & **n8n** files audited white-box.
- 🧰 **Misconfig & CVE hunting → exploitation, safely** — a full CVE pipeline:
  **version fingerprint** (pin exact versions) → **research analyst** (map to
  NVD/GHSA CVEs, judge reachability) → **PoC finder** (locate/vet/adapt a public
  PoC) → **exploit scripter** (write a custom exploit when none exists). Every PoC
  is written to the run's **`pocs/` folder and referenced in the report** so
  findings are reproducible. Plus absurd-misconfig agents (exposed `.git`/`.env`,
  debug/actuator, default creds, dashboards, CORS) and rate-limit testing — all
  under a strict **data-safety/PII guardrail** (no destructive/state-changing
  actions; PII proven with a masked sample, never dumped).
- 🎯 **Re-test one vulnerability** — `--only <agent>` (repeatable /
  comma-separated) runs exactly the agent(s) you name and skips recon-based
  selection — re-test a single finding fast. Works on `run` / `whitebox` /
  `greybox`; `neurosploit agents` lists the names.
- 🔬 **White-box stays white-box** — code agents run under a static-review
  doctrine (symbolic `file:line` receipts, source-to-sink taint tracing, manifest
  version→CVE) that forbids hallucinated live/black-box network actions, and can
  emit a repro PoC to `pocs/`.
- 🗣️ **Natural-language REPL** — in the interactive session, just describe what
  you want, in any language: *"testa https://loja.com com opus, foco em SQLi,
  fora de escopo /admin, roda"*. A hybrid parser sets target/models/focus/
  objective/out-of-scope and toggles (Burp, browser, votes, recon depth) and can
  launch — zero-token deterministic parse for the common shapes, model fallback
  for anything ambiguous. No flags to memorize.
- 🔀 **CI/CD PR gate** — `neurosploit pr <repo> <n> --fail-on critical` reviews a
  pull request, and on a confirmed finding at/above the threshold it **fails the
  check, sets a `neurosploit/security` commit status, and posts a REQUEST_CHANGES
  review** — so branch protection blocks the merge. Ready-made GitHub Actions
  workflows included (PR gate + a **`@neurosploit` mention bot** that runs a scan
  when a writer comments). See [Integrations](#-integrations-github--gitlab--jira).
- 🎯 **Engagement objective & out-of-scope** — give the goal/context and hard
  exclusions in words (`/objective`, `/scope-out`, or `--objective` /
  `--out-of-scope`); both steer every agent prompt.
- 📸 **Proof screenshots in reports** — agents capture visual proof per finding
  (`evidence/<finding-id>-N.png`), embedded beside its vulnerability in the
  Typst/HTML/Markdown reports.
- 🖥️ **Local, uncensored & CPU-only models** — `ollama:` and `llamacpp:` run the
  whole engagement on your box with **no API key** and **no data leaving the
  host**. `llamacpp:` speaks to a `llama-server` OpenAI-compatible endpoint
  (`LLAMACPP_BASE_URL`, default localhost:8080); the `model` is whatever gguf you
  loaded. Ideal for offline/air-gapped work and unfiltered offensive prompting.
- 🕵️ **Burp/ZAP proxy** — `/proxy <url>` (or `/burp`) routes agent traffic
  through your local intercepting proxy so you can inspect & replay in Burp.
- 🗺️ **Attack graph & kill chain** — findings mapped to OWASP / CWE / MITRE
  ATT&CK / stage; rendered as a Mermaid graph in the report.
- ✅ **Cross-model validation** — a different model adjudicates each finding;
  RL-weighted, recon-aware agent selection.
- 🛰️ **Mission Control TUI** — live header/feed/findings/targets panels + a
  composer you can type in *while the run streams* (`summary`, `pause`, …).
- 💾 **Per-project memory** — `<cwd>/.neurosploit/` keeps session, run history and
  command history; the REPL **resumes** on reopen. No database required.
- 🪙 **Token/cost telemetry**, per-agent attribution, graceful Ctrl-C → report or
  discard, Typst/HTML/JSON/MD reports.

> This is the **slim, Rust-only** distribution (`neurosploit-rs/` + `agents_md/`).
> The earlier Python engine and web GUIs live on the older `v3.4.0` branch.

---

## 📦 Install (one line)

**Linux / macOS** (x64 & arm64):
```bash
curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
```

**Windows** (PowerShell, x64 & arm64):
```powershell
irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
```

### Supported platforms

| OS | x64 | arm64 |
|----|-----|-------|
| **Linux** (Kali recommended) | ✅ | ✅ |
| **macOS** | ✅ | ✅ (Apple Silicon) |
| **Windows** | ✅ | ✅ |

Pure Rust + stdlib, so it builds natively everywhere a stable Rust toolchain runs.
The installer auto-detects OS/arch and installs Rust if missing. On native Windows
use `install.ps1`; under WSL2 / Git Bash the `setup.sh` one-liner also works.

The installer auto-installs Rust if needed, clones the repo to `~/.neurosploit`,
builds the release binary, and links `neurosploit` into `~/.local/bin`. Re-run it
any time to update. Tweak with env vars: `NEUROSPLOIT_REF` (branch/tag),
`NEUROSPLOIT_DIR`, `PREFIX`.

Prefer to build by hand?

```bash
git clone https://github.com/JoasASantos/NeuroSploit && cd NeuroSploit/neurosploit-rs
cargo build --release      # → target/release/neurosploit
```

## ⚡ Quick start (60 seconds)

```bash
# easiest path — just run it; the interactive session asks everything:
neurosploit

# or one-liner (subscription login, no API key needed):
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v

# white-box — review a source repository (SAST agents, file:line evidence):
git clone https://github.com/digininja/DVWA /tmp/DVWA
neurosploit whitebox /tmp/DVWA --subscription --model anthropic:claude-opus-4-8 -v

# grey-box — review the code AND exploit the running app together:
neurosploit greybox /tmp/DVWA --url http://localhost:8080/ --creds creds.yaml \
  --subscription --model anthropic:claude-opus-4-8 --mcp -v

# host / infra — Linux / Windows / Active Directory (SSH/Win creds in creds.yaml):
neurosploit host 10.0.0.10 --creds creds.yaml --subscription --model anthropic:claude-opus-4-8 -v

# 🛰  Mission Control TUI — live panels (header/feed/findings/targets) + a composer
#    you can type in WHILE the run streams (summary · pause · errors · notes):
neurosploit tui http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp
```

> Full step-by-step for every mode (black/white/grey/host) is in **[TUTORIAL.md](TUTORIAL.md)**.

No login? Use an **API key** instead — see [Authentication](#authentication--run-via-api-key-or-subscription).

---

## 🖥️ Web console (NEW in v4.0.0)

A browser UI for the same harness — every action spawns the real compiled CLI and parses its
output; nothing about the harness logic is reimplemented in the browser.

```bash
cd neurosploit-rs && cargo build --release   # once
node web/server.js                            # → http://localhost:4173
```

Zero npm dependencies (Node built-ins only).

- **5-step engagement wizard** — Asset (mode + target/repo) → Scope & Auth (objective, focus,
  out-of-scope) → Leads (the 435-agent board below) → Model & Run (provider/model picker,
  API-key vs. subscription toggle, votes/chain-depth/recon) → Review. Every engagement is named
  up front, so runs are identifiable in history instead of by raw target string.
- **Lead board** — all 435 agents auto-categorized (Business Logic, Broken Access Control,
  Injection, LLM Application, Auth & Session, SSRF & Network, Cloud & Infra, …). Toggle a single
  lead, a whole category (indeterminate when partially selected), or use **Select all / Clear
  all** — respects the active search filter. Leave everything off to let the harness's own
  recon-driven selection choose.
- **Custom lead → real agent** — "+ Custom lead" doesn't just add a text hint: it calls the
  `claude` CLI (Opus, your Anthropic subscription) to generate an actual specialist-agent
  markdown file into `agents_md/vulns/`, in the same format every built-in agent uses, pinnable
  immediately. Falls back to a plain focus-text hint if Claude isn't available.
- **Live run view** — phase/progress streamed over SSE, a findings table, and **Generative
  Attack Path Chaining**: a node/edge graph (root = target, one node per confirmed finding,
  positioned by kill-chain stage, edges from `chains_from` when the harness set one) instead of a
  flat list — click any node or row for the full finding detail, including any PoC script the
  exploiting agent wrote to `pocs/`.
- **Real REPL underneath `run`/`whitebox`/`greybox`** — the wizard scripts an actual interactive
  `neurosploit` session (`/target`, `/model`, `/only`, `/run`, …) instead of a one-shot CLI
  invocation, so the session **keeps reading stdin while the engagement streams**. The Activity
  log tab grows a prompt box (`❭`) to send `/status`, `/stop`, `/continue`, or a plain-language
  instruction mid-run — same REPL described in [§6](TUTORIAL.md#6-the-interactive-repl). `host` /
  `aitest` / `skills` stay one-shot (their onboarding menu can't be scripted over piped stdin).
- **Dashboard** — coverage (engagements, targets, agents run), findings by severity, most
  frequent weaknesses, and an **annualized loss exposure computed with FAIR**
  (Loss Event Frequency × Loss Magnitude): frequency from each finding's exploitability and
  validation confidence, magnitude from assumptions that are shown on screen and editable.
  Reported as a min / most-likely / max range, never a single number.
- **Run history in folders** — runs group into one folder per target with a filter box, instead
  of one flat list that grows forever.
- **Terminal dock** — `Ctrl+\`` (or `❭_` in the sidebar) opens a real terminal, xterm.js over an
  unstripped stdout stream, so the harness renders with its own colour and panels. Its header
  switches the terminal between a standalone REPL session and the engagement currently running,
  with local line editing: history, `Tab` completion over the slash commands, `Ctrl+C`/`L`/`U`.
- **Auth & Keys** (one menu) — target auth header + named roles for IDOR/BOLA/BFLA testing
  (materializes an ephemeral `creds.yaml` for the run), and per-provider API keys held in the
  server process's memory only — never written to disk.
- Survives a page refresh: an in-progress run reattaches to the same live stream instead of
  resetting to the wizard.

Full API reference: **[web/API.md](web/API.md)** · quick start: **[web/README.md](web/README.md)**.

### Knowledge: memory + attack knowledge graph

Every model call starts with an empty context window, so without somewhere to put what a run
learned, the harness re-derives the same stack, the same endpoints and the same dead ends every
time. Two stores fix that, both under `.neurosploit/` in the project directory:

- **Layered memory** (`/memory`, `/forget`) — four tiers by scope, not importance: *working*
  (one run), *engagement* (one target), *technique* (one agent/CWE), *reusable* (generalized).
  Promotion is evidence-gated: a claim repeated within a run becomes engagement knowledge, one
  confirmed across runs becomes technique knowledge, and one that held on **two different
  targets** is generalized into a reusable lesson with the host-specific tokens stripped. Recall
  is scored (term overlap × past success × recency) and injected into recon/exploit prompts as
  leads to verify — never as assertions.
- **Attack knowledge graph** (`/graph`, `graph.json`) — typed entities (asset, endpoint,
  weakness, technique, finding, account, credential, impact) joined by typed, weighted,
  provenance-carrying edges, accumulated across runs. It answers what a finding list can't:
  ranked attack paths, which endpoint accumulated the most weaknesses, and the *frontier* —
  entities observed but never proven, i.e. where chaining should look next. Chain edges the
  harness derived itself are marked `inferred` and drawn dashed in the web console. Secrets
  never enter the graph; they stay in the vault.

### Scope: enforced, not requested

`out_of_scope` used to be a sentence in the prompt and nothing checked it — a
*request* to the model, not a control. Scope is now a guard in code
(`crates/harness/src/scope.rs`):

- **Hard scope** — an allowlist of hosts, `*.wildcards`, IPv4 CIDRs and URL
  prefixes, plus exclusions that always win. It defaults to **the engagement's
  target and nothing else**, so discovery can never widen the engagement:
  finding a subdomain in a JS bundle is not authorization to test it.
- **Soft scope** — guardrails inside authorized territory: observe-only zones,
  destructive HTTP verbs (off by default), account-creation cap, request-rate
  guard, and payload classes that are never acceptable (data destruction, DoS)
  — refused even against an in-scope host.
- Findings proven against a host outside the boundary are **withheld from the
  report** and written to `out-of-scope-findings.json` as an incident to
  disclose.

```
/inscope *.example.com 10.0.0.0/24     # authorize more
/scope-out payments.example.com        # host-shaped entries become ENFORCED denials
/observe legacy.example.com            # discovery allowed, interaction blocked
/guardrail destructive on · accounts 5 · rate 60
/policy                                # what is actually enforced
```

### Evidence & Validation Engine

Voting is models checking models, and a confident hallucination passes a vote by
being confident. `crates/harness/src/validation.rs` adds a deterministic layer
that never consults a model:

```
HYPOTHESIS → CANDIDATE → [ VALIDATION ENGINE ] → CONFIRMED | NEEDS_REVIEW | REJECTED
```

Per-CWE rules, because "is this real?" has a different answer per class:

19 validators, each owning a disjoint set of CWEs (a test enforces that no two
claim the same one, so routing never depends on registration order):

| class | what confirms it | what it rejects |
|-------|------------------|-----------------|
| SQLi (89/943/564) | baseline↔attack difference **reproducing ≥2×** | an app that always prints SQL errors |
| XSS (79/80/83/87) | a browser executed a **harness-chosen marker** | reflection in HTML |
| IDOR/BOLA (639/862/863/284/285) | identity B reads A's resource **and the body matches** | a 200 that is really a login page; a 403 |
| SSRF (918) | controlled callback or canary retrieval | timing alone |
| LFI (22/23/35/98/73) | controlled marker or a file signature the baseline lacked | a signature the baseline already had |
| RCE (77/78/94/95/502/917) | unique nonce in output, or a callback | a nonce that is only reflected input |
| SSTI (1336) | an expression evaluated server-side whose **result was never sent** | the payload echoing its own "result" |
| XXE (611/776/827) | entity content returned, or an OOB callback | a parser error mentioning entities |
| Open redirect (601) | 3xx **with** a `Location` pointing off-site | a rendered link; a same-origin redirect |
| CORS (942/346/1385) | reflected `Origin` **plus** credentials | `ACAO: *` without credentials (browsers already refuse it) |
| Cookie flags (614/1004/1275) | decided entirely by `Set-Cookie` + scheme | a cookie that carries all three flags |
| Clickjacking (1021) | neither `X-Frame-Options` nor CSP `frame-ancestors` | either control present |
| Auth bypass (306/287/288) | protected content served with **no credentials sent** | a "bypass" that still carried a cookie; a login redirect |
| JWT (347/345/290) | forged token accepted **and** privileged content returned | a 401 on the forged token |
| Rate limiting (307/799/770) | ≥20 attempts, none throttled | any 429 / `Retry-After` in the burst |
| Session fixation (384) | the session id survives login unchanged | a regenerated id |
| Mass assignment (915/913) | a read-back showing the privileged field persisted | a 200 on the write alone (APIs accept and ignore extras) |
| CSRF (352) | cross-origin state change **read back** | a GET; a 403; a `SameSite` session cookie |
| Exposure (200/538/540/548/312/532) | a real secret/listing signature the baseline lacked | a soft-404 that mirrors the baseline page |

Two rules keep it honest: absent evidence is **never** a pass (it becomes
`needs-review`), and a class with no rule is never auto-confirmed.
`NEUROSPLOIT_VALIDATION=advisory|enforcing|off` — advisory (default) rejects
contradictions but won't demote a voted finding merely for missing artifacts;
enforcing makes the verdict the status.

### Keeping a run going

- **Command rectification** — a mistyped command is corrected (`/staus` → `/status`), completed
  (`/onb` → `/onboard`), or reported as ambiguous, never guessed at. Arguments too: a bare host
  gets its scheme, an out-of-range count is clamped *with a note*, a near-miss model id is
  matched against the live catalog.
- **Automatic backend fallback** — when every configured model is quota-exhausted or its token
  is dead, the pool switches to whatever else this machine can reach (an installed CLI
  subscription, or a provider whose API key is in the environment) and keeps going. It only
  parks the run when nothing at all is available.
- **Pause and resume on demand** — `/pause` in the REPL or the web console's
  pause button holds the run at the model pool's gate: in-flight agents finish,
  every finding is kept, `/continue` picks it back up. The web console also
  exposes *Report so far* and a full log download.
- **Resume where it stopped** — findings are checkpointed live, so an interrupted run is
  recovered on the next start and `/continue` carries them forward. Non-interactive sessions
  (the web console drives the REPL over a pipe) resume automatically, since no one is there to
  type it; set `NEUROSPLOIT_AUTO_RESUME=1` to get the same at a terminal.

---

## 🔌 Integrations (GitHub · GitLab · Jira)

Wire NeuroSploit into your SDLC. Toggle from the REPL (`/integrations`) or the CLI
(`neurosploit integrations enable github|gitlab|jira`). **Tokens are never stored**
— only the *name* of the env var is saved; the value is read from your environment.

```bash
export GITHUB_TOKEN=ghp_...                 # PAT with `repo` scope (private repos)
neurosploit integrations enable github

# Review a Pull Request's code (clones the PR head, white-box) and comment back:
neurosploit pr digininja/DVWA 42 --subscription --model anthropic:claude-opus-4-8 --comment

# Same, but BLOCK the merge on a confirmed critical: fails the check, sets a
# `neurosploit/security` commit status, and posts a REQUEST_CHANGES review.
neurosploit pr digininja/DVWA 42 --model anthropic:claude-opus-4-8 --comment --fail-on critical

# Watch a branch and re-review on every new commit:
neurosploit watch myorg/private-app --branch main --subscription --model anthropic:claude-opus-4-8

# Private GitLab repo (token-injected clone) — works in whitebox/greybox:
export GITLAB_TOKEN=glpat-... ; neurosploit integrations enable gitlab
neurosploit whitebox https://gitlab.com/myorg/private-svc --subscription --model anthropic:claude-opus-4-8

# Open a Jira card per finding (any engagement):
export JIRA_EMAIL=you@org.com JIRA_API_TOKEN=...      # set base/project once: /integrations setup jira
neurosploit whitebox https://github.com/myorg/app --jira --subscription --model anthropic:claude-opus-4-8
```

| Integration | What you get | Env vars |
|-------------|--------------|----------|
| **GitHub** | private clone · `pr` review + comment · **PR gate** (`--fail-on`: fail check + commit status + REQUEST_CHANGES) · `watch` branch | `GITHUB_TOKEN` |
| **GitLab** | private clone for whitebox/greybox | `GITLAB_TOKEN` |
| **Jira** | one card per finding (`--jira`) | `JIRA_EMAIL`, `JIRA_API_TOKEN` |

### Automations (GitHub Actions)

Two ready-made workflows ship in [`examples/github-actions/`](examples/github-actions) — copy
them into your repo:

- **`neurosploit-pr-gate.yml`** — reviews every PR and blocks the merge on a
  confirmed critical. Make it enforcing: *Settings → Branches → require the
  `neurosploit-pr-gate` status check* (and/or require review to honor the
  REQUEST_CHANGES). Set `ANTHROPIC_API_KEY` (or swap the model) in Actions secrets;
  the built-in `GITHUB_TOKEN` covers statuses/reviews.
- **`neurosploit-mention.yml`** — comment **`@neurosploit`** on a PR or issue to
  trigger a scan (only repo writers can). Text after the mention is the
  instruction (any language): `@neurosploit focus SQLi and IDOR`, or
  `@neurosploit scan https://staging.app` for a black-box run.

📖 Step-by-step setup for each tool: **[TUTORIAL-INTEGRATION.md](TUTORIAL-INTEGRATION.md)**.

---

## ☁️ Cloud credentials (AWS/GCP/Azure)

Add a cloud block to `creds.yaml` and the harness exports the right env vars so
the AWS/GCP/Azure agents can drive `aws` / `gcloud` / `az`. Secrets stay in your
file/secret-manager; agents do **read-only enumeration first, never destructive**.

```yaml
# --- AWS: static keys (or a named profile) ---
aws:
  access_key_id: AKIA...
  secret_access_key: ...
  # session_token: ...        # if using temporary creds
  region: us-east-1
  # profile: my-sso-profile   # alternative to keys

# --- GCP: service-account JSON (path recommended; inline single-line also works) ---
gcp:
  service_account_json: /path/to/sa.json
  project: my-project-id

# --- Azure: service principal (recommended for automation) ---
azure:
  tenant_id: ...
  client_id: ...
  client_secret: ...
  subscription_id: ...
```

```bash
neurosploit host my-cloud-account --creds creds.yaml \
  --subscription --model anthropic:claude-opus-4-8 -v
```

Agents cover IAM privilege-escalation, storage exposure (S3/GCS/Blob), compute &
network exposure, secrets (Secrets Manager / Secret Manager / Key Vault),
service-account/SP abuse, and identity enumeration (Entra ID). Best-practice
auth: **AWS** access keys or profile; **GCP** a service-account JSON
(`GOOGLE_APPLICATION_CREDENTIALS`); **Azure** a service principal
(`az login --service-principal`).

---

## 👥 Multiple identities — access-control testing (IDOR / BOLA / BFLA)

Give NeuroSploit two or more **named roles** in `creds.yaml` and it authenticates
as each and tests **cross-role** access (a low-priv role reaching another user's
object or an admin function is a finding):

```yaml
admin:
  jwt: eyJ...                 # per role: jwt | header (raw) | cookie | apikey | login+username+password
user:
  apikey: abc123              # → X-Api-Key: abc123
victim:
  cookie: "session=deadbeef"
```

```bash
neurosploit run https://app.example --creds creds.yaml \
  --subscription --model anthropic:claude-opus-4-8 -v
```

Each finding is proven with the **authorized vs unauthorized** request pair, under
the data-safety guardrail (read-only, PII masked).

## 🏷️ Identification & attribution (anti-plagiarism)

Every request is tagged with an identifying **User-Agent** (default
`NeuroSploit/<ver> …`, change with **`/ua`** or `NEUROSPLOIT_UA`) plus an
`X-NeuroSploit-Scan` header, and every finding is **stamped** "Identified and
validated by NeuroSploit" — so provenance travels in the traffic, the finding
text, `findings.json` and the report footer.

### Provenance — which build made this, and does it still match

Attribution that survives someone else's copy-paste:

- **`JOASNSCOPE`** leads every canary the harness mints, so a marker that
  turns up later — in a response body, a customer's log, somebody else's
  report — extracts whole and names the build that made it.
- **Per-build fingerprint** (`neurosploit provenance show`), plus an optional
  per-customer build id via `NEUROSPLOIT_CUSTOMER_ID`.
- **`findings.json` is stamped** with `_engine`, and a **signed
  `provenance.json`** ships beside it (`NEUROSPLOIT_PROVENANCE_KEY`).
- **Structural signature** over the finding set's shape — it survives
  rewording and reformatting, but not a changed result.
- **Prompts are watermarked** at the single model-pool chokepoint
  (`NEUROSPLOIT_WATERMARK=off` to disable).

```bash
neurosploit provenance show                 # this build's identity
neurosploit provenance scan report.pdf.txt  # is this ours? which build?
neurosploit provenance verify runs/ns-…     # manifest vs findings
```

### Assurance — target gate, CVSS, anchoring, one bundle

**Target authorization gate (default-deny).** Before any recon, the target is
validated against the capability grant — protocol, host, port, URL prefix. A
token that does not cover the target refuses the run with
`DENY_TARGET_OUTSIDE_GRANT`, logs it, and exits non-zero. The CLI target is no
longer auto-trusted when a grant is in force.

**CVSS computed from evidence.** `cvss.rs` implements the FIRST v3.1 base
equation verbatim (checked against first.org reference vectors) and grades each
impact metric against a receipt: `C:H`/`I:H` with no evidence is dropped to the
*demonstrated* vector while the *potential* vector keeps it. SQLi with nothing
extracted is not a 9.8.

**Audit anchoring (P4).** `audit.jsonl` is hash-chained; a signed **anchor**
(`neurosploit audit <run> --anchor`) is written per run and, with
`NEUROSPLOIT_ANCHOR_DIR`, to external append-only storage. Truncation and
silent rebuilds are then detectable, not just neighbour-tampering.

**Assurance bundle (P1–P5 in one run).** Every run emits `assurance.json`: each
artifact with its SHA-256, which of the five properties it produced
(authorization · enforcement · evidence/CVSS · integrity · provenance), a
bundle hash and a signature. Verify independently:

```bash
neurosploit assurance <run>            # assemble + print the P1–P5 summary
neurosploit assurance <run> --verify   # re-hash every artifact + check the signature
neurosploit audit <run> --anchor       # chain + anchors (truncation/rebuild/forgery)
```

A property is reported `present` only when its artifact is actually on disk —
a missing anchor is `partial`, never quietly omitted.

### Egress — how traffic reaches the target

Internal engagements happen *through* something, and the dangerous failure is
the silent one: with the VPN down, `10.20.0.15` is a machine on the operator's
own network, and the scan succeeds against the wrong host. So egress is
**fail-closed** — an internal target with no transport is refused before a
single request leaves.

```bash
--transport socks5://127.0.0.1:1080
--transport openvpn:/path/client.ovpn
--transport ssh://red@bastion.corp                  # dynamic SOCKS forward
--transport ssh://red@bastion.corp?forward=10.0.0.5:445   # one authorized host
--transport cloudflared://db.internal.corp:5432
```

The route is also **verified** once it is up (the apparent source address has
to change), and child processes inherit it.

### Out-of-band channel & inbound SMS

Blind SSRF, XXE, blind RCE and JNDI produce no visible response — so the
harness runs its own Collaborator:

```bash
--oob-domain oob.yourdomain.com --oob-http 0.0.0.0:8080 --oob-dns 0.0.0.0:5353
```

Tokens carry the `JOASNSCOPE` sigil, callbacks are correlated by token, and the
two levels of proof are kept apart in code: an **HTTP callback proves egress**,
a **DNS query proves only that a resolver saw the name**. With no channel
configured, agents are told explicitly that blind classes can only be leads.

`--sms twilio:<sid>:<token>:<number>` (or `webhook:<url>:<number>`) receives OTP
messages. A rate-limit claim then counts *delivered messages carrying distinct
codes* — not HTTP 200s, which is what makes the finding survive a vendor's
review.

### Intercepting proxy — own it, or plug into the tool

The engagement flows through one point the operator can watch and replay:

```bash
--intercept burp            # route straight through Burp / Caido / ZAP / mitmproxy
--intercept own             # the harness's own recording interceptor (passive discovery)
--intercept own+burp        # record here, forward to Burp for full HTTPS interception
```

The own interceptor records plaintext HTTP in full and tunnels HTTPS honestly
(host, timing, bytes — no fake CA). Flows land in `flows.jsonl`; distinct hosts
become passive-discovery leads. Both the harness and the agents' child commands
route through it.

### Sandbox — run the dangerous half off the host

```bash
--sandbox                       # Kali container (kalilinux/kali-rolling)
--sandbox my/custom-image       # or your own
neurosploit sandbox up|exec|install|down
```

No host network, no mounted docker socket, `no-new-privileges`. The workdir is
mounted so evidence comes back; the proxy/transport route is inherited. A
missing runtime is an **explicit** error — never a silent fallback to running
attack payloads on the host.

### PoC re-validation — the harness checking its own work

```bash
--revalidate-poc                       # during a run
neurosploit poc <run> --repeats 3 --apply   # on a finished run
```

Re-runs each finding's recorded proof and sorts the result into **reproduced ·
changed · gone · unverifiable**. The last two are kept apart on purpose: a PoC
that *could not be tested* (out of scope now, state-changing, nothing recorded)
is never reported as one that *failed*. State-changing requests are never
re-run to "confirm" them.

### Compliance mapping — PCI-DSS · HIPAA · SOC 2

```bash
neurosploit run <t> --compliance pci-dss,hipaa,soc2    # section in the report
neurosploit compliance <run> --framework soc2          # on a finished run
```

Maps confirmed findings onto control requirements (PCI-DSS 6.2.4, HIPAA
§164.312(e), SOC 2 CC7.1, …). It **indicates gaps for an assessor** — never a
compliance verdict, and the disclaimer that says so is rendered on top,
non-negotiably. Absence of a finding is never presented as compliance.

### Internal network & Active Directory — the engagement as a graph

An internal result is a path, not a list. `Asset → Exposure → Weakness →
Credential → Privilege → Movement → Crown Jewel`, with business impact,
detection and remediation on the **edges** — because what a client fixes is a
relationship, not a host. The credential→identity→permission→machine loop
expands it, and **`choke_points()`** answers the question a CVSS-sorted list
cannot: *which single change buys the most*.

```bash
neurosploit internal --graph graph.json --scaffold corp.local --from prn01 --mermaid
```

One assumed hop caps the whole chain at informational — a hypothesis about a
Critical is not a Critical.

---

## 📊 How we compare

A rough, honest capability benchmark against Strix, Shannon, Penligent and the
other open-source agents — including where NeuroSploit is **behind** (no
container isolation, no real intercepting proxy, no published benchmark run) —
lives in **[BENCHMARK.md](BENCHMARK.md)**.

---

## Build

```bash
cd neurosploit-rs
cargo build --release        # → target/release/neurosploit
```

Requires a Rust toolchain (`rustup`). **Recommended: run on Kali Linux** (or the
Kali Docker image) so the offensive tools the agents use are already present:

```bash
docker run -it --rm kalilinux/kali-rolling
apt update && apt install -y curl nmap ffuf nodejs npm
# rustscan (faster port scan): cargo install rustscan   (or grab a release from GitHub)
```

The agents degrade gracefully: if `rustscan` isn't installed they use `nmap`; if
neither, they probe with `curl`. If a Playwright MCP browser is available they use
it for JS-heavy pages, otherwise they fall back to `curl`.

---

## Usage

Run with **no arguments** for an interactive wizard:

```bash
./target/release/neurosploit
```

Or drive it directly:

```bash
# Black-box — subscription (no API key), Opus, browser via Playwright if present, verbose
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --subscription --model anthropic:claude-opus-4-8 --mcp -v

# Black-box — API keys, multi-model voting panel (1st finds, others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3

# White-box — clone a vulnerable app and review its source
git clone https://github.com/digininja/DVWA /tmp/DVWA
./target/release/neurosploit whitebox /tmp/DVWA \
    --subscription --model anthropic:claude-opus-4-8 -v

# Offline pipeline self-test (no keys/login needed)
./target/release/neurosploit run http://testphp.vulnweb.com/ --offline

# Utilities
./target/release/neurosploit agents     # library counts
./target/release/neurosploit models      # providers & models
./target/release/neurosploit --help        # full help with examples
```

### Options (`run` / `whitebox`)

| Flag | Meaning |
|------|---------|
| `--model provider:model` | Repeatable. First = primary; the rest fail over **and** form the voting jury. |
| `--subscription` | Use the local CLI login (Claude/Codex/Gemini/Grok) instead of an API key. |
| `--mcp` | Enable Playwright MCP (auto-provisioned via `npx`; backends without MCP use built-in tools). |
| `--vote-n N` | How many models must agree a finding is real (default 3 / 2 for whitebox). |
| `--max-agents N` | Cap agents run (`0` = all matching the recon). |
| `--offline` | Exercise the full pipeline without calling any model. |
| `--budget eco\|balanced\|aggressive` | How to spend reasoning. **Omitted = unlimited**: the full run, unchanged. |
| `--token-limit N` | Hard ceiling on tokens (`0` = none). Independent of `--budget`. |
| `--deep-test-limit N` | Cap on findings that get deep reasoning. |
| `--coverage-first` / `--depth-first` | Map everything first, or chase a lead as it appears. |
| `--sample-per-route N` | Requests per endpoint family — `/api/users/{id}` is sampled, not enumerated. |
| `--intercept <spec>` | Route through Burp/Caido/ZAP/mitmproxy, an own recording interceptor, or both (`own+burp`). |
| `--sandbox [image]` | Run agent commands in a Kali container (docker/podman) instead of on the host. |
| `--revalidate-poc` | Re-run every PoC after validation; demote any that no longer reproduces. |
| `--compliance pci-dss,hipaa,soc2` | Map findings onto compliance controls in the report. |
| `--scope-file <yaml>` | Load the hard scope + guardrails from a YAML file (see `examples/scope.example.yaml`). Enforced in code; a capability token still caps it. |
| `-v, --verbose` | Log each agent as it launches, recon, and votes. |

### Authentication — run via API key *or* subscription

You can run NeuroSploit two ways. They're independent: pick per run.

#### 1) Via API (provider API key)

Export the key(s) for the providers in your model panel, then run **without**
`--subscription`. Any OpenAI-compatible provider works.

```bash
# pick one or more, depending on the models you select
export ANTHROPIC_API_KEY=sk-ant-...        # anthropic:claude-*
export OPENAI_API_KEY=sk-...               # openai:gpt-*
export GEMINI_API_KEY=AIza...              # gemini:gemini-*
export XAI_API_KEY=xai-...                 # xai:grok-*
export NVIDIA_NIM_API_KEY=nvapi-...        # nvidia_nim:*
export DEEPSEEK_API_KEY=...                # deepseek:*
export MISTRAL_API_KEY=...                 # mistral:*
export DASHSCOPE_API_KEY=...               # qwen:*  (Alibaba DashScope)
export GROQ_API_KEY=...                    # groq:*
export TOGETHER_API_KEY=...                # together:*
export MOONSHOT_API_KEY=...                # moonshot:*  (Kimi K3/K2)
export OPENROUTER_API_KEY=...              # openrouter:*
export OPENCODE_API_KEY=...                # opencode:*  (OpenCode Zen gateway)
export NOUS_API_KEY=...                    # nous:*  (Nous Portal — Hermes)
export LITELLM_API_KEY=...                 # litellm:*  (your LiteLLM proxy)
export AZURE_OPENAI_API_KEY=...            # azure:<deployment>  (also set AZURE_OPENAI_ENDPOINT)
# ollama / llamacpp need no key (local)

# then run via API (note: NO --subscription)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --vote-n 3 -v

# multi-provider voting panel via API (1st finds, the others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --model gemini:gemini-2.5-pro
```

Or put the keys in a `.env` and source it (`cp .env.example .env`; edit; `set -a; . ./.env; set +a`).

**Provider → env var → endpoint** (all OpenAI-compatible):

| `--model` prefix | Env var | Base URL |
|------------------|---------|----------|
| `anthropic:` | `ANTHROPIC_API_KEY` | api.anthropic.com |
| `openai:` | `OPENAI_API_KEY` | api.openai.com |
| `gemini:` | `GEMINI_API_KEY` | generativelanguage.googleapis.com |
| `xai:` | `XAI_API_KEY` | api.x.ai |
| `nvidia_nim:` | `NVIDIA_NIM_API_KEY` | integrate.api.nvidia.com |
| `deepseek:` | `DEEPSEEK_API_KEY` | api.deepseek.com |
| `mistral:` | `MISTRAL_API_KEY` | api.mistral.ai |
| `qwen:` | `DASHSCOPE_API_KEY` | dashscope-intl.aliyuncs.com |
| `groq:` | `GROQ_API_KEY` | api.groq.com |
| `together:` | `TOGETHER_API_KEY` | api.together.xyz |
| `moonshot:` | `MOONSHOT_API_KEY` | api.moonshot.ai |
| `openrouter:` | `OPENROUTER_API_KEY` | openrouter.ai |
| `opencode:` | `OPENCODE_API_KEY` | opencode.ai/zen (OpenCode Zen gateway) |
| `nous:` | `NOUS_API_KEY` | inference-api.nousresearch.com (Hermes 4) |
| `litellm:` | `LITELLM_API_KEY` | your LiteLLM proxy (`LITELLM_BASE_URL`, default localhost:4000) |
| `azure:` | `AZURE_OPENAI_API_KEY` | your Azure OpenAI resource (`AZURE_OPENAI_ENDPOINT`) |
| `ollama:` | _(none)_ | localhost:11434 |
| `llamacpp:` | _(none)_ | localhost:8080 |

Run `./target/release/neurosploit models` for the full provider/model list.

> **Local, uncensored & CPU-only** — `ollama:` and `llamacpp:` run entirely on
> your box with no API key and no data leaving the host. `llamacpp:` targets a
> [`llama-server`](https://github.com/ggml-org/llama.cpp) OpenAI-compatible
> endpoint (override with `LLAMACPP_BASE_URL`); the `model` is whatever gguf you
> loaded. Ideal for offline engagements and unfiltered offensive prompting.

#### 2) Via subscription (no API key)

`--subscription` drives your local agentic-CLI login instead of an API key —
install and log into one of the CLIs first:

| `--model` prefix | CLI used | Login |
|------------------|----------|-------|
| `anthropic:` | `claude` (Claude Code) | `claude` then `/login` |
| `openai:` | `codex` | `codex` login |
| `gemini:` | `gemini` | `gemini` login |
| `xai:` | `grok` | `grok` login |
| `opencode:` | `opencode` | `opencode auth login` (or `/connect` in the TUI) — Zen/plan account |
| `nous:` | `hermes` | `hermes setup --portal` — Nous Portal OAuth |

`opencode:` also gets the Playwright MCP (`--mcp`) like anthropic/openai do.
`nous:` relies on Hermes's own built-in toolsets (web/terminal/computer-use)
instead — it has no CLI-level MCP hook.

```bash
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --subscription --model anthropic:claude-opus-4-8 --mcp -v
```

---

## How it works

```
target ─▶ recon (curl/nmap/…) ─▶ INTELLIGENT agent selection (recon-aware)
       ─▶ parallel exploitation ─▶ cross-model validation vote
       ─▶ severity/score ─▶ report (HTML + Typst PDF) ─▶ RL reward update
```

Every run writes a self-contained folder `runs/ns-<ts>-<target>/`:

| File | Contents |
|------|----------|
| `status.json` | `running` → `complete` with a summary |
| `recon.json` / `recon.md` | mapped attack surface |
| `exploitation.md` | raw per-agent transcript |
| `findings.json` / `findings.md` | validated findings (reuse by other tools/AIs) |
| `report.html`, `report.typ`, `report.pdf` | final report (PDF via the Typst engine) |

A reinforcement-learning reward store (`data/rl_state_rs.json`) biases agent
selection on future runs.

## Agent library — `agents_md/` (446)

| Category | Count | Purpose |
|----------|-------|---------|
| `vulns/` | 245 | Exploit a specific vulnerability class (web/API) |
| `code/` | 78 | White-box source-code (SAST) review |
| `ai/` | 30 | AI/LLM red-teaming, jailbreaks, MCP threats |
| `infra/` | 34 | Host/cloud: Linux, Windows, AD, AWS/GCP/Azure |
| `meta/` | 23 | Orchestrator, validator, scorers, reporter, RL |
| `chains/` | 13 | Multi-stage attack chains (SQLi→RCE→LPE, SSRF→cloud, …) |
| `recon/` | 12 | Information gathering / attack surface |

Each agent is a self-contained markdown playbook (`## User Prompt` methodology +
`## System Prompt` strict anti-false-positive rules). Drop a new `.md` into the
matching folder — or generate one from the web console's "+ Custom lead" (see above) — and the
harness picks it up; `neurosploit agents` shows live counts.

---

## Safety

For **authorized** testing only. Agents are instructed to stay in scope, never run
destructive/DoS actions, and require proof-of-exploitation. You are responsible for
having permission for any target.

## Credits

**Joas A Santos** & **Red Team Leaders**.

## License

MIT.
