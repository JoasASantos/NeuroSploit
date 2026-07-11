<h1 align="center">🧠 NeuroSploit v3.6.3</h1>

<p align="center">
  <a href="https://trendshift.io/repositories/22624?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-22624" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/22624/daily?language=Python" alt="JoasASantos%2FNeuroSploit | Trendshift" width="250" height="55"/></a>
</p>

<p align="center">
  <a href="https://github.com/JoasASantos/NeuroSploit/stargazers"><img src="https://img.shields.io/github/stars/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=8b5cf6" alt="Stars"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/network/members"><img src="https://img.shields.io/github/forks/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=a855f7" alt="Forks"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/issues"><img src="https://img.shields.io/github/issues/JoasASantos/NeuroSploit?style=for-the-badge&color=22d3ee" alt="Issues"></a>
  <img src="https://img.shields.io/github/last-commit/JoasASantos/NeuroSploit?style=for-the-badge&color=34d399" alt="Last commit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.6.3-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Harness-Rust%20%7C%20tokio-e6b673?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/MD%20Agents-417-red?style=flat-square">
  <img src="https://img.shields.io/badge/Models-14%20providers-success?style=flat-square">
  <img src="https://img.shields.io/badge/Modes-Black%20%7C%20White%20%7C%20Grey%20%7C%20Host-9cf?style=flat-square">
  <img src="https://img.shields.io/badge/Auth-API%20key%20%7C%20Subscription-orange?style=flat-square">
</p>

<p align="center"><b>Autonomous, multi-model penetration-testing harness — Rust, CLI-only.</b><br>
<i>by Joas A Santos &amp; Red Team Leaders</i></p>

> ⭐ If this is useful, **star the repo** — it helps a lot.
>
> 📖 **New here? Read the [full Tutorial & User Guide →](TUTORIAL.md)** — every mode, flag, config and example explained.

> 🆕 **New in v3.6.3 — resumable interrupted runs + crash-proof browsing:**
> If a run is interrupted (terminal closed, Ctrl-C, crash), **`/continue` now
> relaunches it** on the same target and **carries the recovered findings
> forward** — the offer appears right at launch. And opening **`/results`**,
> **`/finding`** or **`/report`** while a run streams no longer corrupts the
> terminal: live output is paused for the picker (still captured in `/logs`) and
> restored on exit. *(v3.6.2 added live Codex tool-by-tool streaming + the full
> activity feed in `/logs`/`/status`; v3.6.1 added GPT-5.6 sol/terra/luna and
> the Codex exit-1 fix; v3.6.0 added AI-agent/LLM/MCP/Skills/n8n testing +
> onboarding wizard + Cloud scope.)*
> *(v3.5.4 added robust attack chaining + false-positive reduction; v3.5.3
> GitHub/GitLab/Jira **[integrations](TUTORIAL-INTEGRATION.md)**; v3.5.2 the DEPTH
> doctrine + report-hygiene — see [RELEASE.md](RELEASE.md).)*

---

**NeuroSploit** turns a URL, a source repository, a running app, or a host/IP into
an autonomous security engagement. A Rust harness (`tokio`) drives a **pool of
LLMs** — via **API key** or local **subscription** (Claude Code / Codex / Gemini /
Grok) — recons the target, **intelligently selects only the agents that match the
discovered surface**, runs them in parallel, **chains** findings into deeper
impact, and **validates every claim by cross-model voting + tool-receipt
grounding** before reporting. It ships **417 markdown agents** and a **Mission
Control TUI**.

### Engagement modes

| Mode | Command | What it does |
|------|---------|-------------|
| **Black-box** | `neurosploit run <url>` | recon → select → exploit → vote → report |
| **White-box** | `neurosploit whitebox <repo>` | source/SAST review (file:line evidence) |
| **Grey-box** | `neurosploit greybox <repo> --url <app>` | code review **+** live exploitation together |
| **Host/Infra** | `neurosploit host <ip> --creds creds.yaml` | Linux / Windows / AD **and cloud** (AWS/GCP/Azure) testing |
| **Mission Control** | `neurosploit tui <url>` | live TUI panels + composer during the run |
| **Interactive** | `neurosploit` | persistent REPL session (resumes per project) |

### Highlights

- 🧠 **POMDP belief + value-of-information** — the target is partially observable,
  so findings aren't booleans: a property-graph **belief** carries probabilities,
  and "scan more vs exploit now" falls out of belief entropy. The `may_assert`
  gate is a **mathematical anti-hallucination rule** (don't claim exploitability
  while the belief is diffuse).
- 🧾 **Grounding** — hard rule: **no claim without a tool receipt** (raw tool
  output, not paraphrase). Empirical for black-box, symbolic (`file:line`) for
  white-box; ungrounded claims are demoted.
- 🔬 **Deterministic HTTP probe** — before the model recon, the harness runs a
  **real** request/response analysis (status/redirects, security headers, cookie
  flags, CORS reflection, tech fingerprint, linked JS, 404 baseline, high-signal
  paths) and feeds those observed facts into recon, so agent selection and
  exploitation decisions are grounded in evidence — not the model's guess.
- 🔗 **Attack chaining** — 12 multi-stage chain agents (SQLi→RCE→LPE, SSRF→AWS
  creds, upload→LFI→RCE→LPE, default-creds→domain, …); each stage proven before
  advancing.
- ☁️ **Cloud testing** — AWS / GCP / Azure agents that drive the provider CLIs
  (`aws`/`gcloud`/`az`). Connect via `creds.yaml`: AWS keys, a Google
  service-account JSON, or an Azure service principal — see
  [Cloud credentials](#cloud-credentials-awsgcpazure).
- 🧰 **Misconfig & CVE hunting, safely** — dedicated agents for absurd
  misconfigs (exposed `.git`/`.env`, debug/actuator, default creds, dashboards,
  CORS), a **CVE Hunter** (smart, targeted `nuclei`), a **PoC Developer** (writes
  reproducible scripts to the run's `pocs/`), and **rate-limit** testing — all
  under a strict **data-safety/PII guardrail** (no destructive or state-changing
  actions; PII proven with a masked sample, never dumped).
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

## 🔌 Integrations (GitHub · GitLab · Jira)

Wire NeuroSploit into your SDLC. Toggle from the REPL (`/integrations`) or the CLI
(`neurosploit integrations enable github|gitlab|jira`). **Tokens are never stored**
— only the *name* of the env var is saved; the value is read from your environment.

```bash
export GITHUB_TOKEN=ghp_...                 # PAT with `repo` scope (private repos)
neurosploit integrations enable github

# Review a Pull Request's code (clones the PR head, white-box) and comment back:
neurosploit pr digininja/DVWA 42 --subscription --model anthropic:claude-opus-4-8 --comment

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
| **GitHub** | private clone · `pr` review + comment · `watch` branch | `GITHUB_TOKEN` |
| **GitLab** | private clone for whitebox/greybox | `GITLAB_TOKEN` |
| **Jira** | one card per finding (`--jira`) | `JIRA_EMAIL`, `JIRA_API_TOKEN` |

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
export OPENROUTER_API_KEY=...              # openrouter:*
# ollama needs no key (local)

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
| `openrouter:` | `OPENROUTER_API_KEY` | openrouter.ai |
| `ollama:` | _(none)_ | localhost:11434 |

Run `./target/release/neurosploit models` for the full provider/model list.

#### 2) Via subscription (no API key)

`--subscription` drives your local agentic-CLI login instead of an API key —
install and log into one of the CLIs first:

| `--model` prefix | CLI used | Login |
|------------------|----------|-------|
| `anthropic:` | `claude` (Claude Code) | `claude` then `/login` |
| `openai:` | `codex` | `codex` login |
| `gemini:` | `gemini` | `gemini` login |
| `xai:` | `grok` | `grok` login |

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

## Agent library — `agents_md/` (303)

| Category | Count | Purpose |
|----------|-------|---------|
| `vulns/` | 196 | Exploit a specific vulnerability class |
| `recon/` | 12 | Information gathering / attack surface |
| `code/` | 78 | White-box source-code (SAST) review |
| `meta/` | 17 | Orchestrator, validator, scorers, reporter, RL |

Each agent is a self-contained markdown playbook (`## User Prompt` methodology +
`## System Prompt` strict anti-false-positive rules). Drop a new `.md` into the
matching folder and the harness picks it up.

---

## Safety

For **authorized** testing only. Agents are instructed to stay in scope, never run
destructive/DoS actions, and require proof-of-exploitation. You are responsible for
having permission for any target.

## Credits

**Joas A Santos** & **Red Team Leaders**.

## License

MIT.
