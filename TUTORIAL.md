# NeuroSploit — Tutorial & User Guide (v3.6.4)

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
   (it does *not* blindly run all 417).
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
neurosploit --version          # neurosploit 3.6.4
neurosploit agents             # {"vulns":196,...,"chains":12,"total":417}
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
# LiteLLM proxy: point at your gateway and route any model through it:
export LITELLM_BASE_URL=http://localhost:4000/v1   # your LiteLLM proxy
export LITELLM_API_KEY=sk-...                       # litellm:<model the proxy routes>

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

Reviews a **local code repository** with the 78 source-review (SAST) agents:
SQLi, command injection, SSRF, XSS, path traversal, insecure deserialization,
hardcoded secrets, weak crypto, auth/IDOR, XXE, SSTI, language-specific sinks
(PHP/Java/.NET/Go/Node/Python), and more.

```bash
# 1. clone or point at the code you own
git clone https://github.com/digininja/DVWA /tmp/DVWA

# 2. review it (subscription or --model with an API key)
neurosploit whitebox /tmp/DVWA --subscription --model anthropic:claude-opus-4-8 -v

# focus a specific class, cap agents, raise the voting bar:
neurosploit whitebox /tmp/DVWA --focus "injection and access control" \
  --max-agents 8 --vote-n 2 --model openai:gpt-5.5
```

**How it works**

1. **Collects source context** — walks the repo (skips `.git/node_modules/target/
   vendor`), reads supported source files into a bounded review context.
2. **Selects code agents** for the languages/frameworks it sees.
3. Each agent traces **source → sink** dataflow and must quote the **exact
   vulnerable lines as `file:line`**.
4. **Grounding is symbolic**: a finding is only kept if its `file:line` / quoted
   code actually exists in the reviewed source (no hallucinated locations).
5. **Validated** by cross-model voting, then reported with the code reference,
   CWE/OWASP, PoC and remediation.

**Tips**
- No `--mcp` is used in white-box (there's no live app to browse).
- For huge repos, narrow with `--focus` or point at a subdirectory.
- Each finding's `endpoint` field is the `file:line`; `evidence` quotes the code;
  `payload` is the PoC / vulnerable snippet — view it all with `/finding`.

### 5.3 Grey-box (code + live app)

The strongest mode: review the **source** *and* exploit the **running app**
together. Code-review findings become **leads** that the live agents confirm
against the deployed application (so a SQLi spotted in code is proven exploitable
on the running endpoint).

```bash
# code repo + the URL where that code is actually running
neurosploit greybox /tmp/DVWA --url http://localhost:8080/ \
  --creds creds.yaml --focus "auth and IDOR" \
  --subscription --model anthropic:claude-opus-4-8 --mcp -v
```

**How it works**

1. **Recon** the live app (`--url`).
2. **Review the source** with the code agents → produces a list of *leads*
   (suspected vulns with file:line).
3. **Live exploitation** runs with those leads injected as context, so agents go
   straight for the proven-in-code weaknesses and **prove them on the live app**
   (empirical receipt: real request/response).
4. Validate (cross-model) → chain → report.

**Notes**
- Pass `--creds creds.yaml` so agents test **authenticated** flows (login / JWT /
  cookie) — essential for IDOR/BOLA/auth findings.
- `--mcp` enables the Playwright browser for client-side proof (e.g. XSS firing).
- In the REPL: set **both** `/repo <path>` and `/target <url>` → grey-box is
  auto-selected; `/show` displays `mode: greybox (code + live)`.

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

### Runs are non-blocking

`/run` launches the engagement **in the background** and immediately returns the
prompt — you keep typing while it streams live above the prompt. While it runs:

- **`/status`** — live phase, a **progress bar** (agents done / total), elapsed
  time, token/cost and the possible findings so far.
- **`/stop`** — stop with a 3-way choice: **[1]** validate the findings found so
  far, then report · **[2]** raw report **now** without validating · **[3]**
  discard. Choices 2 and 3 abort in-flight agents immediately (running commands
  are killed); choice 1 stops launching new agents but lets validation finish.
- Findings are color-coded by severity (Critical = red … Info = grey), and a
  confirmed vote shows green ✓.
- When it finishes you get `◀ run #n done — N validated finding(s) · /results n · /report n`.

**Findings survive a crash/quit.** Every finding is checkpointed live to
`.neurosploit/active_run.json`. If the REPL is closed (or crashes) mid-run, the
next launch recovers them into `/runs` automatically (`↻ recovered interrupted
run …`), so `/results`, `/finding` and `/report` still work.

**If your tokens/quota run out, the run pauses instead of dying.** When every
candidate model is rate-limited/out of quota, the run **parks** (keeping all
state) and prints `⏸ token/quota exhausted … PAUSED`. Then either:

- wait for your quota to renew and type **`/continue`** to retry the same model, or
- switch model first — **`/model <provider:model>`** (or `/model` for the
  arrow-select menu) — then **`/continue`** to resume on the new model.

(When stdin is piped/non-interactive, `/run` falls back to blocking mode.)

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

One file covers web auth, **multiple roles** (for access-control testing), SSH,
Windows/AD and **cloud** (AWS/GCP/Azure). Mix only the blocks you need. It's a
small YAML subset — flat `key: value` plus one-level nested blocks (2-space indent),
`#` comments, values optionally quoted.

### 8.1 Web auth (single identity)

```yaml
# --- pick one ---
jwt: eyJhbGciOi...                 # → Authorization: Bearer <jwt>
# header: "X-Api-Key: abc123"      # any raw header, sent as-is
# cookie: "session=deadbeef"       # → Cookie: session=deadbeef

# --- OR an automated login the harness performs (real HTTP) to capture a session ---
login:
  url: http://localhost:8080/login
  method: POST
  username_field: username
  password_field: password
  username: admin
  password: password
  success: Logout                  # text shown on a successful login
```

- `jwt`/`header`/`cookie` are used as-is.
- A `login:` block is **executed** (real HTTP) to capture a live session
  cookie/token; if it fails, agents are told to authenticate themselves.

### 8.2 Multiple identities — access-control testing (IDOR / BOLA / BFLA / privesc)

Define two or more **named roles**. With ≥2 roles the harness authenticates as
each and tests **cross-role** access (a low-priv role reaching another user's
object or an admin-only function = finding), proving each with the
**authorized-vs-unauthorized** request pair. The name is free-form (`admin`,
`user`, `victim`, `low`, …); give each role **one** credential type:

```yaml
admin:
  jwt: eyJhbGciOi...               # Bearer token
user:
  apikey: abc123                   # → X-Api-Key: abc123  (or a full "Header: value")
victim:
  cookie: "session=deadbeef"
tester:                            # a role can log in itself instead:
  login: https://app.example/api/login
  username: tester
  password: Passw0rd!
```

Per role you may use: `jwt` · `header` (raw) · `cookie` · `apikey` · or
`login` + `username` + `password`. The first role also becomes the default
session for normal (non-access-control) tests.

### 8.3 Linux host (SSH) & Windows/AD

```yaml
ssh:
  host: 10.0.0.5
  port: 22
  user: ubuntu
  password: s3cret                 # or:
  key: /home/op/id_ed25519

windows:
  host: 10.0.0.10
  domain: CORP
  user: jdoe
  password: Winter2026!            # or pass-the-hash:
  hash: aad3b435b51404eeaad3b435b51404ee:NThashhere
```

`ssh:` / `windows:` tell **host-mode** agents how to authenticate (Linux enum /
privesc, Windows/AD via crackmapexec/impacket/evil-winrm/bloodhound).

### 8.4 Cloud (AWS / GCP / Azure)

Exports the right env vars so the `aws` / `gcloud` / `az` CLIs authenticate
automatically (read-only-first, non-destructive):

```yaml
aws:
  access_key_id: AKIA...
  secret_access_key: ...
  # session_token: ...             # for temporary creds
  region: us-east-1
  # profile: my-sso-profile        # alternative to keys

gcp:
  service_account_json: /path/to/sa.json   # path (recommended); inline JSON also works
  project: my-project-id

azure:                             # service principal (best for automation)
  tenant_id: ...
  client_id: ...
  client_secret: ...
  subscription_id: ...
```

### 8.5 Using it

```bash
neurosploit run https://app.example --creds creds.yaml \
  --subscription --model anthropic:claude-opus-4-8 -v
# host mode uses ssh:/windows:/cloud: — neurosploit host <ip> --creds creds.yaml
```

Or `/creds creds.yaml` in the REPL. **Secrets stay in your file** — nothing is
written elsewhere (inline GCP JSON is copied to a temp file only for the SDK).

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
  session.json     # your config (models, target, repo, auth, focus)
  runs.json        # run history (for /runs, /results, /report, /diff, /retest)
  active_run.json  # live checkpoint of an in-flight run (auto-recovered if interrupted)
  history.txt      # command history (↑/↓)
```

Close and reopen in the same folder → it **resumes** automatically
(`↻ resumed project session`). If a run was interrupted mid-flight, its
checkpointed findings are recovered into `/runs` (`↻ recovered interrupted run`).
No database needed — it's structured state.

---

## 12. How it decides

NeuroSploit treats the target as **partially observable** (a POMDP):

- **Belief world model** — a property graph whose nodes (host/service/vuln/
  exploit/credential) carry *probabilities*, updated by observations.
- **Value-of-information** — "scan more vs exploit now" falls out of belief
  entropy: when a node's belief is diffuse, recon is worth more than exploiting.
- **Anti-hallucination gate** (`may_assert`) — the agent may **not** claim
  exploitability while the belief is diffuse; it must observe more first.
- **Grounding** — **no claim without a receipt**: *empirical* for black-box /
  host / AI (real HTTP/OOB/error output), *symbolic* for white-box SAST & skills
  audits (a `file:line` reference into the reviewed source — the code citation is
  the receipt, no live target needed), and *either* for grey-box. Ungrounded
  claims are demoted and flagged.
- **Chaining** — confirmed findings are chained into deeper impact, each stage
  proven before advancing.

White-box collapses the POMDP toward a near-deterministic MDP (the world model is
built from SAST/dataflow), so uncertainty becomes *path reachability*, not state.

---

## 13. The agent library

`agents_md/` holds **417** markdown agents in categories:

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
