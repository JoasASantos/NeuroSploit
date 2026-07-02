# NeuroSploit v3.5.5 — Release Notes

**Release Date:** July 2026
**Codename:** Cloud Testing, REPL Navigation & Deeper Recon
**License:** MIT
**Credits:** Joas A Santos & Red Team Leaders

---

## TL;DR

v3.5.5 adds **cloud infrastructure testing** (AWS / GCP / Azure) with first-class
credential connection, **27 new agents** (17 cloud + 10 misconfig/CVE/PoC/rate-
limit → library **375**), a much more capable and navigable **REPL** (idle
guardrail, multi-target, results browser), **deeper recon** (downloads & analyzes
JS, request/response differentials, smart nuclei), **Burp/ZAP proxy** support, a
**PoC** workspace, a strict **data-safety/PII guardrail**, and a fix for garbled
interactive line-editing.

## Cloud testing

- **+17 cloud agents.** AWS, GCP and Azure specialists in
  `agents_md/infra/`: IAM/RBAC privilege escalation, storage exposure
  (S3 / GCS / Blob), compute & network exposure + IMDS, secrets (Secrets Manager /
  Secret Manager / Key Vault), service-account & service-principal abuse, and
  Entra ID enumeration — plus a multi-cloud footprint/identity recon agent.
  Read-only-first, non-destructive.
- **Connect cloud credentials via `creds.yaml`** (`aws:`, `gcp:`, `azure:`
  blocks). The harness exports the right env vars so `aws` / `gcloud` / `az` pick
  them up automatically, and tells the agents how to authenticate & what to
  enumerate:
  - **AWS** — `access_key_id`/`secret_access_key`[/`session_token`]/`region`, or a `profile`.
  - **GCP** — a service-account JSON (`service_account_json`, path recommended) →
    `GOOGLE_APPLICATION_CREDENTIALS` + project.
  - **Azure** — a **service principal** (`tenant_id`/`client_id`/`client_secret`/
    `subscription_id`) → `az login --service-principal`.
  - Secrets are never written to disk beyond your `creds.yaml`; inline GCP JSON is
    materialized to a temp file only to satisfy the SDK/CLI.

## REPL — navigation & control

- **Idle guardrail — `/timeout <min>`.** If no NEW finding lands within the
  window, the run soft-stops and validates what was found (`/timeout 1` = 1 min,
  `10` = 10 min, `60` = 1 hour, `0` = off). **Default 5 min.**
- **Multiple targets — `/target url1,url2,url3`.** A comma-separated list; `/run`
  tests them **sequentially** (a queue auto-advances to the next when the current
  finishes) — one report per URL.
- **`/results` navigation browser** (interactive): pick a **target/run** → pick a
  **vulnerability** → see full detail; **Esc steps back a level** (vuln → target →
  back to the live session).
- **`/report` selection**: with multiple runs, choose which report to open from a
  menu.
- **`/chain <n>`** (attack-chain depth), **`/agents list`** (library category
  counts incl. infra/cloud); **`/show`** now shows chain-depth, idle-stop and
  enabled integrations.
- **Fix:** the interactive prompt no longer embeds ANSI/newline, so line editing
  (typing, backspace, history, cursor, multiline) is no longer garbled in a real
  terminal (the readline prompt is plain; color is applied via the highlighter).

## Deeper recon & analysis (agent prompts)

- **Deterministic HTTP probe (native, `harness::probe`).** Before the model
  recon, the harness performs a **real** request/response analysis of the target
  and injects the observed facts into recon so agent-selection and exploitation
  decisions are grounded in evidence (more robust — works even when the model's
  recon is weak): status & redirect, `Server`/`X-Powered-By`/content-type, the 6
  security headers (present/missing), **cookie flags** (HttpOnly/Secure/SameSite),
  **CORS reflection** test (arbitrary Origin + credentials), tech fingerprint,
  linked scripts, form count, a **404 baseline** for soft-404 differentials, and
  a few high-signal paths (`/robots.txt`, `/.git/config`, `/.env`, …). Best-effort
  (never fatal), honors the identifying User-Agent and the Burp/ZAP proxy.
- **RECON_SYS** now crawls pages/params/headers/cookies, **downloads the linked
  JavaScript and analyzes it** (API endpoints, hidden params, GraphQL, secrets /
  keys / tokens, `sourceMappingURL` → recover original source), fingerprints
  **exact** stack versions, and does response-differential analysis; richer JSON
  schema (`js_findings`, `secrets`, `hosts`, …).
- **tool_doctrine** adds JS-analysis (linkfinder / gau / katana + grep for
  endpoints/secrets/source-maps) and request/response-analysis guidance (status,
  all headers, Set-Cookie flags, timing/length differentials, auth-vs-anon and
  valid-vs-invalid comparisons) — applied to both recon and exploitation.

## Exploitation depth, safety & Burp

- **+10 exploitation agents.** Absurd-misconfig hunters (exposed `.git`/`.env`/
  backups, debug/actuator endpoints, default creds, directory listing, exposed
  ops dashboards, permissive CORS, verbose errors), a **CVE Hunter** (fingerprint
  → correlate → safe PoC), a **PoC Developer** (writes runnable exploit scripts),
  and a **Rate-Limit / Anti-Automation** tester.
- **Data-safety / PII guardrail** injected into every exploit/chain/host prompt:
  no modifying, deleting, exfiltrating data or changing state without explicit
  permission; on PII, prove with a single **masked** sample + a count — never
  dump. When unsure an action is safe, don't do it.
- **Smart nuclei in recon** — fingerprint first, then run nuclei on **targeted**
  templates/tags/CVE ids with rate/timeouts (fast, never a blind full scan).
- **Burp/ZAP proxy** — `/proxy <url>` (or `/burp`, default `:8080`) in the REPL,
  or the `NEUROSPLOIT_PROXY` env var. Agents route curl through it (`--proxy … -k`)
  so you can inspect/replay traffic in Burp Suite while the test runs.
- **PoC workspace** — each run gets a `pocs/` directory (`$NEUROSPLOIT_POCS`);
  agents save custom, reproducible exploit scripts there and cite them as evidence.
- **Tool download** (authorized) — agents may `git clone` a specific public PoC/
  exploit repo or download a scanner when needed (reputable/pinned, reviewed).
- **Rate-limit testing** is a first-class control check (small non-disruptive
  burst → look for 429/lockout/Retry-After), never a DoS.

## Multi-role auth & access-control testing

- **Named identities in `creds.yaml`** for IDOR / BOLA / BFLA / privilege-escalation
  testing. Define two or more roles and the agent authenticates as each and tests
  **cross-role access** (control vs unauthorized request):
  ```yaml
  admin:
    jwt: eyJ...              # or header:/cookie:/apikey:/login+username+password
  user:
    apikey: abc123          # → X-Api-Key: abc123
  victim:
    cookie: "session=..."
  ```
  Supported per role: `jwt`, `header` (raw), `cookie`, `apikey`, or a
  `login`/`username`/`password` self-login. With ≥2 roles the harness injects an
  access-control directive (capture one role's object IDs/functions, attempt them
  as another role, prove authorized-vs-denied) under the data-safety guardrail.

## Attribution & identification (anti-plagiarism)

- **Identifying User-Agent** on every request — default
  `NeuroSploit/<ver> (authorized security assessment; +github…)`, plus an
  `X-NeuroSploit-Scan` header. Change it with **`/ua <string>`** (REPL) or the
  `NEUROSPLOIT_UA` env var; the run banner shows it.
- **Attribution stamped into every finding** ("Identified and validated by
  NeuroSploit — multi-model adversarial validation …") so provenance travels with
  the finding across the report, `findings.json` and any copy — in the traffic,
  the finding text, and the report footer, so the work can't be silently re-badged.

## Notes

- Additive/back-compatible. Provider count is 14 (Azure OpenAI added in v3.5.2).
  See the README "Cloud credentials" section for a full `creds.yaml` example.

---

# NeuroSploit v3.5.4 — Release Notes

**Release Date:** July 2026
**Codename:** Robust Attack Chaining & False-Positive Reduction
**License:** MIT
**Credits:** Joas A Santos & Red Team Leaders

---

## TL;DR

v3.5.4 makes NeuroSploit both **deeper** and **more precise**: a real multi-round
**post-exploitation attack-chaining** engine that expands each foothold in new
directions, plus stronger **false-positive** controls so what it reports is
trustworthy.

## Attack chaining (robust, decision-driven)

Replaces the old single-shot chainer with **`attack_chain()`** — an iterative,
per-foothold pivot engine:

- **Per-foothold decisions.** Each round takes the newest confirmed footholds
  (best-first, capped per round) and, for **each one**, an agent decides which
  directions to expand and proves new impact: **post-exploitation** (loot
  creds/keys/config/source), **credential reuse**, **privilege escalation**
  (horizontal & vertical), **lateral movement** to adjacent services/hosts,
  **data exfiltration**, and **new attack surface** the foothold exposes.
- **Loot carried forward.** Credentials/tokens/hosts/endpoints discovered in one
  round are passed to later rounds and reused (agent returns
  `{"findings":[...],"loot":[...]}`), so the engine genuinely pivots in new
  directions instead of re-testing the same spot.
- **No pivoting off false positives.** Each round's new findings are validated
  before they become the next round's footholds.
- **Convergence.** Runs up to `chain_depth` rounds **or** stops when a round finds
  nothing new (loop-until-dry).
- **Control.** New `RunConfig.chain_depth` (default **2**) and a `--chain-depth`
  flag on every engagement command (`0` disables).

## False-positive reduction

- **Robust verdict parsing** (`pool::parse_verdict`) — whitespace-insensitive,
  checks explicit rejection first, counts only explicit confirmations; ambiguous
  replies are *not* counted as confirmed. Replaces the fragile exact-JSON /
  loose-`yes` matching.
- **Severity-aware quorum** (`pool::quorum_confirmed`) — **High/Critical now need
  ≥2 validators AND ≥2/3 agreement** (a single vote can no longer confirm a
  Critical); lower severities need a strict majority. Single-model panels fall
  back to majority so they aren't nuked.
- **Adversarial refute pass** — every confirmed High/Critical is re-examined by a
  skeptical panel that assumes false-positive; findings that can't withstand a
  majority of skeptics are dropped.
- **Stronger validator prompt** with an explicit false-positive checklist
  (reflected-not-executed, version/banner guesses, self-XSS, error-as-injection,
  thin evidence, inflated severity).

## Notes

- Additive and back-compatible; defaults keep behavior sensible if you change
  nothing. Unit tests cover verdict parsing, quorum, and report-hygiene logic.

---

# NeuroSploit v3.5.3 — Release Notes

**Release Date:** June 2026
**Codename:** Integrations (GitHub · GitLab · Jira)
**License:** MIT
**Credits:** Joas A Santos & Red Team Leaders

---

## TL;DR

v3.5.3 plugs NeuroSploit into your SDLC: review **private** GitHub/GitLab repos
and **Pull Requests**, **watch** a branch and re-review on every commit, and open
a **Jira card per finding** — all toggleable via a new `/integrations` command.

## Highlights

- **GitHub integration**
  - **Private repos**: when enabled, `whitebox` / `greybox --repo` / `tui --repo`
    inject your `GITHUB_TOKEN` into the clone URL (token never printed/stored).
  - **`neurosploit pr <owner/repo> <number>`** — clones the **PR head**
    (`refs/pull/N/head`), runs a white-box review, optionally **posts a summary
    comment** back on the PR (`--comment`) and/or **opens Jira cards** (`--jira`).
  - **`neurosploit watch <owner/repo> --branch <b> --interval <s>`** — polls the
    branch and runs a white-box review **each time a new commit lands**.
- **GitLab integration** — private clone (token-injected) for `whitebox`/`greybox`
  against `gitlab.com` or a self-hosted base.
- **Jira integration** — `--jira` on any engagement (or `pr`/`watch`) opens **one
  card per finding** (summary, severity, CVSS, CWE, location, PoC, evidence,
  remediation) in your project via the Jira REST API.
- **`/integrations` (REPL) + `neurosploit integrations` (CLI)** — `show`,
  `enable`/`disable <github|gitlab|jira>`, and `setup <jira|gitlab|github>`
  (interactive). Config persists to `<project>/.neurosploit/integrations.json`.
  **Secrets are never stored** — only the env-var *name* is saved; values come
  from the environment at use time.
- New harness module `integrations` + app commands `pr` / `watch` /
  `integrations`, plus a `--jira` flag on `run` / `whitebox`.

## Setup

Step-by-step for tokens, scopes and configuration is in
**[TUTORIAL-INTEGRATION.md](TUTORIAL-INTEGRATION.md)** and summarized in the README.

## Notes

- Additive and back-compatible: all existing modes/flags are unchanged; if no
  integration is enabled the behavior is identical to v3.5.2.
- Tokens use env vars: `GITHUB_TOKEN`, `GITLAB_TOKEN`, `JIRA_EMAIL` +
  `JIRA_API_TOKEN` (names configurable per integration).

---

# NeuroSploit v3.5.2 — Release Notes

**Release Date:** June 2026
**Codename:** Exploitation Depth & Report Hygiene
**License:** MIT
**Credits:** Joas A Santos & Red Team Leaders

---

## TL;DR

v3.5.2 hard-codes the discipline that separates a great pentest from a noisy
one — distilled from reviewing real AI-pentest output that kept stopping at
*"exposed"* instead of *"exploited"*. The engine now pushes every exposure to
demonstrated impact, **chains** findings, decodes/fingerprints artifacts and
correlates CVEs, audits tokens, and keeps the final report honest (deduplicated
and severity-calibrated).

## Highlights

- **DEPTH doctrine (exploit, don't just expose).** A new doctrine is injected
  into every exploitation prompt (black/grey/chain): any info-disclosure,
  exposed service/catalog/WSDL, leaked credential/token, or reachable dev host
  **must be USED** before it can be a finding — call it, decode it, log in, hit
  the dev host. If it was only observed, it's reported as a **lead**, not a
  confirmed High/Critical.
- **Finding chaining.** Reuse any session/JWT/cookie/credential obtained in one
  step across all other modules; pivot access into IDOR/privesc/exfil and report
  the **chain**, not isolated parts (e.g. captcha-bypass→admin JWT→authenticated
  surface; enum + no-rate-limit→password spraying).
- **Decode & fingerprint → CVE.** Decode opaque tokens/paths (base64/JSON/marshal)
  and pin exact library/gem/plugin/CMS versions, then correlate to known CVEs and
  attempt a safe PoC.
- **Token auditor.** JWT alg-confusion (RS→HS), `alg:none`, kid/jku injection,
  real signature verification, **weak HS256 secret cracking**, and token
  lifecycle (logout/expiry/refresh).
- **Report-hygiene & depth pass (deterministic, in the harness).** After
  validation the run now:
  - **calibrates severity to proven impact** — an unproven High/Critical
    (hedged language, no payload, thin evidence) is capped to Medium and
    re-titled "(potential)";
  - flags **"exposed → exploited" gaps** — exposures on a host with no actual
    exploit get an advisory to go use them;
  - advises **consolidating hygiene** classes (headers/cookies/TLS/HSTS/
    clickjacking/disclosure) repeated across many assets into ONE finding with
    an affected-asset table, instead of inflating the count one-per-host.
- **5 new doctrine meta-agents** (`agents_md/meta/`): `exploit_depth_doctrine`,
  `finding_chainer`, `artifact_decoder`, `token_auditor`, `report_calibrator`
  (meta agents 17 → 22; total library 343 → 348).
- **Source from a GitHub URL.** `whitebox` / `greybox --repo` (and the REPL
  `/repo`) now accept a **git URL** (`https://github.com/owner/repo[.git]`) or an
  `owner/repo` shorthand — the repo is cloned (shallow) into `<base>/repos/` and
  reviewed automatically, no manual `git clone` needed:
  ```bash
  neurosploit whitebox https://github.com/digininja/DVWA \
    --subscription --model anthropic:claude-opus-4-8 -v
  ```
- **Azure OpenAI provider** (resolves #21). OpenAI-compatible: set
  `AZURE_OPENAI_ENDPOINT` (+ optional `AZURE_OPENAI_API_VERSION`, default
  `2024-10-21`) and `AZURE_OPENAI_API_KEY`, then `--model azure:<deployment>`
  (the model name is your Azure *deployment* name; auth via the `api-key`
  header).
- **`GOOGLE_API_KEY` alias for Gemini** (resolves #25 confusion). Gemini's API
  path reads `GEMINI_API_KEY`, and now also accepts `GOOGLE_API_KEY` (Google's
  standard env var) when the former is unset. Local providers (ollama/litellm)
  still need **no** key at all.

## Notes

- Pure-additive and back-compatible: existing modes, REPL, TUI, pause/continue,
  crash-recovery and reports are unchanged. The hygiene pass only annotates and
  down-calibrates unproven severities — it never invents or drops findings.
- New unit tests cover the calibration and depth-audit logic
  (`harness::hygiene`).

---

# NeuroSploit v3.5.1 — Release Notes

**Release Date:** June 2026
**Codename:** Interactive POMDP Harness
**License:** MIT
**Credits:** Joas A Santos & Red Team Leaders

---

## TL;DR

The 3.5.x line turns the Rust harness into a full **interactive REPL** (Claude
Code / Codex / Cursor-CLI style) on top of the multi-model engine: pick models
with arrow-keys, configure API keys per provider, set target/repo/auth/creds and
free-text instructions that steer the agents, then `/run` engagements **in the
background** while you keep typing. v3.5.1 adds a **POMDP belief spine** with
anti-hallucination grounding ("no claim without a tool receipt"), **infra/host**
testing (IP + SSH + Windows/AD) with Linux/Windows/AD agents, **attack-chain
agents**, a **Mission-Control TUI**, structured **Typst** reports, and resilient
run control (live checkpointing, pause-on-quota, instant stop).

## Highlights

- **Interactive REPL** (`neurosploit` with no subcommand): real line editing
  (history ↑/↓, Ctrl-A/E/K, multiline), Tab-completion of `/commands` and
  `@filesystem-paths` (Claude-Code-style file menu), arrow-key model multi-select,
  per-provider API-key config, and a live context bar (`model · cwd · mode▸target`).
- **Engagement modes**: **black-box** (`run`), **white-box** SAST (`whitebox`,
  set `/repo`), **grey-box** (`greybox`, `/repo` + `/target`), **host/infra**
  (`/target <ip>` + `/creds` for SSH / Windows / AD), plus the **TUI** dashboard.
- **POMDP belief state** (`belief.rs`, `pomdp.rs`): a property-graph with
  probabilities + Bayesian update + Shannon-entropy uncertainty, a
  value-of-information planner, and a **grounding gate** (`grounding.rs`,
  `may_assert`) — findings must carry an empirical/symbolic **tool receipt**.
- **Infra / credentials** (`creds.rs`): multi-block YAML (jwt/header/cookie,
  HTTP login, SSH, Windows/AD); real automated login; Linux/Windows/AD agents.
- **Attack-chain agents**: sqli→rce→lpe, ssrf→aws, upload→lfi→rce, and more —
  injected as chain recipes during exploitation.
- **App-stack & CVE hunting**: IIS/.NET (tilde shortname, WebDAV, ViewState),
  CMS (WordPress/Joomla/Drupal), app-server consoles, known-CVE exploitation.
- **13 providers** incl. **LiteLLM** proxy and Gemini/xAI alongside the existing
  OpenAI-compatible set; **subscription mode** drives local agentic CLIs
  (claude/codex/gemini/grok) via stream-json.
- **Mission-Control TUI** (`ratatui`): concurrent activity/findings/targets panels
  with a non-blocking composer active during the run.
- **Structured Typst report**: executive summary, vulnerability-summary table,
  and per-finding sections (criticality, CVSS, OWASP/CWE, PoC, evidence,
  remediation) + an attack-graph / kill-chain mapping (OWASP/CWE/MITRE).
- **Per-project persistence** (`.neurosploit/`, no database): `session.json`,
  `runs.json`, `history.txt` — resumes automatically on reopen.

## Run control (new in 3.5.1)

- **Background `/run`** with a live progress bar, severity-colored findings, and
  the full `file://` report URL on completion/stop.
- **3-way `/stop`**: **[1]** validate findings so far → report · **[2]** raw
  report **now** without validating · **[3]** discard. Raw/discard abort
  in-flight agents immediately (running CLI children are killed via
  `kill_on_drop`); validate soft-stops so the validator still runs.
- **Crash/quit recovery**: every finding is checkpointed live to
  `.neurosploit/active_run.json`; an interrupted run is recovered into `/runs`
  on the next launch, so `/results`, `/finding` and `/report` keep working.
- **Pause-on-exhaustion**: when all models are rate-limited / out of quota the
  run **parks** (state kept) and prints `⏸ token/quota exhausted … PAUSED`.
  Resume with **`/continue`** when your quota renews, or switch with
  **`/model <provider:model>`** (or the `/model` selector) then **`/continue`**.
- **Inspection**: `/results` (live findings), `/finding` (pick one → full
  command + PoC + evidence), `/expand` / Ctrl-O (full untruncated commands),
  `/status`, `/diff`, `/retest`.

## Usage

```bash
cd neurosploit-rs && cargo build --release
./target/release/neurosploit                              # interactive REPL
./target/release/neurosploit run http://target -v --model anthropic:claude-opus-4-8
./target/release/neurosploit whitebox --repo /path/to/code   # white-box SAST
./target/release/neurosploit greybox  --repo /path --target http://target  # grey-box
./target/release/neurosploit run <ip> --creds creds.yaml     # host / infra
./target/release/neurosploit tui http://target --subscription --mcp
```

Cross-platform install (Linux / macOS / Windows, x64 + arm64) via `setup.sh` and
`install.ps1`. See **README.md** and **TUTORIAL.md** for the full walkthrough.

---

# NeuroSploit v3.4.0 — Release Notes

**Release Date:** June 2026
**Codename:** Rust Multi-Model Harness
**License:** MIT

---

## TL;DR

A new **Rust harness** (`neurosploit-rs/`) re-implements the autonomous runtime
as a single, fast binary built on `tokio` + `axum`. It drives a **pool of LLM
models** with concurrency limits, **provider failover**, and **N-model validator
voting** — multiple models must independently agree a finding is real before it
is reported — then serves its own solid web dashboard. It reuses the existing
`agents_md/` library (213 agents) unchanged.

## Highlights

- **`neurosploit-rs/` cargo workspace**: `harness` lib crate + `neurosploit`
  binary. `cargo build --release` → one static-ish binary.
- **Multi-model pool** (`pool.rs`): bounded concurrency + automatic **failover**
  across providers; the same panel is reused as the **validator voting** jury.
- **Pipeline** (`pipeline.rs`): recon → parallel agent exploitation (semaphore
  bounded) → **N-model adversarial vote** → score → report. Streams live
  progress over a channel.
- **11 providers / 31 models** (`models.rs`), all OpenAI-compatible: Anthropic,
  OpenAI, xAI, NVIDIA NIM, DeepSeek, Mistral, Qwen, Groq, Together, OpenRouter,
  Ollama. Models like **Qwen / DeepSeek / Llama** usable directly.
- **Axum web dashboard** (`app/`): multi-model selection panel, live execution
  console, findings, agent browser, embedded HTML report. Single binary serves
  the SPA — no npm/build.
- **CLI**: `neurosploit serve | run <url> | agents | models`, plus `--offline`
  mode to exercise the full pipeline without any API keys.

## Usage

```bash
cd neurosploit-rs && cargo build --release
./target/release/neurosploit serve                 # → http://127.0.0.1:8788
./target/release/neurosploit run https://t.example \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3
```

---

# NeuroSploit v3.3.0 — Release Notes

**Release Date:** June 2026
**Codename:** Autonomous MD-Agent Engine
**License:** MIT

---

## TL;DR

NeuroSploit's pentest agent has been **re-modeled into an autonomous,
markdown-driven engine**. You give it a URL; it composes a master prompt from a
curated library of **213 markdown agents** and drives a locally-installed
**agentic CLI backend** (Claude Code / Codex / Grok CLI, or a Claude
subscription) to run the engagement end-to-end — with **Playwright MCP** for
proof-of-execution and a **reinforcement-learning** loop that adapts agent
selection across runs. The old Python orchestration was retired to `legacy/`.

## Highlights

- **New engine `neurosploit_agent/`** + `./neurosploit` terminal launcher.
  Interactive (`./neurosploit`) or one-shot (`./neurosploit run <url>`).
- **213-agent markdown library (`agents_md/`)**: **196 vulnerability
  specialists** (now covering LLM/AI, cloud/K8s, modern API/auth, advanced
  injection, protocol smuggling, logic/crypto/supply-chain) + **17 meta-agents**.
- **Meta-agents for quality**: `recon`, `exploit_validator`,
  `false_positive_filter`, `severity_assessor`, `impact_evaluator`, `reporter`,
  and `rl_feedback` — the pipeline validates and adversarially refutes every
  candidate before it can become a finding.
- **Pluggable agentic CLI backends** with auto-detection: Claude Code, Codex,
  Grok CLI; **subscription mode** via Claude Code login.
- **Playwright MCP** wired in (`.mcp.json`) so agents prove client-side execution
  (XSS/CSTI) and capture DOM/network/screenshots instead of trusting reflection.
- **Reinforcement learning** (`neurosploit_agent/rl.py` + `meta/rl_feedback.md`):
  bounded per-agent weights with per-tech-stack affinity, persisted to
  `data/rl_state.json`.
- **Latest model registry** (`neurosploit_agent/models.py`): Anthropic Claude
  4.x, OpenAI, xAI Grok, Gemini, OpenRouter, Ollama, and **NVIDIA NIM** (PR #28,
  OpenAI-compatible `integrate.api.nvidia.com`, `nvapi-` keys).
- **Data-driven agent builder** `scripts/build_agents.py` for extending the
  library without boilerplate.

## Breaking changes

- The monolithic `neurosploit.py` orchestrator and Python agent classes moved to
  `legacy/` and are no longer the supported entrypoint. Use `./neurosploit`.
- Primary agent library moved from `prompts/agents/` to `agents_md/` (originals
  preserved; meta/role prompts split into `agents_md/meta/`).

## Upgrade notes

1. Install at least one agentic CLI: Claude Code, Codex, or Grok CLI.
2. `npx` (Node) is required for Playwright MCP.
3. Copy `.env.example` → `.env`; set a provider key (or use Claude subscription).
4. `./neurosploit backends` to confirm detection, then `./neurosploit`.

---

# NeuroSploit v3.0.0 — Release Notes

**Release Date:** February 2026
**Codename:** Autonomous Pentester
**License:** MIT

---

## Overview

NeuroSploit v3 is a ground-up overhaul of the AI-powered penetration testing platform. This release transforms the tool from a scanner into an autonomous pentesting agent — capable of reasoning, adapting strategy in real-time, chaining exploits, validating findings with anti-hallucination safeguards, and executing tools inside isolated Kali Linux containers.

### By the Numbers

| Metric | Count |
|--------|-------|
| Vulnerability types supported | 100 |
| Payload libraries | 107 |
| Total payloads | 477+ |
| Kali sandbox tools | 55 |
| Backend core modules | 63 Python files |
| Backend core code | 37,546 lines |
| Autonomous agent | 7,592 lines |
| AI decision prompts | 100 (per-vuln-type) |
| Anti-hallucination prompts | 12 composable templates |
| Proof-of-execution rules | 100 (per-vuln-type) |
| Known CVE signatures | 400 |
| EOL version checks | 19 |
| WAF signatures | 16 |
| WAF bypass techniques | 12 |
| Exploit chain rules | 10+ |
| Frontend pages | 14 |
| API endpoints | 111+ |
| LLM providers supported | 6 |

---

## Architecture

```
                      +---------------------+
                      |   React/TypeScript   |
                      |     Frontend (14p)   |
                      +----------+----------+
                                 |
                           WebSocket + REST
                                 |
                      +----------v----------+
                      |   FastAPI Backend    |
                      |   14 API routers     |
                      +----------+----------+
                                 |
              +---------+--------+--------+---------+
              |         |        |        |         |
         +----v---+ +---v----+ +v------+ +v------+ +v--------+
         | LLM    | | Vuln   | | Agent | | Kali  | | Report  |
         | Manager| | Engine | | Core  | |Sandbox| | Engine  |
         | 6 provs| | 100typ | |7592 ln| | 55 tl | | 2 fmts  |
         +--------+ +--------+ +-------+ +-------+ +---------+
```

**Stack:** Python 3.10+ / FastAPI / SQLAlchemy (async) / React 18 / TypeScript / Tailwind CSS / Vite / Docker

---

## Core Engine: 100 Vulnerability Types

The vulnerability engine covers 100 distinct vulnerability types organized in 10 categories with dedicated testers, payloads, AI prompts, and proof-of-execution rules for each.

### Categories & Types

| Category | Types | Examples |
|----------|-------|---------|
| **Injection** | 12 | SQLi (error, union, blind, time-based), Command Injection, SSTI, NoSQL, LDAP, XPath, Expression Language, HTTP Parameter Pollution |
| **XSS** | 3 | Reflected, Stored (two-phase form+display), DOM-based |
| **Authentication** | 7 | Auth Bypass, JWT Manipulation, Session Fixation, Weak Password, Default Credentials, 2FA Bypass, OAuth Misconfig |
| **Authorization** | 5 | IDOR, BOLA, BFLA, Privilege Escalation, Mass Assignment, Forced Browsing |
| **Client-Side** | 9 | CORS, Clickjacking, Open Redirect, DOM Clobbering, PostMessage, WebSocket Hijack, Prototype Pollution, CSS Injection, Tabnabbing |
| **File Access** | 5 | LFI, RFI, Path Traversal, XXE, File Upload |
| **Request Forgery** | 3 | SSRF, SSRF Cloud (AWS/GCP/Azure metadata), CSRF |
| **Infrastructure** | 7 | Security Headers, SSL/TLS, HTTP Methods, Directory Listing, Debug Mode, Exposed Admin, Exposed API Docs, Insecure Cookies |
| **Advanced** | 9 | Race Condition, Business Logic, Rate Limit Bypass, Type Juggling, Timing Attack, Host Header Injection, HTTP Smuggling, Cache Poisoning, CRLF |
| **Data Exposure** | 6 | Sensitive Data, Information Disclosure, API Key Exposure, Source Code Disclosure, Backup Files, Version Disclosure |
| **Cloud & Supply Chain** | 6 | S3 Misconfig, Cloud Metadata, Subdomain Takeover, Vulnerable Dependency, Container Escape, Serverless Misconfig |

### Injection Routing

Every vulnerability type is routed to the correct injection point:

- **Parameter injection** (default): SQLi, XSS, IDOR, SSRF, etc.
- **Header injection**: CRLF, Host Header, HTTP Smuggling
- **Body injection**: XXE
- **Path injection**: Path Traversal, LFI
- **Both (param + path)**: LFI, directory traversal variants

### XSS Pipeline (Reflected)

The reflected XSS engine is a multi-stage pipeline:

1. **Canary probe** — unique marker per endpoint+param to detect reflection
2. **Context analysis** — 8 contexts: html_body, attribute_value, script_string, script_block, html_comment, url_context, style_context, event_handler
3. **Filter detection** — batch probe to map allowed/blocked chars, tags, events
4. **AI payload generation** — LLM generates context-aware bypass payloads
5. **Escalation payloads** — WAF/encoding bypass variants
6. **Testing** — up to 30 payloads per param with per-payload dedup
7. **Browser validation** — Playwright popup/cookie/DOM/event verification (optional)

### POST Form Support

- HTML forms detected during recon with method, action, all input fields (including `<select>`, `<textarea>`, hidden fields)
- POST form testing includes **all form fields** (CSRF tokens, hidden inputs) — not just the parameter under test
- Redirect following for POST responses (search forms that redirect to results)
- Full HTTP method support: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD

---

## Autonomous Agent Architecture

### 3-Stream Parallel Auto-Pentest

The agent runs 3 concurrent streams via `asyncio.gather()`:

```
Stream 1: Recon          Stream 2: Junior Tester      Stream 3: Tool Runner
  - Crawl target           - Immediate target test       - Nuclei + Naabu
  - Extract forms           - Consume endpoint queue      - AI-selected tools
  - JS analysis             - 3 payloads/endpoint         - Dynamic install
  - Deep fingerprint        - AI-prioritized types        - Process findings
  - Push to queue           - Skip tested types           - Feed back to recon
        |                         |                             |
        +----------+--------------+-----------------------------+
                   |
            Deep Analysis (50-75%)
            Researcher AI (75%)    ← NEW
            Finalization (75-100%)
```

### Reasoning Engine (ReACT)

AI reasoning at strategic checkpoints (50%, 75%):

- **Think**: analyze situation, available data, findings so far
- **Plan**: recommend next actions, prioritize vuln types
- **Reflect**: evaluate results, adjust strategy

Token budget tracking with graceful degradation:
- 0-60% budget: full AI (reasoning + verification + enhancement)
- 60-80%: reduced (skip enhancement)
- 80-95%: minimal (verification only)
- 95%+: technical only (no AI calls)

### Strategy Adaptation

- **Dead endpoint detection**: skip after 5+ consecutive errors
- **Diminishing returns**: reduce testing on low-yield endpoints
- **Priority recomputation**: re-rank vuln types based on results
- **Pattern propagation**: IDOR on `/users/1` automatically queues `/orders/1`, `/accounts/1`
- **Checkpoint refinement**: at 30%/60%/90% refine attack strategy

### Exploit Chaining

10+ chain rules for multi-step attack paths:

- SSRF -> Internal service access -> Data extraction
- SQLi -> Database-specific escalation (MySQL, PostgreSQL, MSSQL)
- XSS -> Session hijacking -> Account takeover
- LFI -> Source code disclosure -> Credential extraction
- Auth bypass -> Privilege escalation -> Admin access

AI-driven chain discovery during finalization phase.

---

## Validation & Anti-Hallucination Pipeline

### 4-Layer Verification

Every finding passes through 4 independent verification layers before confirmation:

```
Finding Signal
    |
    v
[1] Negative Controls  — Send benign/empty probes. Same response = false positive (-60 penalty)
    |
    v
[2] Proof of Execution — Per-vuln-type proof checks (25+ methods). XSS: context analyzer.
    |                      SSRF: metadata markers. SQLi: DB error patterns. Score 0-60.
    v
[3] AI Interpretation  — LLM analyzes with anti-hallucination system prompt + per-type
    |                      proof requirements. Speculative language rejected.
    v
[4] Confidence Scorer  — Numeric 0-100 score. >=90 confirmed, >=60 likely, <60 rejected.
    |
    v
ValidationJudge (sole authority for finding approval)
```

### Anti-Hallucination System Prompts

12 composable anti-hallucination prompt templates injected into all 17 LLM call sites:

| Prompt | Purpose |
|--------|---------|
| `anti_hallucination` | Core: never claim vuln without concrete proof |
| `anti_scanner` | Don't behave like a scanner — reason like a pentester |
| `negative_controls` | Explain control test methodology |
| `think_like_pentester` | Manual testing mindset |
| `proof_of_execution` | What constitutes real proof per vuln type |
| `frontend_backend_correlation` | Don't confuse client-side vs server-side |
| `multi_phase_tests` | Two-phase testing (submit + verify) |
| `final_judgment` | Conservative final decision framework |
| `confidence_score` | Numeric scoring calibration |
| `anti_severity_inflation` | Don't inflate severity |
| `operational_humility` | Acknowledge uncertainty |
| `access_control_intelligence` | Data comparison, not status code diff |

100 per-vuln-type proof requirements (e.g., SSRF requires metadata content, not just status diff).

### Cross-Validation

- `_cross_validate_ai_claim()` — independent check for XSS, SQLi, SSRF, IDOR, open redirect, CRLF, XXE, NoSQL
- `_evidence_in_response()` — verify AI claim matches actual HTTP response
- Speculative language rejection ("might be", "could be", "possibly")
- Default `False` — findings rejected unless positively proven

### Access Control Intelligence

- BOLA/BFLA/IDOR use **data comparison** methodology (not status code diff)
- JSON field comparison between authenticated user responses
- Adaptive TP/FP learning across scans (9 patterns, 6 known FP patterns)
- Access control types auto-inject specialized prompts

---

## Kali Sandbox & Tool Execution

### Container-Per-Scan Architecture

Each scan gets its own isolated Kali Linux Docker container:

```
ContainerPool (global coordinator)
    |
    +-- Scan A: KaliSandbox (neurosploit-kali-abc123)
    |       +-- nuclei, naabu, httpx (pre-installed)
    |       +-- wpscan (installed on-demand)
    |       +-- sqlmap (installed on-demand)
    |
    +-- Scan B: KaliSandbox (neurosploit-kali-def456)
    |       +-- nuclei, httpx (pre-installed)
    |       +-- dirsearch (installed on-demand)
    |
    +-- max_concurrent, TTL, orphan cleanup
```

### 55 Security Tools

| Category | Count | Examples |
|----------|-------|---------|
| Pre-installed (Go) | 11 | nuclei, naabu, httpx, subfinder, katana, dnsx, ffuf, gobuster, dalfox, waybackurls, uncover |
| Pre-installed (APT) | 5 | nmap, nikto, sqlmap, masscan, whatweb |
| Pre-installed (System) | 12 | curl, wget, git, python3, pip3, go, jq, dig, whois, openssl, netcat, bash |
| APT on-demand | 15 | wpscan, dirb, hydra, john, hashcat, sslscan, amass, enum4linux, dnsrecon, fierce, crackmapexec |
| Go on-demand | 4 | gau, gitleaks, anew, httprobe |
| Pip on-demand | 8 | dirsearch, wfuzz, arjun, wafw00f, sslyze, commix, trufflehog, retire |

### Dynamic Tool Engine

- AI selects tools based on detected tech stack
- On-demand install → execute → collect results → cleanup
- Tool output parsed and converted to structured findings
- Results fed back into recon context for deeper testing

### Researcher AI Agent

Hypothesis-driven 0-day discovery agent with Kali sandbox access:

```
Observe (recon data + existing findings)
    |
    v
Hypothesize (AI generates targeted hypotheses)
    |          - Logic flaws, race conditions
    v          - CVE-based attacks, misconfigurations
Plan Tools (AI selects from 55+ tools)
    |
    v
Execute in Sandbox (isolated Kali container)
    |
    v
Analyze Results (AI verdicts: confirmed/rejected)
    |
    v
Loop (max 15 hypotheses, 30 tool executions, 5 iterations)
```

Enabled via: `ENABLE_RESEARCHER_AI=true` + per-scan checkbox in frontend.

---

## Intelligence Modules

### CVE Hunter

- Extracts software versions from headers, meta tags, error pages, JS files
- Searches NVD API (NIST National Vulnerability Database)
- Searches GitHub for public exploit PoCs
- Correlates CVEs with detected versions
- Optional API keys for higher rate limits

### Banner Analyzer

- 400 known vulnerable version signatures
- 19 end-of-life version categories
- Instant version-to-CVE mapping without API calls
- AI-assisted analysis for unknown versions

### Deep Recon

- JavaScript file crawling for API endpoints, secrets, route definitions
- Sitemap.xml and robots.txt parsing
- OpenAPI/Swagger schema discovery and enumeration
- Deep fingerprinting from multiple sources

### Endpoint Classifier

8 endpoint type categories with risk scoring:

| Type | Risk Weight | Priority Vulns |
|------|-------------|----------------|
| Admin | 0.95 | auth_bypass, privilege_escalation, default_credentials |
| Auth | 0.90 | auth_bypass, brute_force, weak_password |
| Upload | 0.85 | file_upload, xxe, path_traversal |
| API | 0.80 | idor, bola, bfla, jwt_manipulation, mass_assignment |
| Data | 0.75 | idor, bola, mass_assignment, data_exposure |
| Search | 0.70 | sqli_error, xss_reflected, nosql_injection |

### Parameter Analyzer

8 semantic categories for smart parameter prioritization:

- ID params (`id`, `uid`, `user_id`) -> IDOR, BOLA
- File params (`file`, `path`, `include`) -> LFI, Path Traversal
- URL params (`url`, `redirect`, `callback`) -> SSRF, Open Redirect
- Query params (`q`, `search`, `filter`) -> SQLi, XSS
- Auth params (`token`, `jwt`, `session`) -> JWT Manipulation, Auth Bypass
- Code params (`cmd`, `exec`, `template`) -> Command Injection, SSTI

### Payload Mutator

14 mutation strategies for WAF/filter bypass:

- Double encoding, Unicode escape, case variation
- Null byte injection, comment injection, concat bypass
- Hex encoding, newline/tab bypass, charset bypass
- Failure analysis: adapts strategy based on observed response patterns

### WAF Detection & Bypass

- 16 WAF signatures (Cloudflare, AWS WAF, Akamai, Imperva, F5, Sucuri, etc.)
- Passive detection (response headers) + active probing
- 12 bypass techniques per WAF type
- Auto-applied when WAF detected

---

## Request Infrastructure

### Resilient Request Engine

- Automatic retry with exponential backoff
- Rate limiting (requests/second configurable)
- Circuit breaker (open after N consecutive failures, half-open probe, close on success)
- Adaptive timeouts (increase on slow responses)
- Per-domain rate tracking

### Auth Manager

- Multi-user session management
- Login form detection and auto-authentication
- Cookie, Bearer, Basic, Header auth types
- Session refresh on expiry

---

## Multi-Agent Orchestration (Experimental)

Optional replacement for the 3-stream architecture. 5 specialist agents with handoff coordination:

| Agent | Budget | Responsibility |
|-------|--------|----------------|
| ReconAgent | 20% | Deep crawl, JS analysis, API enum, fingerprinting |
| ExploitAgent | 35% | Classify endpoints, prioritize params, test, mutate, validate |
| ValidatorAgent | 20% | Independent re-test, different payloads, reproducibility |
| CVEHunterAgent | 10% | Version extraction, NVD search, GitHub exploit search |
| ReportAgent | 15% | Finding enhancement, PoC generation, report creation |

3-phase pipeline: Parallel (Recon + CVE) -> Sequential (Exploit) -> Parallel (Validator + Report)

Enable: `ENABLE_MULTI_AGENT=true` in `.env`

---

## Frontend

### 14 Pages

| Page | Route | Description |
|------|-------|-------------|
| Home | `/` | Dashboard with stats, activity feed, severity charts |
| Auto Pentest | `/auto` | 3-stream display, live findings, AI reports, Kali checkbox |
| Scan Details | `/scan/:id` | Findings with validation badges, confidence scores, pause/resume/stop |
| New Scan | `/scan/new` | Quick/Full/Custom scan configuration |
| Reports | `/reports` | Report listing with HTML/PDF/JSON download |
| Report View | `/report/:id` | Interactive report viewer |
| Terminal Agent | `/terminal` | AI chat + command execution interface |
| Vuln Lab | `/vuln-lab` | Per-type challenge testing (100 types, 11 categories) |
| Task Library | `/tasks` | Reusable pentest task templates |
| Scheduler | `/scheduler` | Cron/interval scheduling with CRUD |
| Settings | `/settings` | LLM providers, model routing, feature toggles |
| Sandbox Dashboard | `/sandbox` | Kali container monitoring, tool status |
| Agent Status | `/agent/:id` | Real-time agent progress and logs |
| Realtime Task | `/realtime` | Live interactive testing session |

### Key UI Features

- **Real-time WebSocket updates**: live scan progress, findings, logs
- **Confidence badges**: green (>=90), yellow (>=60), red (<60) with breakdown details
- **Validation Pipeline display**: proof of execution, negative controls, scoring breakdown
- **Pause/Resume/Stop**: scan control with 5 internal checkpoints
- **Manual validation**: confirm/reject AI decisions
- **Screenshot evidence**: inline per-finding in PoC section
- **Rejected findings viewer**: expandable section with rejection reasons

---

## Report Generation

### Two Report Engines

| Engine | Format | Style |
|--------|--------|-------|
| Professional | HTML | Dark theme, collapsible findings, click-to-zoom screenshots, severity charts |
| OHVR | HTML | Observation-Hypothesis-Validation-Result methodology, PoC code blocks |

Both engines support:
- Executive summary (AI-generated)
- Severity breakdown with visual charts
- Per-finding: description, PoC, exploitation code, **inline screenshots**, impact, remediation, references
- Rejected findings section (AI-rejected, pending manual review)
- JSON export for programmatic consumption

### Screenshot Placement

Screenshots are embedded **inline within each vulnerability's PoC section** — directly associated with the finding they evidence. No separate gallery at the end.

```
Vulnerability Finding
  +-- Description
  +-- Proof of Concept
  |     +-- Observation
  |     +-- Hypothesis
  |     +-- Validation (payload + request)
  |     +-- Exploitation Code
  |     +-- Visual Evidence (screenshots)  <-- HERE
  |     +-- Result (impact)
  +-- Remediation
  +-- References
```

---

## Cross-Scan Learning

### Execution History

- Tracks attack success/failure across all scans
- Records: tech_stack + vuln_type + target + success rate
- `get_priority_types(tech_stack)` — returns types ranked by historical success
- Auto-influences AI prompts and testing priority in future scans
- Bounded storage (500 records, auto-save every 20)

### Access Control Learner

- Adaptive true-positive / false-positive pattern learning
- 9 detection patterns, 6 known FP patterns
- Influences ValidationJudge scoring in subsequent scans

---

## LLM Provider Support

| Provider | Models | Config |
|----------|--------|--------|
| Anthropic Claude | claude-3.5-sonnet, claude-3-opus, claude-3-haiku | `ANTHROPIC_API_KEY` |
| OpenAI | gpt-4o, gpt-4-turbo, gpt-3.5-turbo | `OPENAI_API_KEY` |
| Google Gemini | gemini-pro, gemini-1.5-pro | `GEMINI_API_KEY` |
| OpenRouter | Any model via unified API | `OPENROUTER_API_KEY` |
| Ollama | Any local model (llama, mistral, etc.) | `OLLAMA_BASE_URL` |
| LM Studio | Any local model | `LMSTUDIO_BASE_URL` |

### Model Routing

Optional task-type routing to different LLM profiles:

| Task Type | Recommended |
|-----------|-------------|
| Reasoning | High-capability (Claude Opus, GPT-4) |
| Analysis | Medium (Claude Sonnet, GPT-4-turbo) |
| Generation | Medium (Sonnet, GPT-4-turbo) |
| Validation | High-capability for accuracy |
| Default | Configurable |

Enable: `ENABLE_MODEL_ROUTING=true` with profiles in `config/config.json`

---

## Configuration

### Environment Variables

```bash
# LLM API Keys (at least one required)
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
OPENROUTER_API_KEY=

# Local LLM (no key needed)
#OLLAMA_BASE_URL=http://localhost:11434
#LMSTUDIO_BASE_URL=http://localhost:1234

# Feature Flags
ENABLE_MODEL_ROUTING=false
ENABLE_KNOWLEDGE_AUGMENTATION=false
ENABLE_BROWSER_VALIDATION=false
ENABLE_REASONING=true
ENABLE_CVE_HUNT=true
ENABLE_MULTI_AGENT=false
ENABLE_RESEARCHER_AI=true

# Optional API Keys
#NVD_API_KEY=
#GITHUB_TOKEN=

# Token Budget (comment out for unlimited)
#TOKEN_BUDGET=100000

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/neurosploit.db

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

---

## Installation

### Backend

```bash
cd /opt/NeuroSploitv2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API key(s)
```

### Frontend

```bash
cd frontend
npm install
npm run build
```

### Kali Sandbox (Optional)

```bash
docker build -f docker/Dockerfile.kali -t neurosploit-kali:latest docker/
```

### Run

```bash
# Backend (serves frontend static files too)
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Or development mode (frontend hot reload)
cd frontend && npm run dev  # Port 3000
python -m uvicorn backend.main:app --reload --port 8000
```

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.10+ | 3.12 |
| Node.js | 18+ | 20 LTS |
| Docker | 24+ | Latest (for Kali sandbox) |
| RAM | 4 GB | 8 GB |
| Disk | 2 GB | 5 GB (with Kali image) |

### Backend Dependencies

- **Framework**: FastAPI, Uvicorn, Pydantic
- **Database**: SQLAlchemy (async), aiosqlite
- **HTTP**: aiohttp
- **LLM**: anthropic, openai
- **Reports**: Jinja2, WeasyPrint
- **Scheduling**: APScheduler
- **Optional**: playwright, docker, mcp

### Frontend Dependencies

- **UI**: React 18, TypeScript, Tailwind CSS
- **State**: Zustand
- **HTTP**: Axios
- **Realtime**: Socket.IO Client
- **Charts**: Recharts
- **Icons**: Lucide React
- **Build**: Vite

---

## Known Limitations

- Anthropic API budget limits cause scan interruption — set a fallback provider in `.env`
- Multi-agent orchestration (`ENABLE_MULTI_AGENT`) is experimental
- Playwright browser validation requires Python 3.10+ and Chromium
- MCP server requires Python 3.10+
- Container-per-scan requires Docker daemon running
- Token budget tracking is approximate (estimates, not exact counts)
- CLI report (`neurosploit.py`) does not embed screenshots (backend reports do)

---

## File Structure

```
NeuroSploitv2/
+-- backend/
|   +-- api/v1/              # 14 API routers (111+ endpoints)
|   +-- core/                # 63 Python modules (37,546 lines)
|   |   +-- vuln_engine/     # 100-type vulnerability engine
|   |   |   +-- registry.py          # 100 vuln info + 100 tester classes
|   |   |   +-- payload_generator.py # 107 libraries, 477+ payloads
|   |   |   +-- ai_prompts.py        # 100 per-type AI decision prompts
|   |   |   +-- system_prompts.py    # 12 anti-hallucination templates
|   |   |   +-- testers/             # 12 tester modules
|   |   +-- autonomous_agent.py      # Main agent (7,592 lines)
|   |   +-- researcher_agent.py      # 0-day discovery AI
|   |   +-- reasoning_engine.py      # ReACT think/plan/reflect
|   |   +-- validation_judge.py      # Finding approval authority
|   |   +-- confidence_scorer.py     # Numeric 0-100 scoring
|   |   +-- proof_of_execution.py    # Per-type proof checks
|   |   +-- negative_control.py      # False positive detection
|   |   +-- request_engine.py        # Retry, rate limit, circuit breaker
|   |   +-- waf_detector.py          # 16 signatures, 12 bypasses
|   |   +-- strategy_adapter.py      # Dead endpoints, priority recompute
|   |   +-- chain_engine.py          # 10+ exploit chain rules
|   |   +-- exploit_generator.py     # AI-enhanced PoC generation
|   |   +-- cve_hunter.py            # NVD + GitHub exploit search
|   |   +-- deep_recon.py            # JS crawling, sitemap, API enum
|   |   +-- banner_analyzer.py       # 400 known CVEs, 19 EOL versions
|   |   +-- endpoint_classifier.py   # 8 types + risk scoring
|   |   +-- param_analyzer.py        # 8 semantic categories
|   |   +-- payload_mutator.py       # 14 mutation strategies
|   |   +-- xss_validator.py         # Playwright browser validation
|   |   +-- xss_context_analyzer.py  # 8 context detection
|   |   +-- auth_manager.py          # Multi-user session management
|   |   +-- token_budget.py          # Budget tracking + degradation
|   |   +-- agent_tasks.py           # Priority queue task manager
|   |   +-- agent_orchestrator.py    # Multi-agent coordinator
|   |   +-- specialist_agents.py     # 5 specialist agents
|   |   +-- execution_history.py     # Cross-scan learning
|   |   +-- access_control_learner.py# TP/FP adaptive learning
|   |   +-- report_generator.py      # Professional HTML reports
|   |   +-- report_engine/           # OHVR report engine
|   +-- models/              # 8 SQLAlchemy ORM models
|   +-- config.py            # Pydantic settings
|   +-- main.py              # FastAPI app entry
+-- frontend/
|   +-- src/
|   |   +-- pages/           # 14 React pages
|   |   +-- components/      # Reusable UI components
|   |   +-- services/        # API client + WebSocket
|   |   +-- store/           # Zustand state management
|   |   +-- types/           # TypeScript interfaces
+-- core/
|   +-- llm_manager.py       # 6-provider LLM routing
|   +-- tool_registry.py     # 55 security tools
|   +-- kali_sandbox.py      # Per-scan container management
|   +-- container_pool.py    # Global container coordinator
|   +-- sandbox_manager.py   # Sandbox abstraction layer
+-- docker/
|   +-- Dockerfile.kali      # Multi-stage Kali Linux image
|   +-- Dockerfile.backend   # Backend service
|   +-- Dockerfile.frontend  # Frontend builder
+-- config/
|   +-- config.json          # Profiles, roles, tools, routing
+-- data/
|   +-- vuln_knowledge_base.json  # 100 vulnerability entries
+-- neurosploit.py           # CLI entry point
+-- .env.example             # Environment template
```
